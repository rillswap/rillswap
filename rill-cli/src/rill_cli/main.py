"""Explicit age recovery, Core sampling, and create-only refund construction."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
import sys
import warnings
from pathlib import Path
from typing import TYPE_CHECKING

from pyrage import x25519
from rill_core.recovery import inspect_recovery_successor
from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    max_spendable_fee,
    validate_unilateral_spend,
)
from rill_core.wire.types import NetworkIdentity
from rill_crypto import Context
from rill_provider.lnd_invoice_observation import LndInvoiceObserver
from rill_provider.relay_client import RelayError

from rill_cli import provider_directory, refund_watcher, swap_command, treasury_cli
from rill_cli.age_container import (
    MAX_CIPHERTEXT_BYTES,
    MAX_PLAINTEXT_BYTES,
    PassphraseCredentials,
    RecoveryCredentials,
    X25519Credentials,
    construct_container_selected_claim,
    construct_container_selected_refund,
    decrypt_verified_plaintext,
    encrypt_verified_plaintext,
    inspect_container,
    inspect_container_recorded_claim_txid,
    inspect_container_selected_funding_context,
    verify_export_ciphertext,
)
from rill_cli.claim_disclosure import (
    ClaimDisclosureRefusedError,
    ClaimDisclosureUnknownError,
    ClaimIntentUncertainError,
    disclose_claim_on_regtest,
)
from rill_cli.claim_plan import prepare_encrypted_claim_plan, verify_encrypted_claim_plan
from rill_cli.claim_watcher import ClaimWatcher
from rill_cli.live_swap import SwapError
from rill_cli.publication import (
    RecoveryPublicationUncertainError,
    publish_new_ciphertext,
)
from rill_cli.recovery_core_observation import RecoveryCoreReader
from rill_cli.refund_broadcast import (
    RefundPreflightError,
    RefundSubmissionUnknownError,
    create_refund_intent,
    submit_prepared_refund,
    verify_refund_intent,
)
from rill_cli.refund_publication import (
    RefundPublicationUncertainError,
    publish_new_broadcast_intent,
    publish_new_signed_refund,
)

if TYPE_CHECKING:
    from rill_core.recovery import OfflineRecoveryInspection, SelectedRecoveryFundingContext


class RecoveryCLIError(ValueError):
    """CLI input is incomplete or unsupported for an explicit recovery action."""


MAX_NETWORK_FILE_BYTES = 4096
MAX_IDENTITY_FILE_BYTES = 1024


def _parser() -> argparse.ArgumentParser:  # noqa: PLR0915 - one flat command table
    parser = argparse.ArgumentParser(
        prog="rill", description="Pre-release RillSwap client and recovery tools"
    )
    parser.add_argument(
        "--log-format",
        choices=("text", "json"),
        default="text",
        help="stderr diagnostics (stdout results are unchanged)",
    )
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING"), default="INFO")
    recover = parser.add_subparsers(dest="category", required=True)
    swap_command.add_parser(recover)
    provider_directory.add_parser(recover)
    treasury_cli.add_parser(recover)
    recovery = recover.add_parser("recover", help="encrypted recovery files (no chain or payments)")
    commands = recovery.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("export", "create a new age file from canonical stdin"),
        ("export-update", "create a successor snapshot relative to one supplied prior file"),
    ):
        export = commands.add_parser(name, help=help_text)
        export.add_argument("--network", required=True, help="complete trusted network JSON file")
        export.add_argument(
            "--crypto-library", required=True, help="verified local native library path"
        )
        export.add_argument("--recipient", required=True, help="one X25519 age public recipient")
        export.add_argument(
            "--identity", required=True, help="protected matching age secret-key file"
        )
        export.add_argument(
            "--output", required=True, help="create-only destination under trusted directory"
        )
        if name == "export-update":
            export.add_argument("--previous", required=True, help="explicit prior X25519 age file")
    inspect = commands.add_parser("inspect", help="redacted offline static inspection")
    inspect.add_argument("--network", required=True, help="complete trusted network JSON file")
    inspect.add_argument(
        "--crypto-library", required=True, help="verified local native library path"
    )
    decrypt_mode = inspect.add_mutually_exclusive_group(required=True)
    decrypt_mode.add_argument("--identity", help="protected age X25519 secret-key file")
    decrypt_mode.add_argument(
        "--passphrase-prompt", action="store_true", help="prompt via terminal"
    )
    inspect.add_argument("file", help="encrypted age v1 binary recovery file")
    for command, description in (
        ("observe-funding", "explicit regtest candidate (never signing authority)"),
        ("observe-claim", "read-only LN-to-BTC claim candidate (no preimage)"),
        ("prepare-claim", "create encrypted LN-to-BTC claim plan (no disclosure)"),
        ("broadcast-claim", "EXPERIMENTAL regtest preimage disclosure and one send"),
        ("sign-refund", "explicit BTC-to-LN refund artifact (never broadcasts)"),
        ("broadcast-refund", "explicit refund submit (never retries)"),
        ("watch-refund", "refund a failed swap with fee escalation until it confirms"),
        ("watch-claim", "claim an LN-to-BTC swap with fee escalation until it confirms"),
    ):
        operation = commands.add_parser(command, help=description)
        operation.add_argument(
            "--network", required=True, help="complete trusted network JSON file"
        )
        operation.add_argument(
            "--crypto-library", required=True, help="verified native library path"
        )
        operation.add_argument(
            "--funding-attempt-id", required=True, help="exact recorded attempt hex"
        )
        operation.add_argument("--binding-revision", required=True, type=int, help="exact revision")
        operation.add_argument(
            "--rpc-cookie", required=True, help="protected local Core cookie path"
        )
        operation.add_argument("--rpc-port", required=True, type=int, help="local Core RPC port")
        operation.add_argument("--rpc-host", default="127.0.0.1", help="numeric loopback only")
        mode = operation.add_mutually_exclusive_group(required=True)
        mode.add_argument("--identity", help="protected age X25519 secret-key file")
        mode.add_argument("--passphrase-prompt", action="store_true", help="prompt via terminal")
        if command in {"sign-refund", "broadcast-refund", "prepare-claim"}:
            operation.add_argument("--fee-sat", required=True, type=int, help="exact spend fee")
            if command == "sign-refund":
                operation.add_argument(
                    "--output", required=True, help="create-only raw transaction file"
                )
            elif command == "broadcast-refund":
                operation.add_argument(
                    "--intent",
                    required=True,
                    help="create-only durable exact-byte submission intent",
                )
            else:
                operation.add_argument(
                    "--output", required=True, help="create-only encrypted claim plan file"
                )
        if command == "watch-refund":
            operation.add_argument(
                "--intent-dir", required=True, help="directory of create-only attempt records"
            )
            operation.add_argument("--initial-fee-sat", required=True, type=int)
            operation.add_argument(
                "--max-fee-sat", required=True, type=int, help="capped by the signed terms"
            )
            operation.add_argument(
                "--escalate-blocks", type=int, default=12, help="blocks to reach the maximum"
            )
            operation.add_argument("--poll-seconds", type=float, default=30.0)
            evidence = operation.add_mutually_exclusive_group(required=True)
            evidence.add_argument(
                "--lnd-port", type=int, help="your LND holding the invoice (with the two below)"
            )
            evidence.add_argument(
                "--chain-only",
                action="store_true",
                help="the invoice is not in your LND: refund past the lock height while the "
                "funding output is unspent, without checking whether the invoice was paid",
            )
            operation.add_argument("--lnd-tls-cert")
            operation.add_argument("--lnd-invoice-macaroon", help="invoices:read macaroon")
        if command == "watch-claim":
            operation.add_argument("--initial-fee-sat", required=True, type=int)
            operation.add_argument(
                "--max-fee-sat", required=True, type=int, help="capped by the signed terms"
            )
            operation.add_argument("--poll-seconds", type=float, default=30.0)
        if command == "broadcast-claim":
            operation.add_argument("--plan", required=True, help="selected encrypted claim plan")
            operation.add_argument(
                "--intent", required=True, help="create-only encrypted disclosure intent"
            )
            operation.add_argument(
                "--acknowledge-regtest-preimage-disclosure",
                required=True,
                action="store_true",
                help="test-only key; may reveal it even on rejection",
            )
        operation.add_argument("file", help="explicit encrypted age recovery file")
    return parser


def _network(path: str) -> NetworkIdentity:
    with Path(path).open("rb") as stream:
        payload = stream.read(MAX_NETWORK_FILE_BYTES + 1)
    if len(payload) > MAX_NETWORK_FILE_BYTES:
        raise RecoveryCLIError("network file exceeds size limit")
    return NetworkIdentity.model_validate_json(payload)


def _identity(path: str) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb", closefd=True) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise RecoveryCLIError("age identity must be a private regular file")
        document = stream.read(MAX_IDENTITY_FILE_BYTES + 1)
    if len(document) > MAX_IDENTITY_FILE_BYTES:
        raise RecoveryCLIError("age identity file exceeds size limit")
    lines = document.decode("ascii").strip().splitlines()
    if len(lines) != 1 or not lines[0].startswith("AGE-SECRET-KEY-1"):
        raise RecoveryCLIError("age identity file must contain one X25519 key")
    return lines[0]


def _previous_ciphertext(path: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb", closefd=True) as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise RecoveryCLIError("prior snapshot must be a regular file")
        ciphertext = stream.read(MAX_CIPHERTEXT_BYTES + 1)
    if not 0 < len(ciphertext) <= MAX_CIPHERTEXT_BYTES:
        raise RecoveryCLIError("prior snapshot exceeds size limit")
    return ciphertext


def _prompt() -> str:
    # getpass opens its own input terminal and can fall back to echoed stdin
    # even when given a tty for prompt output. Turn that warning into failure.
    with Path("/dev/tty").open("r+") as terminal, warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        answer = getpass.getpass("Age passphrase: ", stream=terminal)
    if not answer:
        raise RecoveryCLIError("passphrase must not be empty")
    return answer


def _report(report: OfflineRecoveryInspection) -> str:
    return json.dumps(
        {
            "network": report.network_name,
            "profile": report.profile_id,
            "refund_lock_height": report.refund_lock_height,
            "first_refund_eligible_height": report.first_refund_eligible_height,
            "recorded_binding_count": report.recorded_binding_count,
            "unproven": report.unproven,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _run(args: argparse.Namespace) -> str:  # noqa: PLR0911, PLR0912, PLR0915 - recovery boundaries
    network = _network(args.network)
    with Context(library_path=args.crypto_library) as crypto:
        if args.command in ("export", "export-update"):
            plaintext = sys.stdin.buffer.read(MAX_PLAINTEXT_BYTES + 1)
            if len(plaintext) > MAX_PLAINTEXT_BYTES:
                raise RecoveryCLIError("recovery input exceeds size limit")
            credentials = X25519Credentials(args.recipient, _identity(args.identity))
            previous = None
            if args.command == "export-update":
                previous = decrypt_verified_plaintext(
                    _previous_ciphertext(args.previous),
                    network,
                    credentials=credentials,
                    crypto=crypto,
                )
                inspect_recovery_successor(previous, plaintext, network, crypto=crypto)
            ciphertext = encrypt_verified_plaintext(
                plaintext, network, credentials=credentials, crypto=crypto
            )

            def readback(stored: bytes) -> OfflineRecoveryInspection:
                report = verify_export_ciphertext(
                    stored, plaintext, network, credentials=credentials, crypto=crypto
                )
                if previous is not None:
                    return inspect_recovery_successor(previous, plaintext, network, crypto=crypto)
                return report

            report = publish_new_ciphertext(
                args.output,
                ciphertext,
                verify_from_disk=readback,
            )
            prefix = (
                "Created encrypted successor snapshot relative only to supplied previous file. "
                if previous is not None
                else "Created encrypted recovery file. "
            )
            return prefix + "No funding authority. " + _report(report)
        if args.command in {
            "inspect",
            "observe-funding",
            "observe-claim",
            "prepare-claim",
            "broadcast-claim",
            "sign-refund",
            "broadcast-refund",
            "watch-refund",
            "watch-claim",
        }:
            if args.command in {"prepare-claim", "broadcast-claim"} and not args.identity:
                raise RecoveryCLIError("protected X25519 identity required for claim plan")
            inspection_credentials = (
                PassphraseCredentials(_prompt())
                if args.passphrase_prompt
                else _inspect_identity_credentials(args.identity)
            )
            with Path(args.file).open("rb") as stream:
                ciphertext = stream.read(MAX_CIPHERTEXT_BYTES + 1)
            if args.command == "inspect":
                return _report(
                    inspect_container(
                        ciphertext, network, credentials=inspection_credentials, crypto=crypto
                    )
                )
            selected = inspect_container_selected_funding_context(
                ciphertext,
                network,
                credentials=inspection_credentials,
                funding_attempt_id=args.funding_attempt_id,
                binding_revision=args.binding_revision,
                crypto=crypto,
            )
            if args.command in {"sign-refund", "broadcast-refund", "watch-refund"} and (
                selected.terms.profile_id != "btc-to-ln/v1"
                or selected.terms.refund_party != "client"
            ):
                raise RecoveryCLIError("selected recovery is not a client refund")
            if args.command in {
                "observe-claim",
                "prepare-claim",
                "broadcast-claim",
                "watch-claim",
            } and (
                selected.terms.profile_id != "ln-to-btc/v1" or selected.terms.claimant != "client"
            ):
                raise RecoveryCLIError("selected recovery is not a client claim")
            reader = RecoveryCoreReader(
                port=args.rpc_port,
                host=args.rpc_host,
                cookie_path=Path(args.rpc_cookie),
                network=network,
            )
            if args.command == "watch-claim":
                return _watch_claim(
                    args,
                    network,
                    selected,
                    reader=reader,
                    credentials=inspection_credentials,
                    crypto=crypto,
                )
            if args.command == "watch-refund":
                return _watch_refund(
                    args,
                    network,
                    selected,
                    reader=reader,
                    credentials=inspection_credentials,
                    crypto=crypto,
                )
            if args.command == "broadcast-claim":
                if not isinstance(inspection_credentials, X25519Credentials):
                    raise RecoveryCLIError("protected X25519 identity required")
                with Path(args.plan).open("rb") as stream:
                    plan_ciphertext = stream.read(MAX_CIPHERTEXT_BYTES + 1)
                result = disclose_claim_on_regtest(
                    reader,
                    selected.binding,
                    selected.terms,
                    keys=crypto,
                    recovery_ciphertext=ciphertext,
                    plan_ciphertext=plan_ciphertext,
                    network=network,
                    credentials=inspection_credentials,
                    funding_attempt_id=args.funding_attempt_id,
                    binding_revision=args.binding_revision,
                    intent_path=args.intent,
                )
                return json.dumps(
                    {
                        "kind": "experimental-regtest-claim-disclosure/v1",
                        "claim_txid": result.claim_txid,
                        "sampled_tip_hash": result.sampled_tip_hash,
                        "sampled_tip_height": result.sampled_tip_height,
                        "submission": "node_accepted",
                        "disclosure": "may_have_occurred",
                        "chain_observation": "unobserved_after_send",
                        "authority": "none (not LN settlement or safe first-disclosure proof)",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            if args.command in {"observe-claim", "prepare-claim"}:
                candidate = reader.observe_claim(selected.binding, selected.terms, keys=crypto)
            else:
                candidate = reader.observe(
                    selected.binding,
                    selected.terms,
                    keys=crypto,
                    for_refund=args.command in {"sign-refund", "broadcast-refund"},
                )
            if args.command in {"sign-refund", "broadcast-refund"}:
                funding = FundingOutput(
                    bytes.fromhex(selected.binding.funding_txid),
                    selected.binding.contract_vout,
                    int(selected.binding.contract_value_sat),
                    bytes.fromhex(selected.binding.contract_script_pubkey),
                )
                signed = construct_container_selected_refund(
                    ciphertext,
                    network,
                    credentials=inspection_credentials,
                    funding_attempt_id=args.funding_attempt_id,
                    binding_revision=args.binding_revision,
                    live_funding=funding,
                    sampled_tip_height=candidate.tip_height,
                    fee_sat=args.fee_sat,
                    auxiliary_random=os.urandom(32),
                    crypto=crypto,
                )
                authorization = UnilateralAuthorization.from_terms(
                    selected.terms,
                    funding,
                    "refund",
                    keys=crypto,
                )
                if args.command == "broadcast-refund":
                    validated = validate_unilateral_spend(signed, authorization, verifier=crypto)
                    if validated.fee_sat != args.fee_sat:
                        raise RecoveryCLIError("signed refund fee differs from requested fee")
                    intent = create_refund_intent(
                        signed,
                        txid=validated.txid,
                        binding=selected.binding,
                        terms=selected.terms,
                        fee_sat=args.fee_sat,
                        candidate=candidate,
                    )

                    def check_intent_readback(stored: bytes) -> None:
                        persisted_raw = verify_refund_intent(stored, intent)
                        persisted_spend = validate_unilateral_spend(
                            persisted_raw,
                            authorization,
                            verifier=crypto,
                        )
                        if (
                            persisted_raw != signed
                            or persisted_spend.txid != validated.txid
                            or persisted_spend.fee_sat != args.fee_sat
                        ):
                            raise RecoveryCLIError("persisted refund differs from selected spend")

                    publish_new_broadcast_intent(
                        args.intent,
                        intent,
                        verify_from_disk=check_intent_readback,
                    )
                    submitted_tip = submit_prepared_refund(
                        reader,
                        selected.binding,
                        selected.terms,
                        keys=crypto,
                        raw=signed,
                        expected_txid=validated.txid,
                    )
                    return json.dumps(
                        {
                            "kind": "explicit-regtest-refund-submission/v1",
                            "refund_txid": validated.txid,
                            "submission": "node_accepted",
                            "chain_observation": "unobserved_after_send",
                            "intent_path": str(Path(args.intent).absolute()),
                            "sampled_tip_hash": submitted_tip.tip_hash,
                            "broadcast_attempts_this_invocation": 1,
                            "authority": "none (not confirmed; no payment or lineage proof)",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                checked = None

                def verify_from_disk(stored: bytes) -> None:
                    nonlocal checked
                    checked = validate_unilateral_spend(stored, authorization, verifier=crypto)
                    if checked.fee_sat != args.fee_sat:
                        raise RecoveryCLIError("signed refund fee differs from requested fee")

                publish_new_signed_refund(args.output, signed, verify_from_disk=verify_from_disk)
                if checked is None:
                    raise RecoveryCLIError("signed refund readback was not verified")
                return json.dumps(
                    {
                        "kind": "offline-signed-btc-to-ln-refund/v1",
                        "funding_txid": selected.binding.funding_txid,
                        "contract_vout": selected.binding.contract_vout,
                        "refund_txid": checked.txid,
                        "fee_sat": checked.fee_sat,
                        "sampled_tip_hash": candidate.tip_hash,
                        "sampled_tip_height": candidate.tip_height,
                        "broadcast": False,
                        "authority": "none (manual chain recheck required before broadcast)",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            if args.command == "prepare-claim":
                if not isinstance(inspection_credentials, X25519Credentials):
                    raise RecoveryCLIError("protected X25519 identity required")
                prepared = prepare_encrypted_claim_plan(
                    ciphertext,
                    network,
                    credentials=inspection_credentials,
                    funding_attempt_id=args.funding_attempt_id,
                    binding_revision=args.binding_revision,
                    candidate=candidate,
                    fee_sat=args.fee_sat,
                    auxiliary_random=os.urandom(32),
                    crypto=crypto,
                )

                def verify_claim_readback(stored: bytes) -> object:
                    checked = verify_encrypted_claim_plan(
                        stored,
                        ciphertext,
                        network,
                        credentials=inspection_credentials,
                        funding_attempt_id=args.funding_attempt_id,
                        binding_revision=args.binding_revision,
                        crypto=crypto,
                    )
                    if checked != prepared.receipt:
                        raise RecoveryCLIError("encrypted claim plan readback differs")
                    return checked

                publish_new_ciphertext(
                    args.output,
                    prepared.ciphertext,
                    verify_from_disk=verify_claim_readback,
                )
                return json.dumps(
                    {
                        "kind": "encrypted-ln-to-btc-claim-preparation/v1",
                        "funding_txid": prepared.receipt.funding_txid,
                        "contract_vout": prepared.receipt.contract_vout,
                        "claim_txid": prepared.receipt.claim_txid,
                        "fee_sat": prepared.receipt.fee_sat,
                        "sampled_tip_hash": candidate.tip_hash,
                        "sampled_tip_height": candidate.tip_height,
                        "broadcast": False,
                        "preimage_external_disclosure": False,
                        "authority": "none (encrypted plan; no permission to reveal or broadcast)",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            if args.command == "observe-claim":
                return json.dumps(
                    {
                        "kind": "selected-claim-candidate-observation/v1",
                        "network_identity": network.model_dump(mode="json"),
                        "funding_attempt_id": selected.binding.funding_attempt_id,
                        "binding_revision": selected.binding.binding_revision,
                        "funding_txid": candidate.static_match.funding_txid,
                        "contract_vout": candidate.static_match.contract_vout,
                        "static_transaction_bytes_match": True,
                        "tip_hash": candidate.tip_hash,
                        "tip_height": candidate.tip_height,
                        "chain_only_confirmations": candidate.chain_only_confirmations,
                        "mempool_aware_unspent_sampled": True,
                        "refund_first_eligible_height": candidate.refund_first_eligible_height,
                        "required_funding_confirmations": selected.terms.funding_confirmations,
                        "claim_confirmation_blocks": (
                            selected.terms.timing_policy.claim_confirmation_blocks
                        ),
                        "authority": (
                            "none (staleable sample; no preimage release or claim permission)"
                        ),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            return json.dumps(
                {
                    "kind": "selected-funding-candidate-observation/v1",
                    "network_identity": network.model_dump(mode="json"),
                    "funding_attempt_id": selected.binding.funding_attempt_id,
                    "binding_revision": selected.binding.binding_revision,
                    "funding_txid": candidate.static_match.funding_txid,
                    "contract_vout": candidate.static_match.contract_vout,
                    "static_transaction_bytes_match": True,
                    "tip_hash": candidate.tip_hash,
                    "tip_height": candidate.tip_height,
                    "transaction_lookup_block_hash": candidate.transaction_lookup_block_hash,
                    "sampled_inclusion_height": candidate.sampled_inclusion_height,
                    "chain_only_confirmations": candidate.chain_only_confirmations,
                    "first_refund_eligible_height": candidate.refund_first_eligible_height,
                    "authority": "none (staleable candidate; no signing or action permission)",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        raise RecoveryCLIError("unsupported recovery command")


def _watch_claim(  # noqa: PLR0913 - explicit wiring of the collaborators
    args: argparse.Namespace,
    network: NetworkIdentity,
    selected: SelectedRecoveryFundingContext,
    *,
    reader: RecoveryCoreReader,
    credentials: RecoveryCredentials,
    crypto: Context,
) -> str:
    binding, terms = selected.binding, selected.terms
    funding = FundingOutput(
        bytes.fromhex(binding.funding_txid),
        binding.contract_vout,
        int(binding.contract_value_sat),
        bytes.fromhex(binding.contract_script_pubkey),
    )
    authorization = UnilateralAuthorization.from_terms(terms, funding, "claim", keys=crypto)
    chain, confirmations, submit = refund_watcher.core_claim_collaborators(reader, binding=binding)
    ciphertext = Path(args.file).read_bytes()
    deadline_height = terms.refund_lock_height - terms.timing_policy.claim_confirmation_blocks
    required = terms.funding_confirmations
    reached = False
    reported: int | None = None
    unavailable_reported = False

    def report(line: str) -> None:
        swap_command._report(line)  # noqa: SLF001 - shared command progress renderer

    # The live swap may already have broadcast the claim it prepared (and then
    # given up waiting): watch that one too, observation only.
    recorded = inspect_container_recorded_claim_txid(
        ciphertext,
        network,
        credentials=credentials,
        funding_attempt_id=args.funding_attempt_id,
        binding_revision=args.binding_revision,
        crypto=crypto,
    )
    if recorded is not None:
        report(f"also watching the claim {recorded} prepared by the live swap")

    def funded_chain() -> refund_watcher.ChainView | None:
        # The claim reveals the preimage, so it is signed only at the signed
        # funding depth; until then wait. Once reached, a reorg no longer
        # withholds a claim whose preimage may already be public. Past the
        # deadline the watcher itself decides (no first claim that late).
        nonlocal reached, reported, unavailable_reported
        view = chain()
        if view is None and not unavailable_reported:
            # Absence proves nothing: unconfirmed, spent, or Core unavailable.
            unavailable_reported = True
            report(
                f"no unspent confirmed contract output {binding.funding_txid}:"
                f"{binding.contract_vout} (unconfirmed, already spent, or Core "
                "unavailable); waiting"
            )
        elif view is not None:
            unavailable_reported = False
        if reached or view is None or view.tip_height > deadline_height:
            return view
        depth = confirmations(binding.funding_txid)
        depth = depth if type(depth) is int and depth > 0 else 0
        if depth >= required:
            reached = True
            return view
        if depth != reported:
            reported = depth
            report(f"funding {binding.funding_txid} at depth {depth}/{required}; waiting")
        return None

    def sign(fee: int, tip: int) -> tuple[bytes, str, int, int]:
        signed = construct_container_selected_claim(
            ciphertext,
            network,
            credentials=credentials,
            funding_attempt_id=args.funding_attempt_id,
            binding_revision=args.binding_revision,
            live_funding=funding,
            sampled_tip_height=tip,
            sampled_confirmations=confirmations(binding.funding_txid) or 0,
            fee_sat=fee,
            auxiliary_random=os.urandom(32),
            crypto=crypto,
        )
        checked = validate_unilateral_spend(signed, authorization, verifier=crypto)
        return signed, checked.txid, checked.fee_sat, checked.vsize

    watcher = ClaimWatcher(
        initial_fee_sat=args.initial_fee_sat,
        max_fee_sat=min(args.max_fee_sat, max_spendable_fee(authorization)),
        deadline_height=deadline_height,
        chain=funded_chain,
        confirmations=confirmations,
        sign=sign,
        submit=submit,
        report=report,
        poll_seconds=args.poll_seconds,
        recorded_txids=() if recorded is None else (recorded,),
    )
    outcome, claim_txid = watcher.run()
    return json.dumps(
        {
            "kind": "ln-to-btc-claim-watch/v1",
            "outcome": outcome,
            "claim_txid": claim_txid,
            "funding_txid": binding.funding_txid,
            "contract_vout": binding.contract_vout,
            "attempts": len(watcher.attempts),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _watch_refund(  # noqa: PLR0913 - explicit wiring of the collaborators
    args: argparse.Namespace,
    network: NetworkIdentity,
    selected: SelectedRecoveryFundingContext,
    *,
    reader: RecoveryCoreReader,
    credentials: RecoveryCredentials,
    crypto: Context,
) -> str:
    binding, terms = selected.binding, selected.terms
    funding = FundingOutput(
        bytes.fromhex(binding.funding_txid),
        binding.contract_vout,
        int(binding.contract_value_sat),
        bytes.fromhex(binding.contract_script_pubkey),
    )
    authorization = UnilateralAuthorization.from_terms(terms, funding, "refund", keys=crypto)
    intent_dir = Path(args.intent_dir)
    if not intent_dir.is_dir():
        raise RecoveryCLIError("intent directory must exist")
    attempts = refund_watcher.load_attempts(intent_dir, authorization, verifier=crypto)
    chain, confirmations, submit = refund_watcher.core_collaborators(reader, binding=binding)
    invoice_state = None
    if args.chain_only:
        if args.lnd_tls_cert is not None or args.lnd_invoice_macaroon is not None:
            raise RecoveryCLIError("--chain-only takes no LND credentials")
    else:
        if args.lnd_tls_cert is None or args.lnd_invoice_macaroon is None:
            raise RecoveryCLIError("--lnd-port needs --lnd-tls-cert and --lnd-invoice-macaroon")
        observer = LndInvoiceObserver(
            host="127.0.0.1",
            port=args.lnd_port,
            tls_certificate_path=args.lnd_tls_cert,
            invoice_macaroon_path=args.lnd_invoice_macaroon,
            network=network,
        )
        invoice_state = refund_watcher.lnd_invoice_state(
            observer, terms.invoice_binding.payment_hash
        )

    def sign(fee: int, tip: int) -> tuple[bytes, str, int, int]:
        signed = construct_container_selected_refund(
            Path(args.file).read_bytes(),
            network,
            credentials=credentials,
            funding_attempt_id=args.funding_attempt_id,
            binding_revision=args.binding_revision,
            live_funding=funding,
            sampled_tip_height=tip,
            fee_sat=fee,
            auxiliary_random=os.urandom(32),
            crypto=crypto,
        )
        checked = validate_unilateral_spend(signed, authorization, verifier=crypto)
        return signed, checked.txid, checked.fee_sat, checked.vsize

    watcher = refund_watcher.RefundWatcher(
        attempts=attempts,
        intent_dir=intent_dir,
        funding_txid=binding.funding_txid,
        contract_vout=binding.contract_vout,
        refund_lock_height=terms.refund_lock_height,
        initial_fee_sat=args.initial_fee_sat,
        max_fee_sat=min(args.max_fee_sat, max_spendable_fee(authorization)),
        escalate_blocks=args.escalate_blocks,
        chain=chain,
        invoice_state=invoice_state,
        report=swap_command._report,  # noqa: SLF001 - shared command progress renderer
        sign=sign,
        submit=submit,
        confirmations=confirmations,
        authorization=authorization,
        verifier=crypto,
        poll_seconds=args.poll_seconds,
    )
    outcome = watcher.run()
    return json.dumps(outcome, sort_keys=True, separators=(",", ":"))


def _inspect_identity_credentials(path: str) -> X25519Credentials:
    identity = _identity(path)
    recipient = x25519.Identity.from_str(identity).to_public()
    return X25519Credentials(str(recipient), identity)


def _swap(args: argparse.Namespace) -> int:
    try:
        result = swap_command.run(args, _network(args.network), _identity(args.identity))
    except SwapError as error:
        sys.stderr.write(f"Swap stopped: {error}\n")
        return 5
    except RelayError as error:  # raised before any wallet effect is attempted
        sys.stderr.write(f"Swap refused before funding: {error}\n")
        return 5
    except Exception:  # noqa: BLE001 - must not print secret native/library errors
        if args.command == "ln-to-btc":  # the provider funds and refunds; the user claims
            sys.stderr.write(
                "Swap failed. Keep all recovery files, check the payment in your Lightning "
                "wallet (`lncli listpayments` with LND) and do not pay again. If a funded "
                "recovery snapshot ('.funded') exists, claim with "
                "`rill recover watch-claim` before its refund lock.\n"
            )
        else:
            sys.stderr.write(
                "Swap failed. If a funded recovery snapshot ('.funded') exists, funds may be "
                "committed: keep it and refund after its lock height with `rill recover`.\n"
            )
        return 2
    sys.stdout.write(result + "\n")
    return 0


def _providers(args: argparse.Namespace) -> int:
    try:
        result = provider_directory.run(args, _network(args.network))
    except provider_directory.RelayQueryError:
        sys.stderr.write("Provider listing failed: no relay answered.\n")
        return 5
    except RelayError as error:
        sys.stderr.write(f"Provider listing refused: {error}\n")
        return 5
    except Exception:  # noqa: BLE001 - must not print native/library errors
        sys.stderr.write("Provider listing failed.\n")
        return 2
    sys.stdout.write(result + "\n")
    return 0


def main(argv: list[str] | None = None) -> int:  # noqa: PLR0911 - distinct failure exit codes
    """Run explicit recovery commands only; sanitize errors and private input."""
    args = _parser().parse_args(argv)
    from rill_provider.diagnostics import configure_logging  # noqa: PLC0415 - stderr only

    configure_logging(args.log_level, log_format=args.log_format)
    if args.category == "swap":
        return _swap(args)
    if args.category == "providers":
        return _providers(args)
    if args.category == "treasury":
        return treasury_cli.run(args)
    try:
        result = _run(args)
    except RecoveryPublicationUncertainError:
        sys.stderr.write(
            "Recovery destination may be published, durability unconfirmed; "
            "verify manually, do not fund, pay, reveal a preimage, or broadcast.\n"
        )
        return 3
    except RefundPublicationUncertainError:
        sys.stderr.write(
            "Signed refund output may exist, durability unconfirmed; verify manually; "
            "do not automatically retry or broadcast.\n"
        )
        return 3
    except RefundSubmissionUnknownError:
        sys.stderr.write(
            "Refund submission may have occurred; inspect exact durable intent and chain "
            "manually. Do not retry automatically or create another signed attempt.\n"
        )
        return 4
    except ClaimIntentUncertainError:
        sys.stderr.write(
            "Encrypted claim disclosure intent durability uncertain; do not retry or reveal.\n"
        )
        return 3
    except ClaimDisclosureUnknownError:
        sys.stderr.write(
            "Experimental claim preimage may have reached Core; submission unknown. "
            "Reconcile manually; never retry automatically.\n"
        )
        return 4
    except ClaimDisclosureRefusedError:
        sys.stderr.write(
            "Experimental claim refused before witness-bearing RPC; encrypted intent may remain. "
            "Do not retry automatically.\n"
        )
        return 2
    except RefundPreflightError:
        sys.stderr.write(
            "Refund preflight refused; no send attempted by this invocation. "
            "An intent may remain; do not automatically retry.\n"
        )
        return 2
    except Exception:  # noqa: BLE001 - must not print secret native/library errors
        sys.stderr.write("Recovery operation failed; no payment or funding authority.\n")
        return 2
    sys.stdout.write(result + "\n")
    return 0
