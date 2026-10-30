"""``rill swap btc-to-ln`` and ``rill swap ln-to-btc``: one live swap through a provider."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from rill_core.recovery import (
    COOPERATIVE_RESERVATION_EXTENSION,
    REVERSE_COOPERATIVE_RESERVATION_EXTENSION,
    REVERSE_DISCLOSURE_EXTENSION,
    REVERSE_FALLBACK_EXTENSION,
    inspect_recovery_successor,
)
from rill_core.wire.canonical import parse_json_strict
from rill_crypto import Context
from rill_provider.core_tx_bytes import MAX_FEE_ESTIMATE_CEILING_SAT_VB
from rill_provider.diagnostics import write_progress
from rill_provider.lnd_invoice_decode import LndInvoiceDecoder
from rill_provider.relay_client import RelayConnection, require_relay_route

from rill_cli.age_container import (
    X25519Credentials,
    encrypt_verified_plaintext,
    verify_export_ciphertext,
)
from rill_cli.external_wallet import ExternalWalletPayer, offline_invoice_decoder
from rill_cli.hold_payment import LndHoldPayer
from rill_cli.live_relay import LiveRelayConnection
from rill_cli.live_reverse_swap import ReverseSwapLimits, ReverseSwapOutcome, run_reverse_swap
from rill_cli.live_swap import SwapError, SwapLimits, SwapOutcome, run_swap
from rill_cli.publication import publish_new_ciphertext
from rill_cli.wallet_rpc import WalletRpc

if TYPE_CHECKING:
    import argparse
    from collections.abc import Callable

    from rill_core.recovery import OfflineRecoveryInspection
    from rill_core.wire.types import NetworkIdentity

    from rill_cli.live_reverse_swap import HoldPayer


def add_parser(categories: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``swap btc-to-ln`` and ``swap ln-to-btc``."""
    swap = categories.add_parser("swap", help="live swaps (moves real funds)")
    kinds = swap.add_subparsers(dest="command", required=True)
    forward = kinds.add_parser("btc-to-ln", help="pay a Lightning invoice with on-chain BTC")
    _common_arguments(forward)
    forward.add_argument("--invoice", required=True, help="BOLT11 invoice to be paid")
    forward.add_argument("--max-funding-fee-sat", type=int, default=5_000)
    forward.add_argument("--max-refund-fee-sat", type=int, default=5_000)
    forward.add_argument("--max-refund-delay-blocks", type=int, default=288)
    forward.add_argument("--fee-rate", type=int, default=2, help="funding sat/vB")
    forward.add_argument(
        "--claim-fee-floor-sat",
        type=int,
        default=1,
        help="minimum absolute cooperative claim fee in satoshis (own-node floor may be higher)",
    )
    forward.add_argument(
        "--max-fee-estimate-sat-vb",
        type=int,
        help="cap your Core's fee estimate when checking the cooperative claim fee "
        "(for skewed estimators such as signet's; relay and mempool floors still apply)",
    )
    forward.add_argument("--wallet", required=True, help="Core wallet that funds the swap")
    forward.add_argument("--lnd-macaroon", required=True, help="invoice-decoding macaroon")
    reverse = kinds.add_parser("ln-to-btc", help="receive on-chain BTC by paying over Lightning")
    _common_arguments(reverse, lnd_required=False)
    reverse.add_argument("--payout-sat", required=True, type=int, help="on-chain amount wanted")
    reverse.add_argument(
        "--pay-with",
        choices=("lnd", "external"),
        default="lnd",
        help="lnd: pay the hold invoice from your LND (needs --lnd-port, --lnd-tls-cert and "
        "--lnd-macaroon). external: show it as text and a QR code for any Lightning wallet; "
        "the payment stays pending until the claim (see --claim-confirmations)",
    )
    reverse.add_argument(
        "--min-claim-fee-reserve-sat",
        type=int,
        default=0,
        help="optional floor for the claim fee reserve; the claim pays exactly the "
        "reserve, which always covers your Core's next-block estimate",
    )
    reverse.add_argument(
        "--min-refund-delay-blocks",
        type=int,
        default=72,
        help="blocks the provider must wait before it may refund",
    )
    reverse.add_argument(
        "--max-incoming-htlc-delay-blocks",
        type=int,
        default=432,
        help="how long your Lightning funds may stay held",
    )
    reverse.add_argument("--max-routing-fee-sat", type=int, default=1_000)
    reverse.add_argument(
        "--fee-rate",
        type=int,
        default=0,
        help="optional minimum claim sat/vB above your Core's economical next-block estimate",
    )
    reverse.add_argument(
        "--max-fee-estimate-sat-vb",
        type=int,
        help="cap your Core's next-block estimate when pricing the claim fee reserve "
        "(for skewed estimators such as signet's; relay and mempool floors still apply)",
    )
    reverse.add_argument(
        "--claim-confirmations",
        type=int,
        help="claim after this many confirmations of the provider's funding instead of "
        "the signed depth (0: from the mempool). Riskier: the provider can double-spend "
        "its funding after your claim reveals the preimage",
    )
    reverse.add_argument("--wallet", required=True, help="Core wallet receiving the payout")
    reverse.add_argument(
        "--lnd-macaroon", help="macaroon able to decode and send payments (--pay-with lnd)"
    )


def _common_arguments(command: argparse.ArgumentParser, *, lnd_required: bool = True) -> None:
    command.add_argument("--network", required=True, help="complete trusted network JSON file")
    command.add_argument("--crypto-library", required=True, help="verified native library path")
    command.add_argument("--relay", required=True, help="Nostr relay URL (ws:// or wss://)")
    command.add_argument(
        "--fallback-relay",
        action="append",
        default=[],
        help="additional explicitly permitted swap relay (repeatable)",
    )
    command.add_argument(
        "--relay-proxy",
        help="loopback Tor HTTPTunnelPort URL, required on public networks",
    )
    command.add_argument(
        "--allow-direct-relay",
        action="store_true",
        help="connect to relays directly, revealing your IP address to them",
    )
    command.add_argument("--provider", required=True, help="provider identity x-only key (hex)")
    command.add_argument("--max-success-fee-sat", required=True, type=int)
    command.add_argument("--max-claim-fee-sat", type=int, default=5_000)
    command.add_argument("--core-port", required=True, type=int, help="loopback Core RPC port")
    command.add_argument("--core-cookie", required=True, help="Core .cookie file")
    command.add_argument(
        "--lnd-port", required=lnd_required, type=int, help="loopback LND gRPC port"
    )
    command.add_argument("--lnd-tls-cert", required=lnd_required, help="LND tls.cert")
    command.add_argument("--recipient", required=True, help="X25519 age recipient")
    command.add_argument("--identity", required=True, help="matching private age identity file")
    command.add_argument(
        "--recovery-output",
        required=True,
        help="create-only recovery file "
        "(later '.funded', '.paid', '.fallback', '.cooperating' snapshots)",
    )
    command.add_argument("--timeout", type=float, default=60.0, help="per-answer seconds")
    command.add_argument("--settle-timeout", type=float, default=3600.0)


def _report(line: str) -> None:
    write_progress(line)


def _payment_prompt(line: str) -> None:
    """Intentional invoice/QR display, never part of the diagnostic stream."""
    sys.stderr.write(line + "\n")


def _forward_report(outcome: SwapOutcome) -> str:
    """Distinguish verified payment from claim completion and confirmation."""
    result = (
        f"Paid. preimage {outcome.payment_preimage} "
        f"(funding {outcome.funding_txid}, contract {outcome.contract_hash})"
    )
    if outcome.cooperation == "verified":
        return result + (
            f" Cooperative completion verified ({outcome.cooperative_claim_txid}); "
            "not a chain confirmation."
        )
    if outcome.cooperation == "abandoned":
        return result + (
            " Cooperation abandoned locally, not canceled at the provider. "
            "Preserve all recovery files, including any .cooperating snapshot; "
            "do not retry payment or signing."
        )
    return result


def _reverse_report(outcome: ReverseSwapOutcome) -> str:
    """Report what the destination received, not the gross contract value."""
    return (
        f"Received {outcome.payout_sat - outcome.claim_fee_sat} sat "
        f"(claim fee {outcome.claim_fee_sat} sat). claim {outcome.claim_txid} "
        f"(funding {outcome.funding_txid}, contract {outcome.contract_hash})"
    )


def _funded_path(path: Path) -> Path:
    return path.with_name(path.name + ".funded")


def _snapshot_path(path: Path, document: bytes, previous: bytes | None) -> Path:  # noqa: PLR0911 - closed checkpoint destinations
    """Select distinct create-only destinations, never overwrite learned knowledge.

    Cryptographic successor verification is mandatory before publication;
    this function chooses a destination only and grants no financial authority.
    """
    if previous is None:
        return path
    prior = parse_json_strict(previous)
    current = parse_json_strict(document)
    if not isinstance(prior, dict) or not isinstance(current, dict):
        raise TypeError("recovery snapshot must be an object")
    if prior.get("funding_history") == []:
        return _funded_path(path)
    prior_knowledge = prior.get("monotonic_knowledge")
    current_knowledge = current.get("monotonic_knowledge")
    if (
        not isinstance(prior.get("funding_history"), list)
        or not prior.get("funding_history")
        or current.get("funding_history") != prior.get("funding_history")
        or not isinstance(prior_knowledge, dict)
        or not isinstance(current_knowledge, dict)
    ):
        raise ValueError("unsupported recovery snapshot transition")
    if (
        prior_knowledge.get("preimage_known") is False
        and current_knowledge.get("preimage_known") is True
    ):
        return path.with_name(path.name + ".paid")
    prior_extensions = prior.get("extensions")
    current_extensions = current.get("extensions")
    if (
        prior.get("profile_id") == "ln-to-btc/v1"
        and prior_knowledge == current_knowledge
        and isinstance(prior_extensions, dict)
        and isinstance(current_extensions, dict)
        and REVERSE_FALLBACK_EXTENSION in prior_extensions
        and REVERSE_COOPERATIVE_RESERVATION_EXTENSION not in prior_extensions
        and REVERSE_COOPERATIVE_RESERVATION_EXTENSION in current_extensions
    ):
        return path.with_name(path.name + ".cooperating")
    if (
        prior.get("profile_id") == "ln-to-btc/v1"
        and prior_knowledge == current_knowledge
        and isinstance(prior_extensions, dict)
        and isinstance(current_extensions, dict)
        and REVERSE_FALLBACK_EXTENSION not in prior_extensions
        and REVERSE_FALLBACK_EXTENSION in current_extensions
    ):
        return path.with_name(path.name + ".fallback")
    if (
        prior.get("profile_id") == "ln-to-btc/v1"
        and prior_knowledge == current_knowledge
        and isinstance(prior_extensions, dict)
        and isinstance(current_extensions, dict)
        and REVERSE_FALLBACK_EXTENSION in prior_extensions
        and current_extensions.get(REVERSE_FALLBACK_EXTENSION)
        == prior_extensions[REVERSE_FALLBACK_EXTENSION]
        and REVERSE_DISCLOSURE_EXTENSION not in prior_extensions
        and REVERSE_DISCLOSURE_EXTENSION in current_extensions
    ):
        return path.with_name(path.name + ".disclosing")
    if (
        prior_knowledge.get("preimage_known") is True
        and prior_knowledge == current_knowledge
        and isinstance(prior_extensions, dict)
        and isinstance(current_extensions, dict)
        and COOPERATIVE_RESERVATION_EXTENSION not in prior_extensions
        and COOPERATIVE_RESERVATION_EXTENSION in current_extensions
    ):
        return path.with_name(path.name + ".cooperating")
    raise ValueError("unsupported recovery snapshot transition")


def _write_recovery_snapshot(  # noqa: PLR0913 - explicit local publication dependencies
    output: Path,
    document: bytes,
    previous: bytes | None,
    network: NetworkIdentity,
    *,
    credentials: X25519Credentials,
    crypto: Context,
) -> None:
    """Verify, encrypt, and durably publish a create-only recovery successor."""
    target = _snapshot_path(output, document, previous)
    if previous is not None:
        inspect_recovery_successor(previous, document, network, crypto=crypto)
    ciphertext = encrypt_verified_plaintext(
        document, network, credentials=credentials, crypto=crypto
    )

    def readback(stored: bytes) -> OfflineRecoveryInspection:
        report = verify_export_ciphertext(
            stored, document, network, credentials=credentials, crypto=crypto
        )
        if previous is None:
            return report
        return inspect_recovery_successor(previous, document, network, crypto=crypto)

    publish_new_ciphertext(str(target), ciphertext, verify_from_disk=readback)


def run(args: argparse.Namespace, network: NetworkIdentity, identity: str) -> str:
    """Run the swap; return the final report line."""
    output = Path(args.recovery_output)
    limits: SwapLimits | None = None
    if args.command == "ln-to-btc":
        _check_payment_source(args)
    if args.command == "btc-to-ln":
        limits = SwapLimits(
            max_success_fee_sat=args.max_success_fee_sat,
            max_funding_fee_sat=args.max_funding_fee_sat,
            max_claim_fee_sat=args.max_claim_fee_sat,
            max_refund_fee_sat=args.max_refund_fee_sat,
            max_refund_delay_blocks=args.max_refund_delay_blocks,
            funding_fee_rate_sat_vb=args.fee_rate,
            claim_fee_floor_sat=args.claim_fee_floor_sat,
        )
        limits.validate_cooperative_fee_floor()
    ceiling = getattr(args, "max_fee_estimate_sat_vb", None)
    if ceiling is not None and not 1 <= ceiling <= MAX_FEE_ESTIMATE_CEILING_SAT_VB:
        raise SwapError("fee estimate ceiling out of range")
    if ceiling is not None and network.name == "mainnet":
        # For skewed estimators such as signet's; mainnet's tracks real demand.
        _report(
            f"warning: --max-fee-estimate-sat-vb caps your Core's mainnet fee estimate at "
            f"{ceiling} sat/vB; in a fee spike the claim fee reserve and cooperative claim "
            "checks fall below the next-block rate and claims may confirm late"
        )
    credentials = X25519Credentials(args.recipient, identity)
    # Refuse an unsafe relay route before the native library, files, or wallet.
    proxy = require_relay_route(network, args.relay_proxy, allow_direct=args.allow_direct_relay)
    RelayConnection(args.relay, proxy=proxy)
    for fallback in args.fallback_relay:
        RelayConnection(fallback, proxy=proxy)
    with Context(library_path=args.crypto_library) as crypto:

        def write_recovery(document: bytes, previous: bytes | None) -> bytes:
            _write_recovery_snapshot(
                output, document, previous, network, credentials=credentials, crypto=crypto
            )
            return document  # Only after verified publication, readback, and directory fsync.

        wallet = WalletRpc(
            port=args.core_port,
            cookie_path=args.core_cookie,
            wallet=args.wallet,
            network=network,
            # Caps Core's estimate for cooperative fee evidence (btc-to-ln) and
            # the claim fee reserve (ln-to-btc).
            max_fee_estimate_sat_vb=getattr(args, "max_fee_estimate_sat_vb", None),
        )
        if args.command == "ln-to-btc":
            return asyncio.run(_reverse(args, network, crypto, wallet, write_recovery))
        if limits is None:
            raise SwapError("unsupported swap direction")
        decoder = LndInvoiceDecoder(
            host="127.0.0.1",
            port=args.lnd_port,
            tls_certificate_path=args.lnd_tls_cert,
            macaroon_path=args.lnd_macaroon,
            network=network,
        )

        async def swap() -> str:
            async with LiveRelayConnection(
                args.relay,
                fallbacks=tuple(args.fallback_relay),
                proxy=proxy,
                factory=lambda target: RelayConnection(target, proxy=proxy),
            ) as connection:
                outcome = await run_swap(
                    connection,
                    identity=args.provider,
                    network=network,
                    invoice=args.invoice,
                    decode_invoice=decoder.decode,
                    wallet=wallet,
                    write_recovery=write_recovery,
                    limits=limits,
                    crypto=crypto,
                    timeout=args.timeout,
                    settle_timeout=args.settle_timeout,
                    report=_report,
                )
            return _forward_report(outcome)

        return asyncio.run(swap())


def _check_payment_source(args: argparse.Namespace) -> None:
    """Require LND credentials exactly when the CLI pays from LND."""
    credentials = (args.lnd_port, args.lnd_tls_cert, args.lnd_macaroon)
    if args.pay_with == "lnd" and None in credentials:
        raise SwapError("--pay-with lnd needs --lnd-port, --lnd-tls-cert and --lnd-macaroon")
    if args.pay_with == "external" and credentials != (None, None, None):
        raise SwapError("--pay-with external takes no LND credentials")


async def _reverse(
    args: argparse.Namespace,
    network: NetworkIdentity,
    crypto: Context,
    wallet: WalletRpc,
    write_recovery: Callable[[bytes, bytes | None], bytes | None],
) -> str:
    payer: HoldPayer
    if args.pay_with == "external":
        payer = ExternalWalletPayer(write=_payment_prompt)
        decode_invoice = offline_invoice_decoder(network, crypto)
    else:
        payer = LndHoldPayer(
            port=args.lnd_port,
            tls_certificate_path=args.lnd_tls_cert,
            macaroon_path=args.lnd_macaroon,
            network=network,
        )
        decode_invoice = LndInvoiceDecoder(
            host="127.0.0.1",
            port=args.lnd_port,
            tls_certificate_path=args.lnd_tls_cert,
            macaroon_path=args.lnd_macaroon,
            network=network,
        ).decode
    limits = ReverseSwapLimits(
        max_success_fee_sat=args.max_success_fee_sat,
        min_claim_fee_reserve_sat=args.min_claim_fee_reserve_sat,
        max_claim_fee_sat=args.max_claim_fee_sat,
        min_refund_delay_blocks=args.min_refund_delay_blocks,
        max_incoming_htlc_delay_blocks=args.max_incoming_htlc_delay_blocks,
        max_routing_fee_sat=args.max_routing_fee_sat,
        claim_fee_rate_sat_vb=args.fee_rate,
        claim_confirmations=args.claim_confirmations,
    )
    proxy = require_relay_route(network, args.relay_proxy, allow_direct=args.allow_direct_relay)
    async with LiveRelayConnection(
        args.relay,
        fallbacks=tuple(args.fallback_relay),
        proxy=proxy,
        factory=lambda target: RelayConnection(target, proxy=proxy),
    ) as connection:
        outcome = await run_reverse_swap(
            connection,
            identity=args.provider,
            network=network,
            payout_sat=args.payout_sat,
            decode_invoice=decode_invoice,
            payer=payer,
            wallet=wallet,
            write_recovery=write_recovery,
            limits=limits,
            crypto=crypto,
            timeout=args.timeout,
            settle_timeout=args.settle_timeout,
            report=_report,
        )
    return _reverse_report(outcome)
