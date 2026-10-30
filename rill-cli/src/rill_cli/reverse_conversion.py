"""One original reserved reverse invocation, never completion or replay.

This internal regtest execution boundary owns exact quote, recovery and payer
bindings. It never imports credits, projects LND accounting, provisions a journal
or releases holds. An interrupted/failed SDK call must NOT be invoked again.
Return values are SDK history, not independently verified source/output receipts.
Operator-owned TLS services, Core host/listener and treasury script are explicit
trust premises, not established by typed DTOs or cookie client authentication.
"""

from __future__ import annotations

import hashlib
import math
import os
import threading
import time
from dataclasses import dataclass, fields
from functools import partial
from typing import TYPE_CHECKING

from rill_core.networks import require_supported_network
from rill_core.wire.canonical import canonicalize, parse_json_strict, parse_model_json
from rill_core.wire.messages import ContractTerms, FundingBinding, LnToBtcEconomics, LnToBtcTiming
from rill_provider.core_tx_bytes import CoreTransactionReader, NextBlockFee
from rill_provider.lnd_invoice_decode import LndInvoiceDecoder
from rill_provider.payment_dispatch_record import PaymentAuthority

from rill_cli.age_container import (
    MAX_CIPHERTEXT_BYTES,
    X25519Credentials,
    _identity,
    encrypt_verified_plaintext,
    verify_export_ciphertext,
)
from rill_cli.conversion_journal import PreparedConversion, _read_private
from rill_cli.funding_inclusion import (
    FundingInclusionHint,
    LookupBlock,
    publish_funding_inclusion_hint,
)
from rill_cli.hold_payment import LndHoldPayer
from rill_cli.live_reverse_swap import ReverseSwapLimits, ReverseSwapOutcome, run_reverse_swap
from rill_cli.swap_command import _write_recovery_snapshot
from rill_cli.wallet_rpc import WalletRpc

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from rill_core.wire.messages import InvoiceBinding
    from rill_crypto import Context

    from rill_cli.conversion_journal import ConversionJournal, ConversionReservation, _LiveRight
    from rill_cli.hold_payment import HoldStatus
    from rill_cli.live_relay import RelayTransport
    from rill_cli.wallet_rpc import ConfirmedOutput, HistoricalWalletOutput


class ReverseConversionError(ValueError):
    """Retained liability, never permission to retry or release a conversion."""


@dataclass(frozen=True, slots=True)
class ReverseExecutionConfig:
    """Explicit source and destination transports; constructor does no IO."""

    lnd_port: int
    lnd_tls_root_path: Path
    lnd_read_macaroon_path: Path
    lnd_payment_macaroon_path: Path
    core_port: int
    core_cookie_path: Path
    core_wallet: str


class _DestinationWallet:
    def __init__(self, wallet: WalletRpc, script: bytes) -> None:
        self._wallet, self._script = wallet, script
        self._lock = threading.Lock()
        self.first_tip: int | None = None

    def tip_height(self) -> int:
        tip = self._wallet.tip_height()
        if type(tip) is not int or tip <= 0:
            raise ReverseConversionError("conversion tip unavailable")
        with self._lock:
            if self.first_tip is None:
                self.first_tip = tip
        return tip

    def next_block_fee(self) -> NextBlockFee:
        return self._wallet.next_block_fee()

    def new_destination_script(self) -> bytes:
        return self._script

    def confirmed_output(self, txid: str, vout: int) -> ConfirmedOutput | None:
        return self._wallet.confirmed_output(txid, vout)

    def unspent_on_chain(self, txid: str, vout: int) -> bool:
        return self._wallet.unspent_on_chain(txid, vout)

    def mempool_spender(self, txid: str, vout: int) -> str | None:
        return self._wallet.mempool_spender(txid, vout)

    def wallet_confirmations(self, txid: str) -> int | None:
        return self._wallet.wallet_confirmations(txid)

    def observe_historical_wallet_output(
        self,
        txid: str,
        treasury_script: bytes,
        *,
        deadline_seconds: float = 10,
    ) -> HistoricalWalletOutput:
        """Reuse the original pinned operator backend for explicit observation."""
        return self._wallet.observe_historical_wallet_output(
            txid,
            treasury_script,
            deadline_seconds=deadline_seconds,
        )

    def broadcast(
        self,
        raw: bytes,
        *,
        deadline: float | None = None,
        effect_allowed: Callable[[], bool] | None = None,
    ) -> str:
        return self._wallet.broadcast(raw, deadline=deadline, effect_allowed=effect_allowed)


class _Invocation:
    def __init__(  # noqa: PLR0913, PLR0917 - original owner and its explicit effect dependencies
        self,
        journal: ConversionJournal,
        right: _LiveRight,
        request: ConversionReservation,
        wallet: _DestinationWallet,
        payer: LndHoldPayer,
        limits: ReverseSwapLimits,
        credentials: X25519Credentials,
        crypto: Context,
        approval_deadline: float,
        capture_reader: CoreTransactionReader | None = None,
    ) -> None:
        self.journal, self.right, self.request = journal, right, request.job.request
        self.wallet, self.payer, self.limits = wallet, payer, limits
        self.credentials, self.crypto = credentials, crypto
        self.approval_deadline = approval_deadline
        self.lock = threading.Lock()
        self.previous: bytes | None = None
        self.terms: ContractTerms | None = None
        self.path: Path | None = None
        self.max_expiry: int | None = None
        self.payment_attempted = False
        self.initial_attempted = False
        self.capture_reader = capture_reader
        self.capture_attempted = False

    def allowed(self) -> bool:
        return (
            time.monotonic() < self.approval_deadline and int(time.time()) < self.request.expires_at
        )

    def require_approval(self) -> None:
        if not self.allowed():
            raise ReverseConversionError("original conversion approval expired")

    def initial_terms(self, document: bytes) -> tuple[ContractTerms, PreparedConversion, int]:
        value = parse_json_strict(document)
        authority = self.journal.authority
        if not isinstance(value, dict) or canonicalize(value) != document:
            raise ReverseConversionError("canonical initial conversion recovery required")
        tip = self.wallet.first_tip
        if (
            value.get("format") != "rillswap-recovery"
            or value.get("format_version") != "1-pre.1"
            or value.get("specification_version") != "0.1.0-pre.1"
            or value.get("profile_id") != "ln-to-btc/v1"
            or value.get("network_identity") != authority.network.model_dump(mode="json")
            or value.get("funding_history") != []
            or value.get("extensions") != {}
            or tip is None
            or value.get("chain_scan_birthday_height") != tip
        ):
            raise ReverseConversionError("initial conversion recovery binding differs")
        knowledge, context = value.get("monotonic_knowledge"), value.get("verification_context")
        if (
            not isinstance(knowledge, dict)
            or knowledge.get("preimage_known") is not True
            or knowledge.get("dangerous_signature_issued") is not False
            or not isinstance(context, dict)
        ):
            raise ReverseConversionError("initial reverse recovery knowledge required")
        init, accept = context.get("handshake_init"), context.get("handshake_accept")
        if (
            not isinstance(init, dict)
            or not isinstance(accept, dict)
            or init.get("expected_provider_identity_xonly_key") != authority.provider_identity
            or accept.get("provider_identity_xonly_key") != authority.provider_identity
        ):
            raise ReverseConversionError("conversion handshake provider differs")
        terms = parse_model_json(ContractTerms, canonicalize(value["contract_terms"]))
        economics, timing = terms.economics, terms.timing_policy
        maximum = tip + self.limits.max_incoming_htlc_delay_blocks
        if (
            terms.provider_identity_key != authority.provider_identity
            or terms.network_identity != authority.network
            or terms.client_destination_script != authority.treasury_script
            or not isinstance(economics, LnToBtcEconomics)
            or not isinstance(timing, LnToBtcTiming)
            or int(economics.nominal_payout_sat) != self.request.requested_payout_sat
            or int(terms.max_claim_fee_sat) > self.limits.max_claim_fee_sat
            or int(economics.success_fee_sat) > self.limits.max_success_fee_sat
            or int(economics.claim_fee_reserve_sat) < self.limits.min_claim_fee_reserve_sat
            or not 0 < timing.min_incoming_htlc_expiry_height <= maximum
        ):
            raise ReverseConversionError("conversion firm terms differ from approval")
        minimum = int(economics.contract_amount_sat) - int(terms.max_claim_fee_sat)
        contract_hash = value.get("contract_hash")
        if (
            not isinstance(contract_hash, str)
            or terms.terms_expiry <= int(time.time())
            or terms.invoice_binding.expires_at <= int(time.time())
            or terms.refund_lock_height < tip + self.limits.min_refund_delay_blocks
        ):
            raise ReverseConversionError("conversion firm terms expired or refund delay differs")
        prepared = PreparedConversion(
            contract_hash=contract_hash,
            payment_hash=terms.invoice_binding.payment_hash,
            invoice_sha256=terms.invoice_binding.bolt11_sha256,
            invoice_amount_msat=int(terms.invoice_binding.amount_msat),
            routing_fee_ceiling_msat=self.limits.max_routing_fee_sat * 1000,
            minimum_net_output_sat=minimum,
        )
        return terms, prepared, maximum

    def write_recovery(self, document: bytes, predecessor: bytes | None) -> bytes:
        with self.lock:
            if predecessor is None:
                if self.initial_attempted:
                    raise ReverseConversionError(
                        "initial conversion checkpoint already acknowledged"
                    )
                self.initial_attempted = True
                self.require_approval()
                terms, prepared, maximum = self.initial_terms(document)
                ciphertext = encrypt_verified_plaintext(
                    document,
                    self.journal.authority.network,
                    credentials=self.credentials,
                    crypto=self.crypto,
                )
                self.require_approval()

                def readback(stored: bytes) -> object:
                    return verify_export_ciphertext(
                        stored,
                        document,
                        self.journal.authority.network,
                        credentials=self.credentials,
                        crypto=self.crypto,
                    )

                path = self.journal.checkpoint(
                    self.right, prepared, ciphertext, verify_from_disk=readback
                )
                self.path, self.terms, self.max_expiry = path, terms, maximum
            else:
                if predecessor != self.previous or self.path is None:
                    raise ReverseConversionError("conversion recovery predecessor not acknowledged")
                _write_recovery_snapshot(
                    self.path,
                    document,
                    predecessor,
                    self.journal.authority.network,
                    credentials=self.credentials,
                    crypto=self.crypto,
                )
            self.previous = document
            return document

    def capture_funding_inclusion(
        self, binding: FundingBinding, terms: ContractTerms, sdk_deadline: float
    ) -> None:
        """One original-owner capture, not a stored or generation-based capability."""
        with self.lock, self.right.lock:
            if self.capture_attempted:
                raise ReverseConversionError("original funding capture already attempted")
            self.capture_attempted = True
            if (
                self.capture_reader is None
                or self.path is None
                or self.previous is None
                or not self.payment_attempted
                or terms != self.terms
                or self.right.journal is not self.journal
                or self.right.operation_id != self.request.operation_id
                or self.right.stage != "dispatched"
                or type(sdk_deadline) not in (int, float)
                or not math.isfinite(sdk_deadline)
            ):
                raise ReverseConversionError("original dispatched funding owner required")
            original_path = self.path
            path = original_path.with_suffix(".funding-inclusion.age")
            if os.path.lexists(path):
                raise ReverseConversionError("existing funding hint cannot be replaced")
            previous = parse_json_strict(self.previous)
            if not isinstance(previous, dict):
                raise ReverseConversionError("acknowledged funded recovery required")
            records = previous.get("funding_history")
            if not isinstance(records, list) or not records or not isinstance(records[-1], dict):
                raise ReverseConversionError("acknowledged funded recovery required")
            if records[-1].get("binding") != binding.model_dump(mode="json", warnings="error"):
                raise ReverseConversionError("original acknowledged funding binding required")

            def allowed() -> None:
                self.require_approval()
                if time.monotonic() >= sdk_deadline:
                    raise ReverseConversionError("original funding capture lifetime expired")
                job = self.journal.status(self.request.operation_id)
                if (
                    job.state != "dispatched"
                    or job.prepared is None
                    or (
                        job.prepared.contract_hash != binding.contract_hash
                        or hashlib.sha256(
                            _read_private(original_path, MAX_CIPHERTEXT_BYTES)
                        ).hexdigest()
                        != job.recovery_sha256
                    )
                ):
                    raise ReverseConversionError("original dispatched checkpoint unavailable")

            allowed()
            budget = min(
                10.0, sdk_deadline - time.monotonic(), self.approval_deadline - time.monotonic()
            )
            observed = self.capture_reader.observe_funding_inclusion(
                binding, terms, keys=self.crypto, deadline_seconds=budget
            )
            allowed()
            job = self.journal.status(self.request.operation_id)
            if job.recovery_sha256 is None:
                raise ReverseConversionError("original checkpoint identity unavailable")
            hint = FundingInclusionHint(
                version="conversion-funding-inclusion/regtest/v1",
                operation_id=self.request.operation_id,
                network=self.journal.authority.network,
                original_recovery_sha256=job.recovery_sha256,
                funding_binding=binding,
                funding_block=LookupBlock(
                    height=observed.block_height, block_hash=observed.block_hash
                ),
                sampled_tip=LookupBlock(
                    height=observed.tip_after_height, block_hash=observed.tip_after_hash
                ),
                confirmations=observed.minimum_sampled_confirmations,
            )
            # Completion may race final checks/link. No SQL lock covers data-only
            # publication; this artifact is historical, never execution authority.
            publish_funding_inclusion_hint(
                path, hint, credentials=self.credentials, publication_allowed=allowed
            )

    def pay(  # noqa: PLR0913 - exact existing HoldPayer callback contract
        self,
        bolt11: str,
        *,
        invoice_binding: InvoiceBinding,
        min_final_expiry_height: int,
        max_expiry_height: int,
        fee_limit_sat: int,
        deadline: float | None = None,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> HoldStatus:
        with self.lock:
            terms = self.terms
            if (
                self.payment_attempted
                or terms is None
                or self.previous is None
                or not isinstance(terms.timing_policy, LnToBtcTiming)
                or invoice_binding != terms.invoice_binding
                or hashlib.sha256(bolt11.encode("ascii")).hexdigest()
                != invoice_binding.bolt11_sha256
                or fee_limit_sat != self.limits.max_routing_fee_sat
                or min_final_expiry_height != terms.timing_policy.min_incoming_htlc_expiry_height
                or max_expiry_height != self.max_expiry
                or min_final_expiry_height > max_expiry_height
                or deadline is None
                or not math.isfinite(deadline)
                or submission_allowed is None
            ):
                raise ReverseConversionError("exact original conversion payment binding required")
            self.require_approval()
            # Mark the local attempt before the durable marker too: any uncertain
            # failure is terminal for this owner, never a replacement permission.
            self.payment_attempted = True
            self.journal.dispatch(self.right, invoice_binding.payment_hash)
        original_deadline = min(deadline, self.approval_deadline)

        def allowed() -> bool:
            return self.allowed() and submission_allowed() is True

        return self.payer.pay(
            bolt11,
            invoice_binding=invoice_binding,
            min_final_expiry_height=min_final_expiry_height,
            max_expiry_height=max_expiry_height,
            fee_limit_sat=fee_limit_sat,
            deadline=original_deadline,
            submission_allowed=allowed,
        )


async def run_reserved_conversion(  # noqa: PLR0913 - one explicit original execution boundary
    journal: ConversionJournal,
    reservation: ConversionReservation,
    connection: RelayTransport,
    *,
    config: ReverseExecutionConfig,
    limits: ReverseSwapLimits,
    credentials: X25519Credentials,
    crypto: Context,
    timeout: float = 60,  # noqa: ASYNC109 - existing SDK response timeout, no new protocol
    settle_timeout: float = 1800,
    retain_funding_inclusion: bool = False,
    await_settlement: bool = False,
) -> ReverseSwapOutcome:
    """Invoke once with durable bindings; leave completion/release evidence pending.

    Explicit ``retain_funding_inclusion=True`` captures encrypted historical
    coordinates before claiming. Default behavior and SDK keywords are unchanged.
    Capture failure after payment stops progression with the liability retained;
    inspection, never replacement execution, is required. Old/missing hints
    trigger no acquisition, provisioning, migration or restored invocation rights.

    Explicit ``await_settlement=True`` asks that same original SDK execution to
    observe signed-depth chain completion, using the original wallet and lifetime.
    Neither opt-in persists or completes a receipt, releases the liability, or
    grants a reopened job new execution rights. Default SDK keywords stay intact.
    """
    outcome = None
    try:
        authority, request = journal.authority, reservation.job.request
        require_supported_network(authority.network)
        if (
            authority.network.name != "regtest"
            or journal.status(request.operation_id) != reservation.job
        ):
            raise ReverseConversionError("explicit original regtest reservation required")  # noqa: TRY301 - sanitize private boundary
        if (
            not isinstance(limits, ReverseSwapLimits)
            or type(retain_funding_inclusion) is not bool
            or type(await_settlement) is not bool
            or not isinstance(credentials, X25519Credentials)
            or any(
                type(getattr(limits, field.name)) is not int or getattr(limits, field.name) < 0
                for field in fields(limits)
                # None (the default) waits for the signed funding depth.
                if not (field.name == "claim_confirmations" and limits.claim_confirmations is None)
            )
            or limits.max_routing_fee_sat * 1000 > request.max_routing_fee_msat
            or not math.isfinite(timeout)
            or timeout <= 0
            or not math.isfinite(settle_timeout)
            or settle_timeout <= 0
        ):
            raise ReverseConversionError("immutable conversion limits required")  # noqa: TRY301 - sanitize private boundary
        remaining = request.expires_at - time.time()
        if remaining <= 0:
            raise ReverseConversionError("conversion approval expired")  # noqa: TRY301 - sanitize private boundary
        approval_deadline = time.monotonic() + remaining
        # Reuse the encryption module's local parse/correspondence invariant
        # before consuming a right, without exporting or contacting anything.
        _identity(credentials)
        decoder = LndInvoiceDecoder(
            host="127.0.0.1",
            port=config.lnd_port,
            tls_certificate_path=config.lnd_tls_root_path,
            macaroon_path=config.lnd_read_macaroon_path,
            network=authority.network,
        )
        payer = LndHoldPayer(
            port=config.lnd_port,
            tls_certificate_path=config.lnd_tls_root_path,
            macaroon_path=config.lnd_payment_macaroon_path,
            network=authority.network,
            expected_payer=PaymentAuthority(authority.source_node, authority.network),
        )
        wallet = _DestinationWallet(
            WalletRpc(
                port=config.core_port,
                cookie_path=config.core_cookie_path,
                wallet=config.core_wallet,
                network=authority.network,
            ),
            bytes.fromhex(authority.treasury_script),
        )
        right = journal.invoke(reservation)
        owner = _Invocation(
            journal,
            right,
            reservation,
            wallet,
            payer,
            limits,
            credentials,
            crypto,
            approval_deadline,
            CoreTransactionReader(
                port=config.core_port,
                cookie_path=config.core_cookie_path,
                network=authority.network,
            )
            if retain_funding_inclusion
            else None,
        )
        swap = partial(
            run_reverse_swap,
            connection,
            identity=authority.provider_identity,
            network=authority.network,
            payout_sat=request.requested_payout_sat,
            decode_invoice=decoder.decode,
            payer=owner,
            wallet=wallet,
            write_recovery=owner.write_recovery,
            limits=limits,
            crypto=crypto,
            timeout=timeout,
            settle_timeout=settle_timeout,
        )
        # Default callers receive exactly the original keywords, even when the
        # concrete SDK has been replaced by a closed-signature implementation.
        if await_settlement:
            swap = partial(swap, await_settlement=True)
        if retain_funding_inclusion:
            outcome = await swap(funding_inclusion_observer=owner.capture_funding_inclusion)
        else:
            outcome = await swap()
    except Exception:  # noqa: BLE001, S110 - detach private protocol/RPC/recovery diagnostics
        pass
    if outcome is None:
        raise ReverseConversionError(
            "original conversion unresolved; retain journal and recovery, do not invoke again"
        )
    return outcome
