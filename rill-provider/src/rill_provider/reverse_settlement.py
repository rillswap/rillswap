"""Provider lifecycle for LN to BTC swaps (RS-004 "Funding and settlement").

The provider is the funder and refund party; the client claims. Every step
takes the conservative branch: nothing is funded until every accepted HTLC
is checked, nothing is settled without the preimage of the payment hash,
the hold is canceled only after the refund has its signed depth, and every
signed transaction is recorded before it is broadcast.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import secrets
import time
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, ParamSpec, Protocol, TypeVar

from rill_core.errors import ValidationError
from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    ValidatedUnilateralSpend,
    build_unilateral_spend,
    finalize_unilateral_spend,
    max_spendable_fee,
    reconstruct_taproot_contract,
)
from rill_core.wire.hashes import contract_hash
from rill_core.wire.messages import Envelope, FundingBinding

from rill_provider.core_tx_bytes import (
    MAX_SATS,
    MAX_SPEND_SCAN_BLOCKS,
    CooperativeClaimOutpoint,
    CooperativeFeePolicy,
    CoreRpcError,
    ReverseSpendCheckpoint,
)
from rill_provider.live_session_store import (
    LiveSessionStoreError,
    StaleOwnerError,
    StaleSwapError,
    _ReversePaidProposalEvidence,
)
from rill_provider.lnd_hold_invoice import _BoundInvoiceSyncBeforeSubmissionError
from rill_provider.lnd_payment_observation import LndNotSyncedError, LndObservationError
from rill_provider.settlement_diagnostics import committed_transition
from rill_provider.settlement_policy import offered_terms

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from rill_core.settlement.taproot import TaprootKeyOperations
    from rill_core.wire.messages import ContractTerms, InvoiceBinding

    from rill_provider.core_tx_bytes import FundedOutput, SpendScan
    from rill_provider.live_session_store import (
        LiveSessionStore,
        RequestAnswer,
        ReverseProposalAdmission,
        SettlementItem,
    )
    from rill_provider.lnd_hold_invoice import BoundHoldInvoiceObservation, HoldInvoiceStatus
    from rill_provider.reverse_cooperation import ReverseCooperationWindow
    from rill_provider.reverse_operations import ReverseOperation
    from rill_provider.settlement_engine import EngineCrypto

LOG = logging.getLogger(__name__)
REFUND_ESTIMATE_TARGET = 6
PREIMAGE_BYTES = 32
_P = ParamSpec("_P")
_T = TypeVar("_T")
# Right after a block LND briefly lags Core. Resample a few times inside the
# same nonrenewing window instead of burning the proposal on that race.
TIP_AGREEMENT_ATTEMPTS = 4
TIP_AGREEMENT_PAUSE_SECONDS = 0.5


async def _tip_agreeing[T](
    window: ReverseCooperationWindow,
    observe: Callable[
        [], Awaitable[tuple[CooperativeClaimOutpoint, BoundHoldInvoiceObservation, T]]
    ],
) -> tuple[CooperativeClaimOutpoint, BoundHoldInvoiceObservation, T, float, float]:
    """Return one read-only Core and LND sample that names the same tip.

    A disagreement or an unsynchronized LND proves nothing, so it is only
    resampled; the window is never renewed and still bounds every attempt.
    Returns the sample with its own evidence interval.
    """
    for attempt in range(TIP_AGREEMENT_ATTEMPTS):
        if attempt:
            await asyncio.sleep(TIP_AGREEMENT_PAUSE_SECONDS)
        started = window.evidence_time()
        try:
            core, invoice, extra = await observe()
        except LndNotSyncedError:
            continue
        completed = window.evidence_time()
        if (invoice.last_lnd_height, invoice.last_lnd_block_hash) == (
            core.tip_height,
            core.tip_hash,
        ):
            return core, invoice, extra, started, completed
    raise LiveSessionStoreError("Core and LND tips did not agree")


class HoldInvoiceBackend(Protocol):
    """The hold invoice calls the lifecycle needs (``LndHoldInvoices``)."""

    def lookup(self, payment_hash: str) -> HoldInvoiceStatus:
        """Return the invoice state and accepted parts."""

    def settle(self, preimage: str) -> None:
        """Settle with the verified preimage."""

    def settle_bound_invoice(
        self,
        expected: InvoiceBinding,
        preimage: str,
        *,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> None:
        """Settle authenticated original-invoice debt without unbound fallback."""

    def observe_bound_invoice(
        self,
        expected: InvoiceBinding,
        *,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> BoundHoldInvoiceObservation:
        """Observe the original invoice without financial or signing permission."""

    def observe_bound_settled_invoice(
        self,
        expected: InvoiceBinding,
        *,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> BoundHoldInvoiceObservation:
        """Collect actual sufficiently paid original-invoice knowledge."""

    def cancel(self, payment_hash: str) -> None:
        """Cancel; accepted parts are failed back."""


class ReverseChainBackend(Protocol):
    """The chain calls the lifecycle needs (``CoreTransactionReader``)."""

    def tip_height(self) -> int:
        """Active chain height."""

    def observe_cooperative_claim_outpoint(
        self, binding: FundingBinding, terms: ContractTerms, *, keys: TaprootKeyOperations
    ) -> CooperativeClaimOutpoint:
        """Read the named unspent output (LN to BTC: at any depth) with public-only keys."""

    def observe_cooperative_fee_policy(
        self, target_blocks: int, *, allow_regtest_fixed_fee: bool = False
    ) -> CooperativeFeePolicy:
        """Read conservative estimate and relay/mempool admission floors."""

    def fund_output(
        self, script_pubkey: bytes, value_sat: int, *, max_fee_sat: int
    ) -> FundedOutput:
        """Sign, never broadcast, a wallet payment to the script at index 0."""

    def release_funding_inputs(self, inputs: tuple[tuple[str, int], ...]) -> None:
        """Release identified, affirmatively ungranted funding inputs only."""

    def broadcast(self, raw: bytes, txid: str) -> str:
        """Submit exact bytes; idempotent."""

    def confirmations(self, txid: str) -> int:
        """Return the confirmed depth, 0 in the mempool."""

    def block_hash(self, height: int) -> str:
        """Canonical block hash at an exact height."""

    def funding_scan_boundary(self, txid: str, required_depth: int) -> tuple[int, str]:
        """Canonical parent of the confirmed funding block."""

    def find_spender(
        self,
        txid: str,
        vout: int,
        *,
        from_height: int,
        to_height: int,
        anchor_block: str | None = None,
    ) -> SpendScan:
        """Look for the transaction spending the outpoint."""

    def fee_rate_sat_vb(self, target_blocks: int) -> float | None:
        """Fee estimate, advice only."""


@dataclass(frozen=True, slots=True)
class _ReversePublicKeySnapshot:
    """Exact-input public curve results, not crypto verification or authority.

    Capture on the owner task with its native verifier before queuing Core.
    No engine, native handle, callback, store, or private key crosses to workers.
    This binds curve inputs only; the funding matcher and authenticated owner
    reservation independently bind the complete contract and economic facts.
    """

    user_key: bytes
    provider_key: bytes
    internal: tuple[bytes, int]
    tweak: bytes
    output: tuple[bytes, int]

    @classmethod
    def capture(
        cls, terms: ContractTerms, *, keys: TaprootKeyOperations
    ) -> _ReversePublicKeySnapshot:
        """Compute public results synchronously, never retain the supplied verifier."""
        contract = reconstruct_taproot_contract(terms, keys=keys)
        return cls(
            bytes.fromhex(terms.client_contract_compressed_key),
            bytes.fromhex(terms.provider_contract_compressed_key),
            (contract.internal_key, contract.internal_parity),
            contract.tap_tweak,
            (contract.output_key, contract.output_parity),
        )

    def musig_internal_key(
        self, user_public_key: bytes, provider_public_key: bytes
    ) -> tuple[bytes, int]:
        """Return only the native-verified result for these exact ordered keys."""
        if user_public_key != self.user_key or provider_public_key != self.provider_key:
            raise ValidationError("reverse public curve inputs differ")
        return self.internal

    def musig_output_key(
        self, user_public_key: bytes, provider_public_key: bytes, tap_tweak: bytes
    ) -> tuple[bytes, int]:
        """Return only the native-verified result for these exact keys and tweak."""
        self.musig_internal_key(user_public_key, provider_public_key)
        if tap_tweak != self.tweak:
            raise ValidationError("reverse public curve tweak differs")
        return self.output


class ReverseSettlement:
    """Advance fresh state inside the acquired owner's reverse execution gate."""

    def __init__(  # noqa: PLR0913 - explicit injected backends and fee policy
        self,
        store: LiveSessionStore,
        chain: ReverseChainBackend,
        hold_invoices: HoldInvoiceBackend,
        crypto: EngineCrypto,
        *,
        refund_fee_floor_sat: int = 1_000,
        cooperative_fee_floor_sat: int = 1,
        allow_regtest_fixed_fee: bool = False,
    ) -> None:
        """Bind already-configured backends; no I/O."""
        self._store = store
        self._chain = chain
        self._hold = hold_invoices
        self._crypto = crypto
        self._refund_fee_floor_sat = refund_fee_floor_sat
        self._cooperative_fee_floor_sat = cooperative_fee_floor_sat
        self._allow_regtest_fixed_fee = allow_regtest_fixed_fee
        self._operation: ReverseOperation | None = None

    async def cosign_cooperative_proposal(
        self,
        document: bytes,
        now: int,
        *,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> bytes | None:
        """Answer one client claim proposal with the archived provider contribution.

        Sequence, all under the proposal's original nonrenewing window: retain
        the disclosed preimage and admit debt from fresh Core/LND facts, repay
        by settling the bound hold invoice, collect fresh paid evidence, then
        consume one native nonce and atomically archive the signed reply in
        that same operation. A replayed proposal returns only the exact
        archived reply (or None while none exists); it never signs again.
        Every refusal is terminal for this proposal; the client keeps its
        independent unilateral claim with the preimage it already holds.
        """
        from rill_crypto import Context  # noqa: PLC0415 - native boundary is opt-in

        crypto = self._crypto
        if not isinstance(crypto, Context):
            raise LiveSessionStoreError("reverse cooperative signer unavailable")
        await self._catch_up_funding(document, now)
        receipt = await self._acquire_proposal_debt(
            document, now, wall_clock=wall_clock, monotonic_clock=monotonic_clock
        )
        if receipt.replay:
            async with self._store.reverse_operations.operation() as operation:
                return self._store._reverse_signed_reply_replay(  # noqa: SLF001 - archive only
                    document, operation=operation
                )
        work = self._store.settlement_work(session_id=receipt.session_id)
        if len(work) == 1:
            # Repayment of the admitted debt; a concurrent settlement pass may
            # already have done it, which the paid evidence below rechecks.
            try:
                await self._advance_logged(work[0], now)
            except _BoundInvoiceSyncBeforeSubmissionError:
                await self._repay_original_unsynced_debt(document, now)
        async with self._store.reverse_operations.operation() as operation:
            evidence = await self._collect_paid_proposal_evidence(
                document,
                operation=operation,
                configured_floor_sat=self._cooperative_fee_floor_sat,
                allow_regtest_fixed_fee=self._allow_regtest_fixed_fee,
            )
            return self._store._commit_reverse_signed_reply(  # noqa: SLF001 - same operation
                document, operation=operation, evidence=evidence, crypto=crypto, now=now
            )

    async def verify_cooperative_completion(self, document: bytes, now: int) -> RequestAnswer:
        """Archive a public-transcript receipt, without RPC, nonce, or settlement effects."""
        from rill_crypto import Context  # noqa: PLC0415 - native verification is opt-in

        if not isinstance(self._crypto, Context):
            raise LiveSessionStoreError("reverse cooperative verifier unavailable")
        async with self._store.reverse_operations.operation() as operation:
            return self._store._admit_reverse_cooperative_completion(  # noqa: SLF001 - store-owned admission
                document, operation=operation, crypto=self._crypto, now=now
            )

    async def _catch_up_funding(self, document: bytes, now: int) -> None:
        """Run this swap's own funding depth step before admitting its proposal.

        The client proposes as soon as its node sees the depth it chose, which
        usually precedes the next periodic settlement pass here. Only the
        provider's own Core observation can move FUNDING_SENT to FUNDED; the
        proposal merely selects which retained session to check first. A
        client may claim before the signed depth (its own double-spend risk),
        so admission accepts FUNDING_SENT too; any failure here leaves the
        state unchanged.
        """
        try:
            session_id = Envelope.model_validate_json(document, strict=True).session_id
            work = self._store.settlement_work(session_id=session_id)
            if len(work) == 1 and work[0].state == "FUNDING_SENT":
                await self._advance_logged(work[0], now)
        except (asyncio.CancelledError, StaleOwnerError):
            raise
        except Exception:  # noqa: BLE001 - admission rechecks its own evidence
            LOG.debug("funding catch-up before a reverse proposal did not complete")

    async def _advance_logged(self, item: SettlementItem, now: int) -> None:
        """Step a swap for a proposal and log a move as the periodic pass does.

        A cooperative claim usually funds and settles the swap here, so without
        this the operator log stopped at FUNDING_SENT or FUNDED.
        """
        await self.advance(item, now)

    async def advance(self, item: SettlementItem, now: int) -> str:
        """Reload after serialization, never execute a queued stale snapshot."""
        async with self._store.reverse_operations.operation() as operation:
            work = self._store.settlement_work(session_id=item.session_id)
            if len(work) != 1:
                raise StaleSwapError("reverse swap no longer available for settlement")
            self._operation = operation
            try:
                return await self._step(work[0], now)
            finally:
                self._operation = None

    async def _repay_original_unsynced_debt(self, document: bytes, now: int) -> None:
        """Resample only the original bound debt after a known no-dispatch refusal.

        The first advance is unchanged. These remaining attempts cannot fund,
        refund, renew cooperation, or retry an ambiguous financial submission.
        """
        window: ReverseCooperationWindow | None = None
        completed = False
        try:
            async with self._store.reverse_operations.operation() as operation:
                original = self._store._reverse_live_proposal_context(  # noqa: SLF001 - canonical original-owner join
                    document, operation=operation, purpose="repayment"
                )
                window = original.window
                # The preceding native join authenticates this exact document.
                # Never accept a separately supplied work/session selector.
                session_id = Envelope.model_validate_json(document, strict=True).session_id
            for _ in range(TIP_AGREEMENT_ATTEMPTS - 1):
                window.evidence_time()
                await asyncio.sleep(TIP_AGREEMENT_PAUSE_SECONDS)
                async with self._store.reverse_operations.operation() as operation:
                    context = self._store._reverse_live_proposal_context(  # noqa: SLF001 - after gate wait, never reconstruct a grant
                        document, operation=operation, purpose="repayment"
                    )
                    if context.window is not window or context.binding != original.binding:
                        raise LiveSessionStoreError("reverse original repayment context differs")
                    work = self._store.settlement_work(session_id=session_id)
                    if not work:
                        # Absence of work proves nothing. Affirmatively validate
                        # SETTLED with the exact original preimage before returning.
                        paid = self._store._reverse_live_proposal_context(  # noqa: SLF001 - native original SETTLED join, not financial proof
                            document, operation=operation, purpose="paid-signing"
                        )
                        if paid.window is not window or paid.binding != original.binding:
                            raise LiveSessionStoreError(
                                "reverse original repayment context differs"
                            )
                        completed = True
                        return
                    if (
                        len(work) != 1
                        or work[0].state not in ("FUNDING_SENT", "FUNDED")
                        or work[0].preimage is None
                    ):
                        raise LiveSessionStoreError("reverse original repayment work refused")
                    binding = self._store._reverse_repayment_binding(session_id)  # noqa: SLF001 - same-operation bound-only classification
                    if binding is None or binding != context.terms.invoice_binding:
                        raise LiveSessionStoreError("reverse original repayment binding differs")
                    self._operation = operation
                    try:
                        await self._settle_claim(
                            work[0],
                            context.terms,
                            now,
                            work[0].preimage,
                            cooperation_window=window,
                        )
                    except _BoundInvoiceSyncBeforeSubmissionError:
                        continue
                    finally:
                        self._operation = None
                    completed = True
                    return
            raise LiveSessionStoreError("reverse original repayment synchronization refused")
        finally:
            if window is not None and not completed:
                window.abandon()

    async def _acquire_proposal_debt(
        self,
        document: bytes,
        now: int,
        *,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> ReverseProposalAdmission:
        """Acquire original-owner evidence and admit debt, never activate cooperation.

        INTERNAL ONLY.
        Replays return receipts only, without backend work or renewed authority.
        Core workers receive public snapshots; no SQLite/native handles. LND
        uses its own transport clock plus the original-window predicate, never
        an absolute deadline copied from a possibly unrelated clock domain.
        Admissible evidence age is bounded, not physical worker duration.
        No settlement, nonce, partial signature, or relay response occurs here.
        """
        async with self._store.reverse_operations.operation() as operation:
            window: ReverseCooperationWindow | None = None
            try:
                self._store._retain_reverse_preimage_evidence(  # noqa: SLF001 - original-owner pipeline
                    document, operation=operation, now=now
                )
                receipt = self._store._admit_reverse_cooperative_proposal(  # noqa: SLF001
                    document,
                    operation=operation,
                    wall_clock=wall_clock,
                    monotonic_clock=monotonic_clock,
                )
                if receipt.replay:
                    return receipt
                context = self._store._reverse_live_proposal_context(  # noqa: SLF001
                    document, operation=operation, purpose="acquisition"
                )
                original_window = context.window
                window = original_window
                operation.check()
                keys = _ReversePublicKeySnapshot.capture(context.terms, keys=self._crypto)

                def submission_allowed() -> bool:
                    return operation.submission_allowed() and original_window.time_allowed()

                async def observe() -> tuple[
                    CooperativeClaimOutpoint, BoundHoldInvoiceObservation, None
                ]:
                    core = await operation.worker(
                        partial(
                            self._chain.observe_cooperative_claim_outpoint,
                            context.binding,
                            context.terms,
                            keys=keys,
                        )
                    )
                    operation.check()
                    original_window.check(tip_height=core.tip_height)
                    invoice = await operation.worker(
                        partial(
                            self._hold.observe_bound_invoice,
                            context.terms.invoice_binding,
                            submission_allowed=submission_allowed,
                        )
                    )
                    return core, invoice, None

                core, invoice, _, started, completed = await _tip_agreeing(original_window, observe)
                operation.check()
                self._store._commit_reverse_proposal_debt(  # noqa: SLF001 - single owner financial writer
                    document,
                    operation=operation,
                    core=core,
                    invoice=invoice,
                    observations_started_at=started,
                    observations_completed_at=completed,
                    now=now,
                )
            except (asyncio.CancelledError, StaleOwnerError):
                if window is not None:
                    window.abandon()
                raise
            except Exception:  # noqa: BLE001 - no proposal/preimage/backend oracle
                if window is not None:
                    window.abandon()
            else:
                return receipt
            raise LiveSessionStoreError("reverse proposal acquisition refused")

    async def _preflight_paid_proposal(
        self,
        document: bytes,
        *,
        configured_floor_sat: int,
        allow_regtest_fixed_fee: bool = False,
    ) -> None:
        """Check paid cooperation prerequisites, never return signing authority.

        INTERNAL ONLY, with no production caller. Reconcile independent debt
        repayment first; requesting paid context too early abandons cooperation.
        Success is diagnostic and must not be saved, transferred, or treated as
        nonce/partial signing authority. Any future signing effect must repeat fresh
        evidence and final owner validation inside the same original window.
        No nonce, signature, reply, debt, settlement RPC, or lifecycle write.
        """
        async with self._store.reverse_operations.operation() as operation:
            evidence: _ReversePaidProposalEvidence | None = None
            try:
                evidence = await self._collect_paid_proposal_evidence(
                    document,
                    operation=operation,
                    configured_floor_sat=configured_floor_sat,
                    allow_regtest_fixed_fee=allow_regtest_fixed_fee,
                )
                with self._store._write() as connection:  # noqa: SLF001 - explicit owner transaction
                    self._store._check_reverse_paid_evidence(  # noqa: SLF001
                        connection, document, operation=operation, evidence=evidence
                    )
                # A diagnostic success still charges transaction-exit latency.
                # Future native effects must also authorize before their commit.
                operation.check()
                evidence.context.window.check(tip_height=evidence.core.tip_height)
                evidence.context.window.check_evidence_interval(
                    started_at=evidence.started_at, completed_at=evidence.completed_at
                )
            except (asyncio.CancelledError, StaleOwnerError):
                if evidence is not None:
                    evidence.context.window.abandon()
                raise
            except Exception:  # noqa: BLE001 - no archived preimage, plan, or backend oracle
                if evidence is not None:
                    evidence.context.window.abandon()
            else:
                return
            raise LiveSessionStoreError("reverse paid proposal preflight refused")

    async def _collect_paid_proposal_evidence(
        self,
        document: bytes,
        *,
        operation: ReverseOperation,
        configured_floor_sat: int,
        allow_regtest_fixed_fee: bool,
    ) -> _ReversePaidProposalEvidence:
        """Collect actual stronger-query facts under an already-held operation.

        No SQL transaction spans RPC waits; only public curve snapshots enter
        Core workers. This record confers no authority or RPC provenance by
        its type. The store must revalidate it in this exact operation before
        any future effect, including time spent in final native validation.
        """
        self._store.reverse_operations.check(operation)
        window: ReverseCooperationWindow | None = None
        try:
            if (
                type(configured_floor_sat) is not int
                or not 0 < configured_floor_sat <= MAX_SATS
                or type(allow_regtest_fixed_fee) is not bool
                or (allow_regtest_fixed_fee and self._store.network_identity.name != "regtest")
            ):
                raise ValueError("reverse cooperative fee configuration refused")  # noqa: TRY301
            context = self._store._reverse_live_proposal_context(  # noqa: SLF001 - original-owner gate
                document, operation=operation, purpose="paid-signing"
            )
            original_window = context.window
            window = original_window
            operation.check()
            keys = _ReversePublicKeySnapshot.capture(context.terms, keys=self._crypto)

            def submission_allowed() -> bool:
                return operation.submission_allowed() and original_window.time_allowed()

            async def observe() -> tuple[
                CooperativeClaimOutpoint, BoundHoldInvoiceObservation, CooperativeFeePolicy
            ]:
                core = await operation.worker(
                    partial(
                        self._chain.observe_cooperative_claim_outpoint,
                        context.binding,
                        context.terms,
                        keys=keys,
                    )
                )
                operation.check()
                original_window.check(tip_height=core.tip_height)
                policy = await operation.worker(
                    partial(
                        self._chain.observe_cooperative_fee_policy,
                        context.terms.timing_policy.claim_confirmation_blocks,
                        allow_regtest_fixed_fee=allow_regtest_fixed_fee,
                    )
                )
                operation.check()
                original_window.check(tip_height=core.tip_height)
                invoice = await operation.worker(
                    partial(
                        self._hold.observe_bound_settled_invoice,
                        context.terms.invoice_binding,
                        submission_allowed=submission_allowed,
                    )
                )
                return core, invoice, policy

            core, invoice, policy, started, completed = await _tip_agreeing(
                original_window, observe
            )
            operation.check()
            return _ReversePaidProposalEvidence(
                operation,
                context,
                core,
                policy,
                invoice,
                started,
                completed,
                configured_floor_sat,
                allow_regtest_fixed_fee,
            )
        except (asyncio.CancelledError, StaleOwnerError):
            if window is not None:
                window.abandon()
            raise
        except Exception:  # noqa: BLE001 - no archived preimage, plan, or backend oracle
            if window is not None:
                window.abandon()
        raise LiveSessionStoreError("reverse paid proposal preflight refused")

    def _check_operation(self) -> ReverseOperation:
        if self._operation is None:
            raise LiveSessionStoreError("reverse settlement step not active")
        self._operation.check()
        return self._operation

    async def _worker(self, function: Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs) -> _T:
        return await self._check_operation().worker(partial(function, *args, **kwargs))

    async def _step(self, item: SettlementItem, now: int) -> str:
        if item.preimage is not None and item.state not in {
            "FUNDING_SENT",
            "FUNDED",
            "REFUNDING",
            "SETTLED",
        }:
            raise LiveSessionStoreError("reverse settlement intent in an unexpected state")
        terms = offered_terms(Envelope.model_validate_json(item.terms_offer, strict=True))
        if terms.profile_id != "ln-to-btc/v1":
            raise LiveSessionStoreError("reverse settlement requires LN to BTC terms")
        if item.state == "ACCEPTED":
            return await self._accepted(item, terms, now)
        if item.state == "LN_HELD":
            return await self._held(item, terms, now)
        if item.state == "FUNDING_SENT":
            return await self._funding_sent(item, terms, now)
        if item.state in ("FUNDED", "REFUNDING"):
            return await self._funded(item, terms, now)
        return item.state

    def _move(self, item: SettlementItem, to_state: str, now: int, **fields: object) -> str:
        self._check_operation()
        self._store.advance_reverse_swap(
            item.session_id,
            from_state=item.state,
            to_state=to_state,
            signer=self._crypto,
            now=now,
            **fields,  # type: ignore[arg-type]
        )
        committed_transition(LOG, item.session_id, item.state, to_state, item.terms_offer, **fields)
        return to_state

    async def _abort(self, item: SettlementItem, terms: ContractTerms, now: int, why: str) -> str:
        """Cancel the hold (nothing was funded) and close the swap."""
        await self._worker(self._hold.cancel, terms.invoice_binding.payment_hash)
        LOG.info("LN to BTC swap aborted before funding: %s", why)
        return self._move(item, "ABORTED", now, observation={"kind": "swap_aborted", "reason": why})

    def _funding_window_open(self, terms: ContractTerms, tip: int) -> bool:
        timing = terms.timing_policy.model_dump()
        needed = (
            terms.funding_confirmations
            + int(timing["client_response_blocks"])
            + int(timing["claim_confirmation_blocks"])
        )
        return tip + needed < terms.refund_lock_height

    def _held_as_agreed(self, terms: ContractTerms, status: HoldInvoiceStatus) -> str | None:
        """Return why the accepted hold does not satisfy the terms, or None."""
        economics = terms.economics.model_dump()
        timing = terms.timing_policy.model_dump()
        if status.state != "ACCEPTED":
            return f"hold invoice is {status.state}"
        if status.held_msat != int(economics["hold_invoice_sat"]) * 1000:
            return "held amount differs from H"
        earliest = status.earliest_expiry_height
        first_refund_block = terms.refund_lock_height + 1
        if earliest is None or (
            first_refund_block + int(timing["refund_and_ln_resolution_blocks"]) >= earliest
        ):
            return "incoming HTLC expires too soon"
        return None

    async def _accepted(self, item: SettlementItem, terms: ContractTerms, now: int) -> str:
        """Wait for the hold; move to LN_HELD once every accepted part checks out."""
        status = await self._worker(self._hold.lookup, terms.invoice_binding.payment_hash)
        if status.state == "OPEN":
            if now >= terms.invoice_binding.expires_at:
                return await self._abort(item, terms, now, "hold invoice expired unpaid")
            return item.state
        if status.state == "CANCELED":
            return self._move(
                item,
                "ABORTED",
                now,
                observation={"kind": "swap_aborted", "reason": "hold canceled"},
            )
        problem = self._held_as_agreed(terms, status)
        if problem is not None:
            return await self._abort(item, terms, now, problem)
        tip = await self._worker(self._chain.tip_height)
        if not self._funding_window_open(terms, tip):
            return await self._abort(item, terms, now, "funding window closed")
        return self._move(item, "LN_HELD", now, observation={"kind": "hold_accepted"})

    async def _held(self, item: SettlementItem, terms: ContractTerms, now: int) -> str:
        """Fund the contract: re-check the hold and the window, sign, record, broadcast."""
        status = await self._worker(self._hold.lookup, terms.invoice_binding.payment_hash)
        problem = self._held_as_agreed(terms, status)
        if problem is not None:
            return await self._abort(item, terms, now, problem)
        tip = await self._worker(self._chain.tip_height)
        if not self._funding_window_open(terms, tip):
            return await self._abort(item, terms, now, "funding window closed")
        script = reconstruct_taproot_contract(terms, keys=self._crypto).script_pubkey
        value = int(terms.economics.model_dump()["contract_amount_sat"])
        funded = await self._worker(
            self._chain.fund_output,
            script,
            value,
            max_fee_sat=int(terms.max_funding_fee_sat),
        )
        binding = FundingBinding(
            contract_hash=contract_hash(terms).hex(),
            funding_attempt_id=secrets.token_hex(32),
            binding_revision=0,
            funder_role="provider",
            lineage_anchor_txid=funded.anchor_txid,
            lineage_anchor_vout=funded.anchor_vout,
            funding_txid=funded.txid,
            contract_vout=funded.vout,
            contract_value_sat=str(value),
            contract_script_pubkey=script.hex(),
            replaces_txid=None,
            created_at=now,
        )
        # The grant (and the signed funding_binding for the client) is durable
        # before any broadcast; FUNDING_SENT rebroadcasts.
        try:
            state = self._move(
                item,
                "FUNDING_SENT",
                now,
                funding=(binding, funded.raw),
                funding_fee_sat=funded.fee_sat,
            )
        except Exception as refusal:  # commit failure is not proof of rollback
            if funded.selected_inputs:
                try:
                    operation = self._check_operation()
                    if self._store.reverse_funding_is_ungranted(
                        item.session_id, operation=operation
                    ):
                        await self._worker(
                            self._chain.release_funding_inputs, funded.selected_inputs
                        )
                except Exception:  # noqa: BLE001 - uncertain authority retains locks and original error
                    refusal.add_note("Funding input cleanup unconfirmed; inspect wallet locks.")
            raise
        await self._worker(self._chain.broadcast, funded.raw, funded.txid)
        return state

    async def _funding_sent(self, item: SettlementItem, terms: ContractTerms, now: int) -> str:
        """Keep the funding broadcast; move to FUNDED at the signed depth.

        A client may claim before that depth, even from the mempool, taking
        the double-spend risk itself. Recorded debt (a cooperative proposal) or
        a claim witness already in the mempool settles the hold right away; a
        claim that confirmed unseen is found by the FUNDED scan, which starts
        at the funding block.
        """
        if item.preimage is not None:
            # Affirmatively recorded intent: no rebroadcast or depth gate first.
            return await self._settle_claim(item, terms, now, item.preimage)
        txid, raw = _funding(item)
        try:
            await self._worker(self._chain.broadcast, raw, txid)
        except CoreRpcError:
            # Core refuses to relay a confirmed transaction whose outputs an
            # early claim already spent; only a confirmed copy excuses that.
            if await self._worker(self._chain.confirmations, txid) < 1:
                raise
        tip = await self._worker(self._chain.tip_height)
        anchor = await self._worker(self._chain.block_hash, tip)
        mempool = await self._worker(  # an empty block range: the mempool at this tip only
            self._chain.find_spender,
            txid,
            int(item.funding_vout or 0),
            from_height=tip + 1,
            to_height=tip,
            anchor_block=anchor,
        )
        if mempool.spender is not None:
            preimage = _preimage_in(mempool.spender.witness, terms.invoice_binding.payment_hash)
            if preimage is not None:
                return await self._settle_claim(item, terms, now, preimage)
        depth = await self._worker(self._chain.confirmations, txid)
        if depth < terms.funding_confirmations:
            return item.state
        floor, block = await self._worker(
            self._chain.funding_scan_boundary, txid, terms.funding_confirmations
        )
        return self._move(
            item,
            "FUNDED",
            now,
            scan_checkpoint=ReverseSpendCheckpoint(floor, block, floor, block),
        )

    async def _funded(  # noqa: PLR0911, PLR0912 - explicit conservative evidence outcomes
        self, item: SettlementItem, terms: ContractTerms, now: int
    ) -> str:
        """Settle on a claim revealing the preimage; otherwise refund after the lock."""
        if item.preimage is not None:
            # Affirmatively recorded intent survives vanished witnesses and
            # Core outages. No chain scan or refund may supersede this debt.
            return await self._settle_claim(item, terms, now, item.preimage)
        txid, _raw = _funding(item)
        vout = int(item.funding_vout or 0)
        tip = await self._worker(self._chain.tip_height)
        operation = self._check_operation()
        checkpoint = self._store.reverse_spend_checkpoint(item.session_id, operation=operation)
        if checkpoint is None:
            # FUNDED commits its checkpoint atomically, so a missing one is
            # damaged state: never invent scan coverage or refund without it.
            raise LiveSessionStoreError(
                "reverse scan checkpoint unavailable; operator recovery required"
            )
        floor_block = await self._worker(self._chain.block_hash, checkpoint.floor_height)
        if floor_block != checkpoint.floor_block:
            raise LiveSessionStoreError(
                "reverse scan replay floor reorganized; operator recovery required before refund"
            )
        if (
            checkpoint.height > tip
            or await self._worker(self._chain.block_hash, checkpoint.height) != checkpoint.block
        ):
            self._store.update_reverse_spend_checkpoint(
                item.session_id,
                expected=checkpoint,
                checkpoint=ReverseSpendCheckpoint(
                    checkpoint.floor_height,
                    checkpoint.floor_block,
                    checkpoint.floor_height,
                    checkpoint.floor_block,
                ),
                operation=operation,
                rewind=True,
            )
            return item.state  # The reset is durable before the next bounded batch.
        scan = await self._worker(
            self._chain.find_spender,
            txid,
            vout,
            from_height=checkpoint.height + 1,
            to_height=tip,
            anchor_block=checkpoint.block,
        )
        payment_hash = terms.invoice_binding.payment_hash
        if scan.spender is not None:
            preimage = _preimage_in(scan.spender.witness, payment_hash)
            if preimage is not None:
                return await self._settle_claim(item, terms, now, preimage)
            # Our own refund, or an unknown spend: only our refund is expected here.
            if scan.spender.txid != item.refund_txid:
                LOG.warning("contract spent by an unexpected transaction; not settling")
                return item.state
        if scan.scanned_to < checkpoint.height:
            return item.state
        if scan.scanned_to > min(tip, checkpoint.height + MAX_SPEND_SCAN_BLOCKS):
            raise LiveSessionStoreError("reverse scan exceeded its bounded interval")
        if scan.scanned_block is None:
            raise LiveSessionStoreError("reverse scan canonical progress unavailable")
        progress = ReverseSpendCheckpoint(
            checkpoint.floor_height, checkpoint.floor_block, scan.scanned_to, scan.scanned_block
        )
        self._store.update_reverse_spend_checkpoint(
            item.session_id, expected=checkpoint, checkpoint=progress, operation=operation
        )
        if scan.scanned_to < tip:
            return item.state  # Backlog blocks refund initiation AND refund-based cancellation.
        if item.state == "REFUNDING":
            return await self._refunding(item, terms, now)
        if tip < terms.refund_lock_height:
            return item.state
        spend = await self._refund(item, terms)
        state = self._move(
            item,
            "REFUNDING",
            now,
            refund=(spend.txid, spend.raw_transaction),
            observation={"kind": "refund_broadcast", "refund_txid": spend.txid},
            refund_fee_sat=spend.fee_sat,  # a cost only if the refund wins (REFUNDED)
        )
        await self._worker(self._chain.broadcast, spend.raw_transaction, spend.txid)
        return state

    async def _refunding(self, item: SettlementItem, terms: ContractTerms, now: int) -> str:
        """Keep the refund broadcast; cancel the hold only at the signed depth."""
        if item.refund_txid is None or item.refund_tx is None:
            raise RuntimeError("REFUNDING swap without its refund")
        await self._worker(self._chain.broadcast, item.refund_tx, item.refund_txid)
        depth = await self._worker(self._chain.confirmations, item.refund_txid)
        if depth < terms.refund_resolution_confirmations:
            return item.state
        await self._worker(self._hold.cancel, terms.invoice_binding.payment_hash)
        return self._move(
            item,
            "REFUNDED",
            now,
            refund_confirmations=depth,
            observation={"kind": "refund_confirmed", "refund_txid": item.refund_txid},
        )

    async def _settle_claim(
        self,
        item: SettlementItem,
        terms: ContractTerms,
        now: int,
        preimage: str,
        *,
        cooperation_window: ReverseCooperationWindow | None = None,
    ) -> str:
        operation = self._check_operation()
        self._store.record_reverse_settlement_preimage(
            item.session_id, from_state=item.state, preimage=preimage, now=now
        )
        binding = self._store._reverse_repayment_binding(item.session_id)  # noqa: SLF001 - owner-authenticated archive boundary
        if cooperation_window is not None and binding is None:
            raise LiveSessionStoreError("reverse original repayment binding absent")
        if binding is None:
            await self._settle(preimage, terms.invoice_binding.payment_hash)
        else:
            # Capture the actual task-owned token before queuing an RPC worker.
            # This checkpoint grants no signing authority or deadline renewal.
            submission_allowed = operation.submission_allowed
            if cooperation_window is not None:

                def submission_allowed() -> bool:
                    return operation.submission_allowed() and cooperation_window.time_allowed()

            await self._worker(
                self._hold.settle_bound_invoice,
                binding,
                preimage,
                submission_allowed=submission_allowed,
            )
        return self._move(
            item, "SETTLED", now, preimage=preimage, observation={"kind": "hold_settled"}
        )

    async def _settle(self, preimage: str, payment_hash: str) -> None:
        """Settle the hold; tolerate an earlier settlement of the same invoice."""
        try:
            await self._worker(self._hold.settle, preimage)
        except LndObservationError:
            status = await self._worker(self._hold.lookup, payment_hash)
            if status.state != "SETTLED":
                raise

    async def _refund(self, item: SettlementItem, terms: ContractTerms) -> ValidatedUnilateralSpend:
        self._check_operation()
        txid, _raw = _funding(item)
        funding = FundingOutput(
            txid=bytes.fromhex(txid),
            output_index=int(item.funding_vout or 0),
            value_sat=int(terms.economics.model_dump()["contract_amount_sat"]),
            script_pubkey=reconstruct_taproot_contract(terms, keys=self._crypto).script_pubkey,
        )
        authorization = UnilateralAuthorization.from_terms(
            terms, funding, "refund", keys=self._crypto
        )
        ceiling = max_spendable_fee(authorization)
        floor = min(self._refund_fee_floor_sat, ceiling)
        spend = self._sign_refund(item, authorization, floor)
        try:
            rate = await self._worker(self._chain.fee_rate_sat_vb, REFUND_ESTIMATE_TARGET)
        except Exception:  # noqa: BLE001 - advice only; never defer a timelocked spend for it
            LOG.warning("fee estimate unavailable; signing at the floor fee")
            rate = None
        if rate is None:
            return spend
        wanted = min(ceiling, max(floor, math.ceil(rate * spend.vsize)))
        return spend if wanted == floor else self._sign_refund(item, authorization, wanted)

    def _sign_refund(
        self, item: SettlementItem, authorization: UnilateralAuthorization, fee: int
    ) -> ValidatedUnilateralSpend:
        self._check_operation()
        plan = build_unilateral_spend(authorization, fee_sat=fee)
        signature = self._store.sign_with_contract_key(
            item.session_id, plan.signature_hash, self._crypto
        )
        return finalize_unilateral_spend(plan, signature, verifier=self._crypto)


def _funding(item: SettlementItem) -> tuple[str, bytes]:
    if item.funding_txid is None or item.funding_tx is None:
        raise RuntimeError("funded swap without its funding")
    return item.funding_txid, item.funding_tx


def _preimage_in(witness: tuple[bytes, ...], payment_hash: str) -> str | None:
    """Return the 32-byte witness element hashing to ``payment_hash``, if any."""
    for element in witness:
        if len(element) == PREIMAGE_BYTES and hashlib.sha256(element).hexdigest() == payment_hash:
            return element.hex()
    return None
