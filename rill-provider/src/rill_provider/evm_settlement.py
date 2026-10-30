"""Settlement of ERC20 swaps (RS-010) on top of the EVM HTLC client.

One ``EvmSettlementEngine`` serves one provider process bound to either
``erc20-to-ln/v1`` or ``ln-to-erc20/v1``. Each tick enumerates the store's
open EVM swaps and moves every one at most through its available steps:

* erc20-to-ln: wait for the client's exact ``Lockup`` at funding depth, pay
  the invoice (one durable dispatch grant, exactly like BTC to LN), then
  claim the lock with the preimage and wait for settlement depth.
* ln-to-erc20: wait for the hold invoice, lock the tokens (one durable lock
  grant recorded before broadcast, like LN to BTC), settle the hold with the
  preimage the client's ``Claim`` log reveals, or refund after the timelock.

Every signed transaction is recorded in the store before it is broadcast so
a restart repeats the broadcast instead of signing again. Backend trouble
defers one swap for a tick and never stops the others, with one exception
that serializes the signer's nonces: recorded transactions are rebroadcast
first, and once the node refuses one, the tick signs nothing new (a fresh
"pending" nonce would otherwise reuse the refused one's slot). A claim or
refund whose nonce another transaction consumed anyway (e.g. a second
process sharing the key) is re-signed on that affirmative chain evidence; a
lock never is. One signer key must belong to exactly one provider process.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import TYPE_CHECKING, Any, Protocol

from rill_core.wire.messages import Erc20ToLnTiming, LnToErc20Timing

from rill_provider.diagnostics import diagnostic
from rill_provider.evm_htlc import EvmBackendError, LockParams
from rill_provider.evm_quote_policy import BTC_BLOCK_SECONDS, EvmQuoteContext, EvmQuotePrices
from rill_provider.live_session_store import StaleOwnerError, StaleSwapError
from rill_provider.lnd_invoice_decode import InvoiceRejectedError
from rill_provider.lnd_payment_observation import LndNotSyncedError, LndUnavailableError
from rill_provider.settlement_diagnostics import committed_transition, waiting_observation
from rill_provider.settlement_engine import READINESS_BUDGET_SECONDS, READINESS_SYNC_DELAY

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from rill_core.wire.messages import EvmContractTerms, InvoiceBinding
    from rill_core.wire.types import EvmAssetIdentity

    from rill_provider.evm_htlc import EvmHtlcClient, SignedTx
    from rill_provider.evm_quote_policy import EvmSchedule
    from rill_provider.live_session_store import (
        EnvelopeSigner,
        EvmSettlementItem,
        LiveSessionStore,
    )
    from rill_provider.lnd_hold_invoice import HoldInvoiceStatus
    from rill_provider.lnd_payment_send import PaymentOutcome
    from rill_provider.settlement_engine import LightningBackend

LOG = logging.getLogger(__name__)
LOCKUP_SCAN_MARGIN_BLOCKS = 64  # look a little before the reference block for early locks
SENT_STATES = ("CLAIMING", "FUNDING_SENT", "REFUNDING")  # a recorded transaction of ours


class HoldInvoiceBackend(Protocol):
    """The subset of ``LndHoldInvoices`` the reverse lifecycle uses."""

    def lookup(self, payment_hash: str) -> HoldInvoiceStatus:
        """Return the hold's current state and accepted parts."""
        ...

    def settle(self, preimage: str, *, deadline: float | None = None) -> None:
        """Settle the hold with its preimage."""
        ...

    def cancel(self, payment_hash: str) -> None:
        """Cancel an unsettled hold."""
        ...


def _lock_params(terms: EvmContractTerms) -> LockParams:
    return LockParams.from_terms(terms)


def _forward_timing_ok(terms: EvmContractTerms, *, btc_tip: int, evm_tip: int) -> bool:
    """RS-010 forward inequality re-checked against live heights before paying."""
    timing = terms.timing_policy
    assert isinstance(timing, Erc20ToLnTiming)  # noqa: S101 - profile-bound engine
    ln_seconds = (timing.max_outgoing_htlc_expiry_height - btc_tip) * BTC_BLOCK_SECONDS
    evm_seconds = (terms.htlc_timelock_block - evm_tip) * terms.evm_asset.block_seconds
    return ln_seconds + timing.learn_and_claim_seconds < evm_seconds


def _reverse_window_open(
    terms: EvmContractTerms, *, btc_tip: int, evm_tip: int, earliest_expiry_height: int
) -> bool:
    """RS-010 reverse inequality against the hold's real HTLC expiry and live heights."""
    timing = terms.timing_policy
    assert isinstance(timing, LnToErc20Timing)  # noqa: S101 - profile-bound engine
    if evm_tip + terms.funding_confirmations + terms.settlement_confirmations >= (
        terms.htlc_timelock_block
    ):
        return False
    evm_seconds = (terms.htlc_timelock_block - evm_tip) * terms.evm_asset.block_seconds
    ln_seconds = (earliest_expiry_height - btc_tip) * BTC_BLOCK_SECONDS
    return evm_seconds + timing.refund_and_ln_resolution_seconds < ln_seconds


class EvmSettlementEngine:
    """Drive every open EVM-profile swap of one provider process."""

    def __init__(  # noqa: PLR0913 - explicit injected backends
        self,
        store: LiveSessionStore,
        htlc: EvmHtlcClient,
        signer: EnvelopeSigner,
        *,
        assets: tuple[EvmAssetIdentity, ...],
        rates: Callable[[], Mapping[str, int]],
        schedule: EvmSchedule,
        btc_tip: Callable[[], int | None],
        lightning: LightningBackend | None = None,
        hold_invoices: HoldInvoiceBackend | None = None,
        max_routing_fee_sat: int = 1_000,
        normal_fee_sat: Callable[[int], int] | None = None,
        claim_address: str | None = None,
        quote_pricing: Callable[[], EvmQuotePrices] | None = None,
    ) -> None:
        """``lightning`` serves erc20-to-ln; ``hold_invoices`` serves ln-to-erc20.

        ``normal_fee_sat`` prices a Lightning principal at the operator's
        undiscounted service fee; it bounds routing so that a balance-aware
        discount or rebate never shrinks the budget. Without it the budget
        falls back to the signed fee, never below zero.
        ``claim_address`` changes only new forward quotes' HTLC recipient,
        not the gas signer or any retained swap's committed destination.
        """
        self._store = store
        self._diagnostic_waiting: dict[str, str] = {}
        self._htlc = htlc
        self._signer = signer
        self._assets = assets
        self._rates = rates
        self._schedule = schedule
        self._btc_tip = btc_tip
        self._lightning = lightning
        self._hold = hold_invoices
        self._max_routing_fee_sat = max_routing_fee_sat
        self._normal_fee_sat = normal_fee_sat
        self._claim_address = claim_address
        self._quote_pricing = quote_pricing
        # Nonce gate: a tick signs nothing new once any recorded transaction was
        # refused by the node, so a fresh "pending" nonce never reuses its slot.
        self._may_sign = True

    def _routing_budget(self, principal_sat: int, signed_fee_sat: int) -> int:
        """Bound routing by the operator cap and the normal fee, never a discounted fee."""
        fee = (
            signed_fee_sat if self._normal_fee_sat is None else self._normal_fee_sat(principal_sat)
        )
        return min(self._max_routing_fee_sat, max(fee, 0))

    # -- quoting support -------------------------------------------------

    def quote_context(self) -> EvmQuoteContext:
        """Fix EVM facts, rates and any live gas charge before a hold is opened."""
        try:
            tip: int | None = self._htlc.block_number()
        except Exception:  # noqa: BLE001 - an unavailable node only defers firm offers
            LOG.warning("EVM tip unavailable; quotes answered capacity_unavailable")
            tip = None
        try:
            if self._quote_pricing is None:
                rates, gas = self._rates(), None
            else:
                prices = self._quote_pricing()
                rates, gas = prices.rates, prices.network_fees_token_base
        except Exception as error:  # noqa: BLE001 - never fall back to a stale or zero price
            LOG.warning("EVM prices unavailable (%s)", type(error).__name__)
            rates, gas = {}, {}
        return EvmQuoteContext(
            assets=self._assets,
            rates=rates,
            provider_evm_address=self._claim_address or self._htlc.signer_address,
            schedule=self._schedule,
            tip=tip,
            network_fees_token_base=gas,
        )

    def route_ready(
        self,
        invoice: str,
        *,
        invoice_binding: InvoiceBinding,
        success_fee_sat: int,
        max_expiry_height: int,
    ) -> None:
        """Raise unless LND can route this invoice now (same contract as the Bitcoin engine)."""
        if self._lightning is None:
            raise LndUnavailableError("no Lightning payment backend")
        import time  # noqa: PLC0415 - local monotonic budget

        deadline = time.monotonic() + READINESS_BUDGET_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            try:
                self._lightning.prepare(
                    invoice,
                    invoice_binding=invoice_binding,
                    fee_limit_sat=self._routing_budget(
                        int(invoice_binding.amount_msat) // 1000, success_fee_sat
                    ),
                    max_expiry_height=max_expiry_height,
                    deadline_seconds=max(0.1, remaining),
                )
            except LndNotSyncedError:
                if remaining <= READINESS_SYNC_DELAY:
                    raise
                time.sleep(READINESS_SYNC_DELAY)
            else:
                return

    # -- lifecycle ---------------------------------------------------------

    async def tick(self, now: int) -> dict[str, str]:
        """Advance each EVM swap at most through its available steps; return new states."""
        results: dict[str, str] = {}
        self._may_sign = True
        # Recorded transactions first: their rebroadcasts decide whether this
        # tick may take new nonces (see ``_broadcast``).
        work = sorted(self._store.evm_settlement_work(), key=lambda w: w.state not in SENT_STATES)
        self._diagnostic_waiting = {
            item.session_id: self._diagnostic_waiting[item.session_id]
            for item in work
            if item.session_id in self._diagnostic_waiting
        }
        for item in work:
            try:
                state = await self._advance(item, now)
            except StaleOwnerError:
                raise  # a fenced/uncertain store cannot defer economic work
            except StaleSwapError:
                continue
            except Exception as error:  # noqa: BLE001 - one swap cannot stop other settlement
                diagnostic(
                    LOG,
                    "swap.deferred",
                    "EVM settlement step deferred for one swap",
                    level=logging.WARNING,
                    session_id=item.session_id,
                    state=item.state,
                    error_type=type(error).__name__,
                    reason="backend_or_validation_unavailable",
                )
                continue
            if state != item.state:
                self._diagnostic_waiting.pop(item.session_id, None)
                results[item.session_id] = state
            elif self._diagnostic_waiting.get(item.session_id) != state:
                waiting_observation(LOG, item.session_id, state, item.terms_offer)
                self._diagnostic_waiting[item.session_id] = state
        return results

    async def _broadcast(self, raw: bytes) -> None:
        """Submit recorded bytes; a refusal closes the nonce gate for the rest of the tick."""
        try:
            await asyncio.to_thread(self._htlc.broadcast, raw)
        except Exception:
            self._may_sign = False
            raise

    async def _replace_dead(
        self,
        item: EvmSettlementItem,
        terms: EvmContractTerms,
        now: int,
        old_hash: str,
        prepare: Callable[[], SignedTx],
    ) -> str:
        """Re-sign a claim or refund whose nonce another transaction took (RS-010)."""
        if not self._may_sign:
            return item.state
        if not await asyncio.to_thread(self._htlc.lock_active, _lock_params(terms)):
            LOG.error(
                "EVM %s transaction superseded and the lock is gone: swap %s needs attention",
                item.state,
                item.session_id[:16],
            )
            return item.state
        signed = await asyncio.to_thread(prepare)
        self._store.replace_evm_sent(
            item.session_id,
            state=item.state,
            old_hash=old_hash,
            sent=(signed.tx_hash, signed.raw),
            signer=self._signer,
            now=now,
        )
        LOG.warning(
            "EVM %s transaction %s superseded by another nonce use; re-signed as %s",
            item.state,
            old_hash[:16],
            signed.tx_hash[:16],
        )
        await self._broadcast(signed.raw)
        return item.state

    def _move(self, item: EvmSettlementItem, to_state: str, now: int, **fields: Any) -> str:  # noqa: ANN401
        self._store.advance_evm_swap(
            item.session_id,
            from_state=item.state,
            to_state=to_state,
            signer=self._signer,
            now=now,
            **fields,
        )
        committed_transition(LOG, item.session_id, item.state, to_state, item.terms_offer, **fields)
        return to_state

    async def _advance(self, item: EvmSettlementItem, now: int) -> str:
        terms = item.terms()
        if terms.profile_id == "ln-to-erc20/v1":
            return await self._advance_reverse(item, terms, now)
        return await self._advance_forward(item, terms, now)

    async def _heights(self) -> tuple[int, int]:
        btc_tip = await asyncio.to_thread(self._btc_tip)
        if btc_tip is None or btc_tip <= 0:
            raise EvmBackendError("Bitcoin tip unavailable")
        return btc_tip, await asyncio.to_thread(self._htlc.block_number)

    async def _active_lockup(self, terms: EvmContractTerms, evm_tip: int) -> Any | None:  # noqa: ANN401
        """Return the exact, still active Lockup log for these terms, or None."""
        params = _lock_params(terms)
        lockups = await asyncio.to_thread(
            lambda: self._htlc.find_lockups(
                terms.invoice_binding.payment_hash,
                from_block=max(0, terms.evm_reference_block - LOCKUP_SCAN_MARGIN_BLOCKS),
                to_block=evm_tip,
            )
        )
        for event in lockups:
            if event.matches(params):
                active = await asyncio.to_thread(self._htlc.lock_active, params)
                return event if active else None
        return None

    # -- erc20-to-ln -------------------------------------------------------

    async def _advance_forward(  # noqa: PLR0911, PLR0912 - one closed rule per state
        self, item: EvmSettlementItem, terms: EvmContractTerms, now: int
    ) -> str:
        if item.state == "ACCEPTED":
            btc_tip, evm_tip = await self._heights()
            lockup = await self._active_lockup(terms, evm_tip)
            if lockup is None:
                if now >= terms.invoice_binding.expires_at:
                    return self._move(item, "FAILED", now, observation={"kind": "payment_failed"})
                return item.state
            if evm_tip - lockup.block_number + 1 < terms.funding_confirmations:
                return item.state
            self._move(
                item,
                "FUNDING_SEEN",
                now,
                lockup=(lockup.tx_hash, lockup.log_index, lockup.block_number),
                observation={
                    "kind": "evm_lockup_observed",
                    "lock_tx_hash": lockup.tx_hash,
                    "log_index": lockup.log_index,
                    "block_number": lockup.block_number,
                },
            )
            return await self._advance_forward(_with_state(item, "FUNDING_SEEN"), terms, now)
        if item.state == "FUNDING_SEEN":
            btc_tip, evm_tip = await self._heights()
            if not _forward_timing_ok(terms, btc_tip=btc_tip, evm_tip=evm_tip):
                return self._move(item, "FAILED", now, observation={"kind": "payment_failed"})
            if item.blocked:
                return item.state
            self._move(item, "PAYING", now)
            return await self._advance_forward(
                _with_state(item, "PAYING", dispatch_state="UNSENT"), terms, now
            )
        if item.state == "PAYING":
            outcome = await self._pay(item, terms, now)
            if outcome is None:
                return self._move(item, "FAILED", now, observation={"kind": "payment_failed"})
            if outcome.status == "FAILED":
                return self._move(
                    item,
                    "FAILED",
                    now,
                    failed_by_payer=outcome.payer,
                    observation={"kind": "payment_failed"},
                )
            if outcome.status != "SUCCEEDED" or outcome.preimage is None:
                return item.state
            self._move(
                item,
                "PAID",
                now,
                preimage=outcome.preimage,
                observation={"kind": "payment_settled", "payment_preimage": outcome.preimage},
                routing_fee_msat=outcome.fee_msat,
            )
            return await self._advance_forward(
                _with_state(item, "PAID", preimage=outcome.preimage), terms, now
            )
        if item.state == "PAID" and item.preimage is not None:
            if not self._may_sign:
                return item.state
            preimage = item.preimage
            signed = await asyncio.to_thread(
                lambda: self._htlc.prepare_claim(_lock_params(terms), preimage)
            )
            self._move(
                item,
                "CLAIMING",
                now,
                sent=(signed.tx_hash, signed.raw),
                observation={"kind": "claim_broadcast", "claim_txid": signed.tx_hash},
            )
            await self._broadcast(signed.raw)
            return "CLAIMING"
        if (
            item.state == "CLAIMING"
            and item.claim_tx_hash is not None
            and item.claim_tx is not None
        ):
            receipt = await asyncio.to_thread(self._htlc.receipt, item.claim_tx_hash)
            if receipt is None:
                claim_tx, claim_hash = item.claim_tx, item.claim_tx_hash
                if await asyncio.to_thread(
                    self._htlc.superseded, claim_tx, terms.settlement_confirmations
                ):
                    preimage = item.preimage or ""
                    return await self._replace_dead(
                        item,
                        terms,
                        now,
                        claim_hash,
                        lambda: self._htlc.prepare_claim(_lock_params(terms), preimage),
                    )
                await self._broadcast(claim_tx)
                return item.state
            if receipt.status == "success":
                depth = await asyncio.to_thread(self._htlc.confirmations, item.claim_tx_hash)
                if depth < terms.settlement_confirmations:
                    return item.state
                return self._move(item, "CLAIMED", now, gas_wei=receipt.gas_wei)
            # Our claim reverted: either the client refunded after the timelock
            # (the lock is gone) or the lock is still there and needs an operator.
            active = await asyncio.to_thread(self._htlc.lock_active, _lock_params(terms))
            if not active:
                LOG.error(
                    "EVM claim reverted and the lock is gone: swap %s lost", item.session_id[:16]
                )
                return self._move(item, "LOST", now, gas_wei=receipt.gas_wei)  # reverted, paid
            LOG.error(
                "EVM claim reverted while the lock is active: swap %s needs attention",
                item.session_id[:16],
            )
            return item.state
        return item.state

    async def _pay(  # noqa: PLR0911 - explicit exposure guards before the sole send
        self, item: EvmSettlementItem, terms: EvmContractTerms, now: int
    ) -> PaymentOutcome | None:
        """Return the payment outcome, or None when it must never be sent."""
        if self._lightning is None:
            raise LndUnavailableError("no Lightning payment backend")
        lightning, invoice, payer = self._lightning, terms.invoice_binding, item.payer
        outcome = await asyncio.to_thread(
            lambda: lightning.track(invoice.payment_hash, payer=payer)
        )
        if outcome.status == "FAILED" and payer is None:
            raise LndUnavailableError("tracked failure lacks bound payer authority")
        if outcome.status != "UNKNOWN":
            return outcome
        if item.blocked or item.dispatch_state != "UNSENT":
            return outcome
        btc_tip, evm_tip = await self._heights()
        lockup = await self._active_lockup(terms, evm_tip)
        if lockup is None or evm_tip - lockup.block_number + 1 < terms.funding_confirmations:
            return outcome
        if not _forward_timing_ok(terms, btc_tip=btc_tip, evm_tip=evm_tip):
            return None
        if now >= invoice.expires_at or (
            hashlib.sha256(item.invoice.encode("ascii")).hexdigest() != invoice.bolt11_sha256
        ):
            return None
        timing = terms.timing_policy
        assert isinstance(timing, Erc20ToLnTiming)  # noqa: S101 - forward swap
        if timing.max_outgoing_htlc_expiry_height - btc_tip <= invoice.min_final_cltv_delta:
            return None
        economics = terms.economics.model_dump()
        fee_limit = self._routing_budget(
            int(economics["lightning_principal_sat"]),
            _token_fee_as_sats(
                int(economics["success_fee_token_base"]), int(economics["rate_token_base_per_btc"])
            ),
        )
        try:
            payment = await asyncio.to_thread(
                lambda: lightning.prepare(
                    item.invoice,
                    invoice_binding=invoice,
                    fee_limit_sat=fee_limit,
                    max_expiry_height=timing.max_outgoing_htlc_expiry_height,
                )
            )
        except InvoiceRejectedError:
            return None
        if not self._store.commit_payment_dispatch(
            item.session_id, invoice.payment_hash, payment.dispatch_record
        ):
            return outcome
        return await asyncio.to_thread(lightning.send, payment)

    # -- ln-to-erc20 -------------------------------------------------------

    def _hold_backend(self) -> HoldInvoiceBackend:
        if self._hold is None:
            raise LndUnavailableError("no hold invoice backend")
        return self._hold

    async def _abort(
        self, item: EvmSettlementItem, terms: EvmContractTerms, now: int, why: str
    ) -> str:
        """Cancel the hold (nothing was locked) and close the swap."""
        await asyncio.to_thread(self._hold_backend().cancel, terms.invoice_binding.payment_hash)
        LOG.info("LN to ERC20 swap aborted before locking: %s", why)
        return self._move(item, "ABORTED", now, observation={"kind": "swap_aborted", "reason": why})

    async def _held_problem(self, terms: EvmContractTerms, status: HoldInvoiceStatus) -> str | None:
        """Return why the accepted hold does not satisfy the terms, or None."""
        economics = terms.economics.model_dump()
        timing = terms.timing_policy
        assert isinstance(timing, LnToErc20Timing)  # noqa: S101 - reverse swap
        if status.state != "ACCEPTED":
            return f"hold invoice is {status.state}"
        if status.held_msat != int(economics["hold_invoice_sat"]) * 1000:
            return "held amount differs from H"
        earliest = status.earliest_expiry_height
        if earliest is None or earliest < timing.min_incoming_htlc_expiry_height:
            return "incoming HTLC expires too soon"
        btc_tip, evm_tip = await self._heights()
        if not _reverse_window_open(
            terms, btc_tip=btc_tip, evm_tip=evm_tip, earliest_expiry_height=earliest
        ):
            return "lock window closed"
        return None

    async def _advance_reverse(  # noqa: PLR0911, PLR0912, PLR0915 - one closed rule per state
        self, item: EvmSettlementItem, terms: EvmContractTerms, now: int
    ) -> str:
        hold, payment_hash = self._hold_backend(), terms.invoice_binding.payment_hash
        if item.state == "ACCEPTED":
            status = await asyncio.to_thread(hold.lookup, payment_hash)
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
            problem = await self._held_problem(terms, status)
            if problem is not None:
                return await self._abort(item, terms, now, problem)
            self._move(item, "LN_HELD", now, observation={"kind": "hold_accepted"})
            return await self._advance_reverse(_with_state(item, "LN_HELD"), terms, now)
        if item.state == "LN_HELD":
            status = await asyncio.to_thread(hold.lookup, payment_hash)
            problem = await self._held_problem(terms, status)
            if problem is not None:
                return await self._abort(item, terms, now, problem)
            if item.blocked or not self._may_sign:
                return item.state
            params = _lock_params(terms)
            try:
                approval = await asyncio.to_thread(
                    lambda: self._htlc.ensure_allowance(params.token, params.amount)
                )
            except Exception:
                self._may_sign = False  # the approval may hold a nonce the node refused
                raise
            if approval is not None:
                return item.state  # the approval must be mined before the lock can be estimated
            signed = await asyncio.to_thread(lambda: self._htlc.prepare_lock(params))
            # The grant is durable before any broadcast; FUNDING_SENT rebroadcasts.
            self._move(item, "FUNDING_SENT", now, sent=(signed.tx_hash, signed.raw))
            await self._broadcast(signed.raw)
            return "FUNDING_SENT"
        if (
            item.state == "FUNDING_SENT"
            and item.provider_tx_hash is not None
            and item.provider_tx is not None
        ):
            claim = await self._claim_log(terms)
            if claim is not None:
                return await self._settle(item, terms, now, claim.preimage, claim.tx_hash)
            receipt = await asyncio.to_thread(self._htlc.receipt, item.provider_tx_hash)
            if receipt is None:
                if await asyncio.to_thread(
                    self._htlc.superseded, item.provider_tx, terms.funding_confirmations
                ):
                    # Never re-signed: ERC20Swap forgets a claimed or refunded swap,
                    # so a second lock could fund it again.
                    LOG.error(
                        "EVM lock superseded by another nonce use: swap %s needs attention",
                        item.session_id[:16],
                    )
                    return item.state
                await self._broadcast(item.provider_tx)
                return item.state
            if receipt.status != "success":
                LOG.error("EVM lock reverted: swap %s needs attention", item.session_id[:16])
                return item.state
            depth = await asyncio.to_thread(self._htlc.confirmations, item.provider_tx_hash)
            if depth < terms.funding_confirmations:
                return item.state
            lockup = await self._active_lockup(terms, receipt.block_number + depth - 1)
            observation = (
                {
                    "kind": "evm_lockup_observed",
                    "lock_tx_hash": lockup.tx_hash,
                    "log_index": lockup.log_index,
                    "block_number": lockup.block_number,
                }
                if lockup is not None
                else None
            )
            return self._move(item, "FUNDED", now, observation=observation, gas_wei=receipt.gas_wei)
        if item.state == "FUNDED":
            claim = await self._claim_log(terms)
            if claim is not None:
                return await self._settle(item, terms, now, claim.preimage, claim.tx_hash)
            evm_tip = await asyncio.to_thread(self._htlc.block_number)
            if evm_tip < terms.htlc_timelock_block:
                return item.state
            params = _lock_params(terms)
            if not self._may_sign:
                return item.state
            if not await asyncio.to_thread(self._htlc.lock_active, params):
                return item.state  # claimed in a block we have not scanned yet
            signed = await asyncio.to_thread(lambda: self._htlc.prepare_refund(params))
            self._move(item, "REFUNDING", now, sent=(signed.tx_hash, signed.raw))
            await self._broadcast(signed.raw)
            return "REFUNDING"
        if (
            item.state == "REFUNDING"
            and item.refund_tx_hash is not None
            and item.refund_tx is not None
        ):
            claim = await self._claim_log(terms)
            if claim is not None:
                return await self._settle(item, terms, now, claim.preimage, claim.tx_hash)
            receipt = await asyncio.to_thread(self._htlc.receipt, item.refund_tx_hash)
            if receipt is None:
                if await asyncio.to_thread(
                    self._htlc.superseded, item.refund_tx, terms.settlement_confirmations
                ):
                    refund_params = _lock_params(terms)
                    return await self._replace_dead(
                        item,
                        terms,
                        now,
                        item.refund_tx_hash,
                        lambda: self._htlc.prepare_refund(refund_params),
                    )
                await self._broadcast(item.refund_tx)
                return item.state
            if receipt.status != "success":
                return item.state  # the claim must have won; the next tick finds its log
            depth = await asyncio.to_thread(self._htlc.confirmations, item.refund_tx_hash)
            if depth < terms.settlement_confirmations:
                return item.state
            await asyncio.to_thread(hold.cancel, payment_hash)
            return self._move(
                item,
                "REFUNDED",
                now,
                observation={"kind": "swap_refunded"},
                gas_wei=receipt.gas_wei,
            )
        return item.state

    async def _claim_log(self, terms: EvmContractTerms) -> Any | None:  # noqa: ANN401
        evm_tip = await asyncio.to_thread(self._htlc.block_number)
        return await asyncio.to_thread(
            lambda: self._htlc.find_claim(
                terms.invoice_binding.payment_hash,
                from_block=max(0, terms.evm_reference_block - LOCKUP_SCAN_MARGIN_BLOCKS),
                to_block=evm_tip,
            )
        )

    async def _settle(
        self,
        item: EvmSettlementItem,
        terms: EvmContractTerms,
        now: int,
        preimage: str,
        claim_tx_hash: str,
    ) -> str:
        """Settle the hold with the revealed preimage; tolerate an earlier settlement."""
        hold, payment_hash = self._hold_backend(), terms.invoice_binding.payment_hash
        if hashlib.sha256(bytes.fromhex(preimage)).hexdigest() != payment_hash:
            raise EvmBackendError("claim log preimage does not match the payment hash")
        try:
            await asyncio.to_thread(hold.settle, preimage)
        except Exception:
            status = await asyncio.to_thread(hold.lookup, payment_hash)
            if status.state != "SETTLED":
                raise
        return self._move(
            item,
            "SETTLED",
            now,
            preimage=preimage,
            observed_claim=claim_tx_hash,
            observation={"kind": "hold_settled"},
        )


def _token_fee_as_sats(fee_token_base: int, rate: int) -> int:
    """Return the signed success fee in satoshis, rounded toward minus infinity."""
    return fee_token_base * 100_000_000 // rate


def _with_state(item: EvmSettlementItem, state: str, **fields: Any) -> EvmSettlementItem:  # noqa: ANN401
    from dataclasses import replace  # noqa: PLC0415 - tiny helper

    return replace(item, state=state, **fields)
