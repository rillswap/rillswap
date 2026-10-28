"""Move funded BTC to LN swaps to settlement (RS-003), one tick at a time.

Every consequential step is recorded before its external effect:

- ``FUNDING_SEEN``: the exact bound output must have ``funding_confirmations``
  on our own node (with 0, be unspent in its mempool view; the provider takes
  the client's double-spend risk), and the signed
  ``max_outgoing_htlc_expiry_height`` must still leave the invoice's final
  CLTV. Then ``PAYING`` is recorded (or ``FAILED`` with a ``payment_failed``
  observation).
- ``PAYING``: reconcile first. An affirmative ``UNSENT`` grant plus fresh
  funding permits read-only route preparation. Commit the exact request and
  consume the grant before sending once. The route's absolute expiry cannot
  exceed the signed height. Success records ``PAID`` with the verified
  preimage and a ``payment_settled`` observation atomically.
- ``PAID``: build and sign the unilateral claim (claim leaf, preimage,
  sealed contract key), record its exact bytes as ``CLAIMING`` with a
  ``claim_broadcast`` observation, then broadcast.
- ``CLAIMING``: rebroadcast until ``settlement_confirmations``, then
  ``CLAIMED``.

A blocked (conflicting) session never starts a payment: that is new
financial risk. Claiming only reduces risk and proceeds regardless.
Store calls stay on the event-loop thread; RPCs run in worker threads.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol, TypeGuard

from rill_core.settlement.funding import FundingBindingTransactionMatch
from rill_core.settlement.taproot import reconstruct_taproot_contract
from rill_core.settlement.unilateral import (
    FundingOutput,
    UnilateralAuthorization,
    ValidatedCooperativeClaim,
    ValidatedUnilateralSpend,
    build_cooperative_claim,
    build_unilateral_spend,
    claim_vsizes,
    finalize_unilateral_spend,
    max_spendable_fee,
    validate_cooperative_claim,
    validate_unilateral_spend,
    verify_cooperative_claim_proposal,
)
from rill_core.wire.canonical import canonicalize, parse_json_strict, parse_model_json
from rill_core.wire.fee_policy import FEE_POLICY_EXTENSION, FeeBreakdown
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE, FEE_POLICY_FEATURE, contract_hash
from rill_core.wire.messages import Envelope
from rill_core.wire.settlement_messages import FundingBindingPayload

from rill_provider.core_tx_bytes import (
    CooperativeClaimOutpoint,
    CooperativeFeePolicy,
    CoreProtocolError,
    CoreReadError,
    CoreTransactionUnknownError,
)
from rill_provider.live_session_store import (
    MAX_CLAIM_ATTEMPTS,
    CooperativeClaimObservation,
    CooperativeWinner,
    FundingConflict,
    LiveSessionStoreError,
    PreparedFallback,
    ReadinessChallenge,
    RecordedUnilateralClaim,
    StaleOwnerError,
    StaleSwapError,
)
from rill_provider.lnd_invoice_decode import InvoiceRejectedError
from rill_provider.lnd_payment_observation import LndNotSyncedError, LndUnavailableError
from rill_provider.reverse_settlement import HoldInvoiceBackend, ReverseSettlement
from rill_provider.settlement_policy import SettlementCrypto, offered_terms

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from rill_core.settlement.taproot import TaprootKeyOperations
    from rill_core.wire.messages import ContractTerms, FundingBinding, InvoiceBinding

    from rill_provider.core_tx_bytes import (
        CandidateFundingOutpoint,
        FundedOutput,
        MempoolFundingOutpoint,
        SpendScan,
    )
    from rill_provider.live_session_store import (
        ClaimAttempt,
        LiveSessionStore,
        RequestAnswer,
        SettlementItem,
    )
    from rill_provider.lnd_payment_send import PaymentOutcome, PreparedPayment
    from rill_provider.payment_dispatch_record import PaymentAuthority

LOG = logging.getLogger(__name__)


class ChainBackend(Protocol):
    """The provider's own Bitcoin Core (``CoreTransactionReader``)."""

    def tip_height(self) -> int:
        """Return the validated tip height."""
        ...

    def observe_candidate_outpoint(
        self, binding: FundingBinding, terms: ContractTerms, *, keys: TaprootKeyOperations
    ) -> CandidateFundingOutpoint:
        """Return the exact bound output's confirmations or raise."""
        ...

    def observe_mempool_outpoint(
        self, binding: FundingBinding, terms: ContractTerms, *, keys: TaprootKeyOperations
    ) -> MempoolFundingOutpoint:
        """Return the exact output, unspent counting the mempool, at any depth, or raise."""
        ...

    def observe_cooperative_claim_outpoint(
        self, binding: FundingBinding, terms: ContractTerms, *, keys: TaprootKeyOperations
    ) -> CooperativeClaimOutpoint:
        """Sample the exact outpoint with mempool spends considered (LN to BTC: any depth)."""
        ...

    def observe_cooperative_fee_policy(
        self, target_blocks: int, *, allow_regtest_fixed_fee: bool = False
    ) -> CooperativeFeePolicy:
        """Return strict own-node fee evidence, never optional fallback advice."""
        ...

    def broadcast(self, raw: bytes, txid: str) -> str:
        """Submit exact bytes idempotently."""
        ...

    def confirmations(self, txid: str) -> int:
        """Return best-chain confirmations (0 in mempool) or raise."""
        ...

    def outpoint_unspent(self, txid: str, vout: int) -> bool:
        """Whether the output is unspent on the confirmed chain (mempool ignored)."""
        ...

    def transaction_inputs(self, raw: bytes) -> tuple[str, tuple[tuple[str, int], ...]]:
        """Decode exact bytes into their txid and spent outpoints, or raise."""
        ...

    def block_hash(self, height: int) -> str:
        """Return the active-chain block hash at ``height`` or raise."""
        ...

    def fund_output(
        self, script_pubkey: bytes, value_sat: int, *, max_fee_sat: int
    ) -> FundedOutput:
        """Sign (never broadcast) a wallet payment to the script at index 0 (RS-004)."""

    def release_funding_inputs(self, inputs: tuple[tuple[str, int], ...]) -> None:
        """Release identified, affirmatively ungranted funding inputs only."""

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
        """Look for the transaction spending the outpoint (RS-004)."""

    def fee_rate_sat_vb(self, target_blocks: int) -> float | None:
        """Return a conservative feerate estimate, or ``None`` when the node has none."""
        ...


CONFLICT_LOSS_CONFIRMATIONS = 6  # depth of another spend of a deposit input that proves a loss
CONFLICT_SCAN_MARGIN_BLOCKS = 144  # search for that spend from this far below the first claim
CLAIM_URGENCY_BLOCKS = 6  # claim at the signed maximum fee this far before refund
INCREMENTAL_RELAY_SAT_VB = 1  # BIP125 rule 4 at Core's default incremental relay fee
READINESS_BUDGET_SECONDS = 10.0  # bound each preflight or pre-submission sync retry window
READINESS_SYNC_DELAY = 1.0
COOPERATIVE_PROBE_SECONDS = 30
COOPERATIVE_SAMPLE_SECONDS = 1.0


@dataclass(frozen=True, slots=True)
class ClaimProbeWindow:
    """Owner-process-only pre-echo claim deferral, never restartable authority."""

    session_id: str
    contract_hash: str
    owner_generation: int
    started_at: int
    deadline_at: int
    started_monotonic: float
    abandoned: bool = False


class LightningBackend(Protocol):
    """The provider's own LND (``LndPaymentSender``)."""

    def track(self, payment_hash: str, *, payer: PaymentAuthority | None = None) -> PaymentOutcome:
        """Return the payment status by hash, attesting ``payer`` when bound."""
        ...

    def prepare(
        self,
        bolt11: str,
        *,
        invoice_binding: InvoiceBinding,
        fee_limit_sat: int,
        max_expiry_height: int,
        deadline_seconds: float = 20.0,
    ) -> PreparedPayment:
        """Prepare exact, absolute-bounded dispatch bytes without paying."""
        ...

    def send(self, payment: PreparedPayment) -> PaymentOutcome:
        """Submit the exact committed request once."""
        ...


class EngineCrypto(SettlementCrypto, Protocol):
    """Verification, key operations, and BIP340 signing (``rill_crypto.Context``)."""

    def schnorr_sign(self, secret_key: bytes, message: bytes, auxiliary_random: bytes) -> bytes:
        """Sign a 32-byte digest."""
        ...


@dataclass(frozen=True, slots=True)
class EngineSettings:
    """Operator limits for settlement."""

    # LN to BTC refunds only: the lowest fee of the provider's first refund.
    # BTC to LN claims are priced from the node's fee evidence instead.
    refund_fee_floor_sat: int = 1_000
    max_routing_fee_sat: int = 1_000
    # Absolute minimum fee any cooperative claim must pay, on top of the
    # fresh Core estimate and admission floors. Regtest may explicitly accept
    # a fixed fee when Core has no estimate; other networks never do.
    cooperative_fee_floor_sat: int = 1
    allow_regtest_fixed_fee: bool = False


@dataclass(slots=True)
class _InputScan:
    """Search of one deposit input: next block, its parent's hash, any spender found."""

    next_height: int
    anchor: str | None = None  # hash of block next_height - 1 once a scan authenticated it
    conflict: tuple[str, int, str] | None = None  # spender txid, block height, block hash


@dataclass(slots=True)
class _ConflictScan:
    """Memory-only search of one unknown deposit's inputs; a restart begins again."""

    floor: int
    inputs: dict[tuple[str, int], _InputScan]


class SettlementEngine:
    """Drive every funded swap forward; safe to call repeatedly."""

    def __init__(  # noqa: PLR0913 - explicit injected backends
        self,
        store: LiveSessionStore,
        chain: ChainBackend,
        lightning: LightningBackend,
        crypto: EngineCrypto,
        settings: EngineSettings | None = None,
        *,
        hold_invoices: HoldInvoiceBackend | None = None,
    ) -> None:
        """Bind already-configured backends; no I/O.

        ``hold_invoices`` enables the LN to BTC lifecycle (RS-004); without
        it, swaps of that profile are left untouched.
        """
        self._store = store
        self._chain = chain
        self._lightning = lightning
        self._crypto = crypto
        self._settings = settings or EngineSettings()
        self._reverse = (
            None
            if hold_invoices is None
            else ReverseSettlement(
                store,
                chain,
                hold_invoices,
                crypto,
                refund_fee_floor_sat=self._settings.refund_fee_floor_sat,
                cooperative_fee_floor_sat=self._settings.cooperative_fee_floor_sat,
                allow_regtest_fixed_fee=self._settings.allow_regtest_fixed_fee,
            )
        )
        self._new_exposure_allowed = True
        self._new_featured_sessions: dict[str, tuple[str, int]] = {}
        self._claim_probes: dict[str, ClaimProbeWindow] = {}
        self._conflict_scans: dict[str, _ConflictScan] = {}
        self._cooperative_sample_task: asyncio.Task[object] | None = None
        # Latest usable claim fee evidence per signed confirmation target, for
        # claims that must be signed without waiting on Core (memory only).
        self._claim_fee_evidence: dict[int, CooperativeFeePolicy] = {}

    def register_new_featured_session(self, session_id: str, contract: str) -> bool:
        """Remember one current-process original session, not a stored ADMITTED row.

        Caller must have authenticated both a new acceptance and first funding
        binding under this owner. Relayed replay or restart never recreates it.
        """
        if not self._new_exposure_allowed or not self._store.admitted_featured_claim(
            session_id, contract
        ):
            return False
        if session_id in self._new_featured_sessions or session_id in self._claim_probes:
            return False
        self._new_featured_sessions[session_id] = (contract, self._store.generation)
        return True

    def probe_window(self, session_id: str) -> ClaimProbeWindow | None:
        """Return only the live gate held by this owner (never from SQLite)."""
        window = self._claim_probes.get(session_id)
        if window is None or window.owner_generation != self._store.generation:
            return None
        return window

    def expired_probe_windows(self) -> tuple[ClaimProbeWindow, ...]:
        """List gates requiring independent unilateral recovery."""
        now = time.monotonic()
        return tuple(
            window
            for window in self._claim_probes.values()
            if window.owner_generation == self._store.generation
            and (window.abandoned or now >= window.started_monotonic + COOPERATIVE_PROBE_SECONDS)
        )

    def abandon_probe(self, session_id: str) -> None:
        """Irreversibly stop deferral after failed tip, echo or preparation."""
        window = self.probe_window(session_id)
        if window is not None:
            self._claim_probes[session_id] = replace(window, abandoned=True)

    def _activate_probe(self, session_id: str, terms: ContractTerms) -> bool:
        eligible = self._new_featured_sessions.pop(session_id, None)
        if eligible != (contract_hash(terms).hex(), self._store.generation):
            return False
        if not self._new_exposure_allowed or not self._store.admitted_featured_claim(
            session_id, eligible[0]
        ):
            return False
        started_at = int(time.time())
        self._claim_probes[session_id] = ClaimProbeWindow(
            session_id,
            eligible[0],
            self._store.generation,
            started_at,
            started_at + COOPERATIVE_PROBE_SECONDS,
            time.monotonic(),
        )
        return True

    async def recover_expired_probe(self, window: ClaimProbeWindow, now: int) -> None:
        """Durably select a claim on remembered fee evidence, without Core or LN RPC waits."""
        current = self.probe_window(window.session_id)
        if current != window or window not in self.expired_probe_windows():
            return
        items = self._store.settlement_work(session_id=window.session_id)
        if len(items) != 1:
            return
        item = items[0]
        if item.state != "PAID":
            self._claim_probes.pop(window.session_id, None)
            return  # a selected claim or terminal swap owns recovery now
        if item.preimage is None:
            return  # inconsistent PAID state must not invent a preimage
        if not self._store.immediate_claim_allowed(window.session_id):
            self._claim_probes.pop(window.session_id, None)
            return  # prepared or selected arbitration owns the fallback
        terms = offered_terms(Envelope.model_validate_json(item.terms_offer, strict=True))
        if terms.profile_id != "btc-to-ln/v1" or contract_hash(terms).hex() != window.contract_hash:
            raise LiveSessionStoreError("due probe contract changed")
        if item.funding_binding is None:
            raise LiveSessionStoreError("due probe funding missing")
        funding = Envelope.model_validate_json(item.funding_binding, strict=True)
        binding = parse_model_json(FundingBindingPayload, canonicalize(funding.payload)).binding
        if (
            funding.contract_hash != window.contract_hash
            or binding.contract_hash != window.contract_hash
            or hashlib.sha256(bytes.fromhex(item.preimage)).hexdigest()
            != terms.invoice_binding.payment_hash
        ):
            raise LiveSessionStoreError("due probe binding changed")
        spend = await self._initial_claim(item, terms, binding, fresh=False)
        self._move(
            item,
            "CLAIMING",
            now,
            claim_tx=spend.raw_transaction,
            claim_txid=spend.txid,
            claim_fee_sat=spend.fee_sat,
            claim_height=None,
            observation={"kind": "claim_broadcast", "claim_txid": spend.txid},
        )
        self._claim_probes.pop(window.session_id, None)

    async def prepare_cooperative_window(
        self,
        challenge: ReadinessChallenge,
        *,
        sample_tip: Callable[[], Awaitable[int | None]],
        now: Callable[[], int],
    ) -> None:
        """Commit a verified fallback using the original paid probe's deadlines.

        Sign locally before the last fresh-tip check. No cooperative nonce is
        exposed here; the store's ADMITTED-to-WAITING transaction is the only
        authority for a subsequent signing attempt.
        """
        window = self.probe_window(challenge.session_id)
        if (
            window is None
            or window.abandoned
            or challenge.contract_hash != window.contract_hash
            or challenge.owner_generation != window.owner_generation
            or challenge.started_at != window.started_at
            or challenge.deadline_at != window.deadline_at
            or time.monotonic() >= window.started_monotonic + COOPERATIVE_PROBE_SECONDS
            or now() >= window.deadline_at
        ):
            raise LiveSessionStoreError("original claim probe unavailable")
        items = self._store.settlement_work(session_id=challenge.session_id)
        if len(items) != 1:
            raise LiveSessionStoreError("paid claim unavailable")
        item = items[0]
        if item.state != "PAID" or item.preimage is None:
            raise LiveSessionStoreError("paid claim unavailable")
        terms = offered_terms(Envelope.model_validate_json(item.terms_offer, strict=True))
        if (
            terms.profile_id != "btc-to-ln/v1"
            or contract_hash(terms).hex() != window.contract_hash
            or challenge.deadline_height
            != terms.refund_lock_height - terms.timing_policy.claim_confirmation_blocks
            or item.funding_binding is None
        ):
            raise LiveSessionStoreError("cooperative fallback terms changed")
        funding = Envelope.model_validate_json(item.funding_binding, strict=True)
        binding = parse_model_json(FundingBindingPayload, canonicalize(funding.payload)).binding
        if (
            funding.contract_hash != window.contract_hash
            or binding.contract_hash != window.contract_hash
            or hashlib.sha256(bytes.fromhex(item.preimage)).hexdigest()
            != terms.invoice_binding.payment_hash
        ):
            raise LiveSessionStoreError("cooperative fallback binding changed")
        spend = await self._initial_claim(item, terms, binding, fresh=False)
        tip = await sample_tip()
        committed_at = now()
        if (
            tip is None
            or type(tip) is not int
            or tip >= challenge.deadline_height
            or committed_at >= window.deadline_at
            or time.monotonic() >= window.started_monotonic + COOPERATIVE_PROBE_SECONDS
            or self.probe_window(challenge.session_id) != window
            or not self._new_exposure_allowed
        ):
            raise LiveSessionStoreError("cooperative fallback deadline unavailable")
        self._store.prepare_claim_window(
            challenge.session_id,
            fallback_raw=spend.raw_transaction,
            fallback_txid=spend.txid,
            fallback_fee_sat=spend.fee_sat,
            started_at=window.started_at,
            now=committed_at,
            deadline_at=window.deadline_at,
            deadline_height=challenge.deadline_height,
        )
        self._claim_probes.pop(challenge.session_id, None)

    def disable_new_exposure(self) -> None:
        """Latch off new BTC-to-LN sends after deadline supervision fails."""
        self._new_exposure_allowed = False

    async def _sample_cooperative(
        self, operation: Callable[[], object], *, budget: float
    ) -> object | None:
        """Retain one sampler slot until its worker actually finishes.

        Cancellation or timeout of the waiter does not stop a Core worker.
        Never accumulate another sample behind it or reuse a late result.
        """
        if self._cooperative_sample_task is not None or budget <= 0:
            return None
        started = time.monotonic()
        task = asyncio.create_task(asyncio.to_thread(operation))
        self._cooperative_sample_task = task

        def finished(completed: asyncio.Task[object]) -> None:
            if not completed.cancelled():
                completed.exception()  # consume late failures, never reuse results
            if self._cooperative_sample_task is completed:
                self._cooperative_sample_task = None

        task.add_done_callback(finished)
        try:
            sample = await asyncio.wait_for(asyncio.shield(task), timeout=budget)
        except Exception:  # noqa: BLE001 - failed evidence grants no nonce effect
            return None
        return sample if time.monotonic() - started < budget else None

    async def cosign_reverse_proposal(self, document: bytes, *, now: int) -> bytes | None:
        """Answer one authenticated-on-admission LN to BTC claim proposal.

        Returns the archived signed reply bytes (already committed to the
        outbox), or None for a replay with no archived contribution.
        """
        if self._reverse is None:
            raise LiveSessionStoreError("reverse cooperative signer unavailable")
        return await self._reverse.cosign_cooperative_proposal(document, now)

    async def verify_reverse_completion(self, document: bytes, *, now: int) -> RequestAnswer:
        """Verify a claimant's retained public contribution; never restart cooperation."""
        if self._reverse is None:
            raise LiveSessionStoreError("reverse cooperative verifier unavailable")
        return await self._reverse.verify_cooperative_completion(document, now)

    async def complete_cooperative_claim(  # noqa: PLR0911 - preconsumption refusals, then one commit boundary
        self,
        session_id: str,
        cooperation_id: bytes,
        *,
        now: Callable[[], int],
        allow_regtest_fixed_fee: bool | None = None,
    ) -> str | None:
        """Dormant independent completion preflight after fresh signed admission.

        None is only a precommit refusal: this invocation consumed no custody. Once
        commit begins, errors propagate: consumption or durable completion may
        have occurred. Never automatically retry or reconstruct eligibility.
        This does not broadcast or send; the checked outbox owns disclosure.
        """
        deadline = time.monotonic() + COOPERATIVE_SAMPLE_SECONDS
        if not self._new_exposure_allowed or not callable(now):
            return None
        allow_regtest_fixed_fee = (  # None selects the engine's own network policy
            self._settings.allow_regtest_fixed_fee
            if allow_regtest_fixed_fee is None
            else allow_regtest_fixed_fee
        )
        if type(allow_regtest_fixed_fee) is not bool or (
            allow_regtest_fixed_fee and self._store.network_identity.name != "regtest"
        ):
            return None
        started_at = now()
        if type(started_at) is not int or started_at < 0:
            return None
        candidate = self._store.cooperative_completion_candidate(session_id, cooperation_id)
        if candidate is None:
            return None
        fallback = candidate.fallback
        latest_at = started_at

        def effect_clock() -> int:
            nonlocal latest_at
            if not self._new_exposure_allowed or time.monotonic() >= deadline:
                raise LiveSessionStoreError("cooperative completion evidence expired or revoked")
            current = now()
            # Caller clocks can block or revoke availability. Fence their
            # return before allowing the store's immediately following effect.
            if not self._new_exposure_allowed or time.monotonic() >= deadline:
                raise LiveSessionStoreError("cooperative completion evidence expired or revoked")
            if type(current) is not int or current < 0:
                raise LiveSessionStoreError("cooperative completion clock unavailable")
            latest_at = max(latest_at, current)
            if latest_at >= fallback.deadline_at:
                raise LiveSessionStoreError("cooperative completion deadline elapsed")
            return latest_at

        try:
            effect_clock()  # candidate acquisition and validation share the one-second budget
            terms, binding = self._validate_prepared_fallback(fallback)
            burned = parse_json_strict(candidate.burned_binding)
            if not isinstance(burned, dict):
                return None
            unsigned_transaction = burned["unsigned_transaction"]
            if not isinstance(unsigned_transaction, str):
                return None
            plan = verify_cooperative_claim_proposal(
                bytes.fromhex(unsigned_transaction), self._authorization(terms, binding)
            )
            if (
                terms.network_identity != self._store.network_identity
                or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                or type(burned["fee_sat"]) is not int
                or plan.fee_sat != burned["fee_sat"]
                or plan.signature_hash.hex() != burned["signature_hash"]
                or burned["cooperation_id"] != cooperation_id.hex()
                or burned["session_id"] != session_id
                or burned["network_identity"] != terms.network_identity.model_dump(mode="json")
                or burned["user_key"] != terms.client_contract_compressed_key
                or burned["provider_key"] != terms.provider_contract_compressed_key
                or burned["claimant"] != "provider"
                or burned["tap_tweak"]
                != reconstruct_taproot_contract(terms, keys=self._crypto).tap_tweak.hex()
            ):
                return None

            def sample() -> tuple[CooperativeClaimOutpoint, CooperativeFeePolicy]:
                output = self._chain.observe_cooperative_claim_outpoint(
                    binding, terms, keys=self._crypto
                )
                policy = self._chain.observe_cooperative_fee_policy(
                    terms.timing_policy.claim_confirmation_blocks,
                    allow_regtest_fixed_fee=allow_regtest_fixed_fee,
                )
                return output, policy

            effect_clock()
            sampled = await self._sample_cooperative(sample, budget=deadline - time.monotonic())
            effect_clock()
            if not isinstance(sampled, tuple) or len(sampled) != 2:  # noqa: PLR2004 - own two-part sample
                return None
            output, policy = sampled
            if (
                type(output) is not CooperativeClaimOutpoint
                or not _fee_policy_usable(
                    policy, terms, allow_regtest_fixed_fee=allow_regtest_fixed_fee
                )
                or not _cooperative_outpoint_matches(
                    output, binding, terms, fallback.deadline_height
                )
                or (policy.tip_hash, policy.tip_height) != (output.tip_hash, output.tip_height)
            ):
                return None
            vsize = (4 * len(plan.base_transaction) + 68 + 3) // 4
            fee_floor = policy.fee_floor_sat(
                vsize=vsize, configured_floor_sat=self._settings.cooperative_fee_floor_sat
            )
            if plan.fee_sat < fee_floor:
                return None
            observation = CooperativeClaimObservation(
                network=output.network_identity,
                funding_txid=output.funding_txid,
                funding_vout=output.funding_vout,
                funding_value_sat=output.funding_value_sat,
                funding_script_pubkey=output.funding_script_pubkey,
                tip_height=output.tip_height,
                tip_hash=output.tip_hash,
                confirmations=output.confirmations,
                sampled_at=started_at,
                mempool_unspent=True,
                fee_floor_sat=fee_floor,
            )
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - a failed preflight does not consume the native handle
            return None
        # No catch or automatic retry beyond this private-consumption boundary.
        return self._store.commit_selected_cooperative_claim(
            session_id, cooperation_id, observation, now=effect_clock
        )

    async def initiate_cooperative_proposal(  # noqa: PLR0911 - preflight refusals before the burn
        self, session_id: str, *, now: Callable[[], int]
    ) -> str | None:
        """Queue one BTC-to-LN nonce proposal after fresh bounded preflight.

        None means no attempt was burned. Once burn begins, failures propagate
        because its durable outcome may be unknown. This never signs a partial
        or broadcasts; completion needs independent new chain/fee evidence.
        """
        if not self._new_exposure_allowed:
            return None
        candidates = tuple(
            item for item in self._store.prepared_fallbacks() if item.session_id == session_id
        )
        if len(candidates) != 1:
            return None
        (candidate,) = candidates
        started_at = now()
        if (
            candidate.state != "WAITING"
            or candidate.owner_generation != self._store.generation
            or type(started_at) is not int
            or not 0 <= started_at < candidate.deadline_at
        ):
            return None
        terms, binding = self._validate_prepared_fallback(candidate)
        if (
            terms.network_identity != self._store.network_identity
            or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
        ):
            return None
        allow_regtest_fixed_fee = self._settings.allow_regtest_fixed_fee

        def observe() -> tuple[CooperativeClaimOutpoint, CooperativeFeePolicy]:
            output = self._chain.observe_cooperative_claim_outpoint(
                binding, terms, keys=self._crypto
            )
            policy = self._chain.observe_cooperative_fee_policy(
                terms.timing_policy.claim_confirmation_blocks,
                allow_regtest_fixed_fee=allow_regtest_fixed_fee,
            )
            return output, policy

        sample_deadline = time.monotonic() + COOPERATIVE_SAMPLE_SECONDS
        sampled = await self._sample_cooperative(
            observe, budget=min(COOPERATIVE_SAMPLE_SECONDS, candidate.deadline_at - started_at)
        )
        checked_at = now()
        if (
            not self._new_exposure_allowed
            or type(checked_at) is not int
            or not started_at <= checked_at < candidate.deadline_at
            or not isinstance(sampled, tuple)
            or len(sampled) != 2  # noqa: PLR2004 - own two-part sample
        ):
            return None
        sample, policy = sampled
        if (
            type(sample) is not CooperativeClaimOutpoint
            or not _cooperative_outpoint_matches(sample, binding, terms, candidate.deadline_height)
            or not _fee_policy_usable(
                policy, terms, allow_regtest_fixed_fee=allow_regtest_fixed_fee
            )
            or (policy.tip_hash, policy.tip_height) != (sample.tip_hash, sample.tip_height)
        ):
            return None
        self._claim_fee_evidence[policy.confirmation_blocks] = policy
        # Priced fresh, independent of the fallback: the same key-path floor
        # completion re-checks, and the client checks, against new evidence.
        authorization = self._authorization(terms, binding)
        fee = policy.fee_floor_sat(
            vsize=claim_vsizes(authorization.destination_script)[0],
            configured_floor_sat=self._settings.cooperative_fee_floor_sat,
        )
        if fee > max_spendable_fee(authorization):
            return None
        plan = build_cooperative_claim(authorization, fee_sat=fee)

        def effect_clock() -> int:
            # SQLite/native work must not turn bounded-age height evidence
            # into stale initiation authority, even while wall time is open.
            if not self._new_exposure_allowed or time.monotonic() >= sample_deadline:
                raise LiveSessionStoreError("cooperative proposal evidence expired or revoked")
            current = now()
            if not self._new_exposure_allowed or time.monotonic() >= sample_deadline:
                raise LiveSessionStoreError("cooperative proposal evidence expired or revoked")
            return current

        cooperation_id = secrets.token_bytes(32)
        self._store.burn_selected_cooperative_claim(
            session_id,
            cooperation_id,
            plan,
            now=effect_clock,
            tip_height=sample.tip_height,
            deadline_at=candidate.deadline_at,
            deadline_height=candidate.deadline_height,
        )
        if not self._new_exposure_allowed:
            raise LiveSessionStoreError("cooperative initiation revoked after burn")
        return self._store.begin_selected_cooperative_proposal(
            session_id, cooperation_id, now=effect_clock, tip_height=sample.tip_height
        )

    def _fee_limit(self, success_fee_sat: int, terms: ContractTerms | None = None) -> int:
        """Routing fees may use at most the operator caps and the normal service fee.

        A balance-aware discount, even a rebate, never shrinks the budget: it is
        bounded by the committed policy's undiscounted fee, not the signed one.
        Legacy terms carry no policy and are never discounted; a negative fee
        there yields no budget rather than a negative one.
        """
        if terms is not None and FEE_POLICY_FEATURE in terms.required_features:
            breakdown = FeeBreakdown.model_validate(terms.extensions[FEE_POLICY_EXTENSION])
            principal = int(terms.invoice_binding.amount_msat) // 1000
            return min(
                self._settings.max_routing_fee_sat,
                breakdown.policy.service_fee(principal),
                principal * breakdown.policy.max_routing_fee_ppm // 1_000_000,
            )
        return min(self._settings.max_routing_fee_sat, max(success_fee_sat, 0))

    def select_due_fallbacks(
        self, now: int, *, closed_only: bool = False, height: int | None = None
    ) -> tuple[PreparedFallback, ...]:
        """Validate exact stored claims and select before any network submission.

        This synchronous operation does not wait for Core, LN, or relays. A
        restarted owner may select only a previous generation's CLOSED bundle;
        a live deadline may select only its own expired WAITING bundle.
        """
        if height is not None and (type(height) is not int or height < 0):
            raise LiveSessionStoreError("fallback height unavailable")
        if height == 0:
            height = None  # Core genesis is not height-expiry evidence, never block time expiry
        selected: list[PreparedFallback] = []
        for candidate in self._store.prepared_fallbacks(closed_only=closed_only):
            if (
                candidate.state == "WAITING"
                and now < candidate.deadline_at
                and (height is None or height < candidate.deadline_height)
            ):
                continue
            try:
                self._validate_prepared_fallback(candidate)
            except Exception:  # noqa: BLE001 - bad bundle stays blocked for operator review
                LOG.warning(
                    "prepared fallback refused for %s; operator attention required",
                    candidate.session_id[:16],
                )  # do not log the signed transaction, preimage, or parser details
                continue
            try:
                self._store.select_prepared_fallback(
                    candidate, signer=self._crypto, now=now, height=height
                )
            except StaleSwapError:
                continue  # re-read the new durable state on the next pass
            # Store failure (including StaleOwnerError) cannot be deferred:
            # do not begin serving with a possibly unselected paid swap.
            selected.append(candidate)
        return tuple(selected)

    def _validate_prepared_fallback(
        self, candidate: PreparedFallback
    ) -> tuple[ContractTerms, FundingBinding]:
        terms = offered_terms(Envelope.model_validate_json(candidate.terms_offer, strict=True))
        funding = Envelope.model_validate_json(candidate.funding_binding, strict=True)
        binding = parse_model_json(FundingBindingPayload, canonicalize(funding.payload)).binding
        if (
            terms.profile_id != "btc-to-ln/v1"
            or contract_hash(terms).hex() != candidate.contract_hash
            or binding.contract_hash != candidate.contract_hash
            or funding.contract_hash != candidate.contract_hash
            or hashlib.sha256(bytes.fromhex(candidate.preimage)).hexdigest()
            != terms.invoice_binding.payment_hash
        ):
            raise LiveSessionStoreError("prepared claim binding mismatch")
        verified = validate_unilateral_spend(
            candidate.raw, self._authorization(terms, binding), verifier=self._crypto
        )
        if (
            verified.raw_transaction != candidate.raw
            or verified.txid != candidate.txid
            or verified.fee_sat != candidate.fee_sat
        ):
            raise LiveSessionStoreError("prepared claim validation mismatch")
        return terms, binding

    def recorded_fallbacks(self) -> tuple[PreparedFallback, ...]:
        """Read durable selected work for the independent submission lane."""
        return self._store.recorded_fallbacks()

    def has_current_waiting_claim(self) -> bool:
        """Avoid continuous Core polling when there is no live height deadline."""
        return self._store.has_current_waiting_claim()

    def recorded_unilateral_claims(self) -> tuple[RecordedUnilateralClaim, ...]:
        """Rediscover selected script-path claims, including old ADMITTED rows."""
        return self._store.recorded_unilateral_claims()

    def _validate_recorded_unilateral(self, claim: RecordedUnilateralClaim) -> None:
        terms = offered_terms(Envelope.model_validate_json(claim.terms_offer, strict=True))
        funding = Envelope.model_validate_json(claim.funding_binding, strict=True)
        binding = parse_model_json(FundingBindingPayload, canonicalize(funding.payload)).binding
        if (
            terms.profile_id != "btc-to-ln/v1"
            or terms.network_identity != self._store.network_identity
            or contract_hash(terms).hex() != claim.contract_hash
            or funding.contract_hash != claim.contract_hash
            or binding.contract_hash != claim.contract_hash
            or hashlib.sha256(bytes.fromhex(claim.preimage)).hexdigest()
            != terms.invoice_binding.payment_hash
        ):
            raise LiveSessionStoreError("recorded unilateral binding mismatch")
        verified = validate_unilateral_spend(
            claim.raw, self._authorization(terms, binding), verifier=self._crypto
        )
        if (
            verified.raw_transaction != claim.raw
            or verified.txid != claim.txid
            or (claim.fee_sat is not None and verified.fee_sat != claim.fee_sat)
        ):
            raise LiveSessionStoreError("recorded unilateral spend mismatch")

    async def broadcast_recorded_unilateral(self, claim: RecordedUnilateralClaim) -> None:
        """Broadcast only the still-selected, validated durable script-path bytes."""
        try:
            current = self._store.recorded_unilateral_claims(session_id=claim.session_id)
            if current != (claim,):
                return
            self._validate_recorded_unilateral(claim)
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - corrupted or stale custody must not be submitted
            LOG.warning("recorded unilateral claim invalid for %s", claim.session_id[:16])
            return
        try:
            await asyncio.to_thread(self._chain.broadcast, claim.raw, claim.txid)
        except Exception:  # noqa: BLE001 - CLAIMING remains durable and discoverable
            LOG.warning("selected unilateral claim not accepted yet for %s", claim.session_id[:16])

    def recover_cooperative_winners(self, now: int) -> tuple[CooperativeWinner, ...]:
        """Promote affirmative old PAID winners before accepting new work."""
        promoted: list[CooperativeWinner] = []
        for winner in self._store.cooperative_winners():
            if winner.state != "PAID":
                continue
            try:
                validated = self._validate_cooperative_winner(winner)
            except Exception:  # noqa: BLE001 - invalid persisted bytes cannot be dispatched
                LOG.warning(
                    "cooperative winner invalid for %s; operator attention required",
                    winner.session_id[:16],
                )
                continue
            try:
                self._store.promote_cooperative_winner(
                    winner, fee_sat=validated.fee_sat, signer=self._crypto, now=now
                )
            except StaleSwapError:
                continue
            promoted.append(winner)
        return tuple(promoted)

    def recorded_cooperative_winners(self) -> tuple[CooperativeWinner, ...]:
        """Return selected key-path claims for independent broadcast retries."""
        return tuple(w for w in self._store.cooperative_winners() if w.state == "CLAIMING")

    def _validate_cooperative_winner(self, winner: CooperativeWinner) -> ValidatedCooperativeClaim:
        terms = offered_terms(Envelope.model_validate_json(winner.terms_offer, strict=True))
        funding = Envelope.model_validate_json(winner.funding_binding, strict=True)
        binding = parse_model_json(FundingBindingPayload, canonicalize(funding.payload)).binding
        if (
            terms.profile_id != "btc-to-ln/v1"
            or terms.network_identity != self._store.network_identity
            or contract_hash(terms).hex() != winner.contract_hash
            or funding.contract_hash != winner.contract_hash
            or binding.contract_hash != winner.contract_hash
            or hashlib.sha256(bytes.fromhex(winner.preimage)).hexdigest()
            != terms.invoice_binding.payment_hash
        ):
            raise LiveSessionStoreError("cooperative winner binding mismatch")
        verified = validate_cooperative_claim(
            winner.raw, self._authorization(terms, binding), verifier=self._crypto
        )
        if verified.raw_transaction != winner.raw or verified.txid != winner.txid:
            raise LiveSessionStoreError("cooperative winner validation mismatch")
        return verified

    async def broadcast_cooperative_winner(self, winner: CooperativeWinner) -> None:
        """Submit only the validated, recorded exact key-path winner."""
        try:
            verified = self._validate_cooperative_winner(winner)
            selected = self._store.selected_cooperative_claim(winner.session_id)
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - never publish inconsistent custody
            LOG.warning("recorded cooperative claim invalid for %s", winner.session_id[:16])
            return
        if (
            selected is None
            or selected.raw != winner.raw
            or selected.txid != winner.txid
            or selected.fee_sat != verified.fee_sat
        ):
            LOG.warning("recorded cooperative claim differs for %s", winner.session_id[:16])
            return
        try:
            await asyncio.to_thread(self._chain.broadcast, winner.raw, winner.txid)
        except Exception:  # noqa: BLE001 - durable CLAIMING remains retryable
            LOG.warning(
                "selected cooperative claim not accepted yet for %s", winner.session_id[:16]
            )

    async def broadcast_selected_fallback(self, candidate: PreparedFallback) -> None:
        """Submit an already recorded attempt outside the deadline selector."""
        try:
            self._validate_prepared_fallback(candidate)
        except Exception:  # noqa: BLE001 - persisted bytes must not be trusted on restart
            LOG.warning("recorded fallback failed validation for %s", candidate.session_id[:16])
            return
        try:
            await asyncio.to_thread(self._chain.broadcast, candidate.raw, candidate.txid)
        except Exception:  # noqa: BLE001 - durable CLAIMING is retried by the normal sweep
            LOG.warning("selected fallback not accepted yet for %s", candidate.session_id[:16])

    def route_ready(
        self,
        invoice: str,
        *,
        invoice_binding: InvoiceBinding,
        success_fee_sat: int,
        max_expiry_height: int,
        routing_fee_limit_sat: int | None = None,
    ) -> None:
        """Raise unless LND can route this invoice within the payment's own bounds now.

        Blocking readiness evidence for a firm offer: the node is synced on this
        network and one route exists with the fee limit and absolute expiry the
        payment would use. LND checks first-hop local balance when routing, so
        this also shows outbound liquidity at this moment (not a reservation).
        The prepared route is discarded; nothing is recorded or dispatched.
        LND reports itself unsynchronized for a moment after every block, so
        that one condition is retried briefly instead of refusing the offer.
        """
        deadline = time.monotonic() + READINESS_BUDGET_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            try:
                self._lightning.prepare(
                    invoice,
                    invoice_binding=invoice_binding,
                    fee_limit_sat=(
                        self._fee_limit(success_fee_sat)
                        if routing_fee_limit_sat is None
                        else min(self._fee_limit(success_fee_sat), routing_fee_limit_sat)
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

    async def tick(self, now: int) -> dict[str, str]:
        """Advance each swap at most through its available steps; return new states."""
        results: dict[str, str] = {}
        for item in self._store.settlement_work():
            try:
                state = await self._advance(item, now)
            except StaleOwnerError:
                raise  # a fenced/uncertain store cannot defer economic work
            except StaleSwapError:
                continue
            except Exception as error:  # noqa: BLE001 - one swap's backend trouble never stops others
                # The class only (messages may carry backend detail). A
                # CoreUnavailableError here is also how an unconfirmed funding
                # output looks until its first block.
                LOG.warning(
                    "settlement step deferred for %s (%s)",
                    item.session_id[:16],
                    type(error).__name__,
                )
                continue
            if state != item.state:
                results[item.session_id] = state
        for session_id in await self._close_unfunded(now):
            results[session_id] = "FAILED"
        await self._release_expired()
        return results

    async def _close_unfunded(self, now: int) -> list[str]:
        """Fail accepted, never-funded swaps once the provider can no longer pay.

        Mirrors the FUNDING_SEEN deadline guard. The transition is terminal
        and the store releases the swap's never-dispatched reservation in the
        same transaction. A late funding binding is then refused; the client
        keeps its unilateral refund. A concurrent binding wins as a stale swap.
        """
        closed: list[str] = []
        unfunded = self._store.unfunded_swaps()
        if not unfunded:
            return closed
        try:
            tip = await asyncio.to_thread(self._chain.tip_height)
        except Exception:  # noqa: BLE001 - no fresh tip, no height-based closure
            tip = None
        for session_id, offer in unfunded:
            try:
                terms = offered_terms(Envelope.model_validate_json(offer, strict=True))
                if terms.profile_id != "btc-to-ln/v1":
                    continue  # LN to BTC: the provider funds; ReverseSettlement decides
                invoice = terms.invoice_binding
                expiry = int(terms.timing_policy.model_dump()["max_outgoing_htlc_expiry_height"])
                if now < invoice.expires_at and (
                    tip is None or tip + invoice.min_final_cltv_delta < expiry
                ):
                    continue
                self._store.advance_swap(
                    session_id,
                    from_state="ACCEPTED",
                    to_state="FAILED",
                    signer=self._crypto,
                    now=now,
                    observation={"kind": "payment_failed"},
                )
            except StaleSwapError:
                continue
            except StaleOwnerError:
                raise
            except Exception:  # noqa: BLE001 - one swap's trouble never stops others
                LOG.warning("unfunded swap closure deferred", exc_info=False)
                continue
            closed.append(session_id)
        return closed

    async def _release_expired(self) -> None:
        """Release terminal swaps' reservations once every exposure window closed."""
        try:
            if not self._store.expirable_exposure_pending():
                return
            tip = await asyncio.to_thread(self._chain.tip_height)
            released = self._store.release_expired_exposure(tip)
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - retried next tick; nothing is released
            LOG.warning("exposure release deferred", exc_info=False)
            return
        if released:
            LOG.info("released %d reservations whose exposure windows closed", released)

    def _move(self, item: SettlementItem, to_state: str, now: int, **fields: object) -> str:
        self._store.advance_swap(
            item.session_id,
            from_state=item.state,
            to_state=to_state,
            signer=self._crypto,
            now=now,
            **fields,  # type: ignore[arg-type]
        )
        self._conflict_scans.pop(item.session_id, None)  # only CLAIMING swaps search
        return to_state

    async def _advance(  # noqa: PLR0911, PLR0912 - one ordered lifecycle per state
        self, item: SettlementItem, now: int
    ) -> str:
        terms = offered_terms(Envelope.model_validate_json(item.terms_offer, strict=True))
        if terms.profile_id == "ln-to-btc/v1":
            return item.state if self._reverse is None else await self._reverse.advance(item, now)
        if item.funding_binding is None:
            return item.state  # ACCEPTED: awaiting the client's funding binding
        funding = Envelope.model_validate_json(item.funding_binding, strict=True)
        binding = parse_model_json(FundingBindingPayload, canonicalize(funding.payload)).binding
        invoice = terms.invoice_binding
        timing = terms.timing_policy.model_dump()
        expiry_height = int(timing["max_outgoing_htlc_expiry_height"])
        if item.state == "FUNDING_SEEN":
            if item.blocked or not self._new_exposure_allowed:
                return item.state
            funded_tip = await self._funded_tip(binding, terms)
            if funded_tip is None:
                return item.state
            if (
                funded_tip + invoice.min_final_cltv_delta >= expiry_height
                or now >= invoice.expires_at
            ):
                return self._move(item, "FAILED", now, observation={"kind": "payment_failed"})
            self._move(item, "PAYING", now)
            return await self._advance(_with_state(item, "PAYING", payment_dispatch="UNSENT"), now)
        if item.state == "PAYING":
            outcome = await self._pay(item, terms, binding, expiry_height, now)
            if outcome is None:
                return self._move(item, "FAILED", now, observation={"kind": "payment_failed"})
            if outcome.status == "FAILED":
                # Attributed to the dispatch's own payer, so the reservation
                # can be released; the store checks the attribution itself.
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
            if self._activate_probe(item.session_id, terms):
                return "PAID"  # explicit new original session; echo handled outside this tick
            return await self._advance(_with_state(item, "PAID", preimage=outcome.preimage), now)
        if item.state == "PAID" and item.preimage is not None:
            probe = self.probe_window(item.session_id)
            if (
                probe is not None
                and not probe.abandoned
                and (time.monotonic() < probe.started_monotonic + COOPERATIVE_PROBE_SECONDS)
            ):
                return item.state
            if not self._store.immediate_claim_allowed(item.session_id):
                return item.state  # selection/recovery owns every prepared window
            tip = await asyncio.to_thread(self._chain.tip_height)
            spend = await self._initial_claim(item, terms, binding, fresh=True)
            self._move(
                item,
                "CLAIMING",
                now,
                claim_tx=spend.raw_transaction,
                claim_txid=spend.txid,
                claim_fee_sat=spend.fee_sat,
                claim_height=tip,
                observation={"kind": "claim_broadcast", "claim_txid": spend.txid},
            )
            self._claim_probes.pop(item.session_id, None)
            return await self._advance(
                _with_state(
                    item, "CLAIMING", claim_tx=spend.raw_transaction, claim_txid=spend.txid
                ),
                now,
            )
        if item.state == "CLAIMING":
            return await self._claiming(item, terms, binding, now)
        return item.state

    async def _claiming(  # noqa: PLR0911, PLR0912, PLR0915 - one ordered escalation step
        self, item: SettlementItem, terms: ContractTerms, binding: FundingBinding, now: int
    ) -> str:
        """Confirm any recorded claim, else rebroadcast and bump the fee on schedule.

        Every attempt is recorded before it is broadcast, and every attempt is
        checked because any of them may confirm. A transport or index failure is
        not evidence, so it ends the step without bumping.
        """
        if COOPERATIVE_CLAIM_FEATURE in terms.required_features:
            cooperative = self._store.selected_cooperative_claim(item.session_id)
            if cooperative is not None:
                return await self._claiming_cooperative(item, terms, binding, cooperative, now)
        attempts = self._store.claim_attempts(item.session_id)
        if not attempts:
            LOG.error("claiming swap has no recorded claim; operator attention required")
            return item.state
        tip = await asyncio.to_thread(self._chain.tip_height)
        authorization = self._authorization(terms, binding)
        sizes: dict[int, int] = {}
        for attempt in attempts:
            try:
                checked = validate_unilateral_spend(
                    attempt.raw, authorization, verifier=self._crypto
                )
            except Exception:  # noqa: BLE001 - isolate this swap, never broadcast it
                LOG.error("recorded claim failed validation; operator attention required")  # noqa: TRY400 - no details
                return item.state
            if checked.txid != attempt.txid:
                LOG.error("recorded claim ID mismatch; operator attention required")
                return item.state
            sizes[attempt.attempt] = checked.vsize
            if attempt.fee_sat is None or attempt.first_seen_height is None:
                self._store.observe_claim_attempt(
                    item.session_id, attempt.attempt, fee_sat=checked.fee_sat, height=tip
                )
        attempts = self._store.claim_attempts(item.session_id)
        latest = attempts[-1]
        try:  # harmless if an older attempt is mined: Core rejects the conflict
            await asyncio.to_thread(self._chain.broadcast, latest.raw, latest.txid)
        except Exception:  # noqa: BLE001 - e.g. replacement policy; the next bump retries
            # Every tick rebroadcasts, and a mined claim is always refused.
            LOG.debug("claim broadcast not accepted; checking confirmations")
        for attempt in reversed(attempts):
            try:
                depth = await asyncio.to_thread(self._chain.confirmations, attempt.txid)
            except CoreTransactionUnknownError:
                continue  # never broadcast, evicted, or replaced
            if depth >= terms.settlement_confirmations:
                return self._move(
                    item, "CLAIMED", now, claim_tx=attempt.raw, claim_txid=attempt.txid
                )
            if depth >= 1:
                if item.outpoint_spent_height is not None:
                    self._store.observe_outpoint_spent(item.session_id, None)
                return item.state  # mined; wait for depth, never replace
        # No recorded attempt is mined. If the contract output is gone from the
        # confirmed chain anyway, the client's refund spent it: the claim is
        # lost once that spend has held for refund_resolution_confirmations.
        unspent = await asyncio.to_thread(
            self._chain.outpoint_unspent, binding.funding_txid, binding.contract_vout
        )
        if not unspent:
            return await self._maybe_lost(item, terms, binding, tip, now)
        if item.outpoint_spent_height is not None:
            self._store.observe_outpoint_spent(item.session_id, None)  # reorged back
        fee = claim_fee_target(
            initial=attempts[0].fee_sat,
            maximum=max_spendable_fee(authorization),
            anchor=attempts[0].first_seen_height,
            deadline=terms.refund_lock_height,
            tip=tip,
            latest_fee=latest.fee_sat,
            latest_height=latest.first_seen_height,
            vsize=sizes[latest.attempt],
            attempts=len(attempts),
        )
        if fee is None:
            return item.state
        try:
            spend = self._claim(item, terms, binding, fee)
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - e.g. dust bound; keep the recorded attempts
            LOG.warning("claim fee bump could not be built")
            return item.state
        self._store.record_claim_attempt(
            item.session_id,
            attempt=latest.attempt + 1,
            txid=spend.txid,
            raw=spend.raw_transaction,
            fee_sat=spend.fee_sat,
            height=tip,
        )
        try:
            await asyncio.to_thread(self._chain.broadcast, spend.raw_transaction, spend.txid)
        except Exception:  # noqa: BLE001 - recorded; rebroadcast next tick
            LOG.info("claim replacement not accepted yet")
        return item.state

    async def _claiming_cooperative(
        self,
        item: SettlementItem,
        terms: ContractTerms,
        binding: FundingBinding,
        selected: ClaimAttempt,
        now: int,
    ) -> str:
        """Rebroadcast the exact selected key-path spend; never unilaterally replace it."""
        try:
            verified = validate_cooperative_claim(
                selected.raw, self._authorization(terms, binding), verifier=self._crypto
            )
        except Exception:  # noqa: BLE001 - bad stored claim cannot be broadcast
            LOG.warning("cooperative claim validation refused; operator attention required")
            return item.state
        if (
            verified.txid != selected.txid
            or verified.fee_sat != selected.fee_sat
            or item.claim_tx != selected.raw
            or item.claim_txid != selected.txid
        ):
            LOG.error("cooperative claim state differs; operator attention required")
            return item.state
        try:
            await asyncio.to_thread(self._chain.broadcast, selected.raw, selected.txid)
        except Exception:  # noqa: BLE001 - recorded attempt is retried on the next tick
            LOG.debug("cooperative claim not accepted yet")  # rebroadcast every tick, as above
        try:
            depth = await asyncio.to_thread(self._chain.confirmations, selected.txid)
        except CoreTransactionUnknownError:
            depth = 0
        if depth >= terms.settlement_confirmations:
            return self._move(item, "CLAIMED", now, claim_tx=selected.raw, claim_txid=selected.txid)
        if depth >= 1:
            if item.outpoint_spent_height is not None:
                self._store.observe_outpoint_spent(item.session_id, None)
            return item.state
        tip = await asyncio.to_thread(self._chain.tip_height)
        unspent = await asyncio.to_thread(
            self._chain.outpoint_unspent, binding.funding_txid, binding.contract_vout
        )
        if not unspent:
            return await self._maybe_lost(item, terms, binding, tip, now)
        if item.outpoint_spent_height is not None:
            self._store.observe_outpoint_spent(item.session_id, None)
        return item.state

    async def _pay(  # noqa: PLR0911, PLR0912 - exposure guards and pre-submission sync retry
        self,
        item: SettlementItem,
        terms: ContractTerms,
        binding: FundingBinding,
        expiry_height: int,
        now: int,
    ) -> PaymentOutcome | None:
        """Return the payment outcome, or None when it must never be sent."""
        invoice = terms.invoice_binding
        payer = item.payment_payer
        if payer is None:
            outcome = await asyncio.to_thread(self._lightning.track, invoice.payment_hash)
        else:
            # Same-channel GetInfo must match the dispatch's recorded payer.
            outcome = await asyncio.to_thread(
                lambda: self._lightning.track(invoice.payment_hash, payer=payer)
            )
        if outcome.status == "FAILED" and payer is None:
            # Absent, legacy, or malformed provenance: the configured node is
            # not bound to the historical payer, so its failed record cannot
            # terminate tracking of another node's attempt. send() reports
            # FAILED only after affirmative failure of the sole newly
            # authorized attempt, re-tracked against that attempt's payer.
            raise LndUnavailableError("tracked failure lacks bound payer authority")
        if outcome.status != "UNKNOWN":
            return outcome
        # PAYING is a durable intent, not durable chain evidence. After an
        # interrupted attempt, reconcile LND first, but never start a new
        # payment against a stale confirmation or newly blocked session.
        if item.blocked or item.payment_dispatch != "UNSENT" or not self._new_exposure_allowed:
            return outcome
        if item.session_id in self._new_featured_sessions:
            # A cooperative probe may follow; its fallback is signed without
            # waiting on Core, so remember fee evidence before paying.
            await self._sample_claim_fee(terms)
        if await self._funded_tip(binding, terms) is None:
            return outcome
        if now >= invoice.expires_at or (
            hashlib.sha256(item.invoice.encode("ascii")).hexdigest() != invoice.bolt11_sha256
        ):
            return None
        tip = await asyncio.to_thread(self._chain.tip_height)
        if expiry_height - tip <= invoice.min_final_cltv_delta:
            return None
        fee_limit = self._fee_limit(int(terms.economics.success_fee_sat), terms)
        try:
            payment = await asyncio.to_thread(
                lambda: self._lightning.prepare(
                    item.invoice,
                    invoice_binding=invoice,
                    fee_limit_sat=fee_limit,
                    max_expiry_height=expiry_height,
                )
            )
        except InvoiceRejectedError:
            # An older accepted invoice can be outside the supported routing
            # subset. No dispatch grant has been consumed or request sent.
            return None
        if not self._new_exposure_allowed or not self._store.commit_payment_dispatch(
            item.session_id, invoice.payment_hash, payment.dispatch_record
        ):
            return outcome
        # Only this exception proves SEND was never invoked. Reuse the committed
        # in-memory plan briefly; never restore its grant or retry an ambiguous send.
        deadline = time.monotonic() + READINESS_BUDGET_SECONDS
        while True:
            try:
                return await asyncio.to_thread(self._lightning.send, payment)
            except LndNotSyncedError:
                if (
                    not self._new_exposure_allowed
                    or deadline - time.monotonic() <= READINESS_SYNC_DELAY
                ):
                    raise
                await asyncio.sleep(READINESS_SYNC_DELAY)
                if not self._new_exposure_allowed or time.monotonic() >= deadline:
                    raise

    async def _funded_tip(self, binding: FundingBinding, terms: ContractTerms) -> int | None:
        """Return the sampled tip once the funding meets the signed depth, else None.

        Zero-confirmation terms pay on the output being unspent in the node's
        mempool view: the provider announced that it accepts the client's
        double-spend risk. Every other depth needs confirmed chain evidence.
        """
        if terms.funding_confirmations == 0:
            mempool = await asyncio.to_thread(
                self._chain.observe_mempool_outpoint, binding, terms, keys=self._crypto
            )
            return mempool.tip_height
        seen = await asyncio.to_thread(
            self._chain.observe_candidate_outpoint, binding, terms, keys=self._crypto
        )
        if seen.chain_only_confirmations < terms.funding_confirmations:
            return None
        return seen.tip_height

    async def _maybe_lost(
        self,
        item: SettlementItem,
        terms: ContractTerms,
        binding: FundingBinding,
        tip: int,
        now: int,
    ) -> str:
        """Close a claim as LOST only on anchored, still-active-chain evidence.

        A missing output is not proof of a refund: the funding itself may be
        reorged out. So the funding must be confirmed on the active chain at
        the signed depth and the refund must be possible (tip past the lock
        height). The first sighting is anchored to the tip block hash; the
        anchor must still be on the active chain when the wait ends, otherwise
        the spend may have been reorged and the wait restarts.

        A deposit Core does not know at all (paid from the mempool, then gone)
        is LOST only on proof that it can never confirm: see
        ``_funding_conflict``. Anything less keeps the claim waiting.
        """
        conflict = None
        try:
            funding_depth = await asyncio.to_thread(self._chain.confirmations, binding.funding_txid)
        except CoreTransactionUnknownError:
            funding_depth = 0
            conflict = await self._funding_conflict(item, binding, tip)
        else:
            self._conflict_scans.pop(item.session_id, None)  # known again: no conflict search
        if conflict is not None:
            LOG.error(
                "claim lost: a confirmed transaction double-spent the deposit; "
                "operator attention required"
            )
            return self._move(item, "LOST", now, loss_evidence=conflict)
        # Paying from the mempool (0) still needs a mined funding to call it lost.
        required = max(1, terms.funding_confirmations)
        if funding_depth < required or tip <= terms.refund_lock_height:
            LOG.warning("contract output missing while funding is unconfirmed; waiting")
            if item.outpoint_spent_height is not None:
                self._store.observe_outpoint_spent(item.session_id, None)
            return item.state
        if item.outpoint_spent_height is None or item.outpoint_spent_block is None:
            LOG.error("contract output spent by another transaction; claim may be lost")
            anchor = await asyncio.to_thread(self._chain.block_hash, tip)
            self._store.observe_outpoint_spent(item.session_id, tip, anchor)
            return item.state
        seen_height = item.outpoint_spent_height
        active = await asyncio.to_thread(self._chain.block_hash, seen_height)
        if tip < seen_height or active != item.outpoint_spent_block:
            LOG.warning("lost-claim anchor left the active chain; restarting the wait")
            self._store.observe_outpoint_spent(item.session_id, None)
            return item.state
        if tip - seen_height + 1 >= terms.refund_resolution_confirmations:
            LOG.error("claim lost: the refund resolved; operator attention required")
            return self._move(item, "LOST", now)
        return item.state

    async def _funding_conflict(
        self, item: SettlementItem, binding: FundingBinding, tip: int
    ) -> FundingConflict | None:
        """Return proof that the unknown deposit can never confirm, if there is one yet.

        Proof is another transaction spending one of the deposit's own inputs
        in a block still on the active chain, ``CONFLICT_LOSS_CONFIRMATIONS``
        deep. A mempool spender, an unauthenticated block, the deposit itself,
        or a failed read proves nothing. The search starts
        ``CONFLICT_SCAN_MARGIN_BLOCKS`` below the first claim (the provider
        paid while the deposit was in its mempool) and decodes at most one
        bounded ``find_spender`` range per sweep; a reorg restarts it.
        """
        try:
            scan = self._conflict_scans.get(item.session_id)
            if scan is None:
                scan = await self._new_conflict_scan(item, binding, tip)
                if scan is None:
                    return None
                self._conflict_scans[item.session_id] = scan
            behind: list[tuple[tuple[str, int], _InputScan]] = []
            for outpoint, state in scan.inputs.items():
                if await asyncio.to_thread(self._chain.outpoint_unspent, *outpoint):
                    state.conflict = None  # confirmed and unspent: nothing mined spends it
                elif state.conflict is not None:
                    proof = await self._conflict_proof(binding, outpoint, state, scan.floor, tip)
                    if proof is not None:
                        return proof
                elif state.next_height <= tip:
                    behind.append((outpoint, state))
            if behind:  # the furthest behind, so new blocks on one input never starve another
                outpoint, state = min(behind, key=lambda entry: entry[1].next_height)
                await self._search_input(binding, outpoint, state, scan.floor, tip)
                if state.conflict is not None:
                    return await self._conflict_proof(binding, outpoint, state, scan.floor, tip)
        except (CoreReadError, ValueError):
            LOG.info("deposit conflict search unavailable; retrying next sweep")
        return None

    async def _new_conflict_scan(
        self, item: SettlementItem, binding: FundingBinding, tip: int
    ) -> _ConflictScan | None:
        try:
            envelope = Envelope.model_validate_json(item.funding_binding or b"", strict=True)
            payload = parse_model_json(FundingBindingPayload, canonicalize(envelope.payload))
            raw = bytes.fromhex(payload.funding_transaction)
        except Exception:  # noqa: BLE001 - an unreadable binding names no inputs: no evidence
            return None
        if payload.binding.funding_txid != binding.funding_txid:
            return None
        txid, inputs = await asyncio.to_thread(self._chain.transaction_inputs, raw)
        if txid != binding.funding_txid:
            LOG.error("retained deposit bytes differ from the binding; operator attention required")
            return None
        first = min(
            (
                attempt.first_seen_height
                for attempt in self._store.claim_attempts(item.session_id)
                if attempt.first_seen_height is not None
            ),
            default=tip,
        )
        floor = max(1, first - CONFLICT_SCAN_MARGIN_BLOCKS)
        return _ConflictScan(floor, {outpoint: _InputScan(floor) for outpoint in inputs})

    async def _search_input(
        self,
        binding: FundingBinding,
        outpoint: tuple[str, int],
        state: _InputScan,
        floor: int,
        tip: int,
    ) -> None:
        """Scan the next bounded block range for a mined spender of one deposit input."""
        txid, vout = outpoint
        try:
            anchor = state.anchor or await asyncio.to_thread(
                self._chain.block_hash, state.next_height - 1
            )
            result = await asyncio.to_thread(
                self._chain.find_spender,
                txid,
                vout,
                from_height=state.next_height,
                to_height=tip,
                anchor_block=anchor,
            )
        except CoreProtocolError:  # e.g. the scanned branch changed: search again
            state.next_height, state.anchor = floor, None
            return
        spender = result.spender
        if spender is None:
            state.next_height, state.anchor = result.scanned_to + 1, result.scanned_block
        elif (
            spender.height is not None
            and result.scanned_block is not None
            and spender.txid != binding.funding_txid
        ):
            state.conflict = (spender.txid, spender.height, result.scanned_block)
        # Otherwise in the mempool, unauthenticated, or the deposit itself: retry.

    async def _conflict_proof(
        self,
        binding: FundingBinding,
        outpoint: tuple[str, int],
        state: _InputScan,
        floor: int,
        tip: int,
    ) -> FundingConflict | None:
        """Revalidate a found spender's block; return proof once it is deep enough."""
        assert state.conflict is not None  # noqa: S101 - caller checked
        conflict_txid, height, block = state.conflict
        if tip < height or await asyncio.to_thread(self._chain.block_hash, height) != block:
            LOG.warning("deposit conflict left the active chain; searching again")
            state.next_height, state.anchor, state.conflict = floor, None, None
            return None
        if tip - height + 1 < CONFLICT_LOSS_CONFIRMATIONS:
            return None
        return FundingConflict(
            funding_txid=binding.funding_txid,
            conflict_txid=conflict_txid,
            conflict_input_txid=outpoint[0],
            conflict_input_vout=outpoint[1],
            conflict_height=height,
            conflict_block=block,
            tip_height=tip,
            required_confirmations=CONFLICT_LOSS_CONFIRMATIONS,
        )

    def _authorization(
        self, terms: ContractTerms, binding: FundingBinding
    ) -> UnilateralAuthorization:
        funding = FundingOutput(
            txid=bytes.fromhex(binding.funding_txid),
            output_index=binding.contract_vout,
            value_sat=int(binding.contract_value_sat),
            script_pubkey=bytes.fromhex(binding.contract_script_pubkey),
        )
        return UnilateralAuthorization.from_terms(terms, funding, "claim", keys=self._crypto)

    async def _initial_claim(
        self,
        item: SettlementItem,
        terms: ContractTerms,
        binding: FundingBinding,
        *,
        fresh: bool,
    ) -> ValidatedUnilateralSpend:
        """Build attempt 0 from the node's claim fee evidence.

        ``fresh`` samples Core first. Deadline recovery and fallback
        preparation never wait for fee advice: they use the latest evidence
        this process remembers. Escalation takes over from whatever this
        chooses.
        """
        policy = await self._sample_claim_fee(terms) if fresh else None
        if policy is None:
            policy = self._claim_fee_evidence.get(terms.timing_policy.claim_confirmation_blocks)
        fee = self._unilateral_claim_fee(self._authorization(terms, binding), policy)
        return self._claim(item, terms, binding, fee)

    async def _sample_claim_fee(self, terms: ContractTerms) -> CooperativeFeePolicy | None:
        """Sample and remember fresh claim fee evidence, or None (advice only)."""
        allow_regtest_fixed_fee = self._settings.allow_regtest_fixed_fee
        try:
            policy = await asyncio.to_thread(
                lambda: self._chain.observe_cooperative_fee_policy(
                    terms.timing_policy.claim_confirmation_blocks,
                    allow_regtest_fixed_fee=allow_regtest_fixed_fee,
                )
            )
        except Exception:  # noqa: BLE001 - advice only; never defer a timelocked spend for it
            LOG.warning("claim fee evidence unavailable")
            return None
        if not _fee_policy_usable(policy, terms, allow_regtest_fixed_fee=allow_regtest_fixed_fee):
            return None
        self._claim_fee_evidence[policy.confirmation_blocks] = policy
        return policy

    def _unilateral_claim_fee(
        self, authorization: UnilateralAuthorization, policy: CooperativeFeePolicy | None
    ) -> int:
        """Price a script-path claim like the key-path claim it stands in for.

        The provider prices its claim into the success fee, so every claim
        pays the cooperative (key-path) size at the node's evidence: relay and
        mempool floors and the capped estimate for the signed confirmation
        target. The larger script-path claim then only has to relay;
        escalation bumps it if it stalls. Without evidence a timelocked claim
        never underpays: it pays the signed ceiling.
        """
        ceiling = max_spendable_fee(authorization)
        if policy is None:
            LOG.warning("no claim fee evidence; signing at the signed ceiling")
            return ceiling
        key_path, script_path = claim_vsizes(authorization.destination_script)
        relay = max(policy.min_relay_sat_kvb, policy.mempool_min_sat_kvb)
        priced = policy.fee_floor_sat(
            vsize=key_path, configured_floor_sat=self._settings.cooperative_fee_floor_sat
        )
        return min(ceiling, max(priced, (relay * script_path + 999) // 1000))

    def _claim(
        self, item: SettlementItem, terms: ContractTerms, binding: FundingBinding, fee: int
    ) -> ValidatedUnilateralSpend:
        authorization = self._authorization(terms, binding)
        plan = build_unilateral_spend(
            authorization, fee_sat=fee, claim_preimage=bytes.fromhex(item.preimage or "")
        )
        signature = self._store.sign_with_contract_key(
            item.session_id, plan.signature_hash, self._crypto
        )
        return finalize_unilateral_spend(plan, signature, verifier=self._crypto)


def _fee_policy_usable(
    policy: object, terms: ContractTerms, *, allow_regtest_fixed_fee: bool
) -> TypeGuard[CooperativeFeePolicy]:
    """Check fee evidence for the signed network and confirmation target.

    Public networks need an affirmative estimate within the target; only an
    explicit regtest policy accepts an unavailable one (relay floors only).
    """
    target = terms.timing_policy.claim_confirmation_blocks
    return (
        type(policy) is CooperativeFeePolicy
        and policy.network_identity == terms.network_identity
        and policy.confirmation_blocks == target
        and all(
            type(rate) is int and rate >= 0
            for rate in (policy.min_relay_sat_kvb, policy.mempool_min_sat_kvb)
        )
        and (
            allow_regtest_fixed_fee
            if policy.estimate_sat_kvb is None
            else (
                type(policy.estimate_sat_kvb) is int
                and policy.estimate_sat_kvb > 0
                and type(policy.estimate_blocks) is int
                and 1 <= policy.estimate_blocks <= target
            )
        )
    )


def _cooperative_outpoint_matches(
    sample: CooperativeClaimOutpoint,
    binding: FundingBinding,
    terms: ContractTerms,
    cutoff_height: int,
) -> bool:
    """Check the trusted sampler's exact named-tip evidence, not signing authority."""
    return (
        type(sample.static_match) is FundingBindingTransactionMatch
        and sample.network_identity == terms.network_identity
        and sample.funding_txid == binding.funding_txid == sample.static_match.funding_txid
        and sample.funding_vout == binding.contract_vout == sample.static_match.contract_vout
        and sample.static_match.lineage_anchor_txid == binding.lineage_anchor_txid
        and sample.static_match.lineage_anchor_vout == binding.lineage_anchor_vout
        and sample.funding_value_sat == int(binding.contract_value_sat)
        and sample.funding_script_pubkey == bytes.fromhex(binding.contract_script_pubkey)
        and type(sample.tip_height) is int
        and type(sample.confirmations) is int
        and type(sample.inclusion_height) is int
        and sample.confirmations >= terms.funding_confirmations
        and 0 < sample.inclusion_height <= sample.tip_height < cutoff_height
        and sample.tip_height < terms.refund_lock_height
        and sample.confirmations == sample.tip_height - sample.inclusion_height + 1
        and isinstance(sample.tip_hash, str)
        and isinstance(sample.inclusion_block_hash, str)
        and len(sample.tip_hash) == 64  # noqa: PLR2004 - 32-byte lowercase hash
        and len(sample.inclusion_block_hash) == 64  # noqa: PLR2004
        and all(
            char in "0123456789abcdef" for char in sample.tip_hash + sample.inclusion_block_hash
        )
    )


def claim_fee_target(  # noqa: PLR0913 - explicit schedule inputs
    *,
    initial: int | None,
    maximum: int,
    anchor: int | None,
    deadline: int,
    tip: int,
    latest_fee: int | None,
    latest_height: int | None,
    vsize: int,
    attempts: int,
) -> int | None:
    """Return the next claim fee, or ``None`` when no replacement is due.

    The fee rises linearly from the first attempt's fee at its immutable
    first-seen height to ``maximum`` at ``deadline - CLAIM_URGENCY_BLOCKS``
    (the client can refund after ``deadline``), and is ``maximum`` from then
    on. A replacement needs a new block since the latest attempt (except at
    urgency) and must beat the latest fee by the BIP125 incremental relay fee.
    The last attempt of the budget is reserved for ``maximum``, and a target
    that would leave less than one increment of headroom below ``maximum``
    becomes ``maximum`` so the final replacement is always reachable. Unknown
    fees or heights never trigger a bump.
    """
    if (
        initial is None
        or anchor is None
        or latest_fee is None
        or latest_height is None
        or attempts >= MAX_CLAIM_ATTEMPTS
    ):
        return None
    urgent = deadline - CLAIM_URGENCY_BLOCKS
    if tip >= urgent:
        target = maximum
    elif tip <= latest_height or attempts == MAX_CLAIM_ATTEMPTS - 1:
        return None  # wait for a block; the final slot is kept for the maximum
    else:
        span = max(1, urgent - anchor)
        target = initial + (maximum - initial) * max(0, tip - anchor) // span
    increment = vsize * INCREMENTAL_RELAY_SAT_VB
    target = min(target, maximum)
    if maximum - target < increment:
        target = maximum  # never strand the final replacement below the maximum
    if target < latest_fee + increment:
        return None
    return target


def _with_state(item: SettlementItem, state: str, **changes: object) -> SettlementItem:
    return replace(item, state=state, **changes)  # type: ignore[arg-type]
