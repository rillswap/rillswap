"""Provider handshake service: relays <-> authoritative live session store.

Order of effects is fixed by the store: an accept is committed before any
wrap of it exists, and confirms are admitted only through the store. This
module adds scheduling, routing, and retries, never authority. A confirmed
session grants no quote, funding, or payment action (none is wired).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from contextlib import suppress
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Protocol

from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.evm_quotes import LnToErc20FirmQuoteRequest
from rill_core.wire.fee_policy import (
    NETWORK_FEE_VBYTES,
    BtcFeePolicy,
    FeeBreakdown,
    parse_fee_request,
)
from rill_core.wire.hashes import canonical_model
from rill_core.wire.messages import Envelope, InvoiceBinding
from rill_core.wire.quotes import QuoteError, parse_quote_request
from rill_core.wire.reverse_quotes import ReverseFirmQuoteRequest

from rill_provider import _transport_pow as transport_pow
from rill_provider.dynamic_pricing import DynamicPricing, FeeLimits, LiquiditySample
from rill_provider.evm_quote_policy import EVM_PROFILES, ln_to_erc20_hold_msat
from rill_provider.liquidity_cap import LiquidityCap
from rill_provider.live_session_store import (
    COOPERATION_BUDGET_SECONDS,
    FIRST_REQUEST_SEQUENCE,
    Answer,
    CooperativeWinner,
    LiveSessionStore,
    LiveSessionStoreError,
    RecordedUnilateralClaim,
    SessionBlockedError,
    SessionExpiredError,
    StaleOwnerError,
)
from rill_provider.lnd_invoice_decode import InvoiceRejectedError
from rill_provider.lnd_payment_observation import LndObservationError
from rill_provider.provider_identity import AnnouncementTerms
from rill_provider.quote_policy import (
    ClaimFeeRate,
    FirmSigner,
    HoldOutcome,
    InvoiceOutcome,
    QuoteSchedule,
    QuoteTerms,
    hold_invoice_msat,
    normal_success_fee,
    success_fee,
)
from rill_provider.relay_client import RelayConnection, RelayError
from rill_provider.settlement_policy import answer_client_request

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from rill_core.wire.types import EvmAssetIdentity, NetworkIdentity, ProfileId
    from rill_crypto import Context

    from rill_provider.evm_settlement import EvmSettlementEngine
    from rill_provider.live_session_store import (
        PreparedFallback,
        ReadinessChallenge,
        RequestAnswer,
        RequestContext,
    )
    from rill_provider.lnd_hold_invoice import LndHoldInvoices
    from rill_provider.provider_identity import ProviderIdentity
    from rill_provider.reverse_operations import ReverseOperation
    from rill_provider.settlement_engine import ClaimProbeWindow, SettlementEngine

LOG = logging.getLogger(__name__)
REVERSE_PROFILES = ("ln-to-btc/v1", "ln-to-erc20/v1")  # the provider funds after a hold
NIP59_BACKDATE_SECONDS = 2 * 24 * 60 * 60
REPLAY_CLOCK_SKEW_SECONDS = 10 * 60
URGENT_RETRY_SECONDS = 2.0
MAX_SEEN_EVENTS = 4096
# A client sends its first request right after its confirm, with no answer in
# between; relays may deliver the two in either order. Only the session's own
# client (seal author, after transport work) can fill its slots.
MAX_DEFERRED_PER_SESSION = 2
MAX_DEFERRED_EVENTS = 64
TIP_LOOKUP_WAIT_SECONDS = 2.0  # waiting bound, not cancellation of Core's worker thread
CLAIM_FEE_WAIT_SECONDS = 2.0  # likewise for the per-tick claim fee sample
LIQUIDITY_WAIT_SECONDS = 30.0  # once per announcement; the RPCs carry their own timeouts
PRICING_SAMPLE_WAIT_SECONDS = 2.0  # per quote (cached); a slow sample prices normally
FUNDING_BALANCE_WAIT_SECONDS = 5.0  # per LN to BTC firm quote: refuse fast, never hang
_RELAY_CONNECTED = b""  # in-band wake: tick now and re-announce
# Relay dispositions that recur without telling an operator anything: history
# replays after every resubscribe, flood filtering, and paused admission.
_ROUTINE_DISPOSITIONS = frozenset({"duplicate", "insufficient-work", "unavailable", "deferred"})


def _disposition_level(disposition: str) -> int:
    """Log routine relay dispositions at DEBUG, the rest at INFO."""
    routine = disposition in _ROUTINE_DISPOSITIONS or disposition.endswith("-replay")
    return logging.DEBUG if routine else logging.INFO


class Relay(Protocol):
    """What the service needs from one relay connection."""

    url: str

    async def publish(self, event: bytes) -> bool:
        """Return True only on an explicit relay OK."""
        ...

    async def subscribe(self, filters: list[dict[str, Any]]) -> None:
        """Replace this connection's subscription."""
        ...


@dataclass(frozen=True, slots=True)
class ServicePolicy:
    """Operator-chosen public terms and schedules."""

    network: NetworkIdentity
    profiles: tuple[str, ...]
    amount_bands: tuple[tuple[int, int], ...]
    base_fee_sat: int
    proportional_millionths: int
    slot: str
    relay_urls: tuple[str, ...]
    epoch_period: int = 24 * 60 * 60
    announcement_lifetime: int = 60 * 60
    announcement_refresh: int = 30 * 60
    outbox_retry: int = 60
    handshake_timeout: int = 10 * 60
    max_sends_per_tick: int = 16
    quote: QuoteSchedule = field(default_factory=QuoteSchedule)
    provider_destination_script: str | None = None  # required for firm offers
    profile: ProfileId = "btc-to-ln/v1"  # the one negotiated profile this service serves
    evm_assets: tuple[EvmAssetIdentity, ...] = ()  # RS-010: announced served assets
    evm_funding_confirmations: int = 1  # RS-010: the EVM schedule's funding depth
    relay_proxy: str | None = None  # checked loopback CONNECT proxy, or direct
    # RS-006 transport proof of work required on new sessions' messages; 0 = off.
    transport_pow_bits: int = 0
    # With a liquidity source: announce this random percent range below it.
    follow_liquidity: bool = True
    liquidity_margin_percent: tuple[int, int] = (10, 20)
    fee_policy: BtcFeePolicy | None = None
    # Private balance-aware discounts (never announced); needs a liquidity sample.
    dynamic_fees: FeeLimits | None = None

    def __post_init__(self) -> None:
        """Refuse schedules that would leave advertised epochs undecodable."""
        if not (
            type(self.transport_pow_bits) is int
            and 0 <= self.transport_pow_bits <= transport_pow.MAX_WORK_BITS
            and self.relay_urls
            and 0 < self.announcement_refresh < self.announcement_lifetime
            and self.epoch_period > 0
            and self.outbox_retry > 0
            and self.handshake_timeout > 0
            and self.max_sends_per_tick > 0
        ):
            raise ValueError("service schedule unsupported")

    @property
    def funding_confirmations(self) -> int:
        """The announced depth every quote for the served profile carries (RS-005)."""
        if self.profile in EVM_PROFILES:
            return self.evm_funding_confirmations
        return self.quote.funding_confirmations


@dataclass(frozen=True, slots=True)
class ServiceHealth:
    """What clients can get from this service right now (for operator alerts).

    A source that is not configured is never reported as unavailable.
    """

    relays_connected: int
    announcing: bool  # liquidity covers at least one amount band
    tip_available: bool  # quotes need the chain tip
    claim_fee_available: bool  # LN to BTC quotes with an automatic claim reserve


@dataclass(slots=True)
class _State:
    subscribed: tuple[str, ...] = ()
    replay_groups: tuple[tuple[tuple[str, ...], int | None], ...] = ()
    work: dict[str, int] = field(default_factory=dict)  # recipient key -> required bits
    retry_subscription: bool = False
    relay_drops: dict[int, tuple[Relay, int]] = field(default_factory=dict)
    announced_keys: tuple[str, ...] = ()
    announced_at: int = 0
    announcement: bytes | None = None  # exact bytes, retransmitted unchanged
    announcement_expires: int = 0
    republish: bool = False
    # Bands of the last announcement; quotes admit exactly these. Empty while
    # liquidity covers no band (nothing is announced then).
    bands: tuple[tuple[int, int], ...] = ()
    attempts: dict[str, int] = field(default_factory=dict)
    urgent_until: dict[str, int] = field(default_factory=dict)
    seen: OrderedDict[str, None] = field(default_factory=OrderedDict)
    tip: int | None = None  # per-tick snapshot; requests never trigger RPC
    claim_fee: ClaimFeeRate | None = None  # per-tick snapshot, like the tip
    # (session_id, event_id, received_at, event): frames that reached a session
    # before its confirm, handled once the confirm is admitted.
    deferred: list[tuple[str, str, int, bytes]] = field(default_factory=list)


class HandshakeService:
    """Single-owner orchestration; the caller owns the store and relays."""

    def __init__(  # noqa: PLR0913 - explicit injected resources
        self,
        store: LiveSessionStore,
        identity: ProviderIdentity,
        transport: Context,
        policy: ServicePolicy,
        *,
        clock: Callable[[], float] = time.time,
        chain_tip: Callable[[], int] | None = None,
        invoice_decoder: Callable[[str], InvoiceBinding] | None = None,
        settlement: SettlementEngine | None = None,
        hold_invoices: LndHoldInvoices | None = None,
        evm_settlement: EvmSettlementEngine | None = None,
        liquidity: Callable[[], int] | None = None,
        claim_fee: Callable[[], ClaimFeeRate] | None = None,
        liquidity_sample: Callable[[], LiquiditySample | None] | None = None,
    ) -> None:
        """Bind already-acquired, already-verified resources.

        ``chain_tip`` (blocking; run off the event loop once per tick, never
        per request) supplies an indicative quote's reference height. Without
        it, or when it fails, quotes are answered ``capacity_unavailable``.
        ``invoice_decoder`` (blocking, e.g. LND ``DecodePayReq``) plus a
        ``provider_destination_script`` enable firm offers. ``settlement``
        moves funded swaps to payment and claim once per tick. ``liquidity``
        (blocking, satoshis this provider can pay out in one swap) is sampled
        once per announcement to cap the announced and admitted amounts.
        ``claim_fee`` (blocking, next-block fee evidence) is sampled once per
        tick like the tip and prices LN to BTC claim reserves; without a
        sample, quotes with an automatic reserve answer ``capacity_unavailable``.
        With network pricing enabled it is additionally sampled per request,
        outside store transactions, to freeze the provider's mining charge.
        ``liquidity_sample`` (blocking, cached by the caller) prices
        ``policy.dynamic_fees`` discounts per request; without a sample,
        quotes pay the normal fee.
        """
        self._store = store
        self._identity = identity
        self._transport = transport
        self._policy = policy
        self._clock = clock
        self._chain_tip = chain_tip
        self._invoice_decoder = invoice_decoder
        self._settlement = settlement
        self._hold_invoices = hold_invoices
        self._evm_settlement = evm_settlement  # RS-010 profiles: quotes, readiness, and ticks
        self._liquidity = liquidity
        self._liquidity_cap = (
            None
            if liquidity is None or not policy.follow_liquidity
            else LiquidityCap(policy.amount_bands, margin_percent=policy.liquidity_margin_percent)
        )
        self._liquidity_failing = False
        self._funding_balance_failing = False
        self._state = _State(bands=policy.amount_bands)
        self._deadline_healthy = True
        self._deadline_wall_anchor, self._deadline_monotonic_anchor = self._now(), time.monotonic()
        self._deadline_high_water = self._deadline_wall_anchor
        self._tip_lookup: asyncio.Task[int] | None = None
        self._claim_fee = claim_fee
        self._claim_fee_lookup: asyncio.Task[ClaimFeeRate] | None = None
        self._liquidity_sample = liquidity_sample
        self._tip_lookup_started: float | None = None
        # These maps are never reconstructed from signed outbox or inbox rows.
        self._readiness_probes: dict[str, ReadinessChallenge] = {}
        self._readiness_ready: dict[str, ReadinessChallenge] = {}
        self._readiness_issued: set[str] = set()
        self._readiness_closed = False
        # session -> contract digest of a featured acceptance answered by this
        # process, kept while its swap still awaits the first funding binding.
        self._fresh_featured_accepts: dict[str, str] = {}
        self._probe_supervision_needed = False
        self._connected: dict[str, RelayConnection] = {}  # owned by run()

    def health(self) -> ServiceHealth:
        """Return the current health snapshot; no I/O, event-loop thread only."""
        state = self._state
        return ServiceHealth(
            relays_connected=len(self._connected),
            announcing=bool(state.bands),
            tip_available=self._chain_tip is None or state.tip is not None,
            claim_fee_available=self._claim_fee is None or state.claim_fee is not None,
        )

    def _now(self) -> int:
        return int(self._clock())

    def _deadline_now(self) -> int:
        """Keep deadline eligibility irreversible through clock corrections."""
        self._deadline_high_water = max(
            self._now(),
            self._deadline_high_water,
            self._deadline_wall_anchor + int(time.monotonic() - self._deadline_monotonic_anchor),
        )
        return self._deadline_high_water

    def _live_cooperative_now(self) -> int:
        """Fence new signing exposure, not observations or owed completions."""
        if self._readiness_closed or not self._deadline_healthy:
            raise LiveSessionStoreError("original cooperative service unavailable")
        current = self._deadline_now()
        if self._readiness_closed or not self._deadline_healthy:
            raise LiveSessionStoreError("original cooperative service unavailable")
        return current

    async def start_cooperative_readiness(
        self,
        session_id: str,
        *,
        deadline_height: int | None = None,
        relays: Sequence[Relay] = (),
        window: ClaimProbeWindow | None = None,
    ) -> str | None:
        """Probe one newly paid featured original session at most once per owner.

        Live callers must supply the PAID transition's original probe window;
        older primitive-only callers may supply a height without claim deferral.
        """
        if (
            self._readiness_closed
            or not self._deadline_healthy
            or session_id in self._readiness_issued
        ):
            return None
        self._readiness_issued.add(session_id)  # failed preparation cannot renew the budget
        started_at = self._deadline_now() if window is None else window.started_at
        deadline_at = started_at + COOPERATION_BUDGET_SECONDS
        if window is not None:
            deadline_height = self._live_probe_height(session_id, window, deadline_height)
            if deadline_height is None:
                return None
        tip = await (self._fresh_probe_tip() if window is not None else self._sample_tip())
        if (
            self._readiness_closed
            or not self._deadline_healthy
            or tip is None
            or type(deadline_height) is not int
            or tip >= deadline_height
            or self._deadline_now() >= deadline_at
            or (
                window is not None
                and (
                    self._settlement is None
                    or self._settlement.probe_window(session_id) != window
                    or time.monotonic() >= window.started_monotonic + COOPERATION_BUDGET_SECONDS
                )
            )
        ):
            if window is not None and self._settlement is not None:
                self._settlement.abandon_probe(session_id)
            return None
        try:
            challenge = self._store.issue_cooperative_readiness(
                session_id,
                signer=self._transport,
                started_at=started_at,
                now=self._deadline_now(),
                deadline_at=deadline_at,
                deadline_height=deadline_height,
            )
        except StaleOwnerError:
            raise
        except LiveSessionStoreError:
            if window is not None and self._settlement is not None:
                self._settlement.abandon_probe(session_id)
            return None
        self._readiness_probes[session_id] = challenge
        self._state.urgent_until[challenge.request_id] = deadline_at
        if relays:
            self._expedite_session_delivery(session_id, deadline_at)
            await self._send_pending(challenge.request_id, relays)
        return challenge.request_id

    def _live_probe_height(
        self, session_id: str, window: ClaimProbeWindow, requested: int | None
    ) -> int | None:
        """Bind the original budget and signed chain cutoff to this owner."""
        settlement = self._settlement
        if (
            settlement is None
            or window.session_id != session_id
            or window.owner_generation != self._store.generation
            or window.deadline_at != window.started_at + COOPERATION_BUDGET_SECONDS
            or window.abandoned
            or settlement.probe_window(session_id) != window
            or time.monotonic() >= window.started_monotonic + COOPERATION_BUDGET_SECONDS
            or self._deadline_now() >= window.deadline_at
        ):
            return None
        try:
            cutoff = self._store.cooperative_height_cutoff(session_id, window.contract_hash)
        except StaleOwnerError:
            raise
        except LiveSessionStoreError:
            settlement.abandon_probe(session_id)
            return None
        if cutoff is None or (requested is not None and requested != cutoff):
            settlement.abandon_probe(session_id)
            return None
        return cutoff

    def take_cooperative_readiness(self, session_id: str) -> ReadinessChallenge | None:
        """Consume one original-session echo before preparing the exact fallback."""
        challenge = self._readiness_ready.pop(session_id, None)
        if (
            challenge is None
            or self._readiness_closed
            or self._deadline_now() >= challenge.deadline_at
        ):
            return None
        if challenge.owner_generation != self._store.generation or not self._deadline_healthy:
            return None
        return challenge

    def _abandon_live_echo(self, challenge: ReadinessChallenge) -> None:
        """Retire failed live authority without renewing or exposing a nonce."""
        self._readiness_probes.pop(challenge.session_id, None)
        self._readiness_ready.pop(challenge.session_id, None)
        if self._settlement is not None:
            self._settlement.abandon_probe(challenge.session_id)
        try:
            self._store.retire_cooperative_readiness(challenge)
        except StaleOwnerError:
            raise
        except LiveSessionStoreError:
            LOG.warning("readiness retirement deferred for %s", challenge.session_id[:16])

    async def _prepare_ready_echo(self, challenge: ReadinessChallenge) -> str:
        """Consume the original echo, then commit the fallback before any nonce."""
        settlement = self._settlement
        token = self.take_cooperative_readiness(challenge.session_id)
        if settlement is None or token != challenge:
            self._abandon_live_echo(challenge)
            return "readiness-abandoned"

        async def fresh_tip() -> int | None:
            tip = await self._fresh_probe_tip()
            return tip if not self._readiness_closed and self._deadline_healthy else None

        try:
            await settlement.prepare_cooperative_window(
                token, sample_tip=fresh_tip, now=self._deadline_now
            )
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - no nonce or proposal on uncertain preparation
            self._abandon_live_echo(challenge)
            LOG.warning(
                "cooperative fallback preparation abandoned for %s", challenge.session_id[:16]
            )
            return "readiness-abandoned"
        self._store.retire_cooperative_readiness(challenge)

        def proposal_now() -> int:
            current = self._live_cooperative_now()
            if current >= token.deadline_at:
                raise LiveSessionStoreError("original cooperative deadline elapsed")
            return current

        try:
            proposal_now()  # refuse entry if preparation consumed eligibility
            await settlement.initiate_cooperative_proposal(token.session_id, now=proposal_now)
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - burn may be durable; never retry or renew authority
            LOG.warning("cooperative proposal initiation stopped for %s", challenge.session_id[:16])
        # The normal tick outbox uses time/height-checked _send_pending. Do not
        # disclose a proposal here or restore the consumed echo after failure.
        return "readiness-prepared"

    async def _admit_ready_result(self, document: bytes, session_id: object) -> str:
        """Authenticate the exact signed echo and prepare only its live probe."""
        challenge = self._readiness_probes.get(session_id) if isinstance(session_id, str) else None
        if challenge is None:
            return "refused"  # stored requests never recreate a live token
        live_window = (
            self._settlement.probe_window(challenge.session_id)
            if self._settlement is not None
            else None
        )
        tip = await (self._fresh_probe_tip() if live_window is not None else self._sample_tip())
        if tip is None or self._readiness_closed or not self._deadline_healthy:
            if live_window is not None:
                self._abandon_live_echo(challenge)
            return "refused"
        result = self._store.admit_cooperative_readiness(
            document, challenge, now=self._deadline_now(), tip_height=tip
        )
        if result.replay:
            return "result-replay"  # a replay never restores eligibility
        del self._readiness_probes[challenge.session_id]
        self._readiness_ready[challenge.session_id] = challenge
        if live_window is not None:
            return await self._prepare_ready_echo(challenge)
        return "readiness-admitted"

    def _expire_fresh_accepts(self) -> None:
        """Forget acceptances whose swap no longer awaits its first binding.

        The funding window, not the pre-acceptance handshake timeout, bounds
        them: a browser binds only after its deposit confirms, often more than
        ten minutes after accepting. The store ends that window (bound,
        closed unfunded, or aborted); entries never outlive their ACCEPTED row.
        """
        if not self._fresh_featured_accepts:
            return
        try:
            awaiting = {session_id for session_id, _ in self._store.unfunded_swaps()}
        except StaleOwnerError:
            raise
        except LiveSessionStoreError:
            return  # keep entries; registration rechecks the store
        for session_id in tuple(self._fresh_featured_accepts):
            if session_id not in awaiting:
                del self._fresh_featured_accepts[session_id]

    def _expire_readiness(self) -> None:
        now = self._deadline_now()
        for session_id, challenge in tuple(self._readiness_probes.items()):
            if now >= challenge.deadline_at:
                self._store.retire_cooperative_readiness(challenge)
                del self._readiness_probes[session_id]
                if self._settlement is not None and self._settlement.probe_window(session_id):
                    self._settlement.abandon_probe(session_id)
        for session_id, challenge in tuple(self._readiness_ready.items()):
            if now >= challenge.deadline_at:
                del self._readiness_ready[session_id]
                if self._settlement is not None and self._settlement.probe_window(session_id):
                    self._settlement.abandon_probe(session_id)

    def _abandon_readiness(self) -> None:
        """Discard process-local authorization when this service stops."""
        self._readiness_closed = True
        for challenge in tuple(self._readiness_probes.values()):
            with suppress(LiveSessionStoreError):
                self._store.retire_cooperative_readiness(challenge)
        self._readiness_probes.clear()
        self._readiness_ready.clear()

    async def _publish(
        self,
        event: bytes,
        relays: Sequence[Relay],
        *,
        budget_seconds: float | None = None,
        before_send: Callable[[], bool] | None = None,
    ) -> bool:
        async def send(relay: Relay) -> bool:
            if before_send is not None and not before_send():
                return False
            return await relay.publish(event)

        tasks = [asyncio.create_task(send(relay)) for relay in relays]
        try:
            async with asyncio.timeout(budget_seconds):
                results = await asyncio.gather(*tasks, return_exceptions=True)
        except TimeoutError:
            return any(
                task.done()
                and not task.cancelled()
                and task.exception() is None
                and task.result() is True
                for task in tasks
            )
        return any(result is True for result in results)

    def _filters(self) -> list[dict[str, Any]]:
        # Every still-decodable epoch, not only advertised ones: clients may
        # hold an older, still-valid announcement.
        epochs = self._store.receiving_epochs(now=self._now())
        mailboxes = self._store.mailbox_work()
        required = self._policy.transport_pow_bits
        work = dict.fromkeys(epochs, required)
        for mailbox in mailboxes:
            # A session keeps the work it declared even if the requirement
            # changes. One admitted before any was declared stays exempt until
            # its swap finishes, so enabling work never strands a live swap.
            if mailbox.declared_bits is not None:
                work[mailbox.mailbox_key] = mailbox.declared_bits
            else:
                work[mailbox.mailbox_key] = required if mailbox.finished else 0
        self._state.work = work
        # Firm terms cannot reach the client before this durable reservation. Unlike
        # active_at, it cannot move past a message sent while the provider was offline.
        anchors = {
            mailbox.mailbox_key: mailbox.reserved_at
            for mailbox in mailboxes
            if not mailbox.finished
            and type(mailbox.reserved_at) is int
            and mailbox.reserved_at >= 0
        }
        rolling = self._now() - NIP59_BACKDATE_SECONDS - self._policy.outbox_retry
        filters = [
            {
                "kinds": [1059],
                "#p": sorted(set(work) - anchors.keys()),
                "since": rolling,
            }
        ]
        if anchors:
            filters.append(
                {
                    "kinds": [1059],
                    "#p": sorted(anchors),
                    "since": min(
                        rolling,
                        min(anchors.values()) - NIP59_BACKDATE_SECONDS - REPLAY_CLOCK_SKEW_SECONDS,
                    ),
                }
            )
        return filters

    def _remember_urgent(
        self,
        document: bytes,
        message_id: str,
        *,
        session_id: str | None = None,
    ) -> None:
        """Scheduling only: retained bytes and their original deadline grant no authority."""
        try:
            payload = json.loads(document)["payload"]
            deadline = payload.get("deadline_at")
            if (
                payload.get("action") in {"cooperative_claim_ready", "cooperative_claim_propose"}
                and type(deadline) is int
            ):
                self._state.urgent_until[message_id] = deadline
                if session_id is not None:
                    self._expedite_session_delivery(session_id, deadline)
        except (ValueError, KeyError, TypeError, AttributeError):
            return

    def _expedite_session_delivery(self, session_id: str, deadline: int) -> None:
        """Backfill existing sequence gaps, without new delivery or financial authority."""
        if self._deadline_now() >= deadline:
            return
        # Both claimants need the earlier observations before a readiness request
        # or signed reply. Only positive PENDING evidence grants a retry duty.
        try:
            for entry in self._store.pending_outbox(session_id=session_id):
                self._state.urgent_until.setdefault(entry.message_id, deadline)
        except (TypeError, AttributeError):
            return  # unknown delivery evidence never authorizes a broad replay

    async def _retry_urgent(self, relays: Sequence[Relay]) -> None:
        if not self._state.urgent_until:
            return
        now = self._deadline_now()
        due = []
        for message_id, deadline in tuple(self._state.urgent_until.items()):
            if now >= deadline:
                del self._state.urgent_until[message_id]
            elif now >= self._state.attempts.get(message_id, 0) + URGENT_RETRY_SECONDS:
                due.append(message_id)
        if not due:
            return
        due.sort(key=lambda message_id: self._state.attempts.get(message_id, 0))
        results = await asyncio.gather(
            *(
                self._send_pending(message_id, relays)
                for message_id in due[: self._policy.max_sends_per_tick]
            ),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, StaleOwnerError):
                raise result

    def _has_work(self, event: bytes) -> bool:
        """Whether an inbound gift wrap carries the RS-006 transport work it needs.

        Checked before queueing and again before any decryption. Only hashes:
        a dropped event costs one parse and one SHA-256. Recipients outside the
        current table (a just-admitted session) need the current requirement.
        """
        work = self._state.work
        required = self._policy.transport_pow_bits
        if required == 0 and not any(work.values()):
            return True  # nothing requires work: unchanged behavior
        found = transport_pow.outer_work(event)
        if found is None:
            return False  # no event the store could accept
        recipient, proven = found
        return proven >= work.get(recipient, required)

    def _declares_work(self, init_document: bytes) -> bool:
        """Whether an init binds its session to at least the required work.

        The declaration fixes the work every later message of the session
        carries, so a requirement change never strands the session. A
        malformed declaration is refused even when no work is required.
        """
        try:
            extensions = json.loads(init_document)["payload"]["extensions"]
            declared = transport_pow.requirement(extensions)
        except (ValueError, KeyError, TypeError):
            return False
        required = self._policy.transport_pow_bits
        return required == 0 or (declared is not None and declared >= required)

    async def subscribe(self, relay: Relay) -> None:
        """Install the current filter on one (re)connected relay."""
        await relay.subscribe(self._filters())

    async def tick(self, relays: Sequence[Relay]) -> None:
        """Rotate epochs, refresh the announcement, resubscribe, retry the outbox."""
        self._expire_readiness()
        self._expire_fresh_accepts()
        policy, state, now = self._policy, self._state, self._now()
        epochs = self._store.rotate_epochs(
            now=now,
            period=policy.epoch_period,
            retention=2 * policy.announcement_lifetime,
            advertise_for=2 * policy.announcement_lifetime - 1,
        )
        self._store.expire_idle(now=now, idle_timeout=policy.handshake_timeout)
        self._purge_deferred(now)
        await self._refresh_tip()
        await self._refresh_claim_fee()
        if epochs != state.announced_keys or now >= state.announced_at + (
            policy.announcement_refresh
        ):
            await self._announce(epochs, now)
        if state.republish and state.announcement and now < state.announcement_expires:
            state.republish = not await self._publish(state.announcement, relays)
            if state.republish:
                LOG.warning("announcement not accepted by any relay; will retry")
        await self._resubscribe(relays)
        if self._settlement is not None:
            for session_id, moved in (await self._settlement.tick(now)).items():
                LOG.info("swap %s moved to %s", session_id[:16], moved)
                await self._begin_paid_probe(session_id, moved, relays)
        if self._evm_settlement is not None:
            for session_id, moved in (await self._evm_settlement.tick(now)).items():
                LOG.info("EVM swap %s moved to %s", session_id[:16], moved)
        entries = self._store.pending_outbox()
        for entry in entries:
            self._remember_urgent(entry.canonical_bytes, entry.message_id)
        due = sorted(  # least recently attempted first (never attempted = 0)
            (
                entry.message_id
                for entry in entries
                if now
                >= state.attempts.get(entry.message_id, 0)
                + (
                    URGENT_RETRY_SECONDS
                    if now < state.urgent_until.get(entry.message_id, 0)
                    else policy.outbox_retry
                )
            ),
            key=lambda message_id: state.attempts.get(message_id, 0),
        )[: policy.max_sends_per_tick]  # bounded work per tick; the rest wait
        results = await asyncio.gather(
            *(self._send_pending(message_id, relays) for message_id in due),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, StaleOwnerError):
                raise result
        pending = {entry.message_id for entry in self._store.pending_outbox()}  # one read per tick
        for message_id in list(state.attempts):
            if message_id not in pending:
                del state.attempts[message_id]

    async def _send_fresh_outbox(self, relays: Sequence[Relay]) -> None:
        """Send never-attempted entries now through the tick's checked sender.

        A cooperative proposal or completion shares a deadline of seconds, so
        waiting for the next tick would usually miss it. Retries stay with tick.
        """
        fresh = [
            entry.message_id
            for entry in self._store.pending_outbox()
            if entry.message_id not in self._state.attempts
        ]
        for entry in self._store.pending_outbox():
            if entry.message_id in fresh:
                self._remember_urgent(
                    entry.canonical_bytes, entry.message_id, session_id=entry.session_id
                )
        if not fresh:
            return
        results = await asyncio.gather(
            *(self._send_pending(message_id, relays) for message_id in fresh),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, StaleOwnerError):
                raise result

    async def _begin_paid_probe(self, session_id: str, moved: str, relays: Sequence[Relay]) -> None:
        """Send a challenge only for this owner's fresh PAID transition gate."""
        if moved != "PAID" or not self._probe_supervision_needed or self._settlement is None:
            return
        window = self._settlement.probe_window(session_id)
        if window is not None and not window.abandoned:
            await self.start_cooperative_readiness(session_id, relays=relays, window=window)

    async def _refresh_tip(self) -> None:
        if self._chain_tip is None:
            return
        self._state.tip = await self._sample_tip()
        if self._state.tip is None:
            LOG.warning("chain tip unavailable; quotes answered capacity_unavailable")

    async def _refresh_claim_fee(self) -> None:
        """Replace the claim fee snapshot; a failed sample leaves none, never an old one."""
        if self._claim_fee is None:
            return
        task = self._claim_fee_lookup
        if task is None or task.done():  # share one outstanding Core lookup
            task = asyncio.create_task(asyncio.to_thread(self._claim_fee))
            self._claim_fee_lookup = task

            def consume(done: asyncio.Task[ClaimFeeRate]) -> None:
                if not done.cancelled():
                    with suppress(Exception):
                        done.exception()  # avoid an unobserved late RPC failure

            task.add_done_callback(consume)
        try:
            sample = await asyncio.wait_for(asyncio.shield(task), CLAIM_FEE_WAIT_SECONDS)
        except Exception as error:  # noqa: BLE001 - no fee evidence, no automatic reserve
            sample = None
            LOG.warning(
                "claim fee unavailable (%s); LN to BTC quotes answered capacity_unavailable",
                type(error).__name__,
            )
        self._state.claim_fee = sample if isinstance(sample, ClaimFeeRate) else None

    async def _sample_tip(self) -> int | None:
        height, _ = await self._sample_tip_with_age()
        return height

    async def _sample_tip_with_age(self) -> tuple[int | None, float | None]:
        """Share one outstanding Core lookup, without canceling a timed-out worker."""
        if self._chain_tip is None:
            return None, None
        task = self._tip_lookup
        started: float | None
        if task is None or task.done():
            started = time.monotonic()
            self._tip_lookup_started = started
            task = asyncio.create_task(asyncio.to_thread(self._chain_tip))
            self._tip_lookup = task

            def consume(done: asyncio.Task[int]) -> None:
                if not done.cancelled():
                    with suppress(Exception):
                        done.exception()  # avoid an unobserved late RPC failure

            task.add_done_callback(consume)
        else:
            started = self._tip_lookup_started
        try:
            height = await asyncio.wait_for(asyncio.shield(task), TIP_LOOKUP_WAIT_SECONDS)
        except Exception:  # noqa: BLE001 - no proof of tip, never start another pending RPC
            return None, started
        return (height if type(height) is int and height >= 0 else None), started

    async def _fresh_probe_tip(self) -> int | None:
        height, _ = await self._fresh_tip_evidence()
        return height

    async def _fresh_tip_evidence(self) -> tuple[int | None, float | None]:
        """Refuse an old shared RPC result, including a late timed-out worker."""
        if (
            self._tip_lookup is not None
            and not self._tip_lookup.done()
            and (
                self._tip_lookup_started is None
                or time.monotonic() - self._tip_lookup_started >= TIP_LOOKUP_WAIT_SECONDS
            )
        ):
            return None, None  # never launch a second thread alongside the old lookup
        height, started = await self._sample_tip_with_age()
        if (
            height is None
            or started is None
            or time.monotonic() - started >= TIP_LOOKUP_WAIT_SECONDS
        ):
            return None, None
        return height, started

    async def _liquidity_bands(self) -> tuple[tuple[int, int], ...]:
        """Sample liquidity once and return the bands to announce next."""
        cap, source = self._liquidity_cap, self._liquidity
        if cap is None or source is None:
            return self._policy.amount_bands
        try:
            cap.observe(await asyncio.wait_for(asyncio.to_thread(source), LIQUIDITY_WAIT_SECONDS))
        except Exception:  # noqa: BLE001 - keep the last cap; reverting would raise it
            if not self._liquidity_failing:
                LOG.warning("liquidity unavailable; keeping the announced amounts")
            self._liquidity_failing = True
        else:
            self._liquidity_failing = False
        return cap.bands()

    async def _announce(self, epochs: tuple[str, ...], now: int) -> None:
        policy, state = self._policy, self._state
        bands = await self._liquidity_bands()
        if not bands:
            if state.bands:
                LOG.warning("liquidity below every amount band; not announcing until it recovers")
            # The last announcement expires by itself; quotes refuse every amount
            # meanwhile. Look again at the next scheduled refresh.
            state.bands, state.announcement, state.republish = (), None, False
            state.announced_keys, state.announced_at = epochs, now
            return
        try:
            self._store.record_announcement(now)  # durable ordering before publication
        except StaleOwnerError:
            raise
        except LiveSessionStoreError:
            LOG.warning("announcement skipped: revision would not increase")
            return
        state.announcement = self._identity.build_announcement(
            AnnouncementTerms(
                network=policy.network,
                profiles=policy.profiles,
                amount_bands=bands,
                base_fee_sat=policy.base_fee_sat,
                proportional_millionths=policy.proportional_millionths,
                transport_endpoints=policy.relay_urls,
                epoch_inbox_xonly_keys=epochs,
                slot=policy.slot,
                created_at=now,
                expires_at=now + policy.announcement_lifetime,
                evm_assets=policy.evm_assets,
                transport_pow_bits=policy.transport_pow_bits,
                funding_confirmations=policy.funding_confirmations,
                fee_policy=policy.fee_policy,
            )
        )
        if bands != state.bands:
            LOG.info("announcing amount bands %s", bands)
        state.bands = bands
        state.announced_keys, state.announced_at = epochs, now
        state.announcement_expires = now + policy.announcement_lifetime
        state.republish = True

    async def _resubscribe(self, relays: Sequence[Relay]) -> None:
        filters = self._filters()
        wanted = tuple(sorted(key for group in filters for key in group["#p"]))
        groups = tuple(
            (tuple(group["#p"]), group["since"] if index else None)
            for index, group in enumerate(filters)
        )
        # A full per-relay ingress queue drops a wrapper without closing its
        # socket. Re-REQ the same filter to replay relay history; inbox/outbox
        # admission is idempotent. Snapshot counters before REQ so another drop
        # during publication triggers another bounded retry on the next tick.
        observed: dict[int, tuple[Relay, int]] = {}
        for relay in relays:
            count = getattr(relay, "dropped_events", 0)
            observed[id(relay)] = (relay, count if type(count) is int and count >= 0 else 0)
        lost = []
        for relay in relays:
            previous = self._state.relay_drops.get(id(relay))
            seen = previous[1] if previous is not None and previous[0] is relay else 0
            if observed[id(relay)][1] > seen:
                lost.append(relay)
        if lost:
            LOG.warning("relay inbound queue overflow; replay subscription requested")
        refresh_all = groups != self._state.replay_groups or self._state.retry_subscription
        if refresh_all or lost:
            targets = relays if refresh_all else lost
            results = await asyncio.gather(
                *(self.subscribe(relay) for relay in targets), return_exceptions=True
            )
            if any(isinstance(result, BaseException) for result in results):
                self._state.retry_subscription = True  # retry even if the filter is empty
                return
            self._state.subscribed = wanted
            self._state.replay_groups = groups
            self._state.retry_subscription = False
        self._state.relay_drops = observed  # prune disconnected connection IDs

    async def _send_pending(self, message_id: str, relays: Sequence[Relay]) -> None:
        self._state.attempts[message_id] = self._now()
        requires_live = self._store.pending_requires_live_cooperation(message_id)

        def service_available() -> bool:
            return not requires_live or (not self._readiness_closed and self._deadline_healthy)

        if requires_live is None or not service_available():
            self._state.urgent_until.pop(message_id, None)
            return
        now = self._deadline_now()
        tip: int | None = None
        readiness = next(
            (probe for probe in self._readiness_probes.values() if probe.request_id == message_id),
            None,
        )
        if not self._store.pending_sendable(message_id, now=now):
            tip = await self._sample_tip()
            if tip is None:
                # No independent tip, so no proposal disclosure. Keep the
                # underlying RPC single-flight if the waiter merely timed out.
                return
            if not self._pending_sendable(message_id, tip=tip, readiness=readiness):
                return
        if not service_available():
            return
        wrap = self._store.wrap_pending(message_id, transport=self._transport)
        if not self._pending_sendable(message_id, tip=tip, readiness=readiness):
            return  # arbitration may have closed before wrapping finished
        if not service_available():
            return
        urgent = self._deadline_now() < self._state.urgent_until.get(message_id, 0)
        if not await self._publish(
            wrap,
            relays,
            budget_seconds=URGENT_RETRY_SECONDS if urgent else None,
            before_send=lambda: (
                service_available()
                and self._pending_sendable(message_id, tip=tip, readiness=readiness)
            ),
        ):
            LOG.warning("outbox wrap not accepted by any relay; will retry")

    def _pending_sendable(
        self, message_id: str, *, tip: int | None, readiness: ReadinessChallenge | None
    ) -> bool:
        now = self._deadline_now()
        if readiness is not None:
            return self._store.pending_sendable(
                message_id, now=now, tip_height=tip, readiness=readiness
            )
        return self._store.pending_sendable(message_id, now=now, tip_height=tip)

    def _first_sight(self, event: bytes) -> bool:
        try:
            event_id = json.loads(event)["id"]
        except (ValueError, KeyError, TypeError):
            return False
        seen = self._state.seen
        if type(event_id) is not str or event_id in seen:
            return False
        seen[event_id] = None
        if len(seen) > MAX_SEEN_EVENTS:
            seen.popitem(last=False)
        return True

    def _defer(self, session_id: str, event: bytes, now: int) -> None:
        """Hold one frame that reached its session before the confirm (bounded)."""
        state = self._state
        event_id = json.loads(event)["id"]
        self._purge_deferred(now)
        # Forget the sighting, so a relay replay can bring back a dropped frame.
        state.seen.pop(event_id, None)
        if any(held[1] == event_id for held in state.deferred):
            return
        mine = [held for held in state.deferred if held[0] == session_id]
        if len(mine) >= MAX_DEFERRED_PER_SESSION:
            state.deferred.remove(mine[0])
        elif len(state.deferred) >= MAX_DEFERRED_EVENTS:
            del state.deferred[0]
        state.deferred.append((session_id, event_id, now, event))

    def _purge_deferred(self, now: int) -> None:
        timeout = self._policy.handshake_timeout
        self._state.deferred = [held for held in self._state.deferred if now - held[2] < timeout]

    async def _handle_deferred(self, session_id: object, relays: Sequence[Relay]) -> None:
        """Handle the frames held for a session whose confirm was just admitted."""
        state = self._state
        held = [frame for frame in state.deferred if frame[0] == session_id]
        if not held:
            return
        state.deferred = [frame for frame in state.deferred if frame[0] != session_id]
        for _, _, _, event in held:
            disposition = await self._handle_contained(event, relays)
            LOG.log(_disposition_level(disposition), "deferred relay event: %s", disposition)

    async def _handle_contained(self, event: bytes, relays: Sequence[Relay]) -> str:
        """``handle`` for the serving loop: one bad event cannot stop every session.

        Ownership loss still stops the service. Any other failure drops the
        event and is logged by type only, keeping event content out of logs.
        """
        try:
            return await self.handle(event, relays)
        except StaleOwnerError:
            raise
        except Exception as error:  # noqa: BLE001 - deadline supervision must outlive one event
            LOG.warning("relay event failed: %s", type(error).__name__)
            return "failed"

    async def handle(self, event: bytes, relays: Sequence[Relay]) -> str:  # noqa: PLR0911, PLR0912, PLR0915 - one disposition per outcome
        """Route one untrusted relay event; return a content-free disposition."""
        if not self._deadline_healthy or self._readiness_closed:
            return "unavailable"  # do not mark as seen; replay is safe after restart
        if not self._has_work(event):
            return "insufficient-work"  # before the seen cache, so junk cannot evict it
        if not self._first_sight(event):
            return "duplicate"
        store = self._store
        try:
            try:
                document = store.open_mailbox_frame(event, transport=self._transport)
            except StaleOwnerError:
                raise
            except LiveSessionStoreError:
                document = None
            now = self._now()
            if document is not None:
                message_type = json.loads(document).get("message_type")
                if message_type == "handshake_confirm":
                    try:
                        admitted = store.admit_confirm(document, now=now)
                    except (StaleOwnerError, SessionBlockedError, SessionExpiredError):
                        raise
                    except LiveSessionStoreError:
                        # Not a valid confirm: classify it like any signed message,
                        # so reusing an admitted sequence is still a conflict.
                        return await self._answer(document, relays, now)
                    await self._resubscribe(relays)
                    await self._handle_deferred(json.loads(document).get("session_id"), relays)
                    return "confirm-replay" if admitted.replay else "confirm-admitted"
                if message_type == "action_result":
                    envelope = json.loads(document)
                    payload = envelope.get("payload")
                    if (
                        isinstance(payload, dict)
                        and payload.get("action") == "cooperative_claim_ready"
                    ):
                        disposition = await self._admit_ready_result(
                            document, envelope.get("session_id")
                        )
                        if disposition == "readiness-prepared":
                            # The proposal shares the echo's short window; a
                            # tick-later send would usually miss it.
                            await self._send_fresh_outbox(relays)
                        return disposition
                    result = store._admit_cooperative_result(document, now=now)  # noqa: SLF001 - store-owned admission; no signer or reply
                    if (
                        self._settlement is not None
                        and result.status == "signed"
                        and not result.replay
                    ):
                        try:
                            self._live_cooperative_now()
                            # Admission authenticated and context-checked this
                            # exact document. IDs are lookup keys, not authority.
                            await self._settlement.complete_cooperative_claim(
                                result.session_id,
                                bytes.fromhex(payload["cooperation_id"]),
                                now=self._live_cooperative_now,
                            )
                        except StaleOwnerError:
                            raise
                        except Exception:  # noqa: BLE001 - durable admission survives uncertain completion; never retry
                            LOG.warning(
                                "cooperative completion stopped for %s", result.session_id[:16]
                            )
                        else:
                            # Deliver the completion before the shared deadline.
                            await self._send_fresh_outbox(relays)
                    return "result-replay" if result.replay else "result-admitted"
                if message_type == "action_request" and self._policy.profile == "ln-to-btc/v1":
                    payload = json.loads(document).get("payload")
                    if (
                        isinstance(payload, dict)
                        and payload.get("action") == "cooperative_claim_propose"
                    ):
                        return await self._cosign_reverse_proposal(document, relays)
                    if (
                        isinstance(payload, dict)
                        and payload.get("action") == "cooperative_claim_complete"
                    ):
                        return await self._verify_reverse_completion(document, relays, now)
                session_id = json.loads(document).get("session_id")
                if type(session_id) is str and store.session_awaiting_confirm(session_id) is True:
                    # Relays deliver stored wraps by randomized created_at, so a
                    # replay can bring the first request before its confirm.
                    self._defer(session_id, event, now)
                    return "deferred"
                return await self._answer(document, relays, now)
            init = store.open_epoch_frame(event, now=now, transport=self._transport)
            if not self._declares_work(init.document):
                return "refused"
            reserved = store.reserve(init, now=now)
            if reserved.revision != 0:
                return "init-replay"  # outbox retries own any re-send
            committed = store.create_accept(
                reserved.session_id,
                identity=self._identity,
                transport_endpoints=self._policy.relay_urls,
            )
            # Listen on the new mailbox before the accept can reach the client:
            # each relay then sees our REQ before the accept on this socket, so
            # the confirm and first request usually arrive live and in order.
            await self._resubscribe(relays)
            await self._send_pending(committed.message_id, relays)
        except StaleOwnerError:
            raise  # ownership lost: never keep acting on this store
        except SessionBlockedError:
            return "blocked"
        except SessionExpiredError:
            return "expired"
        except LiveSessionStoreError:
            return "refused"
        return "init-accepted"

    def _firm_signer(self) -> FirmSigner | None:
        script = self._policy.provider_destination_script
        if self._invoice_decoder is None or (
            script is None and self._policy.profile not in EVM_PROFILES
        ):
            return None
        return FirmSigner(
            network=self._policy.network,
            provider_identity_key=self._identity.xonly_public_key,
            provider_destination_script=script,
            sign=self._identity.sign_provider_terms,
        )

    async def _decode_invoice(self, document: bytes) -> InvoiceOutcome:
        """Decode a firm request's invoice, only for a new first request."""
        envelope = json.loads(document)
        payload = envelope.get("payload")
        if (
            self._invoice_decoder is None
            or envelope.get("message_type") != "quote_request"
            or envelope.get("sequence") != FIRST_REQUEST_SEQUENCE
            or not isinstance(payload, dict)
            or payload.get("mode") != "firm"
            or not isinstance(payload.get("invoice"), str)
            or self._store.classify_request(document) != "new"
        ):
            return None
        try:
            return await asyncio.to_thread(self._invoice_decoder, payload["invoice"])
        except InvoiceRejectedError:
            return "rejected"
        except Exception:  # noqa: BLE001 - an unavailable backend only defers firm quotes
            LOG.warning("invoice decoding unavailable; firm quote answered capacity_unavailable")
            return "unavailable"

    async def _open_hold(
        self, document: bytes, terms: QuoteTerms, *, operation: ReverseOperation
    ) -> HoldOutcome:
        """Open the hold invoice for a new LN to BTC firm request (RS-004).

        Runs before the store transaction, like invoice decoding. The invoice
        is for exactly ``H`` at this payout with the schedule's final CLTV, so
        the offer can bind its decoding. Cleanup requires positive committed
        refusal evidence; unknown admission outcomes leave the invoice intact.
        An unavailable backend only defers.
        """
        operation.check()
        envelope = json.loads(document)
        payload = envelope.get("payload")
        if (
            self._hold_invoices is None
            or self._invoice_decoder is None
            or terms.firm is None
            or terms.profile not in REVERSE_PROFILES
            or envelope.get("message_type") != "quote_request"
            or envelope.get("sequence") != FIRST_REQUEST_SEQUENCE
            or not isinstance(payload, dict)
            or payload.get("mode") != "firm"
            or self._store.classify_request(document) != "new"
        ):
            return None
        try:
            request = parse_quote_request(canonicalize(payload))
        except ValueError:
            return None  # the quote rules answer request_unacceptable
        if isinstance(request, ReverseFirmQuoteRequest):
            value_msat = hold_invoice_msat(terms, request)  # None: unquotable now
        elif isinstance(request, LnToErc20FirmQuoteRequest):
            value_msat = ln_to_erc20_hold_msat(terms, request)  # None: unquotable now
        else:
            return None
        if (
            value_msat is None
            or self._store.payment_hash_reserved(request.payment_hash)
            or not self._store.firm_capacity_available()
            or (
                isinstance(request, ReverseFirmQuoteRequest)
                and not await self._can_fund(
                    value_msat // 1000 - success_fee(terms, int(request.nominal_payout_sat)), terms
                )
            )
        ):
            return None  # refused without opening anything
        hold_invoices, decoder, schedule = (
            self._hold_invoices,
            self._invoice_decoder,
            terms.schedule,
        )
        try:
            bolt11 = await operation.worker(
                lambda: hold_invoices.add(
                    request.payment_hash,
                    value_msat=value_msat,
                    expiry_seconds=schedule.hold_invoice_lifetime,
                    cltv_expiry_delta=schedule.incoming_htlc_expiry_delta_blocks,
                )
            )
            binding = await operation.worker(lambda: decoder(bolt11))
        except LiveSessionStoreError:
            raise
        except Exception as error:  # noqa: BLE001 - an unavailable backend only defers
            LOG.warning(
                "hold invoice unavailable (%s); firm quote answered capacity_unavailable",
                type(error).__name__,
            )
            return "unavailable"
        return (bolt11, binding)

    async def _can_fund(self, contract_sat: int, terms: QuoteTerms) -> bool:
        """Whether the funding wallet now covers the contract and its maximum funding fee.

        Liquidity moves between announcements. A refusal here costs the client
        one quote, while a hold invoice the provider cannot fund holds the
        client's payment until it is canceled. Only a known shortfall refuses:
        without a source, or while the balance cannot be read (e.g. an
        ``rpcwhitelist`` without ``getbalances``), quotes are admitted as before.
        """
        source = self._liquidity
        if source is None:
            return True
        try:
            balance = await asyncio.wait_for(
                asyncio.to_thread(source), FUNDING_BALANCE_WAIT_SECONDS
            )
        except Exception as error:  # noqa: BLE001 - unknown is not a shortfall
            if not self._funding_balance_failing:
                LOG.warning(
                    "funding balance unavailable (%s); firm quotes not checked against it",
                    type(error).__name__,
                )
            self._funding_balance_failing = True
            return True
        self._funding_balance_failing = False
        if balance < contract_sat + terms.schedule.max_funding_fee_sat:
            LOG.warning("funding wallet cannot cover the request; answered capacity_unavailable")
            return False
        return True

    def _matching_unused_hold(  # noqa: PLR0911 - each failed proof independently forbids cleanup
        self,
        document: bytes,
        answer: RequestAnswer,
        hold: HoldOutcome,
        *,
        operation: ReverseOperation,
    ) -> bool:
        """Require owned committed refusal, not absence or replay classification.

        ADD must have returned a newly created invoice for this operation.
        The owned outbox supplies authenticity, not a new signing grant. Message
        IDs are nonces: consistency means matching IDs and canonical bytes, not
        deriving a new hash-based ID. Missing/delivered evidence proves nothing.
        """
        operation.check()
        if not isinstance(hold, tuple):
            return False
        # Ownership/transaction failures remain fatal, outside the parser guard.
        pending = self._store.pending_outbox()
        try:
            original = parse_model_json(Envelope, document)
            if (
                original.session_id != answer.session_id
                or original.message_id != answer.request_message_id
                or original.message_type != "quote_request"
                or original.sequence != FIRST_REQUEST_SEQUENCE
                or original.profile_id not in REVERSE_PROFILES
                or original.network_identity != self._policy.network
            ):
                return False
            request = parse_quote_request(canonicalize(original.payload))
            if not isinstance(request, ReverseFirmQuoteRequest | LnToErc20FirmQuoteRequest) or (
                request.payment_hash != hold[1].payment_hash
            ):
                return False
            matches = [entry for entry in pending if entry.message_id == answer.response_message_id]
            if len(matches) != 1:
                return False
            entry = matches[0]
            response = parse_model_json(Envelope, entry.canonical_bytes)
            if (
                canonical_model(response) != entry.canonical_bytes
                or entry.session_id != answer.session_id
                or response.session_id != answer.session_id
                or response.message_id != answer.response_message_id
                or response.in_reply_to != answer.request_message_id
                or response.profile_id not in REVERSE_PROFILES
                or response.network_identity != self._policy.network
                or response.contract_hash is not None
                or response.signature is None
                or response.message_type != "error"
            ):
                return False
            QuoteError.model_validate(response.payload, strict=True)
        except Exception:  # noqa: BLE001 - inconsistent owned bytes grant no destructive cleanup
            return False
        operation.check()
        return True

    async def _cancel_hold(self, hold: HoldOutcome, *, operation: ReverseOperation) -> None:
        operation.check()
        if not isinstance(hold, tuple) or self._hold_invoices is None:
            return
        hold_invoices, payment_hash = self._hold_invoices, hold[1].payment_hash
        try:
            await operation.worker(lambda: hold_invoices.cancel(payment_hash))
        except LiveSessionStoreError:
            raise
        except Exception as error:  # noqa: BLE001 - the invoice expires on its own
            LOG.warning("unused hold invoice not canceled (%s)", type(error).__name__)

    async def _route_ready(  # noqa: PLR0911 - one closed rule per branch
        self, document: bytes, terms: QuoteTerms
    ) -> QuoteTerms:
        """Offer firm terms only when settlement could pay this invoice now."""
        binding, tip = terms.invoice, terms.tip_height
        settlement = self._settlement if self._settlement is not None else self._evm_settlement
        if (
            terms.firm is None
            or not isinstance(binding, InvoiceBinding)
            or settlement is None
            or tip is None
        ):
            return terms
        principal = int(binding.amount_msat) // 1000
        if not any(low <= principal <= high for low, high in terms.amount_bands):
            return terms  # the quote rules refuse this without asking for a route
        if not self._store.firm_capacity_available():
            return terms  # already full: the quote rules refuse without a route query
        try:
            routing_limits = (
                {}
                if terms.fee_policy is None
                else {
                    "routing_fee_limit_sat": min(
                        terms.fee_policy.service_fee(principal),
                        principal * terms.fee_policy.max_routing_fee_ppm // 1_000_000,
                    )
                }
            )
            await asyncio.to_thread(
                lambda: settlement.route_ready(
                    json.loads(document)["payload"]["invoice"],
                    invoice_binding=binding,
                    # Undiscounted: a rebate never shrinks what routing may cost.
                    success_fee_sat=normal_success_fee(terms, principal),
                    max_expiry_height=tip + terms.schedule.outgoing_cltv_budget_blocks,
                    **routing_limits,
                )
            )
        except InvoiceRejectedError:
            return replace(terms, invoice="rejected")
        except LndObservationError as error:  # fixed, non-secret adapter messages
            LOG.warning(
                "no payable route now (%s); firm quote answered capacity_unavailable", error
            )
            return replace(terms, invoice="unavailable")
        except Exception as error:  # noqa: BLE001 - any readiness failure only defers
            LOG.warning(
                "route readiness failed (%s); firm quote answered capacity_unavailable",
                type(error).__name__,
            )
            return replace(terms, invoice="unavailable")
        return terms

    async def _dynamic_pricing(self, now: int) -> DynamicPricing | None:
        """Return this request's balance evidence, or None to price the normal fee."""
        limits, sample = self._policy.dynamic_fees, self._liquidity_sample
        if limits is None or sample is None:
            return None
        try:
            liquidity = await asyncio.wait_for(
                asyncio.to_thread(sample), timeout=PRICING_SAMPLE_WAIT_SECONDS
            )
            commitments = self._store.pricing_commitments(now)
        except Exception as error:  # noqa: BLE001 - unknown balances grant no discount
            LOG.warning("balance pricing unavailable (%s)", type(error).__name__)
            return None
        if liquidity is None or commitments.open_volume_sat is None:
            return None
        return DynamicPricing(
            limits, liquidity, commitments.open_volume_sat, commitments.rebates_committed_sat
        )

    async def _network_pricing(self, document: bytes, terms: QuoteTerms) -> QuoteTerms:
        """Freeze one independently bounded fee sample before any hold is opened."""
        policy = terms.fee_policy
        if policy is None or self._claim_fee is None:
            return terms
        try:
            request = parse_quote_request(canonicalize(json.loads(document)["payload"]))
            binding = parse_fee_request(request.extensions)
            if binding is None or binding.policy_hash != policy.commitment():
                return terms
            if request.kind == "btc-to-ln":
                principal = int(request.lightning_principal_sat)
            elif request.kind == "ln-to-btc":
                principal = int(request.nominal_payout_sat)
            else:
                raise ValueError("Bitcoin profile required for network fees")  # noqa: TRY301
            sampled_at = max(terms.now, self._deadline_now())
            fee = await asyncio.wait_for(
                asyncio.to_thread(self._claim_fee), timeout=CLAIM_FEE_WAIT_SECONDS
            )
            rate = max(fee.rate_sat_kvb, fee.floor_sat_kvb)
            if rate > min(
                int(policy.max_network_feerate_sat_kvb),
                int(binding.max_network_feerate_sat_kvb),
            ):
                return terms
            issued_at = max(sampled_at, self._deadline_now())
            service = policy.service_fee(principal)
            if terms.dynamic is not None:  # a discount, never above the committed policy
                service = terms.dynamic.service_fee(
                    profile=terms.profile, normal_fee_sat=service, principal_sat=principal
                )
            breakdown = FeeBreakdown(
                offer_event_id=binding.offer_event_id,
                policy=policy,
                feerate_sat_kvb=str(rate),
                estimated_at=sampled_at,
                issued_at=issued_at,
                service_fee_sat=str(service),
                network_fee_sat=str(-(-NETWORK_FEE_VBYTES * rate // 1000)),
            )
            spend_cap = (
                terms.schedule.max_claim_fee_sat
                if request.kind == "btc-to-ln"
                else terms.schedule.max_funding_fee_sat
            )
            if int(breakdown.network_fee_sat) > spend_cap:
                return terms
        except Exception as error:  # noqa: BLE001 - failures grant no hold or pricing authority
            LOG.warning("network fee quote unavailable (%s)", type(error).__name__)
            return terms
        return replace(terms, now=issued_at, fee_breakdown=breakdown)

    async def _prepare_answer(
        self,
        document: bytes,
        now: int,
        *,
        operation: ReverseOperation | None,
    ) -> tuple[RequestAnswer, list[str]]:
        """Own reverse hold creation, committed disposition, and proven cleanup.

        Exceptions provide no rollback certificate. Leave any possibly committed
        invoice intact and preserve the original error, then drain the operation.
        Expiry limits payment eligibility, not LND's historical record storage.
        """
        policy = self._policy
        if operation is not None:
            now = max(now, self._deadline_now())
        invoice = await self._decode_invoice(document)
        terms = QuoteTerms(
            amount_bands=self._state.bands,  # exactly what was last announced
            base_fee_sat=policy.base_fee_sat,
            proportional_millionths=policy.proportional_millionths,
            schedule=policy.quote,
            tip_height=self._state.tip,
            now=now,
            firm=self._firm_signer(),
            invoice=invoice,
            profile=policy.profile,
            claim_fee=self._state.claim_fee,
            fee_policy=policy.fee_policy,
        )
        if policy.profile in EVM_PROFILES:
            evm = self._evm_settlement
            terms = replace(
                terms, evm=await asyncio.to_thread(evm.quote_context) if evm is not None else None
            )
        terms = replace(terms, dynamic=await self._dynamic_pricing(now))
        terms = await self._network_pricing(document, terms)
        pricing_ready = policy.fee_policy is None or terms.fee_breakdown is not None
        if pricing_ready:
            terms = await self._route_ready(document, terms)
        if operation is not None and pricing_ready:
            terms = replace(terms, hold=await self._open_hold(document, terms, operation=operation))
        # Core/LND preparation can consume wall time; it cannot reserve an old
        # timestamp or renew a request's existing signed deadline.
        if operation is not None or policy.fee_policy is not None:
            now = max(now, self._deadline_now())
            terms = replace(terms, now=now)
        sent: list[str] = []

        def responder(
            request: Envelope, prior: tuple[Envelope, ...], context: RequestContext
        ) -> Answer:
            answer = answer_client_request(request, prior, context, terms, self._transport)
            sent.append(answer.message_type)
            if (
                answer.message_type == "error"
                and answer.payload.get("code") == "capacity_unavailable"
                and not context.economic_capacity_available
            ):
                LOG.warning(
                    "max_active_reservations reached; firm quote answered capacity_unavailable"
                )
            return answer

        if operation is not None:
            operation.check()
        answer = self._store.answer_request(
            document, responder=responder, signer=self._transport, now=now
        )
        if (
            operation is not None
            and sent != ["terms_offer"]
            and self._matching_unused_hold(document, answer, terms.hold, operation=operation)
        ):
            await self._cancel_hold(terms.hold, operation=operation)
        return answer, sent

    async def _cosign_reverse_proposal(self, document: bytes, relays: Sequence[Relay]) -> str:
        """Cosign one LN to BTC claim proposal, or refuse without any reply.

        Refusal is safe for the client: it disclosed the preimage only to
        claim, and keeps its independent unilateral claim path.
        """
        settlement = self._settlement
        if settlement is None:
            return "refused"
        try:
            reply = await settlement.cosign_reverse_proposal(
                document, now=self._live_cooperative_now()
            )
        except StaleOwnerError:
            raise
        except Exception as error:  # noqa: BLE001 - no proposal, preimage, or backend oracle
            # The class only, for the operator; the client still gets no reply.
            LOG.warning("reverse cooperative proposal refused (%s)", type(error).__name__)
            return "refused"
        if reply is None:
            return "proposal-replay"
        response = Envelope.model_validate_json(reply, strict=True)
        self._remember_urgent(document, response.message_id, session_id=response.session_id)
        await self._send_pending(response.message_id, relays)
        return "proposal-signed"

    async def _verify_reverse_completion(
        self, document: bytes, relays: Sequence[Relay], now: int
    ) -> str:
        """Deliver an archived verification receipt, not new cooperative authority."""
        if self._settlement is None:
            return "refused"
        try:
            answer = await self._settlement.verify_reverse_completion(document, now=now)
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - no transcript or signature oracle
            LOG.warning("reverse cooperative completion refused")
            return "refused"
        await self._send_pending(answer.response_message_id, relays)
        return "completion-replay" if answer.replay else "completion-verified"

    async def _answer(self, document: bytes, relays: Sequence[Relay], now: int) -> str:
        policy = self._policy
        if policy.profile in REVERSE_PROFILES:
            async with self._store.reverse_operations.operation() as operation:
                answer, sent = await self._prepare_answer(document, now, operation=operation)
        else:
            answer, sent = await self._prepare_answer(document, now, operation=None)
        # Relay delivery and independent unilateral supervision do not own the
        # reverse economic gate. Committed payable terms never become cleanup.
        if not answer.replay and sent == ["ack"] and self._settlement is not None:
            request = Envelope.model_validate_json(document, strict=True)
            digest = request.contract_hash
            if digest is not None and request.message_type == "terms_accept":
                if self._store.admitted_featured_claim(request.session_id, digest):
                    self._fresh_featured_accepts[request.session_id] = digest
            elif digest is not None and request.message_type == "funding_binding":
                fresh = self._fresh_featured_accepts.pop(request.session_id, None)
                if fresh == digest and self._settlement.register_new_featured_session(
                    request.session_id, digest
                ):
                    self._probe_supervision_needed = True
        # A replay re-sends the recorded answer (RS-001 stable replay).
        await self._send_pending(answer.response_message_id, relays)
        return "request-replay" if answer.replay else "request-answered"

    def _start_deadline_supervision(  # noqa: PLR0915 - one supervisor owns selection and dispatch
        self, stop: asyncio.Event
    ) -> tuple[set[asyncio.Task[None]], asyncio.Task[None] | None]:
        """Recover before relay admissions; never wait for a Core RPC on a deadline."""
        settlement = self._settlement
        if settlement is None:
            return set(), None
        # Acquisition closes old WAITING rows, but never broadcasts them. Do
        # not admit a new relay request before valid old-owner fallback bundles
        # have been selected. Submission runs separately from relay/tick I/O.
        broadcasts: set[asyncio.Task[None]] = set()
        in_flight: set[tuple[str, str]] = set()
        retry_after: dict[tuple[str, str], float] = {}
        probe_in_flight: set[str] = set()
        probe_retry_after: dict[str, float] = {}
        height_evidence: tuple[int, float] | None = None

        def unhealthy() -> None:
            self._deadline_healthy = False
            settlement.disable_new_exposure()

        # This lane requires real durable custody; lightweight service fakes
        # exercise the older fallback lanes without pretending to be SQLite.
        unilateral_custody = isinstance(self._store, LiveSessionStore)

        def dispatch(
            candidate: PreparedFallback | CooperativeWinner | RecordedUnilateralClaim,
        ) -> None:
            key = (candidate.session_id, candidate.txid)
            if key in in_flight or time.monotonic() < retry_after.get(key, 0):
                return
            in_flight.add(key)
            retry_after[key] = time.monotonic() + 15
            task = asyncio.create_task(
                settlement.broadcast_cooperative_winner(candidate)
                if isinstance(candidate, CooperativeWinner)
                else (
                    settlement.broadcast_recorded_unilateral(candidate)
                    if isinstance(candidate, RecordedUnilateralClaim)
                    else settlement.broadcast_selected_fallback(candidate)
                )
            )
            broadcasts.add(task)

            def complete(done: asyncio.Task[None]) -> None:
                broadcasts.discard(done)
                in_flight.discard(key)
                if not done.cancelled() and done.exception() is not None:
                    LOG.warning("fallback submission task failed for %s", key[0][:16])

            task.add_done_callback(complete)

        def dispatch_recorded_unilateral() -> None:
            if unilateral_custody:
                for claim in settlement.recorded_unilateral_claims():
                    dispatch(claim)

        def recover_probe(window: ClaimProbeWindow) -> None:
            session_id = window.session_id
            if session_id in probe_in_flight or time.monotonic() < probe_retry_after.get(
                session_id, 0
            ):
                return
            probe_in_flight.add(session_id)
            probe_retry_after[session_id] = time.monotonic() + 1
            task = asyncio.create_task(
                settlement.recover_expired_probe(window, self._deadline_now())
            )
            broadcasts.add(task)

            def complete(done: asyncio.Task[None]) -> None:
                broadcasts.discard(done)
                probe_in_flight.discard(session_id)
                if not done.cancelled() and done.exception() is not None:
                    LOG.warning("due claim probe recovery deferred for %s", session_id[:16])

            task.add_done_callback(complete)

        try:
            for candidate in settlement.select_due_fallbacks(
                self._deadline_now(), closed_only=True
            ):
                dispatch(candidate)
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - selected rows remain discoverable below
            unhealthy()
            LOG.warning("startup fallback selection deferred; admissions disabled")
        try:
            for winner in settlement.recover_cooperative_winners(self._deadline_now()):
                dispatch(winner)
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - recover again in the deadline loop
            unhealthy()
            LOG.warning("startup cooperative winner recovery deferred; admissions disabled")
        if unilateral_custody:
            try:
                dispatch_recorded_unilateral()
            except StaleOwnerError:
                raise
            except Exception:  # noqa: BLE001 - startup dispatch is retried independently
                unhealthy()
                LOG.warning("startup unilateral discovery deferred; admissions disabled")

        async def sample_height() -> None:
            """Keep Core lookups off the wall-clock selection path."""
            nonlocal height_evidence
            while not stop.is_set():
                try:
                    if settlement.has_current_waiting_claim():
                        tip, started = await self._fresh_tip_evidence()
                        height_evidence = (
                            (tip, started)
                            if tip is not None and tip > 0 and started is not None
                            else None
                        )
                    else:
                        height_evidence = None
                except Exception:  # noqa: BLE001 - no stale height can authorize selection
                    height_evidence = None
                with suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=0.25)

        if self._chain_tip is not None:
            broadcasts.add(asyncio.create_task(sample_height()))

        async def supervise() -> None:
            while not stop.is_set():
                try:
                    self._expire_readiness()
                    self._store.reconcile_expired_cooperative_proposals(self._deadline_now())
                    if self._probe_supervision_needed:
                        for window in settlement.expired_probe_windows():
                            recover_probe(window)
                    current = height_evidence
                    height = (
                        current[0]
                        if current is not None
                        and time.monotonic() - current[1] < TIP_LOOKUP_WAIT_SECONDS
                        else None
                    )
                    due = (
                        settlement.select_due_fallbacks(self._deadline_now())
                        if height is None
                        else settlement.select_due_fallbacks(self._deadline_now(), height=height)
                    )
                    for candidate in due:
                        dispatch(candidate)
                except StaleOwnerError:
                    unhealthy()
                    stop.set()
                    return  # no more writes or submissions from this owner
                except Exception:  # noqa: BLE001 - retry original deadline, never select early
                    unhealthy()
                    LOG.warning("deadline selector unhealthy; retrying without shortening windows")
                try:
                    for candidate in settlement.recorded_fallbacks():
                        dispatch(candidate)
                    for winner in settlement.recover_cooperative_winners(self._deadline_now()):
                        dispatch(winner)
                    for winner in settlement.recorded_cooperative_winners():
                        dispatch(winner)
                    dispatch_recorded_unilateral()
                except StaleOwnerError:
                    unhealthy()
                    stop.set()
                    return
                except Exception:  # noqa: BLE001 - retry recorded claim discovery
                    unhealthy()
                    LOG.warning("recorded fallback discovery unavailable; retrying")
                with suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=0.25)

        return broadcasts, asyncio.create_task(supervise())

    async def run(self, stop: asyncio.Event, *, tick_seconds: float = 15.0) -> None:  # noqa: PLR0915 - one supervised loop owns every relay and duty
        """Serve until ``stop`` is set, reconnecting relays with backoff."""
        broadcasts, deadline_task = self._start_deadline_supervision(stop)
        connected = self._connected
        inbound: asyncio.Queue[bytes] = asyncio.Queue(1024)

        async def maintain(url: str) -> None:
            delay = 1.0
            unavailable = False
            while not stop.is_set():
                try:
                    async with RelayConnection(url, proxy=self._policy.relay_proxy) as connection:
                        connected[url] = connection
                        delay = 1.0
                        await self.subscribe(connection)
                        if unavailable:
                            LOG.info("relay available: %s", url)
                            unavailable = False
                        await inbound.put(_RELAY_CONNECTED)
                        async for event in connection.events():
                            if self._has_work(event):  # drop floods before the queue
                                await inbound.put(event)
                except RelayError:
                    if not unavailable:
                        LOG.warning("relay unavailable: %s", url)
                    unavailable = True
                except Exception:  # noqa: BLE001 - a hostile relay must not end reconnection
                    if not unavailable:
                        LOG.warning("relay connection failed: %s", url)
                    unavailable = True
                finally:
                    connected.pop(url, None)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60.0)

        tasks = [asyncio.create_task(maintain(url)) for url in self._policy.relay_urls]
        try:
            while not stop.is_set():
                try:
                    await self.tick(list(connected.values()))
                except StaleOwnerError:
                    raise  # ownership lost: stop, never act on a fenced store
                except LiveSessionStoreError as error:
                    LOG.warning("tick refused: %s", error)  # e.g. clock behind; keep serving
                deadline = time.monotonic() + tick_seconds
                while not stop.is_set() and (remaining := deadline - time.monotonic()) > 0:
                    event = await _next_or_stop(inbound, stop, min(remaining, URGENT_RETRY_SECONDS))
                    if event is None:
                        await self._retry_urgent(list(connected.values()))
                        continue
                    if event == _RELAY_CONNECTED:
                        self._state.republish = True  # a new relay lacks our announcement
                        break
                    disposition = await self._handle_contained(event, list(connected.values()))
                    LOG.log(_disposition_level(disposition), "relay event: %s", disposition)
                    await self._retry_urgent(list(connected.values()))
        finally:
            self._readiness_closed = True  # fence operations suspended before cleanup awaits
            for task in [*tasks, *broadcasts, *(() if deadline_task is None else (deadline_task,))]:
                task.cancel()
            await asyncio.gather(
                *tasks,
                *broadcasts,
                *(() if deadline_task is None else (deadline_task,)),
                return_exceptions=True,
            )
            self._abandon_readiness()


async def _next_or_stop(
    queue: asyncio.Queue[bytes], stop: asyncio.Event, wait_seconds: float
) -> bytes | None:
    """Return the next item, or None on stop/timeout; never leak waiter tasks."""
    getter = asyncio.ensure_future(queue.get())
    stopper = asyncio.ensure_future(stop.wait())
    try:
        await asyncio.wait(
            {getter, stopper}, timeout=wait_seconds, return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        for waiter in (getter, stopper):
            if not waiter.done():
                waiter.cancel()
        await asyncio.gather(getter, stopper, return_exceptions=True)
    if getter.cancelled() or getter.exception() is not None:
        return None
    return getter.result()
