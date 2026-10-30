"""Regtest BTC to LN swap client over Nostr relays (RS-001, RS-003, RS-005).

One swap, one fresh session: discover and verify the provider announcement,
handshake, request firm terms for the user's invoice, verify them, write the
encrypted recovery file, accept, fund from the local Core wallet, write the
funded recovery snapshot, bind the funding, broadcast, then wait for the
provider's ``payment_settled`` observation and check the preimage.

Every irreversible step is preceded by a durable recovery record: the terms
recovery file exists before acceptance, and the snapshot with the signed
binding exists before the funding transaction is broadcast. If the provider
never pays, the user refunds after ``refund_lock_height`` with
``rill recover watch-refund`` (or ``sign-refund``/``broadcast-refund``).
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import json
import logging
import math
import secrets
import time
from contextlib import asynccontextmanager, contextmanager, suppress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

from rill_core.domain.chain import MAX_EXACT_JSON_INTEGER
from rill_core.recovery import (
    COOPERATIVE_RESERVATION_EXTENSION,
    inspect_recovery_plaintext,
    inspect_recovery_successor,
)
from rill_core.settlement import (
    FundingPlan,
    authorize_funding_transaction,
    reconstruct_taproot_contract,
)
from rill_core.settlement.unilateral import (
    FundingOutput,
    UnilateralAuthorization,
    finalize_cooperative_claim,
    verify_cooperative_claim_proposal,
)
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.cooperative_messages import (
    CooperativeClaimComplete,
    CooperativeClaimPropose,
    CooperativeClaimReadyRequest,
    check_cooperative_action_context,
)
from rill_core.wire.envelope_authentication import verify_static_signed_envelope
from rill_core.wire.fee_policy import (
    FEE_POLICY_EXTENSION,
    BtcFeePolicy,
    FeePolicyRequest,
    parse_fee_policy,
)
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_EXTENSION,
    EPOCH_SESSION_FEATURE,
    FEE_POLICY_FEATURE,
    SUPPORTED_HANDSHAKE_FEATURES,
    client_acceptance_hash,
    contract_hash,
    epoch_bound_session_id,
    funding_binding_hash,
    handshake_accept_hash,
    handshake_hash,
    provider_terms_hash,
    tagged_hash,
    unsigned_envelope_hash,
)
from rill_core.wire.messages import (
    ClientAcceptance,
    Envelope,
    FundingBinding,
    HandshakeAccept,
    HandshakeAcceptPayload,
    HandshakeInit,
)
from rill_core.wire.quotes import (
    FirmQuoteRequest,
    QuoteError,
    QuoteLimits,
    TermsOfferPayload,
    check_terms_offer,
)
from rill_core.wire.settlement_messages import PaymentSettled, parse_observation
from rill_provider import _nip01_event as nip01
from rill_provider import _transport_pow as transport_pow
from rill_provider._nip59_receive import _decode_gift_wrap_candidate
from rill_provider._nip59_send import _wrap_envelope
from rill_provider.core_tx_bytes import CooperativeClaimOutpoint, CooperativeFeePolicy
from rill_provider.diagnostics import diagnostic, diagnostic_context
from rill_provider.provider_identity import (
    ADVERTISEMENT_TAG,
    ANNOUNCEMENT_KIND,
    FUNDING_CONFIRMATIONS_EXTENSION,
)
from rill_provider.settlement_diagnostics import terms_facts

from rill_cli.wallet_rpc import CooperativeClaimEvidence

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator

    from rill_core.settlement.taproot import TaprootKeyOperations
    from rill_core.settlement.unilateral import CooperativeClaimPlan, ValidatedCooperativeClaim
    from rill_core.wire.messages import ContractTerms, InvoiceBinding
    from rill_core.wire.types import NetworkIdentity
    from rill_crypto import Context
    from rill_provider.core_tx_bytes import NextBlockFee

    from rill_cli.live_relay import RelayTransport
    from rill_cli.wallet_rpc import WalletFunding

PROFILE: Literal["btc-to-ln/v1"] = "btc-to-ln/v1"
type ProfileId = Literal["btc-to-ln/v1", "ln-to-btc/v1"]
ENCRYPTION_SUITES = ("noise-xk-secp256k1-chachapoly-sha256/v1",)
CAPABILITIES = ("core/v1", "recovery/v1")
# Handshake features this client negotiates; cooperative claims are always requested.
NEGOTIATED_FEATURES = SUPPORTED_HANDSHAKE_FEATURES
NIP59_BACKDATE_SECONDS = 2 * 24 * 60 * 60
MAX_PROVIDER_SEQUENCE_WINDOW = 16
MAX_PROVIDER_PENDING_BYTES = 256 * 1024
MAX_PROVIDER_MESSAGES = 4096
MAX_PROVIDER_INBOX_MESSAGES = 64
MAX_PROVIDER_INBOX_BYTES = 256 * 1024
GIFT_WRAP_KIND = 1059
MAX_DISCOVERY_EVENTS = 256


class SwapError(RuntimeError):
    """The swap stopped; the message says whether funds were committed."""


class Wallet(Protocol):
    """The user's own Core wallet (``WalletRpc``)."""

    def tip_height(self) -> int:
        """Return the best height."""
        ...

    def new_destination_script(self) -> bytes:
        """Return a fresh refund destination scriptPubKey."""
        ...

    def next_block_fee(self) -> NextBlockFee:
        """Return independent own-node feerate evidence for featured quotes."""
        ...

    def fund(self, script_pubkey: bytes, amount_sat: int, *, fee_rate_sat_vb: int) -> WalletFunding:
        """Return a signed, unbroadcast funding transaction."""
        ...

    def broadcast(self, raw: bytes) -> str:
        """Submit exact bytes."""
        ...

    def observe_cooperative_claim_evidence(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
        allow_regtest_fixed_fee: bool = False,
    ) -> CooperativeClaimEvidence:
        """Read independent own-node outpoint and fee policy at one named tip."""
        ...


@dataclass(frozen=True, slots=True)
class SwapLimits:
    """The user's ceilings for the firm offer."""

    max_success_fee_sat: int
    max_funding_fee_sat: int = 5_000
    max_claim_fee_sat: int = 5_000
    max_refund_fee_sat: int = 5_000
    max_refund_delay_blocks: int = 288
    funding_fee_rate_sat_vb: int = 2
    claim_fee_floor_sat: int = 1

    def validate_cooperative_fee_floor(self) -> None:
        """Refuse unusable local policy before discovery, wallet work, or funding."""
        if (
            type(self.claim_fee_floor_sat) is not int
            or self.claim_fee_floor_sat <= 0
            or type(self.max_claim_fee_sat) is not int
            or self.claim_fee_floor_sat > self.max_claim_fee_sat
        ):
            raise SwapError(
                "cooperative claim fee floor must be a positive integer "
                "within the claim fee ceiling"
            )


@dataclass(frozen=True, slots=True)
class SwapOutcome:
    """A settled swap: the preimage proves the invoice was paid."""

    session_id: str
    contract_hash: str
    funding_txid: str
    payment_preimage: str
    refund_lock_height: int
    cooperation: Literal["not_negotiated", "verified", "abandoned"] = "not_negotiated"
    cooperative_claim_txid: str | None = None


def _scalar(crypto: Context) -> tuple[bytes, bytes]:
    """Return a fresh valid secret scalar and its compressed public key."""
    while True:
        secret = secrets.token_bytes(32)
        try:
            return secret, bytes(crypto.public_key(secret))
        except Exception:  # noqa: BLE001, S112 - out of range, draw again
            continue


def verify_announcement(  # noqa: PLR0913 - explicit trust inputs
    raw: bytes,
    *,
    identity: str,
    network: NetworkIdentity,
    crypto: Context,
    now: int,
    profile: ProfileId = PROFILE,
) -> dict[str, Any]:
    """Return the advertisement of a valid, unexpired announcement or raise."""
    event = nip01._verify_signed_event(raw, verifier=crypto)  # noqa: SLF001
    if event.pubkey != identity or event.kind != ANNOUNCEMENT_KIND:
        raise SwapError("announcement from another key or kind")
    wrapper = json.loads(event.content)
    advertisement = wrapper["advertisement"]
    if type(advertisement.get("revision")) is not int or not (
        0 <= advertisement["revision"] <= MAX_EXACT_JSON_INTEGER
    ):
        raise SwapError("announcement does not offer an exact bounded revision")
    crypto.schnorr_verify(
        bytes.fromhex(identity),
        tagged_hash(ADVERTISEMENT_TAG, canonicalize(advertisement)),
        bytes.fromhex(wrapper["signature"]),
    )
    if (
        advertisement["provider_identity_xonly_key"] != identity
        or network.model_dump(mode="json") not in advertisement["network_identities"]
        or profile not in advertisement["profiles"]
        or not advertisement["created_at"] <= now < advertisement["expires_at"]
        or not advertisement["epoch_inbox_xonly_keys"]
    ):
        raise SwapError("announcement does not offer this swap now")
    _transport_work(advertisement)
    announced_funding_confirmations(advertisement)
    policy = announced_fee_policy(advertisement)
    result = dict(advertisement)
    if policy is not None:
        result["_fee_offer_event_id"] = json.loads(raw)["id"]
    return result


def _extensions(advertisement: dict[str, Any]) -> dict[str, Any]:
    """Return the signed extensions; RS-005 clients ignore keys they do not know.

    A known key must still be well formed: its parser refuses the announcement.
    """
    extensions = advertisement.get("extensions", {})
    if not isinstance(extensions, dict):
        raise SwapError("announcement extensions unsupported")
    return extensions


def announced_fee_policy(advertisement: dict[str, Any]) -> BtcFeePolicy | None:
    """Validate a known fee policy against the advertised service coefficients."""
    policy = parse_fee_policy(_extensions(advertisement))
    if policy is not None:
        indicative = advertisement["indicative_fee_policy"]
        if (
            policy.base_sat != indicative["base_sat"]
            or policy.proportional_millionths != indicative["proportional_millionths"]
            or any(p not in {PROFILE, "ln-to-btc/v1"} for p in advertisement["profiles"])
        ):
            raise SwapError("announcement network fee policy contradicts its service fees")
    return policy


def network_fee_request(
    advertisement: dict[str, Any], *, independent_rate_sat_kvb: int
) -> dict[str, Any]:
    """Bind the selected offer, allowing at most twice our own node's estimate."""
    policy = announced_fee_policy(advertisement)
    if policy is None:
        return {}
    if independent_rate_sat_kvb <= 0:
        raise SwapError("independent network fee estimate unavailable")
    request = FeePolicyRequest(
        offer_event_id=advertisement["_fee_offer_event_id"],
        policy_hash=policy.commitment(),
        max_network_feerate_sat_kvb=str(
            min(int(policy.max_network_feerate_sat_kvb), independent_rate_sat_kvb * 2)
        ),
    )
    return {FEE_POLICY_EXTENSION: request.model_dump(mode="json")}


def announced_funding_confirmations(advertisement: dict[str, Any]) -> int | None:
    """Return the RS-005 announced funding depth, or None when not announced.

    None is unknown, never 0 or 1. Zero is only valid when every listed
    profile is BTC to LN, where only the paying provider takes the risk.
    """
    extensions = _extensions(advertisement)
    if FUNDING_CONFIRMATIONS_EXTENSION not in extensions:
        return None
    value = extensions[FUNDING_CONFIRMATIONS_EXTENSION]
    depth = value.get("confirmations") if isinstance(value, dict) and len(value) == 1 else None
    profiles = advertisement.get("profiles")
    if (
        type(depth) is not int
        or not 0 <= depth <= MAX_EXACT_JSON_INTEGER
        or not isinstance(profiles, list)
        or (depth == 0 and any(profile != PROFILE for profile in profiles))
    ):
        raise SwapError("announcement funding confirmations unsupported")
    return depth


def require_announced_depth(offered: int, advertisement: dict[str, Any]) -> None:
    """Refuse terms waiting more funding confirmations than announced (fewer is fine)."""
    announced = announced_funding_confirmations(advertisement)
    if announced is not None and offered > announced:
        raise SwapError(
            f"terms wait {offered} funding confirmations, more than the announced {announced}"
        )


def _transport_work(advertisement: dict[str, Any]) -> int:
    """Return the RS-006 transport proof of work the provider requires (0: none)."""
    try:
        return transport_pow.requirement(_extensions(advertisement)) or 0
    except transport_pow.TransportWorkError:
        raise SwapError("announcement transport work unsupported") from None


async def discover(  # noqa: PLR0913 - explicit trust inputs
    connection: RelayTransport,
    *,
    identity: str,
    network: NetworkIdentity,
    crypto: Context,
    now: int,
    timeout: float = 10.0,  # noqa: ASYNC109
    profile: ProfileId = PROFILE,
) -> dict[str, Any]:
    """Select the highest valid revision observed during a bounded relay query.

    A relay can withhold announcements; this is not a proof of global freshness.
    Refuse equivocation or a truncated flood rather than accepting the first ad.
    """
    await connection.subscribe([{"kinds": [ANNOUNCEMENT_KIND], "authors": [identity]}])
    best: dict[str, Any] | None = None
    seen = 0
    try:
        async with asyncio.timeout(timeout):
            async for raw in connection.events():
                seen += 1
                if seen > MAX_DISCOVERY_EVENTS:
                    raise SwapError(
                        "provider discovery event limit exceeded; nothing was committed"
                    )
                try:
                    found = verify_announcement(
                        raw,
                        identity=identity,
                        network=network,
                        crypto=crypto,
                        now=now,
                        profile=profile,
                    )
                except Exception:  # noqa: BLE001, S112 - ignore invalid events
                    continue
                if best is not None and found["revision"] == best["revision"] and found != best:
                    raise SwapError("provider announced conflicting data at the same revision")
                if best is None or found["revision"] > best["revision"]:
                    best = found
    except TimeoutError:
        pass
    if best is None:
        raise SwapError("no valid provider announcement found; nothing was committed")
    return best


class _Session:
    """One client session's keys, sequence, and authenticated inbox."""

    def __init__(
        self,
        connection: RelayTransport,
        crypto: Context,
        network: NetworkIdentity,
        *,
        timeout: float,
        profile: ProfileId = PROFILE,
    ) -> None:
        self.connection = connection
        self.crypto = crypto
        self.network = network
        self.timeout = timeout
        self.profile = profile
        self.secret, public = _scalar(crypto)
        self.key = public[1:].hex()
        self.session_id = secrets.token_hex(32)  # replaced by the epoch-bound ID in _handshake
        self.sequence = 0
        self.provider_key: str | None = None
        self.work_bits = 0  # RS-006 transport work declared at initiation, on every send
        self._expected_accept: tuple[Envelope, HandshakeInit, str] | None = None
        self.seen: set[str] = set()
        self.inbox: list[Envelope] = []
        self._inbox_bytes = 0
        self._provider_next = 0
        self._provider_by_id: dict[str, bytes] = {}
        self._provider_by_sequence: dict[int, tuple[str, bytes]] = {}
        self._provider_pending: dict[int, tuple[Envelope, int]] = {}
        self._provider_pending_bytes = 0
        self._settlement_active = False
        self._cooperative_attempt_started = False
        self._publication_guard: Callable[[], None] | None = None

    @asynccontextmanager
    async def settlement_stream(self) -> AsyncIterator[None]:
        """One settlement consumer owns the FIFO even while awaiting effects."""
        if self._settlement_active:
            raise SwapError("original settlement stream already owned")
        self._settlement_active = True
        try:
            yield
        finally:
            self._settlement_active = False

    def envelope(  # noqa: PLR0913 - explicit per-envelope negotiated features
        self,
        message_type: str,
        payload: dict[str, Any],
        *,
        in_reply_to: str | None = None,
        contract: str | None = None,
        signed: bool = True,
        required_features: tuple[str, ...] = (),
    ) -> Envelope:
        unsigned = Envelope.model_validate_json(
            canonicalize(
                {
                    "protocol": "rillswap",
                    "wire_version": "1",
                    "profile_id": self.profile,
                    "network_identity": self.network.model_dump(mode="json"),
                    "session_id": self.session_id,
                    "message_id": secrets.token_hex(32),
                    "sender_session_key": self.key,
                    "sequence": self.sequence,
                    "in_reply_to": in_reply_to,
                    "contract_hash": contract,
                    "message_type": message_type,
                    "payload": payload,
                    "required_features": list(required_features),
                    "extensions": {},
                    "signature": None,
                }
            ),
            strict=True,
        )
        self.sequence += 1
        if not signed:
            return unsigned
        signature = self.crypto.schnorr_sign(
            self.secret, unsigned_envelope_hash(unsigned), secrets.token_bytes(32)
        )
        return unsigned.model_copy(update={"signature": bytes(signature).hex()})

    @contextmanager
    def guard_publication(self, guard: Callable[[], None]) -> Iterator[None]:
        """Fence actual writes, including any transport-owned reconnect waits."""
        previous, self._publication_guard = self._publication_guard, guard
        try:
            yield
        finally:
            self._publication_guard = previous

    async def send(self, envelope: Envelope, recipient: str) -> None:
        before_publish = self._publication_guard
        event = _wrap_envelope(
            canonicalize(envelope.model_dump(mode="json")),
            sender_session_secret=self.secret,
            recipient_xonly_key=recipient,
            crypto=self.crypto,
            work_bits=self.work_bits,
        )
        for _ in range(3):
            if before_publish is not None:
                before_publish()
            guarded = getattr(self.connection, "publish_guarded", None)
            accepted = (
                await guarded(event, before_publish)
                if guarded is not None and before_publish is not None
                else await self.connection.publish(event)
            )
            if accepted:
                return
        raise SwapError(f"relay did not accept {envelope.message_type}")

    async def listen(self) -> None:
        await self.connection.subscribe(
            [
                {
                    "kinds": [GIFT_WRAP_KIND],
                    "#p": [self.key],
                    "since": int(time.time()) - NIP59_BACKDATE_SECONDS,
                }
            ]
        )

    def expect_accept(self, request: Envelope, initiation: HandshakeInit, identity: str) -> None:
        """Do not bind an unsigned accept until its identity signature verifies."""
        if self.provider_key is not None or self._expected_accept is not None:
            raise SwapError("handshake already started")
        self._expected_accept = (request, initiation, identity)

    def _authenticate_initial_accept(self, envelope: Envelope) -> bool:
        """Bind only the identity-authenticated provider session key."""
        if envelope.message_type != "handshake_accept" or self._expected_accept is None:
            return False
        request, initiation, identity = self._expected_accept
        try:
            if (
                envelope.sequence != 0
                or envelope.signature is not None
                or envelope.in_reply_to != request.message_id
                or envelope.contract_hash is not None
                or set(envelope.required_features) - {EPOCH_SESSION_FEATURE}
            ):
                return False
            payload = parse_model_json(HandshakeAcceptPayload, canonicalize(envelope.payload))
            accepted = payload.accept
            accepted.validate_against(initiation, supported_features=NEGOTIATED_FEATURES)
            if accepted.provider_session_xonly_key != envelope.sender_session_key:
                return False
            self.crypto.schnorr_verify(
                bytes.fromhex(identity),
                handshake_accept_hash(accepted),
                bytes.fromhex(payload.provider_identity_signature),
            )
        except Exception:  # noqa: BLE001 - invalid accept cannot establish a provider
            return False
        self.provider_key = envelope.sender_session_key
        self._expected_accept = None
        return True

    def _admit(self, raw: bytes) -> Envelope | None:
        try:
            frame = _decode_gift_wrap_candidate(
                raw,
                recipient_mailbox_secret=self.secret,
                expected_recipient_xonly_key=self.key,
                expected_network=self.network,
                expected_profile_id=self.profile,
                crypto=self.crypto,
            )
        except Exception:  # noqa: BLE001 - not for us or malformed
            return None
        envelope = frame.envelope
        if (
            envelope.session_id != self.session_id
            or frame.seal_author_xonly_key != envelope.sender_session_key
            or (self.provider_key is not None and envelope.sender_session_key != self.provider_key)
        ):
            return None
        if self.provider_key is None:
            if not self._authenticate_initial_accept(envelope):
                return None
        else:
            if envelope.message_type == "handshake_accept":
                return None  # only the first identity-authenticated accept binds the session
            try:
                self.crypto.schnorr_verify(
                    bytes.fromhex(envelope.sender_session_key),
                    unsigned_envelope_hash(envelope),
                    bytes.fromhex(envelope.signature or ""),
                )
            except Exception:  # noqa: BLE001 - unsigned or forged
                return None
        return self._order_provider(envelope)

    def _order_provider(self, envelope: Envelope) -> Envelope | None:
        """Admit authenticated provider bytes only across a contiguous stream."""
        if envelope.message_type == "handshake_accept":
            self.seen.add(envelope.message_id)
            self._provider_by_id[envelope.message_id] = unsigned_envelope_hash(envelope)
            self._provider_by_sequence[0] = (
                envelope.message_id,
                self._provider_by_id[envelope.message_id],
            )
            self._provider_next = 1
            return envelope
        digest = unsigned_envelope_hash(envelope)
        existing_id = self._provider_by_id.get(envelope.message_id)
        existing_sequence = self._provider_by_sequence.get(envelope.sequence)
        if (existing_id is not None and existing_id != digest) or (
            existing_sequence is not None and existing_sequence != (envelope.message_id, digest)
        ):
            raise SwapError("provider signed a conflicting sequence or message ID")
        if existing_id is not None:
            return None  # exact replay cannot repeat a client effect
        if (
            envelope.sequence < self._provider_next
            or envelope.sequence > self._provider_next + MAX_PROVIDER_SEQUENCE_WINDOW
            or len(self._provider_by_id) >= MAX_PROVIDER_MESSAGES
        ):
            raise SwapError("provider sequence outside the bounded live window")
        size = len(canonicalize(envelope.model_dump(mode="json")))
        if envelope.sequence != self._provider_next and (
            len(self._provider_pending) >= MAX_PROVIDER_SEQUENCE_WINDOW
            or self._provider_pending_bytes + size > MAX_PROVIDER_PENDING_BYTES
        ):
            raise SwapError("provider future-message buffer exhausted")
        self.seen.add(envelope.message_id)
        self._provider_by_id[envelope.message_id] = digest
        self._provider_by_sequence[envelope.sequence] = (envelope.message_id, digest)
        if envelope.sequence != self._provider_next:
            self._provider_pending[envelope.sequence] = (envelope, size)
            self._provider_pending_bytes += size
            return None
        self._provider_next += 1
        while pending := self._provider_pending.pop(self._provider_next, None):
            ready, buffered_size = pending
            self._provider_pending_bytes -= buffered_size
            self._buffer_inbox(ready)
            self._provider_next += 1
        return envelope

    def _buffer_inbox(self, envelope: Envelope) -> None:
        """Keep selectively deferred messages within a small process budget."""
        size = len(canonicalize(envelope.model_dump(mode="json")))
        if (
            len(self.inbox) >= MAX_PROVIDER_INBOX_MESSAGES
            or self._inbox_bytes + size > MAX_PROVIDER_INBOX_BYTES
        ):
            raise SwapError("provider live inbox exhausted")
        self.inbox.append(envelope)
        self.inbox.sort(key=lambda item: item.sequence)
        self._inbox_bytes += size

    def _pop_inbox(self, index: int) -> Envelope:
        envelope = self.inbox.pop(index)
        self._inbox_bytes -= len(canonicalize(envelope.model_dump(mode="json")))
        return envelope

    async def receive(
        self,
        wanted: Callable[[Envelope], bool],
        *,
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> Envelope:
        for index, envelope in enumerate(self.inbox):
            if wanted(envelope):
                return self._pop_inbox(index)
        duration = self.timeout if timeout is None else timeout
        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration
        try:
            async with asyncio.timeout(duration):
                async for raw in self.connection.events():
                    # Already-queued invalid/replayed frames need not suspend,
                    # so the timeout callback alone cannot bound this loop.
                    if loop.time() >= deadline:
                        break
                    admitted = self._admit(raw)
                    if admitted is None:
                        continue
                    if wanted(admitted):
                        return admitted
                    self._buffer_inbox(admitted)
                    for index, ready in enumerate(self.inbox):
                        if wanted(ready):
                            return self._pop_inbox(index)
        except TimeoutError:
            pass
        raise TimeoutError

    async def receive_next(self, *, timeout: float | None = None) -> Envelope:  # noqa: ASYNC109
        """Take the first admitted provider message, never skipping an earlier one."""
        return await self.receive(lambda _item: True, timeout=timeout)

    async def reply_to(self, request: Envelope, expected: str) -> Envelope:
        try:
            answer = await self.receive(lambda item: item.in_reply_to == request.message_id)
        except TimeoutError:
            raise SwapError(f"no answer to {request.message_type}") from None
        if answer.message_type == "error":
            # Only a closed protocol code reaches the terminal, never provider text.
            try:
                code: str = QuoteError.model_validate(answer.payload).code
            except ValueError:
                code = "malformed error"
            raise SwapError(f"provider refused {request.message_type}: {code}")
        if answer.message_type != expected:
            raise SwapError(f"unexpected answer {answer.message_type}")
        return answer


async def _wait_for_payment(
    session: _Session,
    terms: ContractTerms,
    *,
    deadline: float,
    refund_hint: str,
) -> str:
    """Dispatch the original provider stream in order under one fixed lifetime.

    Cooperation is not negotiated by the current client. Never skip an action
    request to a later payment observation, and never echo readiness before
    a complete signing/completion handler is available.
    """
    loop = asyncio.get_running_loop()
    expected_contract = contract_hash(terms).hex()
    timeout_error = "provider settlement not observed in time; " + refund_hint
    async with session.settlement_stream():
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise SwapError(timeout_error)
            try:
                message = await session.receive_next(timeout=remaining)
            except TimeoutError:
                raise SwapError(timeout_error) from None
            except SwapError as error:
                raise SwapError(f"provider session stopped: {error}; " + refund_hint) from None
            if loop.time() >= deadline:
                raise SwapError(timeout_error)
            if message.contract_hash != expected_contract or message.in_reply_to is not None:
                raise SwapError("unexpected provider settlement context; " + refund_hint)
            if message.message_type == "action_request":
                raise SwapError(
                    "cooperation unavailable; payment status unresolved; " + refund_hint
                )
            if message.message_type != "observation":
                raise SwapError("unexpected provider settlement message; " + refund_hint)
            try:
                seen = parse_observation(canonicalize(message.payload))
            except ValueError:
                raise SwapError("invalid provider settlement observation; " + refund_hint) from None
            if isinstance(seen, PaymentSettled):
                preimage = seen.payment_preimage
                if hashlib.sha256(bytes.fromhex(preimage)).hexdigest() != (
                    terms.invoice_binding.payment_hash
                ):
                    raise SwapError("provider sent a wrong preimage; " + refund_hint)
                return preimage
            if seen.kind == "payment_failed":
                raise SwapError("provider reports the payment failed; " + refund_hint)


def _validate_cooperative_readiness(  # noqa: PLR0913 - all independent bindings are explicit
    session: _Session,
    request: Envelope,
    *,
    terms: ContractTerms,
    init: HandshakeInit,
    accept: HandshakeAccept,
    provider_key: str,
    observed_preimage: str | None,
    now: int,
    tip_height: int,
) -> CooperativeClaimReadyRequest:
    """Verify a readiness request and learn its preimage without replying.

    The complete handler must durably retain the learned preimage before any
    readiness echo. Validation grants no signing authority and changes neither
    session sequence nor recovery state. It does not establish FIFO admission.
    """
    if (
        request.sender_session_key != provider_key
        or session.provider_key != provider_key
        or session.session_id != init.session_id
        or request.message_type != "action_request"
    ):
        raise SwapError("readiness is not from this provider session")
    try:
        session.crypto.schnorr_verify(
            bytes.fromhex(provider_key),
            unsigned_envelope_hash(request),
            bytes.fromhex(request.signature or ""),
        )
        payload = check_cooperative_action_context(request, terms, init, accept)
    except Exception:  # noqa: BLE001 - a signed but invalid request grants no effect
        raise SwapError("cooperative readiness refused") from None
    if not isinstance(payload, CooperativeClaimReadyRequest) or (
        type(now) is not int
        or type(tip_height) is not int
        or now < 0
        or tip_height < 0
        or not now < payload.deadline_at <= now + 30
        or not tip_height
        < payload.deadline_height
        <= (terms.refund_lock_height - terms.timing_policy.claim_confirmation_blocks)
        or hashlib.sha256(bytes.fromhex(payload.payment_preimage)).hexdigest()
        != terms.invoice_binding.payment_hash
        or (observed_preimage is not None and payload.payment_preimage != observed_preimage)
    ):
        raise SwapError("cooperative readiness refused")
    return payload


async def _answer_cooperative_readiness(  # noqa: PLR0913 - explicit independent bindings
    session: _Session,
    request: Envelope,
    *,
    terms: ContractTerms,
    init: HandshakeInit,
    accept: HandshakeAccept,
    provider_key: str,
    observed_preimage: str | None,
    now: int,
    tip_height: int,
) -> str:
    """Revalidate then echo one readiness request, outside the attempt owner.

    Production dispatch echoes through ``_CooperativeClaimAttempt._ready``,
    which first publishes its learned-preimage recovery successor; this
    standalone helper never does, so it must not be wired into dispatch.
    """
    payload = _validate_cooperative_readiness(
        session,
        request,
        terms=terms,
        init=init,
        accept=accept,
        provider_key=provider_key,
        observed_preimage=observed_preimage,
        now=now,
        tip_height=tip_height,
    )
    reply = session.envelope(
        "action_result",
        {
            "action": "cooperative_claim_ready",
            "challenge": payload.challenge,
            "status": "ready",
        },
        in_reply_to=request.message_id,
        contract=contract_hash(terms).hex(),
        required_features=(COOPERATIVE_CLAIM_FEATURE,),
    )
    await session.send(reply, provider_key)
    return payload.payment_preimage


@dataclass(frozen=True, repr=False)
class _CooperativeClaimOutcome:
    """Paid knowledge survives abandonment; it does not cancel a provider winner."""

    preimage: str = field(repr=False)
    recovery: bytes = field(repr=False)
    claim: ValidatedCooperativeClaim | None
    pending_recovery: bytes | None = field(default=None, repr=False)
    # Why cooperation stopped; a local SwapError message or an exception class name.
    abandoned_because: str | None = None


def _abandon_reason(error: BaseException) -> str:
    """Name a local failure without echoing adapter or peer-controlled detail."""
    return str(error) if type(error) is SwapError else type(error).__name__


class _CooperativeClaimAttempt:
    """Dormant original-session BTC-to-LN owner, never constructed by recovery.

    One consumer, one budget, one reservation and one partial. The caller must
    retain the crypto context until wait_for_workers finishes, even after
    cancellation. A canceled to_thread await does not stop a writer or RPC.
    Forward dispatch constructs this for every authenticated featured swap;
    new swaps always negotiate the feature.
    """

    def __init__(  # noqa: PLR0913 - independently retained live bindings
        self,
        session: _Session,
        *,
        terms: ContractTerms,
        init: HandshakeInit,
        accept: HandshakeAccept,
        funded_recovery: bytes,
        contract_secret: bytes,
        wallet: Wallet,
        write_recovery: Callable[[bytes, bytes | None], bytes | None],
        settlement_deadline: float,
        configured_fee_floor_sat: int,
        allow_regtest_fixed_fee: bool = False,
        wall_clock: Callable[[], int] = lambda: int(time.time()),
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if session._cooperative_attempt_started:  # noqa: SLF001 - colocated ephemeral custody
            raise SwapError("original session cooperation already reserved")
        inspect_recovery_plaintext(funded_recovery, session.network, crypto=session.crypto)
        record: dict[str, Any] = json.loads(funded_recovery)
        if not isinstance(record, dict):
            raise SwapError("invalid original funded recovery")
        context = record["verification_context"]
        if (
            not isinstance(context, dict)
            or terms.profile_id != PROFILE
            or session.profile != PROFILE
            or terms.network_identity != session.network
            or init.session_id != session.session_id
            or init.client_session_xonly_key != session.key
            or accept.provider_session_xonly_key != session.provider_key
            or session.crypto.public_key(session.secret)[1:].hex() != session.key
            or record["contract_terms"] != terms.model_dump(mode="json")
            or context["handshake_init"] != init.model_dump(mode="json")
            or context["handshake_accept"] != accept.model_dump(mode="json")
            or record["user_secret"]
            != {"kind": "raw-secp256k1-v1", "contract_secret_key": contract_secret.hex()}
            or not record["funding_history"]
            or record["monotonic_knowledge"]
            != {
                "preimage_known": False,
                "preimage": None,
                "dangerous_signature_issued": record["monotonic_knowledge"][
                    "dangerous_signature_issued"
                ],
            }
            or COOPERATIVE_RESERVATION_EXTENSION in record["extensions"]
            or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
            or not math.isfinite(settlement_deadline)
            or type(configured_fee_floor_sat) is not int
            or configured_fee_floor_sat <= 0
            or type(allow_regtest_fixed_fee) is not bool
            or (allow_regtest_fixed_fee and session.network.name != "regtest")
        ):
            raise SwapError("cooperation requires the original live funded session")
        self.session, self.terms, self.init, self.accept = session, terms, init, accept
        self.wallet, self.write_recovery = wallet, write_recovery
        self.recovery, self.contract_secret = funded_recovery, contract_secret
        self.pending_recovery: bytes | None = None
        self.binding = FundingBinding.model_validate_json(
            canonicalize(record["funding_history"][-1]["binding"]), strict=True
        )
        self.deadline = settlement_deadline
        self.wall_deadline: int | None = None
        self.height_deadline = (
            terms.refund_lock_height - terms.timing_policy.claim_confirmation_blocks
        )
        self.fee_floor, self.fixed_fee = configured_fee_floor_sat, allow_regtest_fixed_fee
        self.wall_clock, self.monotonic_clock = wall_clock, monotonic_clock
        self.last_wall, self.last_mono = 0, 0.0
        self.preimage: str | None = None
        self.stage = "fresh"
        self.workers: set[asyncio.Future[Any]] = set()
        self.proposal: Envelope | None = None
        self.plan: CooperativeClaimPlan | None = None
        self.partial_result: Envelope | None = None
        self.public_transcript: dict[str, Any] | None = None
        self.client_partial: bytes | None = None
        self._clock()
        session._cooperative_attempt_started = True  # noqa: SLF001 - never reset this session's attempt

    def _clock(self) -> tuple[int, float]:
        wall, mono = self.wall_clock(), self.monotonic_clock()
        if (
            type(wall) is not int
            or wall < 0
            or type(mono) not in (int, float)
            or not math.isfinite(mono)
            or mono < 0
        ):
            raise SwapError("cooperative clock unavailable")
        self.last_wall, self.last_mono = max(self.last_wall, wall), max(self.last_mono, mono)
        if self.last_mono >= self.deadline or (
            self.wall_deadline is not None and self.last_wall >= self.wall_deadline
        ):
            raise SwapError("cooperative attempt expired")
        return self.last_wall, self.last_mono

    def _remaining(self) -> float:
        wall, mono = self._clock()
        return min(
            self.deadline - mono,
            float(self.wall_deadline - wall) if self.wall_deadline is not None else math.inf,
        )

    def wait_for_workers(self) -> asyncio.Future[list[Any]]:
        """Return actual completion, not a globally cancelable cleanup Task."""
        return asyncio.gather(*tuple(self.workers), return_exceptions=True)

    def _worker_done(self, task: asyncio.Future[Any]) -> None:
        self.workers.discard(task)
        if not task.cancelled():
            task.exception()  # consume late errors, never use a late result

    async def _effect(self, operation: Callable[[], Any], *, sample: bool = False) -> Any:  # noqa: ANN401
        if self.workers:
            raise SwapError("cooperative worker still owned")
        budget = min(self._remaining(), 1.0 if sample else math.inf)
        context = contextvars.copy_context()
        task = asyncio.get_running_loop().run_in_executor(None, context.run, operation)
        self.workers.add(task)
        task.add_done_callback(self._worker_done)
        # Cancellation of wait's private waiter never cancels actual executor
        # work. Unlike a canceled shield in Python 3.14, it does not log late
        # exceptions (which may contain sensitive adapter details).
        async with asyncio.timeout(budget):
            await asyncio.wait((task,))
        result = task.result()
        self._clock()
        return result

    async def _publish(self, candidate: bytes) -> None:
        previous = self.recovery
        inspect_recovery_successor(
            previous, candidate, self.session.network, crypto=self.session.crypto
        )
        self.pending_recovery = candidate
        await self._effect(lambda: self.write_recovery(candidate, previous))
        self.recovery = candidate
        self.pending_recovery = None

    async def _learn_payment(
        self, preimage: str, *, readiness: CooperativeClaimReadyRequest | None = None
    ) -> bool:
        if (
            hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
            != self.terms.invoice_binding.payment_hash
        ):
            raise SwapError("cooperative preimage refused")
        newly_known = self.preimage is None
        if not newly_known and preimage != self.preimage:
            raise SwapError("cooperative preimage conflict")
        self.preimage = preimage  # knowledge survives even an expiring clock guard
        wall, mono = self._clock()
        if newly_known:
            self.wall_deadline = wall + 30
            self.deadline = min(self.deadline, mono + 30)
        eligible = True
        if readiness is not None:
            eligible = (
                wall < readiness.deadline_at <= wall + 30
                and 0 < readiness.deadline_height <= self.height_deadline
            )
            if eligible:
                self.wall_deadline = min(
                    self.wall_deadline or readiness.deadline_at, readiness.deadline_at
                )
                self.deadline = min(self.deadline, mono + readiness.deadline_at - wall)
                self.height_deadline = readiness.deadline_height
        if newly_known:
            # Unusable readiness still discloses valuable invoice knowledge.
            # Preserve it within the local budget without granting eligibility
            # or applying an expired advertised deadline to recovery storage.
            record = json.loads(self.recovery)
            record["updated_at"] = max(record["updated_at"], wall)
            record["monotonic_knowledge"].update(preimage_known=True, preimage=preimage)
            await self._publish(canonicalize(record))
        return eligible

    async def _sample(self) -> tuple[CooperativeClaimEvidence, float]:
        _, started = self._clock()
        sample = await self._effect(
            lambda: self.wallet.observe_cooperative_claim_evidence(
                self.binding,
                self.terms,
                keys=self.session.crypto,
                allow_regtest_fixed_fee=self.fixed_fee,
            ),
            sample=True,
        )
        self._check_sample(sample, started)
        return sample, started

    def _check_sample(self, sample: CooperativeClaimEvidence, started: float) -> None:
        _, now = self._clock()
        if type(sample) is not CooperativeClaimEvidence:
            raise SwapError("cooperative evidence refused")
        output, policy = sample.outpoint, sample.fee_policy
        if type(output) is not CooperativeClaimOutpoint or type(policy) is not CooperativeFeePolicy:
            raise SwapError("cooperative evidence refused")
        if (
            now - started >= 1
            or output.network_identity != self.session.network
            or policy.network_identity != self.session.network
            or (output.tip_hash, output.tip_height) != (policy.tip_hash, policy.tip_height)
            or output.funding_txid != self.binding.funding_txid
            or output.funding_vout != self.binding.contract_vout
            or output.funding_value_sat != int(self.binding.contract_value_sat)
            or output.funding_script_pubkey != bytes.fromhex(self.binding.contract_script_pubkey)
            or output.confirmations < self.terms.funding_confirmations
            or type(output.confirmations) is not int
            or type(output.tip_height) is not int
            or output.tip_height < 0
            or output.tip_height >= self.height_deadline
            or policy.confirmation_blocks != self.terms.timing_policy.claim_confirmation_blocks
            or (policy.estimate_sat_kvb is None and not self.fixed_fee)
            or any(
                type(rate) is not int or rate < 0
                for rate in (
                    policy.min_relay_sat_kvb,
                    policy.mempool_min_sat_kvb,
                )
            )
            or (
                policy.estimate_sat_kvb is not None
                and (
                    type(policy.estimate_sat_kvb) is not int
                    or policy.estimate_sat_kvb <= 0
                    or type(policy.estimate_blocks) is not int
                    or not 1
                    <= policy.estimate_blocks
                    <= self.terms.timing_policy.claim_confirmation_blocks
                )
            )
        ):
            raise SwapError("cooperative evidence refused")
        if self.plan is not None:
            vsize = (4 * len(self.plan.base_transaction) + 68 + 3) // 4
            if self.plan.fee_sat < policy.fee_floor_sat(
                vsize=vsize, configured_floor_sat=self.fee_floor
            ):
                raise SwapError("cooperative fee refused")

    async def _send(self, reply: Envelope) -> None:
        await asyncio.wait_for(
            self.session.send(reply, self.accept.provider_session_xonly_key),
            timeout=self._remaining(),
        )
        self._clock()

    def _authenticate(self, message: Envelope) -> None:
        verify_static_signed_envelope(
            canonicalize(message.model_dump(mode="json")),
            expected_session_id=self.session.session_id,
            expected_profile=PROFILE,
            expected_network=self.session.network,
            expected_sender_key=self.accept.provider_session_xonly_key,
            supported_features=SUPPORTED_HANDSHAKE_FEATURES,
            crypto=self.session.crypto,
        )
        if (
            message.contract_hash != contract_hash(self.terms).hex()
            or message.in_reply_to is not None
        ):
            raise SwapError("cooperative provider context refused")

    async def _ready(self, message: Envelope, payload: CooperativeClaimReadyRequest) -> None:
        if self.stage != "fresh":
            raise SwapError("cooperative readiness already consumed")
        self.stage = "preparing"
        if not await self._learn_payment(payload.payment_preimage, readiness=payload):
            raise SwapError("cooperative readiness deadline refused")
        sample, started = await self._sample()
        self._check_sample(sample, started)
        reply = self.session.envelope(
            "action_result",
            {
                "action": "cooperative_claim_ready",
                "challenge": payload.challenge,
                "status": "ready",
            },
            in_reply_to=message.message_id,
            contract=contract_hash(self.terms).hex(),
            required_features=(COOPERATIVE_CLAIM_FEATURE,),
        )
        self._check_sample(sample, started)
        await self._send(reply)
        self.ready = payload
        self.stage = "echoed"

    async def _propose(self, message: Envelope, payload: CooperativeClaimPropose) -> None:
        if self.stage != "echoed":
            raise SwapError("cooperative proposal unavailable")
        self.stage = "reserved"  # consumed before validation/publication/nonce effects
        if (
            payload.payment_preimage != self.preimage
            or payload.deadline_at != self.ready.deadline_at
            or payload.deadline_height != self.ready.deadline_height
        ):
            raise SwapError("cooperative proposal context refused")
        funding = FundingOutput(
            txid=bytes.fromhex(self.binding.funding_txid),
            output_index=self.binding.contract_vout,
            value_sat=int(self.binding.contract_value_sat),
            script_pubkey=bytes.fromhex(self.binding.contract_script_pubkey),
        )
        self.plan = verify_cooperative_claim_proposal(
            bytes.fromhex(payload.unsigned_transaction),
            UnilateralAuthorization.from_terms(
                self.terms, funding, "claim", keys=self.session.crypto
            ),
        )
        self.session.crypto.musig_public_nonce_validate(bytes.fromhex(payload.public_nonce))
        await self._sample()
        record = json.loads(self.recovery)
        wall, _ = self._clock()
        record["updated_at"] = max(record["updated_at"], wall)
        record["extensions"][COOPERATIVE_RESERVATION_EXTENSION] = {
            "version": 1,
            "proposal": message.model_dump(mode="json"),
            "signature_hash": self.plan.signature_hash.hex(),
        }
        await self._publish(canonicalize(record))
        sample, started = await self._sample()  # never reuse pre-publication evidence
        artifacts = reconstruct_taproot_contract(self.terms, keys=self.session.crypto)
        self._check_sample(sample, started)
        attempt, nonce = self.session.crypto.musig_begin(
            secret_key=self.contract_secret,
            user_public_key=bytes.fromhex(self.terms.client_contract_compressed_key),
            provider_public_key=bytes.fromhex(self.terms.provider_contract_compressed_key),
            tap_tweak=artifacts.tap_tweak,
            message=self.plan.signature_hash,
            cooperation_id=bytes.fromhex(payload.cooperation_id),
        )
        try:
            self._check_sample(sample, started)
            self.client_partial = attempt.partial_sign_once(bytes.fromhex(payload.public_nonce))
            self._check_sample(sample, started)
        finally:
            attempt.close()
        self.public_transcript = {
            "user_public_key": bytes.fromhex(self.terms.client_contract_compressed_key),
            "provider_public_key": bytes.fromhex(self.terms.provider_contract_compressed_key),
            "tap_tweak": artifacts.tap_tweak,
            "message": self.plan.signature_hash,
            "user_public_nonce": nonce,
            "provider_public_nonce": bytes.fromhex(payload.public_nonce),
        }
        self.session.crypto.musig_partial_verify(
            **self.public_transcript, signer_index=0, partial_signature=self.client_partial
        )
        self._check_sample(sample, started)
        self.partial_result = self.session.envelope(
            "action_result",
            {
                "action": "cooperative_claim_propose",
                "cooperation_id": payload.cooperation_id,
                "status": "signed",
                "public_nonce": nonce.hex(),
                "partial_signature": self.client_partial.hex(),
            },
            in_reply_to=message.message_id,
            contract=contract_hash(self.terms).hex(),
            required_features=(COOPERATIVE_CLAIM_FEATURE,),
        )
        self._check_sample(sample, started)
        self.proposal = message
        self.stage = "partial issued"
        await self._send(self.partial_result)

    async def _complete(
        self, message: Envelope, payload: CooperativeClaimComplete
    ) -> ValidatedCooperativeClaim:
        if (
            self.stage != "partial issued"
            or self.proposal is None
            or self.plan is None
            or self.public_transcript is None
            or self.client_partial is None
        ):
            raise SwapError("cooperative completion unavailable")
        self.stage = "verifying"
        check_cooperative_action_context(
            message, self.terms, self.init, self.accept, prior_request=self.proposal
        )
        height = await self._effect(self.wallet.tip_height, sample=True)
        if type(height) is not int or not 0 <= height < self.height_deadline:
            raise SwapError("cooperative completion cutoff reached")
        self._clock()
        partial = bytes.fromhex(payload.partial_signature)
        self.session.crypto.musig_partial_verify(
            **self.public_transcript, signer_index=1, partial_signature=partial
        )
        signature = self.session.crypto.musig_aggregate(
            **self.public_transcript,
            user_partial_signature=self.client_partial,
            provider_partial_signature=partial,
        )
        claim = finalize_cooperative_claim(self.plan, signature, verifier=self.session.crypto)
        self._clock()
        receipt = self.session.envelope(
            "action_result",
            {
                "action": "cooperative_claim_complete",
                "cooperation_id": payload.cooperation_id,
                "status": "verified",
            },
            in_reply_to=message.message_id,
            contract=contract_hash(self.terms).hex(),
            required_features=(COOPERATIVE_CLAIM_FEATURE,),
        )
        await self._send(receipt)
        self.stage = "completed"
        return claim

    async def run(self) -> _CooperativeClaimOutcome:
        if self.stage != "fresh":
            raise SwapError("cooperative attempt cannot resume")
        async with self.session.settlement_stream():
            try:
                while True:
                    message = await self.session.receive_next(timeout=self._remaining())
                    self._clock()  # queued arrival never reserves deadline authority
                    self._authenticate(message)
                    if message.message_type == "observation":
                        seen = parse_observation(canonicalize(message.payload))
                        if isinstance(seen, PaymentSettled):
                            await self._learn_payment(seen.payment_preimage)
                        elif seen.kind == "payment_failed":
                            raise SwapError("provider reports payment failure")  # noqa: TRY301 - terminal lifecycle
                        continue
                    payload = check_cooperative_action_context(
                        message, self.terms, self.init, self.accept, prior_request=self.proposal
                    )
                    if isinstance(payload, CooperativeClaimReadyRequest):
                        await self._ready(message, payload)
                    elif isinstance(payload, CooperativeClaimPropose):
                        await self._propose(message, payload)
                    elif isinstance(payload, CooperativeClaimComplete):
                        claim = await self._complete(message, payload)
                        return _CooperativeClaimOutcome(self.preimage or "", self.recovery, claim)
                    else:
                        raise SwapError("unexpected cooperative provider action")  # noqa: TRY301 - terminal lifecycle
            except asyncio.CancelledError:
                self.stage = "abandoned"
                raise
            except Exception as error:  # noqa: BLE001 - no failure reopens nonce or payment authority
                self.stage = "abandoned"
                if self.preimage is None:
                    raise SwapError(
                        "cooperation stopped; payment status unresolved; preserve funded recovery"
                    ) from None
                # This is known payment with bounded fallback, NOT cancellation
                # of a provider's already selected key-path winner.
                return _CooperativeClaimOutcome(
                    self.preimage,
                    self.recovery,
                    None,
                    self.pending_recovery,
                    _abandon_reason(error),
                )


def _recovery_document(  # noqa: PLR0913 - one record's explicit parts
    *,
    session: _Session,
    init: HandshakeInit,
    accept: HandshakeAccept,
    accept_signature: str,
    offer: TermsOfferPayload,
    acceptance_signature: str,
    contract_secret: bytes,
    birthday: int,
    created_at: int,
    funding: tuple[tuple[FundingBinding, str], ...] = (),
    preimage: bytes | None = None,
) -> bytes:
    # The Bitcoin offer was validated by _check_offer before recovery is written.
    terms = cast("ContractTerms", offer.terms.contract_terms)
    artifacts = reconstruct_taproot_contract(terms, keys=session.crypto)
    return canonicalize(
        {
            "format": "rillswap-recovery",
            "format_version": "1-pre.1",
            "specification_version": "0.1.0-pre.1",
            "created_at": created_at,
            "updated_at": int(time.time()) if funding else created_at,
            "network_identity": session.network.model_dump(mode="json"),
            "profile_id": session.profile,
            "contract_hash": offer.terms.contract_hash,
            "contract_terms": terms.model_dump(mode="json"),
            "verification_context": {
                "handshake_init": init.model_dump(mode="json"),
                "handshake_accept": accept.model_dump(mode="json"),
                "provider_identity_signature": accept_signature,
                "handshake_hash": offer.terms.handshake_hash,
                "client_session_xonly_key": session.key,
                "provider_session_xonly_key": accept.provider_session_xonly_key,
                "expected_provider_identity_source": {
                    "kind": "manual",
                    "advertisement_digest": None,
                },
                "provider_terms_signature": offer.provider_terms_signature,
                "client_acceptance_signature": acceptance_signature,
            },
            "taproot_contract": {
                "internal_xonly_key": artifacts.internal_key.hex(),
                "internal_key_parity": artifacts.internal_parity,
                "claim_script": artifacts.claim_script.hex(),
                "refund_script": artifacts.refund_script.hex(),
                "claim_leaf_hash": artifacts.claim_leaf_hash.hex(),
                "refund_leaf_hash": artifacts.refund_leaf_hash.hex(),
                "merkle_root": artifacts.merkle_root.hex(),
                "tap_tweak": artifacts.tap_tweak.hex(),
                "output_xonly_key": artifacts.output_key.hex(),
                "output_key_parity": artifacts.output_parity,
                "script_pubkey": artifacts.script_pubkey.hex(),
                "claim_control_block": artifacts.claim_control_block.hex(),
                "refund_control_block": artifacts.refund_control_block.hex(),
            },
            "user_secret": {
                "kind": "raw-secp256k1-v1",
                "contract_secret_key": contract_secret.hex(),
            },
            "funding_history": [
                {"binding": binding.model_dump(mode="json"), "funder_session_signature": sig}
                for binding, sig in funding
            ],
            "chain_scan_birthday_height": birthday,
            "fee_policy": {
                "max_claim_fee_sat": terms.max_claim_fee_sat,
                "max_refund_fee_sat": terms.max_refund_fee_sat,
            },
            "recovery_authorization_xonly_key": terms.recovery_authorization_xonly_key,
            "monotonic_knowledge": {
                "preimage_known": preimage is not None,
                "preimage": None if preimage is None else preimage.hex(),
                "dangerous_signature_issued": False,
            },
            "extensions": {},
        }
    )


async def _handshake(
    session: _Session, advertisement: dict[str, Any], identity: str
) -> tuple[HandshakeInit, HandshakeAccept, str, str]:
    """Return init, accept, identity signature, and handshake hash."""
    # Every session is bound to the provider epoch it is sent to.
    epoch = advertisement["epoch_inbox_xonly_keys"][0]
    session.session_id = epoch_bound_session_id(session.network, identity, epoch, session.key).hex()
    extensions: dict[str, Any] = {EPOCH_SESSION_EXTENSION: {"epoch_inbox_xonly_key": epoch}}
    # The declaration binds every message of this session to the advertised work.
    session.work_bits = _transport_work(advertisement)
    if session.work_bits:
        extensions[transport_pow.TRANSPORT_POW_EXTENSION] = {"bits": session.work_bits}
    init = HandshakeInit(
        protocol="rillswap",
        wire_version="1",
        profile_id=session.profile,
        network_identity=session.network,
        session_id=session.session_id,
        client_challenge=secrets.token_hex(32),
        client_session_xonly_key=session.key,
        expected_provider_identity_xonly_key=identity,
        requested_encryption_suites=ENCRYPTION_SUITES,
        requested_capabilities=CAPABILITIES,
        # Cooperative MuSig2 claims are mandatory; a provider that does not
        # echo them fails ``validate_against`` below before any terms.
        required_features=tuple(
            sorted(
                {COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_FEATURE}
                | (
                    {FEE_POLICY_FEATURE}
                    if announced_fee_policy(advertisement) is not None
                    else set()
                )
            )
        ),
        extensions=extensions,
    )
    request = session.envelope("handshake_init", init.model_dump(mode="json"), signed=False)
    session.expect_accept(request, init, identity)
    await session.listen()
    await session.send(request, epoch)
    answer = await session.reply_to(request, "handshake_accept")
    accept = parse_model_json(HandshakeAccept, canonicalize(answer.payload["accept"]))
    signature = str(answer.payload["provider_identity_signature"])
    accept.validate_against(init, supported_features=NEGOTIATED_FEATURES)
    session.crypto.schnorr_verify(
        bytes.fromhex(identity), handshake_accept_hash(accept), bytes.fromhex(signature)
    )
    if accept.provider_session_xonly_key != answer.sender_session_key:
        raise SwapError("handshake accept names another provider session key")
    session.provider_key = answer.sender_session_key
    transcript = handshake_hash(init, accept).hex()
    confirm = session.envelope(
        "handshake_confirm",
        {
            "handshake_hash": transcript,
            "session_id": session.session_id,
            "client_session_xonly_key": session.key,
            "provider_session_xonly_key": session.provider_key,
        },
        in_reply_to=answer.message_id,
    )
    await session.send(confirm, session.provider_key)
    return init, accept, signature, transcript


def _check_offer(  # noqa: PLR0913 - every binding checked explicitly
    offer: TermsOfferPayload,
    request: FirmQuoteRequest,
    *,
    envelope: Envelope,
    transcript: str,
    invoice: InvoiceBinding,
    identity: str,
    network: NetworkIdentity,
    crypto: Context,
    now: int,
) -> ContractTerms:
    check_terms_offer(request, offer, handshake_hash=transcript, invoice_binding=invoice, now=now)
    # check_terms_offer rejects ERC20 terms, but its return type cannot narrow this union.
    terms = cast("ContractTerms", offer.terms.contract_terms)
    crypto.schnorr_verify(
        bytes.fromhex(identity),
        provider_terms_hash(offer.terms),
        bytes.fromhex(offer.provider_terms_signature),
    )
    if not (
        contract_hash(terms).hex() == offer.terms.contract_hash == envelope.contract_hash
        and terms.provider_identity_key == identity
        and terms.network_identity == network
        and now < terms.terms_expiry
    ):
        raise SwapError("terms offer is not bound to this provider, network, or time")
    if COOPERATIVE_CLAIM_FEATURE not in terms.required_features:
        raise SwapError("terms offer does not commit to cooperative claims")
    return terms


async def _drain_cooperative_workers(owner: _CooperativeClaimAttempt) -> None:
    """Keep crypto alive until real workers finish, even under repeated cancellation.

    Cleanup is not new signing authority and is deliberately outside the
    settlement budget. Do not silently turn cancellation during return into
    success. Shielded gather Futures own cleanup, never another writer or sample.
    """
    draining = asyncio.gather(owner.wait_for_workers())
    canceled = False
    while not draining.done():
        try:
            await asyncio.shield(draining)
        except asyncio.CancelledError:
            canceled = True
    draining.result()
    if canceled:
        raise asyncio.CancelledError


async def run_swap(  # noqa: PLR0913, PLR0915 - one ordered swap story
    connection: RelayTransport,
    *,
    identity: str,
    network: NetworkIdentity,
    invoice: str,
    decode_invoice: Callable[[str], InvoiceBinding],
    wallet: Wallet,
    write_recovery: Callable[[bytes, bytes | None], bytes | None],
    limits: SwapLimits,
    crypto: Context,
    timeout: float = 60.0,  # noqa: ASYNC109
    settle_timeout: float = 600.0,
    report: Callable[[str], None] = lambda _line: None,
) -> SwapOutcome:
    """Run one BTC to LN swap; see the module docstring for the order."""
    limits.validate_cooperative_fee_floor()
    if not math.isfinite(settle_timeout) or settle_timeout <= 0:
        raise SwapError("settlement timeout must be finite and positive")
    now = int(time.time())
    binding_invoice = decode_invoice(invoice)
    if binding_invoice.bolt11_sha256 != hashlib.sha256(invoice.encode("ascii")).hexdigest():
        raise SwapError("invoice decoder returned another invoice")
    principal = int(binding_invoice.amount_msat) // 1000
    advertisement = await discover(
        connection, identity=identity, network=network, crypto=crypto, now=now
    )
    session = _Session(connection, crypto, network, timeout=timeout)
    init, accept, accept_signature, transcript = await _handshake(session, advertisement, identity)
    source_report = report
    diagnostic_fields: dict[str, object] = {
        "session_id": session.session_id,
        "profile": "btc-to-ln/v1",
        "network": network.name,
        "payment_hash": binding_invoice.payment_hash,
        "amount_msat": binding_invoice.amount_msat,
    }

    def contextual_report(line: str) -> None:
        with diagnostic_context(**diagnostic_fields):
            source_report(line)

    report = contextual_report
    report(f"session {session.session_id[:16]} confirmed")
    provider_key = session.provider_key or ""

    contract_secret, contract_public = _scalar(crypto)
    _, recovery_public = _scalar(crypto)  # authorization key; its secret is not needed
    tip = await asyncio.to_thread(wallet.tip_height)
    destination = await asyncio.to_thread(wallet.new_destination_script)
    fee_extensions: dict[str, Any] = {}
    if announced_fee_policy(advertisement) is not None:
        fee = await asyncio.to_thread(wallet.next_block_fee)
        fee_extensions = network_fee_request(
            advertisement, independent_rate_sat_kvb=max(fee.rate_sat_kvb, fee.floor_sat_kvb)
        )
    request_model = FirmQuoteRequest(
        kind="btc-to-ln",
        mode="firm",
        lightning_principal_sat=str(principal),
        invoice=invoice,
        client_contract_compressed_key=contract_public.hex(),
        recovery_authorization_xonly_key=recovery_public[1:].hex(),
        client_destination_script=destination.hex(),
        limits=QuoteLimits(
            max_success_fee_sat=str(limits.max_success_fee_sat),
            max_funding_fee_sat=str(limits.max_funding_fee_sat),
            max_claim_fee_sat=str(limits.max_claim_fee_sat),
            max_refund_fee_sat=str(limits.max_refund_fee_sat),
            max_refund_lock_height=tip + limits.max_refund_delay_blocks,
        ),
        extensions=fee_extensions,
    )
    request = session.envelope("quote_request", request_model.model_dump(mode="json"))
    await session.send(request, provider_key)
    answer = await session.reply_to(request, "terms_offer")
    offer = parse_model_json(TermsOfferPayload, canonicalize(answer.payload))
    terms = _check_offer(
        offer,
        request_model,
        envelope=answer,
        transcript=transcript,
        invoice=binding_invoice,
        identity=identity,
        network=network,
        crypto=crypto,
        now=int(time.time()),
    )
    require_announced_depth(terms.funding_confirmations, advertisement)
    economics = terms.economics
    with suppress(Exception):  # optional metadata has no financial authority
        diagnostic_fields.update(terms_facts(terms))
    diagnostic(
        logging.getLogger(__name__),
        "terms.verified",
        "Verified signed swap terms",
        details=diagnostic_fields,
    )
    report(
        f"terms: fund {economics.contract_amount_sat} sat, refund after block "
        f"{terms.refund_lock_height}"
    )

    acceptance = ClientAcceptance(
        contract_hash=offer.terms.contract_hash,
        handshake_hash=transcript,
        session_id=session.session_id,
        client_session_xonly_key=session.key,
        provider_session_xonly_key=provider_key,
    )
    acceptance_signature = bytes(
        crypto.schnorr_sign(
            session.secret, client_acceptance_hash(acceptance), secrets.token_bytes(32)
        )
    ).hex()
    record = {
        "session": session,
        "init": init,
        "accept": accept,
        "accept_signature": accept_signature,
        "offer": offer,
        "acceptance_signature": acceptance_signature,
        "contract_secret": contract_secret,
        "birthday": tip,
        "created_at": int(time.time()),
    }
    document = _recovery_document(**record)  # type: ignore[arg-type]
    await asyncio.to_thread(write_recovery, document, None)
    report("recovery file written (terms, no funding yet)")
    if int(time.time()) >= terms.terms_expiry:
        raise SwapError("quote expired before acceptance; request a fresh quote")
    accepted = session.envelope(
        "terms_accept",
        {
            "acceptance": acceptance.model_dump(mode="json"),
            "client_acceptance_signature": acceptance_signature,
        },
        in_reply_to=answer.message_id,
        contract=offer.terms.contract_hash,
    )
    await session.send(accepted, provider_key)
    await session.reply_to(accepted, "ack")

    script = reconstruct_taproot_contract(terms, keys=crypto).script_pubkey
    amount = int(economics.contract_amount_sat)
    funded = await asyncio.to_thread(
        lambda: wallet.fund(script, amount, fee_rate_sat_vb=limits.funding_fee_rate_sat_vb)
    )
    plan = FundingPlan(
        approved_inputs=funded.inputs,
        lineage_anchor=funded.inputs[0],
        approved_noncontract_outputs=funded.other_outputs,
    )
    authorized = authorize_funding_transaction(funded.raw_transaction, terms, plan, keys=crypto)
    attempt_id = secrets.token_hex(32)
    binding = FundingBinding(
        contract_hash=offer.terms.contract_hash,
        funding_attempt_id=attempt_id,
        binding_revision=0,
        funder_role="client",
        lineage_anchor_txid=funded.inputs[0].txid.hex(),
        lineage_anchor_vout=funded.inputs[0].output_index,
        funding_txid=authorized.txid,
        contract_vout=authorized.contract_vout,
        contract_value_sat=str(authorized.contract_value_sat),
        contract_script_pubkey=script.hex(),
        replaces_txid=None,
        created_at=int(time.time()),
    )
    binding_signature = bytes(
        crypto.schnorr_sign(session.secret, funding_binding_hash(binding), secrets.token_bytes(32))
    ).hex()
    successor = _recovery_document(
        **record,  # type: ignore[arg-type]
        funding=((binding, binding_signature),),
    )
    await asyncio.to_thread(write_recovery, successor, document)
    report(
        f"funded recovery snapshot written (funding {authorized.txid}, "
        f"attempt {attempt_id} revision 0)"
    )
    bound = session.envelope(
        "funding_binding",
        {
            "binding": binding.model_dump(mode="json"),
            "funding_binding_signature": binding_signature,
            "funding_transaction": funded.raw_transaction.hex(),
        },
        contract=offer.terms.contract_hash,
    )
    await session.send(bound, provider_key)
    await session.reply_to(bound, "ack")
    txid = await asyncio.to_thread(wallet.broadcast, funded.raw_transaction)
    if txid != authorized.txid:
        raise SwapError("Core broadcast another transaction; check the wallet")
    settlement_deadline = asyncio.get_running_loop().time() + settle_timeout
    report(f"funding broadcast {txid}; waiting for the provider to pay")

    refund_hint = (
        "funds are committed; check invoice status; "
        f"refund after block {terms.refund_lock_height} with "
        f"`rill recover watch-refund --funding-attempt-id {attempt_id} --binding-revision 0` "
        "on the funded recovery file"
    )
    if COOPERATIVE_CLAIM_FEATURE in terms.required_features:
        owner = _CooperativeClaimAttempt(
            session,
            terms=terms,
            init=init,
            accept=accept,
            funded_recovery=successor,
            contract_secret=contract_secret,
            wallet=wallet,
            write_recovery=write_recovery,
            settlement_deadline=settlement_deadline,
            configured_fee_floor_sat=limits.claim_fee_floor_sat,
            # Regtest Core rarely estimates fees; public networks never skip it.
            allow_regtest_fixed_fee=session.network.name == "regtest",
            monotonic_clock=asyncio.get_running_loop().time,
        )
        try:
            result = await owner.run()
        finally:
            await _drain_cooperative_workers(owner)
        knowledge = json.loads(result.recovery)["monotonic_knowledge"]
        if not knowledge["preimage_known"] or knowledge["preimage"] != result.preimage:
            raise SwapError(
                "payment verified but paid recovery snapshot publication could not be confirmed; "
                "preserve all recovery files and inspect any .paid snapshot; do not retry payment"
            )
        if result.claim is None:
            report(
                "payment verified; cooperation abandoned locally "
                f"({result.abandoned_because}), not canceled at the provider; "
                "preserve all recovery files, including any .cooperating snapshot; "
                "do not retry payment or signing"
            )
        else:
            report(
                f"cooperative completion verified (claim {result.claim.txid}); "
                "not a chain confirmation"
            )
        return SwapOutcome(
            session.session_id,
            offer.terms.contract_hash,
            txid,
            result.preimage,
            terms.refund_lock_height,
            cooperation="verified" if result.claim is not None else "abandoned",
            cooperative_claim_txid=result.claim.txid if result.claim is not None else None,
        )
    preimage = await _wait_for_payment(
        session,
        terms,
        deadline=settlement_deadline,
        refund_hint=refund_hint,
    )
    paid_recovery = _recovery_document(
        **record,  # type: ignore[arg-type]
        funding=((binding, binding_signature),),
        preimage=bytes.fromhex(preimage),
    )
    try:
        await asyncio.to_thread(write_recovery, paid_recovery, successor)
    except Exception:  # noqa: BLE001 - do not misreport known payment as unpaid
        raise SwapError(
            "payment verified but paid recovery snapshot "
            "publication could not be confirmed; "
            "preserve all recovery files and inspect any .paid snapshot; "
            "do not retry payment"
        ) from None
    report("paid recovery snapshot written (verified payment preimage retained)")
    return SwapOutcome(
        session.session_id,
        offer.terms.contract_hash,
        txid,
        preimage,
        terms.refund_lock_height,
    )
