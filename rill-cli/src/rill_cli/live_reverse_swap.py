"""LN to BTC swap client over Nostr relays (RS-001, RS-004, RS-005).

One swap, one fresh session: discover and verify the provider announcement,
handshake, request firm terms for a payout the client chose (the client
picks the preimage), verify the terms and the hold invoice, write the
encrypted recovery file (with the preimage), accept, pay the hold invoice
from the local LND (or show it for an external wallet), wait for the
provider's signed ``funding_binding``,
verify it, write the funded recovery snapshot, wait for the signed depth,
then claim the contract to the client's destination: by key path with the
provider's MuSig2 partial when the terms require cooperative claims, otherwise
(or after any cooperative failure) by script path revealing the preimage.

Nothing of the client's is at risk before the hold is paid; after that the
Lightning funds stay held until the claim reveals the preimage or the
provider's refund resolves the hold. If this process dies after paying, the
funded recovery snapshot plus ``rill recover watch-claim`` finish the claim,
with the same fee escalation.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import inspect
import math
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol, TypeVar, cast

from rill_core.errors import ValidationError
from rill_core.recovery import (
    REVERSE_COOPERATIVE_RESERVATION_EXTENSION,
    REVERSE_DISCLOSURE_EXTENSION,
    REVERSE_FALLBACK_EXTENSION,
    inspect_recovery_successor,
)
from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    build_cooperative_claim,
    build_unilateral_spend,
    check_funding_binding_transaction,
    claim_vsizes,
    finalize_cooperative_claim,
    finalize_unilateral_spend,
    max_spendable_fee,
    reconstruct_taproot_contract,
)
from rill_core.wire.canonical import canonicalize, parse_json_strict, parse_model_json
from rill_core.wire.cooperative_messages import (
    CooperativeClaimSigned,
    check_cooperative_action_context,
)
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    client_acceptance_hash,
    contract_hash,
    funding_binding_hash,
    provider_terms_hash,
)
from rill_core.wire.messages import ClientAcceptance, LnToBtcEconomics
from rill_core.wire.quotes import TermsOfferPayload
from rill_core.wire.reverse_quotes import (
    ReverseFirmQuoteRequest,
    ReverseQuoteLimits,
    check_reverse_claim_window,
    check_reverse_terms_offer,
)
from rill_core.wire.settlement_messages import FundingBindingPayload, parse_observation
from rill_core.wire.types import NetworkIdentity
from rill_provider.core_tx_bytes import NextBlockFee
from rill_provider.lnd_payment_observation import LndObservationError

from rill_cli.claim_watcher import ClaimAttempt, ClaimWatcher
from rill_cli.external_wallet import DO_NOT_PAY_AGAIN
from rill_cli.live_swap import (
    SwapError,
    _handshake,
    _recovery_document,
    _scalar,
    _Session,
    discover,
    network_fee_request,
    require_announced_depth,
)
from rill_cli.refund_watcher import ChainView
from rill_cli.wallet_rpc import HistoricalWalletOutput

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from types import TracebackType
    from typing import Any, Self

    from rill_core.wire.messages import (
        ContractTerms,
        Envelope,
        FundingBinding,
        HandshakeAccept,
        HandshakeInit,
        InvoiceBinding,
    )
    from rill_crypto import Context

    from rill_cli.hold_payment import HoldStatus
    from rill_cli.live_relay import RelayTransport
    from rill_cli.wallet_rpc import ConfirmedOutput

PROFILE: Literal["ln-to-btc/v1"] = "ln-to-btc/v1"
POLL_SECONDS = 5.0
# The provider caps its own nonrenewing window at 30 s; stay inside it.
REVERSE_PROPOSAL_SECONDS = 20
REVERSE_REPLY_GRACE_SECONDS = 5
# Settlement lifetime that must remain after the cooperative wait, so a silent
# provider costs privacy only, never the bounded unilateral claim.
REVERSE_UNILATERAL_RESERVE_SECONDS = 60
_T = TypeVar("_T")
_CHECK_PAYMENT = "check the payment in your Lightning wallet (`lncli listpayments` with LND)"
_UNRESOLVED = (
    f"reverse swap status unresolved; preserve all recovery files, {_CHECK_PAYMENT}, "
    "and do not retry payment; if funded, use `rill recover watch-claim` before the refund lock"
)


class _ReverseLifetime:
    """Own actual workers across startup and one nonrenewing payment lifetime.

    Startup work may precede the anchor, but payment and claim authorization
    require start(). Cancellation stops future effects, never the owned tasks.
    Cleanup waits outside the budget so SDK callers cannot close crypto early.
    """

    def __init__(self, duration: float) -> None:
        if not math.isfinite(duration) or duration <= 0:
            raise SwapError("settlement timeout must be finite and positive")
        self._duration = duration
        self._deadline: float | None = None
        self._stopped = threading.Event()
        self._workers: set[asyncio.Future[Any]] = (
            set()
        )  # Heterogeneous results, consumed only for drainage.

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _kind: type[BaseException] | None,
        error: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self._stopped.set()

        # Neither executor bridges nor this gather are Tasks. Loop-wide Task
        # cancellation must not mark an actual running thread as completed.
        draining = asyncio.gather(*self._workers, return_exceptions=True)
        canceled = isinstance(error, asyncio.CancelledError)
        while not draining.done():
            try:
                await asyncio.shield(draining)
            except asyncio.CancelledError:
                canceled = True
        draining.result()
        self._workers.clear()
        if canceled:
            raise asyncio.CancelledError

    def start(self) -> None:
        """Anchor immediately before scheduling the exact invoice submission."""
        if self._deadline is not None or self._stopped.is_set():
            raise SwapError("reverse lifetime start refused")
        self._deadline = time.monotonic() + self._duration

    @property
    def deadline(self) -> float:
        if self._deadline is None:
            raise SwapError("reverse payment lifetime not started")
        return self._deadline

    def allowed(self) -> bool:
        """Expose only local, thread-safe payment/signing permission."""
        return (
            self._deadline is not None
            and not self._stopped.is_set()
            and time.monotonic() < self._deadline
        )

    def check(self) -> None:
        if not self.allowed():
            raise TimeoutError

    def _check_work(self) -> None:
        if self._stopped.is_set() or (
            self._deadline is not None and time.monotonic() >= self._deadline
        ):
            raise TimeoutError

    async def worker(self, function: Callable[[], _T]) -> _T:
        """Shield execution, reject late authority, retain uncertain work to drain."""
        self._check_work()

        def execute() -> _T:
            self._check_work()  # Executor queueing cannot reserve authority.
            return function()

        context = contextvars.copy_context()
        task = asyncio.get_running_loop().run_in_executor(None, context.run, execute)
        self._workers.add(task)
        try:
            if self._deadline is None:
                await asyncio.wait((task,))
            else:
                async with asyncio.timeout(max(0, self._deadline - time.monotonic())):
                    await asyncio.wait((task,))
            result = task.result()
            self._check_work()
            return result  # noqa: TRY300 - a late-result refusal must stop future work
        except (TimeoutError, asyncio.CancelledError):
            self._stopped.set()
            raise
        finally:
            if task.done():
                if not task.cancelled():
                    task.exception()  # Consume an uncertain late failure before releasing custody.
                self._workers.discard(task)


class ClaimWallet(Protocol):
    """The user's own Core node and wallet (``WalletRpc``)."""

    def tip_height(self) -> int:
        """Return the best height."""
        ...

    def next_block_fee(self) -> NextBlockFee:
        """Return this node's next-block advice and relay floors."""
        ...

    def new_destination_script(self) -> bytes:
        """Return a fresh payout scriptPubKey."""
        ...

    def confirmed_output(self, txid: str, vout: int) -> ConfirmedOutput | None:
        """Return the outpoint as Core sees it, or None when unknown or spent."""
        ...

    def unspent_on_chain(self, txid: str, vout: int) -> bool:
        """Whether the output is unspent in the active chain (mempool ignored)."""
        ...

    def mempool_spender(self, txid: str, vout: int) -> str | None:
        """Return the txid of a mempool transaction spending the output, or None."""
        ...

    def wallet_confirmations(self, txid: str) -> int | None:
        """Depth of a wallet transaction, ``None`` when unknown."""
        ...

    def broadcast(
        self,
        raw: bytes,
        *,
        deadline: float | None = None,
        effect_allowed: Callable[[], bool] | None = None,
    ) -> str:
        """Submit exact bytes; return Core's txid."""
        ...


class HoldPayer(Protocol):
    """The user's own LND (``LndHoldPayer``) or wallet (``ExternalWalletPayer``).

    ``"SHOWN"`` means the invoice was shown for an external wallet, whose
    payment is not observable; only the provider's funding proves it is held.
    """

    def pay(  # noqa: PLR0913 - exact invoice bounds and original lifetime
        self,
        bolt11: str,
        *,
        invoice_binding: InvoiceBinding,
        min_final_expiry_height: int,
        max_expiry_height: int,
        fee_limit_sat: int,
        deadline: float | None = None,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> HoldStatus | Literal["SHOWN"]:
        """Submit (or show) the hold payment once."""
        ...


@dataclass(frozen=True, slots=True)
class ReverseSwapLimits:
    """The user's ceilings for the firm offer and the payment.

    The requested claim fee reserve is at least ``min_claim_fee_reserve_sat``
    and the larger script-path claim at Core's next-block estimate (never
    below Core's relay and mempool floor) or ``claim_fee_rate_sat_vb`` (an
    optional floor, 0 for none), whichever is higher, so the cooperative
    claim pays at least that rate too. The claim pays exactly the signed
    reserve, so the destination receives exactly the nominal payout.

    ``claim_confirmations`` claims after fewer confirmations of the provider's
    funding than the signed ``funding_confirmations`` (0: from the mempool).
    ``None`` waits for the signed depth. Claiming earlier discloses the
    preimage while the provider can still double-spend its funding.
    """

    max_success_fee_sat: int
    min_claim_fee_reserve_sat: int
    max_claim_fee_sat: int
    min_refund_delay_blocks: int  # blocks the provider must wait before refunding
    max_incoming_htlc_delay_blocks: int  # how long the LN funds may stay held
    max_routing_fee_sat: int
    claim_fee_rate_sat_vb: int = 0
    claim_confirmations: int | None = None


@dataclass(frozen=True, slots=True)
class ReverseSwapOutcome:
    """A claimed swap: the claim transaction pays the client's destination.

    ``payout_sat`` is the contract value; the destination receives it less
    ``claim_fee_sat``, the fee of the confirmed claim transaction.
    """

    session_id: str
    contract_hash: str
    funding_txid: str
    claim_txid: str
    payout_sat: int
    claim_fee_sat: int


def minimum_claim_fee_reserve_sat(
    destination: bytes, fee: NextBlockFee, limits: ReverseSwapLimits
) -> int:
    """Return the least claim fee reserve to ask for (see ``ReverseSwapLimits``)."""
    if type(fee) is not NextBlockFee or type(limits.claim_fee_rate_sat_vb) is not int:
        raise SwapError("claim fee inputs unsupported")
    if limits.claim_fee_rate_sat_vb < 0:
        raise SwapError("claim fee inputs unsupported")
    try:
        _, unilateral = claim_vsizes(destination)  # the script path is the larger claim
    except ValidationError:
        raise SwapError("claim destination unsupported") from None
    rate = max(fee.rate_sat_kvb, fee.floor_sat_kvb, limits.claim_fee_rate_sat_vb * 1000)
    return max(limits.min_claim_fee_reserve_sat, -(-unilateral * rate // 1000))


def _check_offer(  # noqa: PLR0913 - every binding checked explicitly
    offer: TermsOfferPayload,
    request: ReverseFirmQuoteRequest,
    *,
    envelope: Envelope,
    transcript: str,
    hold: InvoiceBinding,
    identity: str,
    network: NetworkIdentity,
    crypto: Context,
    now: int,
) -> ContractTerms:
    check_reverse_terms_offer(
        request, offer, handshake_hash=transcript, invoice_binding=hold, now=now
    )
    # The validator rejects ERC20 terms before this Bitcoin-only path.
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


def _check_funding(  # noqa: PLR0913 - every binding checked explicitly
    envelope: Envelope,
    *,
    terms: ContractTerms,
    contract: str,
    provider_key: str,
    script: bytes,
    crypto: Context,
) -> tuple[FundingBinding, str, bytes]:
    """Return the provider's binding, its signature, and the exact transaction bytes."""
    payload = parse_model_json(FundingBindingPayload, canonicalize(envelope.payload))
    binding = payload.binding
    crypto.schnorr_verify(
        bytes.fromhex(provider_key),
        funding_binding_hash(binding),
        bytes.fromhex(payload.funding_binding_signature),
    )
    if not (
        binding.contract_hash == contract == envelope.contract_hash
        and binding.funder_role == "provider"
        and binding.binding_revision == 0
        and binding.replaces_txid is None
        and binding.contract_script_pubkey == script.hex()
        and binding.contract_value_sat == terms.economics.contract_amount_sat
    ):
        raise SwapError("provider's funding binding does not fund these terms")
    raw = bytes.fromhex(payload.funding_transaction)
    match = check_funding_binding_transaction(raw, binding, terms, keys=crypto)
    if (match.funding_txid, match.contract_vout) != (binding.funding_txid, binding.contract_vout):
        raise SwapError("provider's funding transaction differs from its binding")
    return binding, payload.funding_binding_signature, raw


async def _await_funding(  # noqa: PLR0912, PLR0913 - one FIFO and its explicit waiting bounds
    session: _Session,
    *,
    contract: str,
    timeout: float,  # noqa: ASYNC109
    terms: ContractTerms,
    provider_key: str,
    script: bytes,
    crypto: Context,
    absolute_deadline: float | None = None,
) -> tuple[FundingBinding, str, bytes]:
    """Own the original FIFO until funding under one nonrenewing wait budget.

    Never skip an earlier action or foreign context to a later binding. Reverse
    cooperation is not available here; no readiness or signing is attempted.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise SwapError("funding timeout must be finite and positive")
    deadline = time.monotonic() + timeout
    if absolute_deadline is not None:
        if type(absolute_deadline) not in (int, float) or not math.isfinite(absolute_deadline):
            raise SwapError("funding deadline must be finite")
        deadline = min(deadline, absolute_deadline)
    timeout_error = (
        f"provider funding not observed in time; {_CHECK_PAYMENT}; "
        "the held payment fails back when the provider cancels the hold; do not retry payment"
    )
    context_hint = f"funding status unresolved; {_CHECK_PAYMENT}; do not retry payment"
    async with session.settlement_stream():
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SwapError(timeout_error)
            try:
                message = await session.receive_next(timeout=remaining)
            except TimeoutError:
                raise SwapError(timeout_error) from None
            except SwapError:
                raise SwapError("provider session stopped; " + context_hint) from None
            if time.monotonic() >= deadline:
                raise SwapError(timeout_error)
            if message.in_reply_to is not None or message.contract_hash != contract:
                raise SwapError("unexpected provider funding context; " + context_hint)
            if message.message_type == "funding_binding":
                checked = _check_funding(
                    message,
                    terms=terms,
                    contract=contract,
                    provider_key=provider_key,
                    script=script,
                    crypto=crypto,
                )
                if time.monotonic() >= deadline:
                    raise SwapError(timeout_error)
                return checked
            if message.message_type != "observation":
                raise SwapError("unexpected provider funding message; " + context_hint)
            try:
                seen = parse_observation(canonicalize(message.payload))
            except ValueError:
                raise SwapError("invalid provider funding observation; " + context_hint) from None
            if seen.kind == "swap_aborted":
                raise SwapError(
                    f"provider reported an abort before funding ({seen.reason}); " + context_hint
                )


async def _await_depth(  # noqa: PLR0913 - explicit waiting bounds
    wallet: ClaimWallet,
    *,
    binding: FundingBinding,
    script: bytes,
    value: int,
    depth: int,
    lock_height: int,
    lifetime: _ReverseLifetime,
    report: Callable[[str], None],
) -> None:
    """Poll Core until the contract output has ``depth`` confirmations.

    The contract is funded by now, so a failed Core read is no evidence and
    never ends the swap: it waits within the lifetime, like the claim does.
    """
    unavailable = False
    while True:
        lifetime.check()
        sample = await lifetime.worker(lambda: _depth_sample(wallet, binding))
        lifetime.check()
        if sample is None:
            if not unavailable:  # once per outage
                report(f"Core unavailable while funding {binding.funding_txid} confirms; retrying")
            unavailable = True
        else:
            unavailable = False
            seen, tip = sample
            if tip >= lock_height:
                raise SwapError("the refund lock passed before funding was usable; " + _UNRESOLVED)
            if seen is not None:
                if (seen.script_pubkey, seen.value_sat) != (script, value):
                    raise SwapError("Core shows another output at the provider's funding outpoint")
                if seen.confirmations >= depth:
                    return
            report(
                f"funding {binding.funding_txid} at depth "
                f"{0 if seen is None else seen.confirmations}/{depth}"
            )
        await asyncio.sleep(min(POLL_SECONDS, max(0, lifetime.deadline - time.monotonic())))


def _depth_sample(
    wallet: ClaimWallet, binding: FundingBinding
) -> tuple[ConfirmedOutput | None, int] | None:
    """Return the contract output as Core sees it and the tip, or ``None`` if Core failed."""
    try:
        seen = wallet.confirmed_output(binding.funding_txid, binding.contract_vout)
        return seen, wallet.tip_height()
    except Exception:  # noqa: BLE001 - a failed sample is no evidence; wait
        return None


def _claim_signer(  # noqa: PLR0913 - explicit signing inputs
    terms: ContractTerms,
    binding: FundingBinding,
    *,
    script: bytes,
    contract_secret: bytes,
    preimage: bytes,
    crypto: Context,
    check_authority: Callable[[], None] | None = None,
) -> tuple[Callable[[int, int], tuple[bytes, str, int, int]], int]:
    """Return ``sign(fee, tip) -> (raw, txid, fee, vsize)`` and the fee ceiling."""
    funding = FundingOutput(
        txid=bytes.fromhex(binding.funding_txid),
        output_index=binding.contract_vout,
        value_sat=int(terms.economics.contract_amount_sat),
        script_pubkey=script,
    )
    if check_authority is not None:
        check_authority()
    authorization = UnilateralAuthorization.from_terms(terms, funding, "claim", keys=crypto)

    def sign(fee: int, _tip: int) -> tuple[bytes, str, int, int]:
        if check_authority is not None:
            check_authority()
        plan = build_unilateral_spend(authorization, fee_sat=fee, claim_preimage=preimage)
        if check_authority is not None:
            check_authority()
        signature = bytes(
            crypto.schnorr_sign(contract_secret, plan.signature_hash, secrets.token_bytes(32))
        )
        spend = finalize_unilateral_spend(plan, signature, verifier=crypto)
        if check_authority is not None:
            check_authority()
        return spend.raw_transaction, spend.txid, spend.fee_sat, spend.vsize

    return sign, max_spendable_fee(authorization)


def _chain_view(
    wallet: ClaimWallet,
    binding: FundingBinding,
    *,
    unconfirmed_funding: bool = False,
    resubmit_funding: Callable[[], object] | None = None,
) -> ChainView | None:
    """Sample whether a confirmed transaction may already spend the funding output.

    ``unconfirmed_funding`` is for claims below the signed depth, where the
    funding may still be unconfirmed: it is then absent from the chain-only
    UTXO set, yet nothing confirmed can spend it while Core's mempool holds it
    unspent or holds a spender (normally our claim; a confirmed output cannot
    have one once spent on chain). The checks run in an order where a funding
    or claim confirming between them reads as unspent or as our confirmed
    claim, never as a foreign spend. At the signed depth only the chain counts.

    Below the signed depth, funding gone from every view proves no foreign
    spend: it may have been evicted from the mempool (or double-spent by the
    provider, which only a confirmed conflict would show). That sample is
    unknown, so the watcher keeps checking our own claims and waiting within
    its lifetime, and ``resubmit_funding`` rebroadcasts the provider's signed
    funding so that the claim can follow it again.
    """
    txid, vout = binding.funding_txid, binding.contract_vout
    try:
        tip = wallet.tip_height()
        if wallet.unspent_on_chain(txid, vout):
            return ChainView(tip, unspent_on_chain=True)
        if not unconfirmed_funding:
            return ChainView(tip, unspent_on_chain=False)
        if (
            wallet.confirmed_output(txid, vout) is not None
            or wallet.mempool_spender(txid, vout) is not None
        ):
            return ChainView(tip, unspent_on_chain=True)
    except Exception:  # noqa: BLE001 - a failed sample is no evidence; wait
        return None
    if resubmit_funding is not None:
        resubmit_funding()
    return None


def _funding_resubmitter(  # noqa: PLR0913 - one funding and the watcher's live state
    wallet: ClaimWallet,
    binding: FundingBinding,
    raw: bytes,
    *,
    attempts: Sequence[ClaimAttempt],
    submit: Callable[[bytes, str], bool],
    report: Callable[[str], None],
) -> Callable[[], None]:
    """Rebroadcast the provider's verified funding when an early claim finds it gone.

    ``attempts`` is the watcher's live claim list. At depth 0 the funding and
    our claim usually confirm in one block, which also empties every view: if
    one of our claims confirmed, the watcher finds it and nothing is sent.
    Otherwise the funding was evicted or double-spent: put the signed parent
    back so the claim can follow it. A rejection (its inputs already spent)
    changes nothing; the watcher keeps waiting within its lifetime.
    """
    missing = False

    def resubmit() -> None:
        nonlocal missing
        try:
            ours = any(
                type(confirmed := wallet.wallet_confirmations(attempt.txid)) is int
                and confirmed > 0
                for attempt in attempts
            )
        except Exception:  # noqa: BLE001 - no evidence either way; the next sample retries
            return
        if ours:
            return
        if not missing:
            missing = True
            report(
                f"the provider's funding {binding.funding_txid} is not visible to Core "
                "(evicted or double-spent); rebroadcasting it before the claim"
            )
        if submit(raw, binding.funding_txid):
            missing = False

    return resubmit


def claim_depth(signed: int, requested: int | None) -> int:
    """Return the funding depth to claim at: the signed one unless the user asked for less."""
    if requested is None:
        return signed
    if type(requested) is not int or requested < 0:
        raise SwapError("claim confirmations must be a nonnegative integer")
    return min(requested, signed)


def early_claim_warning(depth: int, signed: int) -> str | None:
    """Explain the double-spend risk of claiming below the signed depth, or None."""
    if depth >= signed:
        return None
    funding = "unconfirmed funding" if depth == 0 else f"funding at {depth} confirmation(s)"
    return (
        f"warning: claiming on {funding}, below the provider's signed {signed}. "
        "Claiming reveals the preimage, which lets the provider settle your Lightning "
        "payment; until its funding is buried it can still double-spend it and keep both. "
        "Only lower this for providers and amounts you are willing to lose."
    )


def _submit(wallet: ClaimWallet, raw: bytes, txid: str, lifetime: _ReverseLifetime) -> bool:
    lifetime.check()  # Expired authority is not an ordinary retryable RPC failure.
    try:
        result = wallet.broadcast(raw, deadline=lifetime.deadline, effect_allowed=lifetime.allowed)
    except TimeoutError:
        raise
    except Exception:  # noqa: BLE001 - e.g. a replacement below the mempool's; retried
        lifetime.check()  # WalletRpc reports authority refusal as WalletRpcError.
        return False
    lifetime.check()
    return result == txid


async def _publish_reverse_fallback(  # noqa: PLR0913 - exact retained predecessor and private claim
    lifetime: _ReverseLifetime,
    *,
    funded_document: bytes,
    binding: FundingBinding,
    transaction: bytes,
    session: _Session,
    write_recovery: Callable[[bytes, bytes | None], bytes | None],
) -> bytes:
    """Require the trusted writer's exact acknowledgment, never infer disclosure authority.

    The CLI returns bytes only after durable encrypted publication and readback.
    Matching bytes detect accidental no-ops, not a lying storage adapter. A late
    or uncertain write may leave a valid sibling, but cannot reopen cooperation.
    """
    lifetime.check()

    def prepare() -> bytes:
        lifetime.check()
        record = parse_json_strict(funded_document)
        if not isinstance(record, dict):
            raise SwapError("reverse fallback predecessor unavailable")
        extensions = record.get("extensions")
        if not isinstance(extensions, dict):
            raise SwapError("reverse fallback predecessor unavailable")
        if REVERSE_FALLBACK_EXTENSION in extensions:
            raise SwapError("reverse fallback already prepared; restart cannot resume cooperation")
        extensions[REVERSE_FALLBACK_EXTENSION] = {
            "version": 1,
            "funding_binding_hash": funding_binding_hash(binding).hex(),
            "transaction": transaction.hex(),
        }
        candidate = canonicalize(record)
        inspect_recovery_successor(
            funded_document, candidate, session.network, crypto=session.crypto
        )
        lifetime.check()
        return candidate

    try:
        candidate = await lifetime.worker(prepare)
        acknowledged = await lifetime.worker(lambda: write_recovery(candidate, funded_document))
    except (TimeoutError, asyncio.CancelledError):
        raise
    except Exception:  # noqa: BLE001 - publication errors may contain encrypted/plaintext secrets
        raise SwapError("reverse fallback publication uncertain; " + _UNRESOLVED) from None
    lifetime.check()
    if type(acknowledged) is not bytes or acknowledged != candidate:
        raise SwapError("reverse fallback publication not acknowledged; " + _UNRESOLVED)
    return candidate


async def _publish_reverse_disclosure(  # noqa: PLR0913 - exact acknowledged predecessor and original proposal
    lifetime: _ReverseLifetime,
    *,
    acknowledged_fallback: bytes,
    binding: FundingBinding,
    proposal: Envelope,
    session: _Session,
    write_recovery: Callable[[bytes, bytes | None], bytes | None],
) -> bytes:
    """Publish a local disclosure reservation without sending its proposal.

    INTERNAL ONLY. The live caller must retain its exact trusted-writer fallback
    acknowledgment, not load a restored snapshot as authority. Byte equality
    detects accidental no-ops, not dishonest storage or lost nonce custody.
    Core inspection preserves historical evidence; this live boundary separately
    checks current wall time before and after publication. An uncertain or late
    write can leave a valid file without granting transmission/signing authority.
    """
    lifetime.check()
    wall_high_water: float | None = None
    proposal_document = proposal.model_dump(mode="json")
    signed_deadline = proposal_document["payload"].get("deadline_at")

    def check_wall(predecessor_time: int) -> float:
        nonlocal wall_high_water
        lifetime.check()
        wall = time.time()
        if (
            type(signed_deadline) is not int
            or type(wall) not in (int, float)
            or not math.isfinite(wall)
            or wall < predecessor_time
            or (wall_high_water is not None and wall < wall_high_water)
            or wall >= signed_deadline
        ):
            raise SwapError("reverse disclosure publication time refused")
        wall_high_water = wall
        return wall

    def prepare() -> tuple[bytes, int]:
        lifetime.check()
        record = parse_json_strict(acknowledged_fallback)
        if not isinstance(record, dict):
            raise SwapError("reverse disclosure predecessor unavailable")
        extensions = record.get("extensions")
        previous_time = record.get("updated_at")
        if (
            not isinstance(extensions, dict)
            or REVERSE_FALLBACK_EXTENSION not in extensions
            or REVERSE_DISCLOSURE_EXTENSION in extensions
            or type(previous_time) is not int
        ):
            raise SwapError("reverse disclosure predecessor unavailable")
        record["updated_at"] = int(check_wall(previous_time))
        extensions[REVERSE_DISCLOSURE_EXTENSION] = {
            "version": 1,
            "funding_binding_hash": funding_binding_hash(binding).hex(),
            "proposal": proposal_document,
        }
        candidate = canonicalize(record)
        inspect_recovery_successor(
            acknowledged_fallback, candidate, session.network, crypto=session.crypto
        )
        lifetime.check()
        return candidate, previous_time

    try:
        candidate, previous_time = await lifetime.worker(prepare)

        def publish() -> bytes | None:
            check_wall(previous_time)
            return write_recovery(candidate, acknowledged_fallback)

        acknowledged = await lifetime.worker(publish)
        check_wall(previous_time)
    except (TimeoutError, asyncio.CancelledError):
        raise
    except Exception:  # noqa: BLE001 - never expose preimage, proposal, or storage details
        raise SwapError("reverse disclosure publication uncertain; " + _UNRESOLVED) from None
    lifetime.check()
    if type(acknowledged) is not bytes or acknowledged != candidate:
        raise SwapError("reverse disclosure publication not acknowledged; " + _UNRESOLVED)
    return candidate


async def _publish_reverse_cooperation_reservation(  # noqa: PLR0913 - exact durable predecessor boundary
    lifetime: _ReverseLifetime,
    *,
    acknowledged_fallback: bytes,
    binding: FundingBinding,
    cooperation_id: bytes,
    session: _Session,
    write_recovery: Callable[[bytes, bytes | None], bytes | None],
    check_window: Callable[[], None],
) -> bytes:
    """Burn one original live attempt before allocating any native nonce."""

    def prepare() -> bytes:
        lifetime.check()
        check_window()
        record = parse_json_strict(acknowledged_fallback)
        if not isinstance(record, dict):
            raise SwapError("reverse reservation predecessor unavailable")
        extensions, record_time = record.get("extensions"), record.get("updated_at")
        if (
            not isinstance(extensions, dict)
            or REVERSE_FALLBACK_EXTENSION not in extensions
            or REVERSE_COOPERATIVE_RESERVATION_EXTENSION in extensions
            or REVERSE_DISCLOSURE_EXTENSION in extensions
            or type(record_time) is not int
        ):
            raise SwapError("reverse reservation predecessor unavailable")
        wall = time.time()
        if type(wall) not in (int, float) or not math.isfinite(wall) or wall < record_time:
            raise SwapError("reverse reservation time refused")
        record["updated_at"] = int(wall)
        extensions[REVERSE_COOPERATIVE_RESERVATION_EXTENSION] = {
            "funding_binding_hash": funding_binding_hash(binding).hex(),
            "cooperation_id": cooperation_id.hex(),
        }
        candidate = canonicalize(record)
        inspect_recovery_successor(
            acknowledged_fallback, candidate, session.network, crypto=session.crypto
        )
        check_window()
        return candidate

    try:
        candidate = await lifetime.worker(prepare)

        def publish() -> bytes | None:
            lifetime.check()
            check_window()
            return write_recovery(candidate, acknowledged_fallback)

        acknowledged = await lifetime.worker(publish)
        check_window()
    except (TimeoutError, asyncio.CancelledError):
        raise
    except Exception:  # noqa: BLE001 - no recovery or signer details in diagnostics
        raise SwapError("reverse cooperation reservation uncertain; " + _UNRESOLVED) from None
    if type(acknowledged) is not bytes or acknowledged != candidate:
        raise SwapError("reverse cooperation reservation not acknowledged; " + _UNRESOLVED)
    return candidate


async def _cooperative_claim(  # noqa: PLR0911, PLR0912, PLR0913, PLR0915 - keep the ordered one-shot custody boundaries together
    lifetime: _ReverseLifetime,
    *,
    session: _Session,
    init: HandshakeInit,
    accept: HandshakeAccept,
    terms: ContractTerms,
    binding: FundingBinding,
    script: bytes,
    contract_secret: bytes,
    preimage: bytes,
    fee_sat: int,
    acknowledged_fallback: bytes,
    wallet: ClaimWallet,
    write_recovery: Callable[[bytes, bytes | None], bytes | None],
    report: Callable[[str], None],
    on_disclosure: Callable[[], None] = lambda: None,
) -> ClaimAttempt | None:
    """Try the private key-path claim once; None means claim unilaterally.

    The signed script-path fallback is already durable, so the preimage leaves
    this process only inside a proposal whose exact disclosure snapshot was
    acknowledged first. The native nonce is used for at most this one reply
    and closed on every path. Any refusal, timeout, or invalid reply returns
    None; the caller's watcher then claims with the preimage as before.
    """
    # The one window starts before any native authorization/plan preparation.
    lifetime.check()
    started, wall_started = time.monotonic(), time.time()
    needed = (
        REVERSE_PROPOSAL_SECONDS + REVERSE_REPLY_GRACE_SECONDS + REVERSE_UNILATERAL_RESERVE_SECONDS
    )
    if lifetime.deadline - started < needed:
        report("cooperative claim window unavailable; claiming unilaterally")
        return None
    deadline = min(
        started + REVERSE_PROPOSAL_SECONDS + REVERSE_REPLY_GRACE_SECONDS,
        lifetime.deadline - REVERSE_UNILATERAL_RESERVE_SECONDS,
    )
    deadline_at = int(wall_started + deadline - started)
    wall_high_water = wall_started

    def check_window() -> None:
        nonlocal wall_high_water
        lifetime.check()
        now, wall = time.monotonic(), time.time()
        if not math.isfinite(now) or not math.isfinite(wall):
            raise SwapError("cooperative clock unavailable")
        wall_high_water = max(wall_high_water, wall)
        if now < started or now >= deadline or wall_high_water >= deadline_at:
            raise SwapError("cooperative window expired")

    crypto = session.crypto
    deadline_height = terms.refund_lock_height - terms.timing_policy.claim_confirmation_blocks
    try:
        check_window()
        funding = FundingOutput(
            txid=bytes.fromhex(binding.funding_txid),
            output_index=binding.contract_vout,
            value_sat=int(terms.economics.contract_amount_sat),
            script_pubkey=script,
        )
        authorization = UnilateralAuthorization.from_terms(terms, funding, "claim", keys=crypto)
        plan = build_cooperative_claim(authorization, fee_sat=fee_sat)
        tweak = reconstruct_taproot_contract(terms, keys=crypto).tap_tweak
        tip = await lifetime.worker(wallet.tip_height)
        check_window()
    except (TimeoutError, asyncio.CancelledError):
        raise
    except Exception:  # noqa: BLE001 - no fresh tip, no disclosure; claim unilaterally
        tip = None
    if type(tip) is not int or tip > deadline_height:
        report("cooperative claim window unavailable; claiming unilaterally")
        return None
    user_key = bytes.fromhex(terms.client_contract_compressed_key)
    provider_key = bytes.fromhex(terms.provider_contract_compressed_key)
    cooperation_id = secrets.token_bytes(32)
    try:
        burned = await _publish_reverse_cooperation_reservation(
            lifetime,
            acknowledged_fallback=acknowledged_fallback,
            binding=binding,
            cooperation_id=cooperation_id,
            session=session,
            write_recovery=write_recovery,
            check_window=check_window,
        )
        check_window()
    except SwapError:
        report("cooperative attempt not reserved; claiming unilaterally")
        return None
    try:
        attempt, nonce = crypto.musig_begin(
            secret_key=contract_secret,
            user_public_key=user_key,
            provider_public_key=provider_key,
            tap_tweak=tweak,
            message=plan.signature_hash,
            cooperation_id=cooperation_id,
        )
    except Exception:  # noqa: BLE001 - the durable burn is never retried after native failure
        lifetime.check()
        report("cooperative nonce unavailable; claiming unilaterally")
        return None
    try:
        proposal = session.envelope(
            "action_request",
            {
                "action": "cooperative_claim_propose",
                "cooperation_id": cooperation_id.hex(),
                "unsigned_transaction": plan.base_transaction.hex(),
                "payment_preimage": preimage.hex(),
                "public_nonce": nonce.hex(),
                "deadline_at": deadline_at,
                "deadline_height": deadline_height,
            },
            contract=contract_hash(terms).hex(),
            required_features=(COOPERATIVE_CLAIM_FEATURE,),
        )
        try:
            await _publish_reverse_disclosure(
                lifetime,
                acknowledged_fallback=burned,
                binding=binding,
                proposal=proposal,
                session=session,
                write_recovery=write_recovery,
            )
        except SwapError:
            report("cooperative disclosure not recorded; claiming unilaterally")
            return None
        try:
            check_window()
            async with asyncio.timeout(max(0, deadline - time.monotonic())):
                on_disclosure()  # Sending may disclose the preimage even when the reply is lost.
                with session.guard_publication(check_window):
                    await session.send(proposal, session.provider_key or "")
                check_window()
                report("cooperative claim proposed; waiting for the provider's signature")
                reply = await session.receive(
                    lambda item: item.in_reply_to == proposal.message_id,
                    timeout=max(0, deadline - time.monotonic()),
                )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - relay loss or reply timeout; the claim must proceed
            lifetime.check()  # An expired swap lifetime is not a cooperative refusal.
            report("no cooperative signature in time; claiming unilaterally")
            return None
        lifetime.check()
        try:
            check_window()
            payload = check_cooperative_action_context(
                reply, terms, init, accept, prior_request=proposal
            )
            if not isinstance(payload, CooperativeClaimSigned):
                report("provider declined cooperation; claiming unilaterally")
                return None
            transcript = {
                "user_public_key": user_key,
                "provider_public_key": provider_key,
                "tap_tweak": tweak,
                "message": plan.signature_hash,
                "user_public_nonce": nonce,
                "provider_public_nonce": bytes.fromhex(payload.public_nonce),
            }
            provider_partial = bytes.fromhex(payload.partial_signature)
            crypto.musig_partial_verify(
                **transcript, signer_index=1, partial_signature=provider_partial
            )
            check_window()
            user_partial = attempt.partial_sign_once(transcript["provider_public_nonce"])
            check_window()
            signature = crypto.musig_aggregate(
                **transcript,
                user_partial_signature=user_partial,
                provider_partial_signature=provider_partial,
            )
            claim = finalize_cooperative_claim(plan, signature, verifier=crypto)
            check_window()
        except Exception:  # noqa: BLE001 - an invalid reply only costs privacy, never funds
            report("provider cooperative signature invalid; claiming unilaterally")
            return None
        try:
            check_window()
            complete = session.envelope(
                "action_request",
                {
                    "action": "cooperative_claim_complete",
                    "cooperation_id": cooperation_id.hex(),
                    "partial_signature": user_partial.hex(),
                },
                contract=contract_hash(terms).hex(),
                required_features=(COOPERATIVE_CLAIM_FEATURE,),
            )
            async with asyncio.timeout(max(0, deadline - time.monotonic())):
                await session.send(complete, session.provider_key or "")
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a receipt is not required for the verified key-path claim
            lifetime.check()
            report("cooperative completion delivery uncertain; continuing with verified claim")
    finally:
        attempt.close()
    accepted = await lifetime.worker(
        lambda: _submit(wallet, claim.raw_transaction, claim.txid, lifetime)
    )
    report(
        f"cooperative claim {claim.txid} at {claim.fee_sat} sat "
        f"{'broadcast' if accepted else 'not accepted yet'}"
    )
    return ClaimAttempt(claim.txid, claim.raw_transaction, claim.fee_sat, claim.vsize, tip)


def _settlement_capability(
    wallet: ClaimWallet,
    *,
    await_settlement: bool,
) -> Callable[..., HistoricalWalletOutput] | None:
    """Admit the explicit stronger mode before secrets or remote effects.

    This capability is an operator-trusted wallet dependency, not provenance
    conferred by a returned record's type. Legacy wallets are never inspected.
    """
    if type(await_settlement) is not bool:
        raise SwapError("await_settlement must be a boolean")
    if not await_settlement:
        return None
    try:
        observer = getattr(wallet, "observe_historical_wallet_output", None)
        supported = (
            callable(observer)
            and not inspect.iscoroutinefunction(observer)
            and not inspect.iscoroutinefunction(getattr(observer, "__call__", None))  # noqa: B004 - inspect async callable methods after the separate callability check
        )
        # Check the named budget contract without calling the backend. This
        # prevents a structurally unsupported capability from failing after pay.
        if supported:
            inspect.signature(cast("Callable[..., HistoricalWalletOutput]", observer)).bind(
                "00" * 32, b"\x51\x20" + bytes(32), deadline_seconds=1.0
            )
    except Exception:  # noqa: BLE001 - operator callback details may contain secrets
        supported = False
    if not supported:
        raise SwapError(
            "terminal settlement requires a synchronous historical wallet observer"
        ) from None
    return cast("Callable[..., HistoricalWalletOutput]", observer)


async def _await_claim_settlement(  # noqa: PLR0913 - original operation and exact selected spend
    lifetime: _ReverseLifetime,
    observer: Callable[..., HistoricalWalletOutput],
    selected: ClaimAttempt,
    *,
    network: NetworkIdentity,
    destination: bytes,
    value_sat: int,
    depth: int,
    report: Callable[[str], None],
) -> None:
    """Observe signed-depth completion; never resume the effectful watcher.

    Historical output timestamps are epoch times, not execution clocks. Live
    admission/result acceptance uses the original monotonic owner instead.
    Both native claim constructors/validators require one destination output,
    therefore its index is zero, not the funding contract's output index.
    """
    while True:
        lifetime.check()

        def acquire() -> HistoricalWalletOutput:
            # Compute remaining time inside the admitted executor callback.
            lifetime.check()
            remaining = lifetime.deadline - time.monotonic()
            observed = observer(selected.txid, destination, deadline_seconds=min(10.0, remaining))
            # Dispose only native coroutines, without executing arbitrary
            # awaitables. Do this here even if ownership expires during the call
            # and the worker's result will never be admitted by its caller.
            if inspect.iscoroutine(observed):
                observed.close()
            return observed

        failed = False
        expired = False
        try:
            observed = await lifetime.worker(acquire)
            valid = (
                type(observed) is HistoricalWalletOutput
                and type(observed.network) is NetworkIdentity
                and observed.network == network
                and type(observed.txid) is str
                and observed.txid == selected.txid
                and type(observed.vout) is int
                and observed.vout == 0
                and type(observed.value_sat) is int
                and observed.value_sat == value_sat - selected.fee_sat > 0
                and type(observed.script_pubkey) is bytes
                and observed.script_pubkey == destination
                and type(observed.confirmations) is int
                and observed.confirmations > 0
                and type(observed.block_height) is int
                and observed.block_height > 0
                and type(observed.block_hash) is str
                and re.fullmatch(r"[0-9a-f]{64}", observed.block_hash) is not None
                and type(observed.started_at) in (int, float)
                and math.isfinite(observed.started_at)
                and type(observed.completed_at) in (int, float)
                and math.isfinite(observed.completed_at)
                and observed.started_at <= observed.completed_at
            )
        except TimeoutError:
            expired = True
        except Exception:  # noqa: BLE001 - upstream errors may carry private transaction material
            failed = True
        # Raise outside upstream handlers so public errors retain neither private
        # callback arguments nor their exception context.
        if expired:
            raise TimeoutError
        if failed:
            raise SwapError("claim settlement observation is unresolved; " + _UNRESOLVED)
        if not valid:
            raise SwapError("claim settlement observation differs; " + _UNRESOLVED)
        lifetime.check()
        if observed.confirmations >= depth:
            report(f"claim {selected.txid} observed at signed settlement depth {depth}")
            lifetime.check()
            return
        await asyncio.sleep(min(POLL_SECONDS, max(0, lifetime.deadline - time.monotonic())))


async def run_reverse_swap(  # noqa: PLR0912, PLR0913, PLR0915 - one ordered swap story
    connection: RelayTransport,
    *,
    identity: str,
    network: NetworkIdentity,
    payout_sat: int,
    decode_invoice: Callable[[str], InvoiceBinding],
    payer: HoldPayer,
    wallet: ClaimWallet,
    write_recovery: Callable[[bytes, bytes | None], bytes | None],
    limits: ReverseSwapLimits,
    crypto: Context,
    timeout: float = 60.0,  # noqa: ASYNC109
    settle_timeout: float = 1800.0,
    await_settlement: bool = False,
    report: Callable[[str], None] = lambda _line: None,
    funding_inclusion_observer: Callable[[FundingBinding, ContractTerms, float], None]
    | None = None,
) -> ReverseSwapOutcome:
    """Run one LN to BTC swap; see the module docstring for the order.

    Optional ``funding_inclusion_observer`` is synchronous and awaited after
    funded recovery acknowledgment/required depth, before first claim signing.
    It receives the original absolute monotonic settlement deadline, not a new
    budget. Failure stops progression; cancellation drains its worker before
    return. Work/publication may finish late, but late results authorize no claim.

    Default completion is claim progress, not signed-depth terminal completion.
    Explicit ``await_settlement=True`` requires the trusted wallet's synchronous
    ``observe_historical_wallet_output`` capability before creating a session.
    After the selected claim confirms, only read-only observation continues under
    the original lifetime, enforcing the signed depth and active-block evidence.
    The backend must perform fresh block-hash revalidation; its record's type
    alone supplies no provenance. Success observes chain completion for that
    claim, not irreversible finality, merchant payment or available inventory.
    The outcome's existing five-field shape is unchanged in either mode.
    """
    if not math.isfinite(settle_timeout) or settle_timeout <= 0:
        raise SwapError("settlement timeout must be finite and positive")
    claim_depth(0, limits.claim_confirmations)  # refuse a malformed request before any session
    settlement_observer = _settlement_capability(wallet, await_settlement=await_settlement)
    if funding_inclusion_observer is not None and (
        not callable(funding_inclusion_observer)
        or inspect.iscoroutinefunction(funding_inclusion_observer)
        or inspect.iscoroutinefunction(getattr(funding_inclusion_observer, "__call__", None))  # noqa: B004 - inspect async callable method, not a callability test
    ):
        raise SwapError("funding inclusion observer must be synchronous")
    now = int(time.time())
    preimage = secrets.token_bytes(32)
    payment_hash = hashlib.sha256(preimage).hexdigest()
    advertisement = await discover(
        connection, identity=identity, network=network, crypto=crypto, now=now, profile=PROFILE
    )
    session = _Session(connection, crypto, network, timeout=timeout, profile=PROFILE)
    init, accept, accept_signature, transcript = await _handshake(session, advertisement, identity)
    report(f"session {session.session_id[:16]} confirmed")
    provider_key = session.provider_key or ""

    contract_secret, contract_public = _scalar(crypto)
    _, recovery_public = _scalar(crypto)  # authorization key; its secret is not needed
    try:
        async with _ReverseLifetime(settle_timeout) as lifetime:
            tip = await lifetime.worker(wallet.tip_height)
            destination = await lifetime.worker(wallet.new_destination_script)
            # No estimate, no swap: the reserve must pay the next-block claim.
            fee = await lifetime.worker(wallet.next_block_fee)
            minimum_reserve = minimum_claim_fee_reserve_sat(destination, fee, limits)
            if minimum_reserve > limits.max_claim_fee_sat:
                raise SwapError(
                    f"the minimum claim fee reserve ({minimum_reserve} sat, at least the "
                    "next-block fee) exceeds your maximum claim fee "
                    f"({limits.max_claim_fee_sat} sat)"
                )
            request_model = ReverseFirmQuoteRequest(
                kind="ln-to-btc",
                mode="firm",
                nominal_payout_sat=str(payout_sat),
                payment_hash=payment_hash,
                client_contract_compressed_key=contract_public.hex(),
                recovery_authorization_xonly_key=recovery_public[1:].hex(),
                client_destination_script=destination.hex(),
                limits=ReverseQuoteLimits(
                    max_success_fee_sat=str(limits.max_success_fee_sat),
                    min_claim_fee_reserve_sat=str(minimum_reserve),
                    max_claim_fee_sat=str(limits.max_claim_fee_sat),
                    min_refund_lock_height=tip + limits.min_refund_delay_blocks,
                    max_incoming_htlc_expiry_height=tip + limits.max_incoming_htlc_delay_blocks,
                ),
                extensions=network_fee_request(
                    advertisement,
                    independent_rate_sat_kvb=max(fee.rate_sat_kvb, fee.floor_sat_kvb),
                ),
            )
            request = session.envelope("quote_request", request_model.model_dump(mode="json"))
            await session.send(request, provider_key)
            answer = await session.reply_to(request, "terms_offer")
            offer = parse_model_json(TermsOfferPayload, canonicalize(answer.payload))
            if offer.hold_invoice is None:
                raise SwapError("terms offer carries no hold invoice")
            hold = decode_invoice(offer.hold_invoice)
            if hold.bolt11_sha256 != hashlib.sha256(offer.hold_invoice.encode("ascii")).hexdigest():
                raise SwapError("invoice decoder returned another invoice")
            terms = _check_offer(
                offer,
                request_model,
                envelope=answer,
                transcript=transcript,
                hold=hold,
                identity=identity,
                network=network,
                crypto=crypto,
                now=int(time.time()),
            )
            require_announced_depth(terms.funding_confirmations, advertisement)
            # Blocks found while negotiating shorten the delay the request asked for.
            fresh_tip = await lifetime.worker(wallet.tip_height)
            try:
                check_reverse_claim_window(
                    terms,
                    tip_height=fresh_tip,
                    min_refund_delay_blocks=limits.min_refund_delay_blocks,
                )
            except ValueError as error:
                raise SwapError(str(error)) from None
            depth = claim_depth(terms.funding_confirmations, limits.claim_confirmations)
            warning = early_claim_warning(depth, terms.funding_confirmations)
            if warning is not None:
                report(warning)  # before paying, so the user can still stop
            economics = terms.economics
            contract = offer.terms.contract_hash
            min_incoming = int(terms.timing_policy.model_dump()["min_incoming_htlc_expiry_height"])
            report(
                f"terms: pay {int(hold.amount_msat) // 1000} sat on Lightning for "
                f"{economics.contract_amount_sat} sat on chain; provider refunds after block "
                f"{terms.refund_lock_height}"
            )
            acceptance = ClientAcceptance(
                contract_hash=contract,
                handshake_hash=transcript,
                session_id=session.session_id,
                client_session_xonly_key=session.key,
                provider_session_xonly_key=provider_key,
            )
            acceptance_signature = bytes(
                crypto.schnorr_sign(
                    session.secret,
                    client_acceptance_hash(acceptance),
                    secrets.token_bytes(32),
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
                "preimage": preimage,
            }
            document = _recovery_document(**record)  # type: ignore[arg-type]
            await lifetime.worker(lambda: write_recovery(document, None))
            report("recovery file written (terms and preimage, nothing paid yet)")
            if int(time.time()) >= terms.terms_expiry:
                raise SwapError("quote expired before acceptance; request a fresh quote")
            accepted = session.envelope(
                "terms_accept",
                {
                    "acceptance": acceptance.model_dump(mode="json"),
                    "client_acceptance_signature": acceptance_signature,
                },
                in_reply_to=answer.message_id,
                contract=contract,
            )
            await session.send(accepted, provider_key)
            await session.reply_to(accepted, "ack")

            lifetime.start()  # Includes queueing and uncertain submission, never renewed.
            try:
                status = await lifetime.worker(
                    lambda: payer.pay(
                        offer.hold_invoice or "",
                        invoice_binding=hold,
                        min_final_expiry_height=min_incoming,
                        max_expiry_height=request_model.limits.max_incoming_htlc_expiry_height,
                        fee_limit_sat=limits.max_routing_fee_sat,
                        deadline=lifetime.deadline,
                        submission_allowed=lifetime.allowed,
                    )
                )
            except LndObservationError:
                raise SwapError("hold payment outcome unknown; " + _UNRESOLVED) from None
            if status == "SHOWN":
                report("waiting for your wallet's payment, then for the provider's funding")
            elif status == "FAILED":
                raise SwapError("the hold invoice could not be paid; nothing is at risk")
            elif status in {"IN_FLIGHT", "SUCCEEDED"}:
                report(f"hold payment observed ({status}); waiting for the provider's funding")
            else:
                raise SwapError("hold payment outcome unknown; " + _UNRESOLVED)

            lifetime.check()
            script = reconstruct_taproot_contract(terms, keys=crypto).script_pubkey
            lifetime.check()
            binding, binding_signature, funding_raw = await _await_funding(
                session,
                contract=contract,
                timeout=settle_timeout,
                terms=terms,
                provider_key=provider_key,
                script=script,
                crypto=crypto,
                absolute_deadline=lifetime.deadline,
            )
            successor = _recovery_document(
                **record,  # type: ignore[arg-type]
                funding=((binding, binding_signature),),
            )
            await lifetime.worker(lambda: write_recovery(successor, document))
            report(
                f"funded recovery snapshot written (funding {binding.funding_txid}, "
                f"attempt {binding.funding_attempt_id} revision 0)"
            )
            if status == "SHOWN":  # the external wallet may already show a timeout
                report(
                    f"The provider funded, so it holds your payment {hold.payment_hash} of "
                    f"invoice {offer.hold_invoice}. {DO_NOT_PAY_AGAIN}"
                )
            value = int(economics.contract_amount_sat)
            await _await_depth(
                wallet,
                binding=binding,
                script=script,
                value=value,
                depth=depth,
                lock_height=terms.refund_lock_height,
                lifetime=lifetime,
                report=report,
            )
            if funding_inclusion_observer is not None:
                # Widen the return only at this runtime validation boundary;
                # the public contract remains a synchronous None acknowledgment.
                observer: Callable[[FundingBinding, ContractTerms, float], object] = (
                    funding_inclusion_observer
                )

                def capture() -> None:
                    observed = observer(binding, terms, lifetime.deadline)
                    if observed is not None:
                        # Validate within the owned worker, including late
                        # results. A coroutine must never bypass capture or leak
                        # unawaited when lifetime admission rejects its result.
                        if inspect.iscoroutine(observed):
                            observed.close()
                        raise SwapError("funding inclusion observer must return None")

                await lifetime.worker(capture)
                lifetime.check()
            sign, ceiling = _claim_signer(
                terms,
                binding,
                script=script,
                contract_secret=contract_secret,
                preimage=preimage,
                crypto=crypto,
                check_authority=lifetime.check,
            )
            # The claim pays exactly the signed reserve (priced for the next
            # block), so the destination receives exactly the nominal payout.
            if not isinstance(terms.economics, LnToBtcEconomics):
                raise SwapError("terms are not LN to BTC")
            initial_fee = max(1, min(ceiling, int(terms.economics.claim_fee_reserve_sat)))
            cooperative: ClaimAttempt | None = None
            fallback: ClaimAttempt | None = None
            preimage_disclosed = False

            def mark_disclosed() -> None:
                nonlocal preimage_disclosed
                preimage_disclosed = True

            if COOPERATIVE_CLAIM_FEATURE in terms.required_features:
                prepared_height = await lifetime.worker(wallet.tip_height)
                prepared_claim = await lifetime.worker(lambda: sign(initial_fee, prepared_height))
                fallback = ClaimAttempt(
                    prepared_claim[1],
                    prepared_claim[0],
                    prepared_claim[2],
                    prepared_claim[3],
                    prepared_height,
                )
                successor = await _publish_reverse_fallback(
                    lifetime,
                    funded_document=successor,
                    binding=binding,
                    transaction=prepared_claim[0],
                    session=session,
                    write_recovery=write_recovery,
                )
                report("private signed fallback snapshot acknowledged")
                # Same absolute fee as the unilateral claim: a higher feerate
                # for the smaller key-path spend, and a consistent bump schedule.
                cooperative = await _cooperative_claim(
                    lifetime,
                    session=session,
                    init=init,
                    accept=accept,
                    terms=terms,
                    binding=binding,
                    script=script,
                    contract_secret=contract_secret,
                    preimage=preimage,
                    fee_sat=initial_fee,
                    acknowledged_fallback=successor,
                    wallet=wallet,
                    write_recovery=write_recovery,
                    report=report,
                    on_disclosure=mark_disclosed,
                )

            early = depth < terms.funding_confirmations
            watcher = ClaimWatcher(
                initial_fee_sat=initial_fee,
                max_fee_sat=max(1, ceiling),
                deadline_height=terms.refund_lock_height
                - terms.timing_policy.claim_confirmation_blocks,
                chain=lambda: _chain_view(
                    wallet,
                    binding,
                    unconfirmed_funding=early,
                    resubmit_funding=resubmit_funding if early else None,
                ),
                confirmations=wallet.wallet_confirmations,
                sign=sign,
                submit=lambda raw, txid: _submit(wallet, raw, txid, lifetime),
                report=report,
                poll_seconds=POLL_SECONDS,
                deadline=lifetime.deadline,
                effect_allowed=lifetime.allowed,
                preimage_disclosed=preimage_disclosed,
            )
            resubmit_funding = _funding_resubmitter(
                wallet,
                binding,
                funding_raw,
                attempts=watcher.attempts,
                submit=lambda raw, txid: _submit(wallet, raw, txid, lifetime),
                report=report,
            )
            if cooperative is not None:
                # Rebroadcast the key-path claim; only a due fee bump replaces
                # it with the (already durable) script-path claim.
                watcher.attempts.append(cooperative)
            elif fallback is not None:
                # The pre-disclosure signed fallback remains recoverable even if
                # cooperation consumed the height window. Possession alone grants
                # no late submission authority; the watcher checks exposure evidence.
                watcher.attempts.append(fallback)
            outcome, claim_txid = await lifetime.worker(watcher.run)
            if outcome == "claim_window_passed":
                raise SwapError("the claim window closed; " + _UNRESOLVED)
            if outcome != "claim_confirmed" or claim_txid is None:
                raise SwapError("the contract was spent by another transaction; " + _UNRESOLVED)
            report(f"claim {claim_txid} confirmed")
            # No recorded txids are passed, so the confirmed claim is one of our
            # attempts; its fee is what the destination did not receive.
            selected = [attempt for attempt in watcher.attempts if attempt.txid == claim_txid]
            if len(selected) != 1:
                raise SwapError("the confirmed claim is unresolved; " + _UNRESOLVED)
            if settlement_observer is not None:
                await _await_claim_settlement(
                    lifetime,
                    settlement_observer,
                    selected[0],
                    network=network,
                    destination=destination,
                    value_sat=value,
                    depth=terms.settlement_confirmations,
                    report=report,
                )
                lifetime.check()
            return ReverseSwapOutcome(
                session.session_id,
                contract,
                binding.funding_txid,
                claim_txid,
                value,
                selected[0].fee_sat,
            )
    except TimeoutError:
        raise SwapError("original reverse settlement lifetime expired; " + _UNRESOLVED) from None
