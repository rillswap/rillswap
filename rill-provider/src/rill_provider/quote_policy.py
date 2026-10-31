"""Answer policy for ``quote_request`` (RS-003 and RS-004 quotes).

Called by the live store inside the transaction that records the answer, so
every input (tip height, decoded invoice, clock) is fixed beforehand.
Indicative quotes grant no authority. A firm request, only as the first
request of a session, gets identity-signed ``ProviderTermsV1`` whose payment
hash the store reserves forever in the same transaction.

A provider serves one profile per configured handshake profile. BTC to LN
firm requests bring the client's invoice; LN to BTC firm requests bring the
client's payment hash, and the caller opens the hold invoice for ``H`` before
the transaction (``QuoteTerms.hold``) so the offer can bind its decoding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from rill_core.domain.amounts import MAX_SATS
from rill_core.errors import ValidationError
from rill_core.settlement import claim_vsizes
from rill_core.wire.canonical import JsonValue, canonicalize, parse_model_json
from rill_core.wire.fee_policy import (
    FEE_POLICY_EXTENSION,
    QUOTE_LIFETIME_SECONDS,
    BtcFeePolicy,
    FeeBreakdown,
    parse_fee_request,
)
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE, FEE_POLICY_FEATURE, contract_hash
from rill_core.wire.messages import ContractTerms, InvoiceBinding, ProviderTerms
from rill_core.wire.quotes import (
    MAX_INDICATIVE_REQUESTS_PER_SESSION,
    FirmQuoteRequest,
    IndicativeQuoteRequest,
    QuoteOffer,
    parse_quote_request,
)
from rill_core.wire.reverse_quotes import (
    ReverseFirmQuoteRequest,
    ReverseIndicativeQuoteRequest,
    ReverseQuoteOffer,
)

from rill_provider.funding_discovery import WATCH_EXTENSION, WATCH_REORG_MARGIN_BLOCKS
from rill_provider.live_session_store import Answer

if TYPE_CHECKING:
    from collections.abc import Callable

    from rill_core.wire.messages import Envelope
    from rill_core.wire.types import NetworkIdentity, ProfileId

    from rill_provider.dynamic_pricing import DynamicPricing, TokenPricing
    from rill_provider.evm_quote_policy import EvmQuoteContext
    from rill_provider.live_session_store import RequestContext

MILLIONTHS = 1_000_000
MAX_WIRE_INTEGER = 9_007_199_254_740_991  # RS-001 exact JSON integer
MAX_INVOICE_CLOCK_SKEW = 600

type InvoiceOutcome = InvoiceBinding | Literal["rejected", "unavailable"] | None
# LN to BTC: the hold invoice the caller opened for this request and its decoding.
type HoldOutcome = tuple[str, InvoiceBinding] | Literal["unavailable"] | None
MAX_HOLD_CLTV_DELTA = 2016  # what LND accepts for an invoice's final CLTV
INDICATIVE_CLAIM_DESTINATION = bytes([0x51, 0x20]) + bytes(32)  # P2TR: the larger claim


@dataclass(frozen=True, slots=True)
class QuoteSchedule:
    """Operator-chosen quote parameters beyond the public announcement terms."""

    # Depth before paying (BTC to LN; 0 = pay from the mempool) or before the
    # client may claim (LN to BTC, at least 1). Announced (RS-005).
    funding_confirmations: int = 1
    settlement_confirmations: int = 3
    refund_resolution_confirmations: int = 6
    max_refund_delay_blocks: int = 288
    max_funding_fee_sat: int = 5_000
    max_claim_fee_sat: int = 5_000
    max_refund_fee_sat: int = 5_000
    minimum_invoice_remaining_seconds: int = 1_800
    lifetime: int = 60
    outgoing_cltv_budget_blocks: int = 144
    learn_and_claim_blocks: int = 72
    client_response_blocks: int = 36
    claim_confirmation_blocks: int = 6
    terms_lifetime: int = 120
    # LN to BTC (RS-004): the provider funds and may refund after this delay.
    reverse_refund_delay_blocks: int = 144
    refund_and_ln_resolution_blocks: int = 40
    # None: priced per quote from next-block fees (``reverse_claim_fee_reserve``).
    claim_fee_reserve_sat: int | None = None
    hold_invoice_lifetime: int = 3_600

    def __post_init__(self) -> None:
        """Refuse values the wire cannot carry or timing that cannot fit."""
        counts = (
            self.reverse_refund_delay_blocks,
            self.refund_and_ln_resolution_blocks,
            self.hold_invoice_lifetime,
            self.settlement_confirmations,
            self.refund_resolution_confirmations,
            self.max_refund_delay_blocks,
            self.minimum_invoice_remaining_seconds,
            self.lifetime,
            self.outgoing_cltv_budget_blocks,
            self.learn_and_claim_blocks,
            self.client_response_blocks,
            self.claim_confirmation_blocks,
            self.terms_lifetime,
        )
        fees = (
            self.max_funding_fee_sat,
            self.max_claim_fee_sat,
            self.max_refund_fee_sat,
            0 if self.claim_fee_reserve_sat is None else self.claim_fee_reserve_sat,
        )
        if not (
            all(0 < value <= MAX_WIRE_INTEGER for value in counts)
            and 0 <= self.funding_confirmations <= MAX_WIRE_INTEGER
            and all(0 <= value <= MAX_SATS for value in fees)
            and self.outgoing_cltv_budget_blocks + self.learn_and_claim_blocks
            < self.max_refund_delay_blocks
            # RS-004: fund, wait for the client, and let it confirm before refund.
            and self.funding_confirmations
            + self.client_response_blocks
            + self.claim_confirmation_blocks
            < self.reverse_refund_delay_blocks
            and self.incoming_htlc_expiry_delta_blocks <= MAX_HOLD_CLTV_DELTA
            # RS-004: the offer must be acceptable for terms_lifetime while the
            # hold invoice still has the required remaining time.
            and self.hold_invoice_lifetime
            >= self.minimum_invoice_remaining_seconds + self.terms_lifetime
        ):
            raise ValueError("quote schedule unsupported")

    @property
    def incoming_htlc_expiry_delta_blocks(self) -> int:
        """Blocks from the reference height to the least acceptable ``E_in``."""
        return self.reverse_refund_delay_blocks + self.refund_and_ln_resolution_blocks + 1


@dataclass(frozen=True, slots=True)
class FirmSigner:
    """What a firm offer needs beyond the schedule; absent means no firm offers."""

    network: NetworkIdentity
    provider_identity_key: str
    provider_destination_script: str | None  # None: no Bitcoin firm offers (EVM profiles)
    sign: Callable[[ProviderTerms], str]


@dataclass(frozen=True, slots=True)
class ClaimFeeRate:
    """Next-block fee evidence for pricing the LN to BTC claim, in sat/kvB.

    ``rate_sat_kvb`` is the next-block estimate both claim paths must pay;
    ``floor_sat_kvb`` (the node's relay and mempool minimum) only bounds it
    from below.
    """

    rate_sat_kvb: int
    floor_sat_kvb: int


@dataclass(frozen=True, slots=True)
class QuoteTerms:
    """Everything one answer depends on, fixed before the store transaction."""

    amount_bands: tuple[tuple[int, int], ...]
    base_fee_sat: int
    proportional_millionths: int
    schedule: QuoteSchedule
    tip_height: int | None
    now: int
    firm: FirmSigner | None = None
    invoice: InvoiceOutcome = None
    profile: ProfileId = "btc-to-ln/v1"
    hold: HoldOutcome = None
    evm: EvmQuoteContext | None = None  # RS-010 profiles only
    claim_fee: ClaimFeeRate | None = None  # this tick's sample; LN to BTC only
    fee_policy: BtcFeePolicy | None = None
    fee_breakdown: FeeBreakdown | None = None
    dynamic: DynamicPricing | None = None  # balance-aware discounts, if configured
    funding_watch: bool = False  # serving engine can monitor accepted Bitcoin deposits


def _error(code: str, message: str) -> Answer:
    return Answer("error", {"code": code, "message": message})


def normal_service_fee(base_fee_sat: int, proportional_millionths: int, principal: int) -> int:
    """Return the advertised, undiscounted service fee: base plus the proportional ceiling."""
    return base_fee_sat + -(-principal * proportional_millionths // MILLIONTHS)


def _network_fee(terms: QuoteTerms) -> int:
    return 0 if terms.fee_breakdown is None else int(terms.fee_breakdown.network_fee_sat)


def service_fee(terms: QuoteTerms, principal: int, token: TokenPricing | None = None) -> int:
    """Return the signed service fee: the frozen breakdown's, else balance-aware, else normal.

    The breakdown is frozen before the store transaction (it may already
    back a reverse hold invoice), so once present it is the price.
    """
    if terms.fee_breakdown is not None:
        return int(terms.fee_breakdown.service_fee_sat)
    normal = normal_service_fee(terms.base_fee_sat, terms.proportional_millionths, principal)
    if terms.dynamic is None:
        return normal
    return terms.dynamic.service_fee(
        profile=terms.profile, normal_fee_sat=normal, principal_sat=principal, token=token
    )


def success_fee(terms: QuoteTerms, principal: int, token: TokenPricing | None = None) -> int:
    """Return service pricing plus the frozen, separately disclosed network charge."""
    return service_fee(terms, principal, token) + _network_fee(terms)


def normal_success_fee(terms: QuoteTerms, principal: int) -> int:
    """Return the undiscounted success fee, which bounds routing readiness checks."""
    normal = normal_service_fee(terms.base_fee_sat, terms.proportional_millionths, principal)
    return normal + _network_fee(terms)


def granted_rebate(terms: QuoteTerms, context: RequestContext, service: int) -> int | None:
    """Return the rebate a firm offer grants; None when the budget cannot cover it.

    The store computes ``rebates_committed_sat`` inside this transaction, so
    concurrent quotes can never both spend the same allowance.
    """
    rebate = max(0, -service)
    if rebate == 0:
        return 0
    committed = context.rebates_committed_sat
    if terms.dynamic is None or committed is None:
        return None
    return rebate if rebate <= terms.dynamic.limits.rebate_budget_sat - committed else None


def rebate_exhausted() -> Answer:
    """Refuse like any other capacity shortage: the budget state is private."""
    return _error("capacity_unavailable", "firm quotes temporarily unavailable")


def _fee_extensions(terms: QuoteTerms) -> dict[str, Any]:
    return (
        {}
        if terms.fee_breakdown is None
        else {FEE_POLICY_EXTENSION: terms.fee_breakdown.model_dump(mode="json")}
    )


def _quote_expiry(terms: QuoteTerms, lifetime: int) -> int:
    deadline = terms.now + lifetime
    if terms.fee_breakdown is not None:
        deadline = min(deadline, terms.fee_breakdown.issued_at + QUOTE_LIFETIME_SECONDS)
    return deadline


def _pricing_problem(
    extensions: dict[str, JsonValue], context: RequestContext, terms: QuoteTerms
) -> Answer | None:
    requested_policy = parse_fee_request(extensions)
    if terms.fee_policy is not None:
        if not context.network_fees or requested_policy is None:
            return _error("request_unacceptable", "network fee policy must be negotiated and bound")
        if requested_policy.policy_hash != terms.fee_policy.commitment():
            return _error("request_unacceptable", "selected fee policy is no longer offered")
        if terms.fee_breakdown is None or terms.now >= _quote_expiry(
            terms, terms.schedule.terms_lifetime
        ):
            return _error("capacity_unavailable", "fresh network fee quote unavailable")
        if (
            terms.fee_breakdown.offer_event_id != requested_policy.offer_event_id
            or terms.fee_breakdown.policy != terms.fee_policy
            or int(terms.fee_breakdown.feerate_sat_kvb)
            > int(requested_policy.max_network_feerate_sat_kvb)
        ):
            return _error("limits_unsatisfiable", "network fee limits cannot be met")
    elif context.network_fees or requested_policy is not None:
        return _error("unsupported_request", "network fee policy is not offered")
    return None


def answer_quote(  # noqa: PLR0911 - one closed answer per rule
    request: Envelope, prior: tuple[Envelope, ...], context: RequestContext, terms: QuoteTerms
) -> Answer:
    """Answer one admitted request."""
    earlier = [item.payload.get("mode") for item in prior]
    if "firm" in earlier:  # RS-003: unconditional, whatever the payload
        return _error("unsupported_request", "no request may follow a firm request")
    try:
        parsed = parse_quote_request(canonicalize(request.payload))
    except ValueError:
        return _error("request_unacceptable", "malformed quote request")
    if parsed.kind != terms.profile.split("/")[0]:
        return _error("unsupported_request", "profile not served in this session")
    pricing_problem = _pricing_problem(parsed.extensions, context, terms)
    if pricing_problem is not None:
        return pricing_problem
    if isinstance(parsed, FirmQuoteRequest | ReverseFirmQuoteRequest):
        if earlier:
            return _error("unsupported_request", "a firm request must open a fresh session")
        if isinstance(parsed, ReverseFirmQuoteRequest):
            return _reverse_firm(parsed, context, terms)
        return _firm(parsed, context, terms)
    if len(earlier) >= MAX_INDICATIVE_REQUESTS_PER_SESSION:
        return _error("unsupported_request", "indicative request limit reached")
    if isinstance(parsed, ReverseIndicativeQuoteRequest):
        return _reverse_indicative(parsed, terms)
    assert isinstance(parsed, IndicativeQuoteRequest)  # noqa: S101 - closed union
    principal = int(parsed.lightning_principal_sat)
    if not any(low <= principal <= high for low, high in terms.amount_bands):
        return _error("amount_out_of_range", "amount outside announced bands")
    if terms.tip_height is None or terms.tip_height <= 0:
        return _error("capacity_unavailable", "quotes temporarily unavailable")
    fee = success_fee(terms, principal)
    schedule = terms.schedule
    offer: dict[str, Any] = {
        "kind": "btc-to-ln",
        "indicative": True,
        "economics": {
            "kind": "btc-to-ln",
            "lightning_principal_sat": str(principal),
            "success_fee_sat": str(fee),
            "contract_amount_sat": str(principal + fee),
        },
        "funding_confirmations": schedule.funding_confirmations,
        "settlement_confirmations": schedule.settlement_confirmations,
        "refund_resolution_confirmations": schedule.refund_resolution_confirmations,
        "reference_height": terms.tip_height,
        "max_refund_delay_blocks": schedule.max_refund_delay_blocks,
        "max_funding_fee_sat": str(schedule.max_funding_fee_sat),
        "max_claim_fee_sat": str(schedule.max_claim_fee_sat),
        "max_refund_fee_sat": str(schedule.max_refund_fee_sat),
        "minimum_invoice_remaining_seconds": schedule.minimum_invoice_remaining_seconds,
        "expires_at": _quote_expiry(terms, schedule.lifetime),
        "extensions": _fee_extensions(terms),
    }
    try:  # never sign a payload the wire model would refuse (e.g. overflow)
        parse_model_json(QuoteOffer, canonicalize(offer))
    except ValueError:
        return _error("capacity_unavailable", "quotes temporarily unavailable")
    return Answer("quote_offer", offer)


def _invoice_problem(binding: InvoiceBinding, principal: int, terms: QuoteTerms) -> str | None:
    schedule = terms.schedule
    if binding.amount_msat != str(principal * 1000):
        return "invoice amount differs from the principal"
    if binding.expires_at - terms.now < schedule.minimum_invoice_remaining_seconds:
        return "invoice expires too soon"
    if binding.created_at > terms.now + MAX_INVOICE_CLOCK_SKEW:
        return "invoice created in the future"
    if binding.min_final_cltv_delta >= schedule.outgoing_cltv_budget_blocks:
        return "invoice final CLTV exceeds the routing budget"
    return None


def _firm(  # noqa: PLR0911 - one closed answer per rule
    request: FirmQuoteRequest, context: RequestContext, terms: QuoteTerms
) -> Answer:
    firm, schedule, tip = terms.firm, terms.schedule, terms.tip_height
    if firm is None or firm.provider_destination_script is None:
        return _error("unsupported_request", "firm requests are not offered")
    principal = int(request.lightning_principal_sat)
    if not any(low <= principal <= high for low, high in terms.amount_bands):
        return _error("amount_out_of_range", "amount outside announced bands")
    binding = terms.invoice
    if (
        tip is None
        or tip <= 0
        or binding is None
        or binding == "unavailable"
        or not context.economic_capacity_available
    ):
        return _error("capacity_unavailable", "firm quotes temporarily unavailable")
    if binding == "rejected":
        return _error("invoice_unacceptable", "invoice could not be decoded")
    if context.is_payment_hash_reserved(binding.payment_hash):  # RS-003: no ownership oracle
        return _error("request_unacceptable", "request cannot be offered")
    problem = _invoice_problem(binding, principal, terms)
    if problem is not None:
        return _error("invoice_unacceptable", problem)
    fee = success_fee(terms, principal)
    rebate = granted_rebate(terms, context, service_fee(terms, principal))
    if rebate is None:
        return rebate_exhausted()
    limits = request.limits
    lock = min(tip + schedule.max_refund_delay_blocks - 1, limits.max_refund_lock_height)
    htlc_expiry = tip + schedule.outgoing_cltv_budget_blocks
    if (
        fee > int(limits.max_success_fee_sat)
        or schedule.max_funding_fee_sat > int(limits.max_funding_fee_sat)
        or schedule.max_claim_fee_sat > int(limits.max_claim_fee_sat)
        or schedule.max_refund_fee_sat > int(limits.max_refund_fee_sat)
        or htlc_expiry + schedule.learn_and_claim_blocks >= lock + 1
    ):
        return _error("limits_unsatisfiable", "client limits cannot be met")
    contract: dict[str, Any] = {
        "protocol": "rillswap",
        "contract_version": "1",
        "profile_id": "btc-to-ln/v1",
        "network_identity": firm.network.model_dump(mode="json"),
        "provider_identity_key": firm.provider_identity_key,
        "client_contract_compressed_key": request.client_contract_compressed_key,
        "provider_contract_compressed_key": context.provider_contract_key,
        "claimant": "provider",
        "refund_party": "client",
        "invoice_binding": binding.model_dump(mode="json"),
        "economics": {
            "kind": "btc-to-ln",
            "lightning_principal_sat": str(principal),
            "success_fee_sat": str(fee),
            "contract_amount_sat": str(principal + fee),
        },
        "refund_lock_height": lock,
        "funding_confirmations": schedule.funding_confirmations,
        "settlement_confirmations": schedule.settlement_confirmations,
        "refund_resolution_confirmations": schedule.refund_resolution_confirmations,
        "max_funding_fee_sat": str(schedule.max_funding_fee_sat),
        "max_claim_fee_sat": str(schedule.max_claim_fee_sat),
        "max_refund_fee_sat": str(schedule.max_refund_fee_sat),
        "client_destination_script": request.client_destination_script,
        "provider_destination_script": firm.provider_destination_script,
        "recovery_authorization_xonly_key": request.recovery_authorization_xonly_key,
        # Never outlive the invoice time the payment still needs.
        "terms_expiry": min(
            _quote_expiry(terms, schedule.terms_lifetime),
            binding.expires_at - schedule.minimum_invoice_remaining_seconds,
        ),
        "timing_policy": {
            "kind": "btc-to-ln",
            "max_outgoing_htlc_expiry_height": htlc_expiry,
            "learn_and_claim_blocks": schedule.learn_and_claim_blocks,
            "client_response_blocks": schedule.client_response_blocks,
            "claim_confirmation_blocks": schedule.claim_confirmation_blocks,
        },
        "required_features": sorted(
            ([COOPERATIVE_CLAIM_FEATURE] if context.cooperative else [])
            + ([FEE_POLICY_FEATURE] if context.network_fees else [])
        ),
        "extensions": {
            **_fee_extensions(terms),
            **(
                {
                    WATCH_EXTENSION: {
                        "version": 1,
                        "from_height": max(1, tip - WATCH_REORG_MARGIN_BLOCKS),
                    }
                }
                if terms.funding_watch
                else {}
            ),
        },
    }
    try:
        contract_terms = parse_model_json(ContractTerms, canonicalize(contract))
    except ValueError:  # e.g. a client key colliding with a provider key
        return _error("request_unacceptable", "request cannot form valid terms")
    offer = ProviderTerms(
        contract_hash=contract_hash(contract_terms).hex(),
        contract_terms=contract_terms,
        handshake_hash=context.handshake_hash,
    )
    payload = {
        "terms": offer.model_dump(mode="json"),
        "provider_terms_signature": firm.sign(offer),
    }
    return Answer(
        "terms_offer",
        payload,
        payment_hash=binding.payment_hash,
        contract_hash=offer.contract_hash,
        rebate_sat=rebate,
    )


def reverse_claim_fee_reserve(
    terms: QuoteTerms, request: ReverseFirmQuoteRequest | None = None
) -> int | None:
    """Return the claim fee reserve ``C``, or ``None`` when none can be quoted now.

    A configured reserve is used as is. Otherwise the client's claim pays
    exactly ``C``, so the destination receives exactly the nominal payout:
    ``C`` pays the larger script-path claim at this tick's next-block rate
    (the node floor only as a lower bound), so the cooperative (key-path)
    claim pays at least that rate too, and honors the client's minimum.
    Indicative quotes size a P2TR destination, the larger claim. A reserve
    above ``max_claim_fee_sat`` could not be spent as signed, so it is not
    quoted.
    """
    schedule = terms.schedule
    if schedule.claim_fee_reserve_sat is not None:
        return schedule.claim_fee_reserve_sat
    fee = terms.claim_fee
    if fee is None:
        return None
    destination = (
        INDICATIVE_CLAIM_DESTINATION
        if request is None
        else bytes.fromhex(request.client_destination_script)
    )
    try:
        _, unilateral = claim_vsizes(destination)  # the script path is the larger claim
    except ValidationError:
        return None
    reserve = max(
        -(-unilateral * max(fee.rate_sat_kvb, fee.floor_sat_kvb) // 1000),
        0 if request is None else int(request.limits.min_claim_fee_reserve_sat),
    )
    return reserve if reserve <= schedule.max_claim_fee_sat else None


def reverse_economics(terms: QuoteTerms, payout: int, reserve: int) -> dict[str, str]:
    """RS-004 economics for payout ``D``: ``V = D + C``, ``H = V + S`` (no prepayment)."""
    fee = success_fee(terms, payout)
    return {
        "kind": "ln-to-btc",
        "contract_amount_sat": str(payout + reserve),
        "nominal_payout_sat": str(payout),
        "claim_fee_reserve_sat": str(reserve),
        "success_fee_sat": str(fee),
        "mining_prepayment_sat": "0",
        "hold_invoice_sat": str(payout + reserve + fee),
    }


def hold_invoice_msat(terms: QuoteTerms, request: ReverseFirmQuoteRequest) -> int | None:
    """Return the hold invoice amount ``H`` in msat, or ``None`` when unquotable now."""
    payout = int(request.nominal_payout_sat)
    reserve = reverse_claim_fee_reserve(terms, request)
    if reserve is None or not any(low <= payout <= high for low, high in terms.amount_bands):
        return None
    return int(reverse_economics(terms, payout, reserve)["hold_invoice_sat"]) * 1000


def _reverse_indicative(request: ReverseIndicativeQuoteRequest, terms: QuoteTerms) -> Answer:
    payout = int(request.nominal_payout_sat)
    if not any(low <= payout <= high for low, high in terms.amount_bands):
        return _error("amount_out_of_range", "amount outside announced bands")
    reserve = reverse_claim_fee_reserve(terms)
    if terms.tip_height is None or terms.tip_height <= 0 or reserve is None:
        return _error("capacity_unavailable", "quotes temporarily unavailable")
    schedule = terms.schedule
    offer: dict[str, Any] = {
        "kind": "ln-to-btc",
        "indicative": True,
        "economics": reverse_economics(terms, payout, reserve),
        "funding_confirmations": schedule.funding_confirmations,
        "settlement_confirmations": schedule.settlement_confirmations,
        "refund_resolution_confirmations": schedule.refund_resolution_confirmations,
        "reference_height": terms.tip_height,
        "refund_delay_blocks": schedule.reverse_refund_delay_blocks,
        "incoming_htlc_expiry_delta_blocks": schedule.incoming_htlc_expiry_delta_blocks,
        "max_funding_fee_sat": str(schedule.max_funding_fee_sat),
        "max_claim_fee_sat": str(schedule.max_claim_fee_sat),
        "max_refund_fee_sat": str(schedule.max_refund_fee_sat),
        "expires_at": _quote_expiry(terms, schedule.lifetime),
        "extensions": _fee_extensions(terms),
    }
    try:
        parse_model_json(ReverseQuoteOffer, canonicalize(offer))
    except ValueError:
        return _error("capacity_unavailable", "quotes temporarily unavailable")
    return Answer("quote_offer", offer)


def _reverse_firm(  # noqa: PLR0911 - one closed answer per rule
    request: ReverseFirmQuoteRequest, context: RequestContext, terms: QuoteTerms
) -> Answer:
    firm, schedule, tip = terms.firm, terms.schedule, terms.tip_height
    if firm is None or firm.provider_destination_script is None:
        return _error("unsupported_request", "firm requests are not offered")
    payout = int(request.nominal_payout_sat)
    if not any(low <= payout <= high for low, high in terms.amount_bands):
        return _error("amount_out_of_range", "amount outside announced bands")
    if context.is_payment_hash_reserved(request.payment_hash):  # RS-004: no ownership oracle
        return _error("request_unacceptable", "request cannot be offered")
    limits = request.limits
    if (
        schedule.claim_fee_reserve_sat is None
        and int(limits.min_claim_fee_reserve_sat) > schedule.max_claim_fee_sat
    ):  # no claim could spend such a reserve, whatever fees do
        return _error("limits_unsatisfiable", "client limits cannot be met")
    hold = terms.hold
    reserve = reverse_claim_fee_reserve(terms, request)
    if (
        tip is None
        or tip <= 0
        or hold is None
        or hold == "unavailable"
        or reserve is None
        or not context.economic_capacity_available
    ):
        return _error("capacity_unavailable", "firm quotes temporarily unavailable")
    bolt11, binding = hold
    economics = reverse_economics(terms, payout, reserve)
    rebate = granted_rebate(terms, context, service_fee(terms, payout))
    if rebate is None:
        return rebate_exhausted()
    if (
        binding.payment_hash != request.payment_hash
        or binding.amount_msat != str(int(economics["hold_invoice_sat"]) * 1000)
        or binding.min_final_cltv_delta < schedule.incoming_htlc_expiry_delta_blocks
    ):
        return _error("capacity_unavailable", "firm quotes temporarily unavailable")
    lock = tip + schedule.reverse_refund_delay_blocks - 1  # first refundable block: tip + delay
    min_incoming = tip + schedule.incoming_htlc_expiry_delta_blocks
    if (
        int(economics["success_fee_sat"]) > int(limits.max_success_fee_sat)
        or reserve < int(limits.min_claim_fee_reserve_sat)
        or schedule.max_claim_fee_sat > int(limits.max_claim_fee_sat)
        or lock < limits.min_refund_lock_height
        or min_incoming > limits.max_incoming_htlc_expiry_height
    ):
        return _error("limits_unsatisfiable", "client limits cannot be met")
    contract: dict[str, Any] = {
        "protocol": "rillswap",
        "contract_version": "1",
        "profile_id": "ln-to-btc/v1",
        "network_identity": firm.network.model_dump(mode="json"),
        "provider_identity_key": firm.provider_identity_key,
        "client_contract_compressed_key": request.client_contract_compressed_key,
        "provider_contract_compressed_key": context.provider_contract_key,
        "claimant": "client",
        "refund_party": "provider",
        "invoice_binding": binding.model_dump(mode="json"),
        "economics": economics,
        "refund_lock_height": lock,
        "funding_confirmations": schedule.funding_confirmations,
        "settlement_confirmations": schedule.settlement_confirmations,
        "refund_resolution_confirmations": schedule.refund_resolution_confirmations,
        "max_funding_fee_sat": str(schedule.max_funding_fee_sat),
        "max_claim_fee_sat": str(schedule.max_claim_fee_sat),
        "max_refund_fee_sat": str(schedule.max_refund_fee_sat),
        "client_destination_script": request.client_destination_script,
        "provider_destination_script": firm.provider_destination_script,
        "recovery_authorization_xonly_key": request.recovery_authorization_xonly_key,
        # The client must pay before the hold invoice expires with margin.
        "terms_expiry": min(
            _quote_expiry(terms, schedule.terms_lifetime),
            binding.expires_at - schedule.minimum_invoice_remaining_seconds,
        ),
        "timing_policy": {
            "kind": "ln-to-btc",
            "min_incoming_htlc_expiry_height": min_incoming,
            "refund_and_ln_resolution_blocks": schedule.refund_and_ln_resolution_blocks,
            "client_response_blocks": schedule.client_response_blocks,
            "claim_confirmation_blocks": schedule.claim_confirmation_blocks,
        },
        "required_features": sorted(
            ([COOPERATIVE_CLAIM_FEATURE] if context.cooperative else [])
            + ([FEE_POLICY_FEATURE] if context.network_fees else [])
        ),
        "extensions": _fee_extensions(terms),
    }
    try:
        contract_terms = parse_model_json(ContractTerms, canonicalize(contract))
    except ValueError:  # e.g. a client key colliding with a provider key, or expiry too soon
        return _error("request_unacceptable", "request cannot form valid terms")
    offer = ProviderTerms(
        contract_hash=contract_hash(contract_terms).hex(),
        contract_terms=contract_terms,
        handshake_hash=context.handshake_hash,
    )
    payload = {
        "terms": offer.model_dump(mode="json"),
        "provider_terms_signature": firm.sign(offer),
        "hold_invoice": bolt11,
    }
    return Answer(
        "terms_offer",
        payload,
        payment_hash=binding.payment_hash,
        contract_hash=offer.contract_hash,
        rebate_sat=rebate,
    )
