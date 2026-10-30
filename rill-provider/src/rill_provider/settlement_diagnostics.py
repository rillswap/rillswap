"""Allowlisted facts from already verified terms and committed settlement results."""

from __future__ import annotations

from contextlib import suppress
from typing import TYPE_CHECKING

from rill_core.wire.messages import Envelope

from rill_provider.diagnostics import diagnostic
from rill_provider.settlement_policy import offered_any_terms

if TYPE_CHECKING:
    import logging

    from rill_core.wire.messages import AnyContractTerms

    from rill_provider.diagnostics import Fact

ECONOMIC_FIELDS = (
    "lightning_principal_sat",
    "success_fee_sat",
    "contract_amount_sat",
    "nominal_payout_sat",
    "claim_fee_reserve_sat",
    "mining_prepayment_sat",
    "hold_invoice_sat",
    "success_fee_token_base",
    "lock_amount_token_base",
    "payout_token_base",
    "payout_sat_equivalent",
    "rate_token_base_per_btc",
)

WAIT_REASONS = {
    "FUNDING_SEEN": "Funding observed; waiting for the required confirmations",
    "PAYING": "Reconciling the original Lightning payment; unknown is not permission to pay again",
    "PAID": "Payment verified; waiting for cooperation or the recorded fallback deadline",
    "LN_HELD": "Lightning payment held; preparing or confirming provider funding",
    "FUNDING_SENT": "Funding submitted; waiting for required confirmations",
    "FUNDED": "Funding confirmed; waiting for the client's claim",
    "CLAIMING": "Claim recorded; waiting for chain confirmation",
    "REFUNDING": "Refund recorded; waiting for chain confirmation",
}


def terms_facts(terms: AnyContractTerms) -> dict[str, Fact]:
    """Never serialize a terms object: invoices and secrets are not diagnostics."""
    facts: dict[str, Fact] = {
        "profile": terms.profile_id,
        "network": terms.network_identity.name,
        "payment_hash": terms.invoice_binding.payment_hash,
        "invoice_hash": terms.invoice_binding.bolt11_sha256,
        "amount_msat": terms.invoice_binding.amount_msat,
        "refund_height": getattr(terms, "refund_lock_height", None),
        "timelock_block": getattr(terms, "htlc_timelock_block", None),
    }
    for name in ECONOMIC_FIELDS:
        value = getattr(terms.economics, name, None)
        if isinstance(value, str):
            facts[name] = value
    return facts


def committed_transition(
    logger: logging.Logger,
    session_id: str,
    from_state: str,
    to_state: str,
    terms_offer: bytes,
    **results: object,
) -> None:
    """Call only after commit; diagnostic decoding cannot invalidate that commit."""
    facts: dict[str, object] = {}
    with suppress(Exception):  # retained metadata cannot break post-commit reporting
        facts.update(
            terms_facts(offered_any_terms(Envelope.model_validate_json(terms_offer, strict=True)))
        )
    for source, target in (
        ("routing_fee_msat", "routing_fee_msat"),
        ("claim_fee_sat", "claim_fee_sat"),
        ("funding_fee_sat", "funding_fee_sat"),
        ("refund_fee_sat", "refund_fee_sat"),
        ("gas_wei", "gas_cost_wei"),
        ("claim_txid", "claim_txid"),
    ):
        if source in results:
            facts[target] = results[source]
    for source in ("sent", "lockup", "refund"):
        pair = results.get(source)
        if isinstance(pair, tuple) and pair and isinstance(pair[0], str):
            facts["txid"] = pair[0]  # never the signed bytes in the next tuple position
    funding = results.get("funding")
    if isinstance(funding, tuple) and funding:
        with suppress(Exception):
            facts["funding_txid"] = getattr(funding[0], "funding_txid", None)
    diagnostic(
        logger,
        "swap.transition",
        f"swap {session_id[:16]} moved to {to_state}",
        session_id=session_id,
        from_state=from_state,
        to_state=to_state,
        details=facts,
    )


def waiting_observation(
    logger: logging.Logger,
    session_id: str,
    state: str,
    terms_offer: bytes,
) -> None:
    """Report a changed wait from each engine's bounded active-swap cache."""
    facts: dict[str, object] = {}
    with suppress(Exception):
        facts.update(
            terms_facts(offered_any_terms(Envelope.model_validate_json(terms_offer, strict=True)))
        )
    if state == "ACCEPTED":
        message = (
            "Waiting for held Lightning payment"
            if str(facts.get("profile", "")).startswith("ln-to-")
            else "Waiting for client funding"
        )
    else:
        message = WAIT_REASONS.get(state, "Waiting for the next verified settlement observation")
    diagnostic(logger, "swap.waiting", message, session_id=session_id, state=state, details=facts)
