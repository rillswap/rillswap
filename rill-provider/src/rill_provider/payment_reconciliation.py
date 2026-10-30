"""Reconcile one retained payment without acquiring any new financial exposure.

This path deliberately cannot prepare/send routes, construct claims, or access
Core and relays. Normal settlement may continue from a verified PAID result on
the next service run. Missing LND state never creates a dispatch grant.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from rill_core.wire.messages import Envelope

from rill_provider.live_session_store import LiveSessionStoreError
from rill_provider.settlement_diagnostics import committed_transition
from rill_provider.settlement_policy import offered_terms

HASH_HEX_LENGTH = 64

if TYPE_CHECKING:
    from rill_provider.live_session_store import EnvelopeSigner, LiveSessionStore
    from rill_provider.lnd_payment_send import PaymentOutcome


class PaymentTracker(Protocol):
    """Read-only payment status capability, with no send or routing interface."""

    def track(self, payment_hash: str) -> PaymentOutcome:
        """Observe one hash without preparing, sending, or retrying a payment."""
        ...


@dataclass(frozen=True, slots=True)
class PaymentReconciliation:
    """Secret-free operator result, not evidence of refund or resend safety."""

    session_id: str
    payment_status: str
    swap_state: str
    state_changed: bool


def reconcile_payment(
    store: LiveSessionStore,
    tracker: PaymentTracker,
    signer: EnvelopeSigner,
    *,
    session_id: str,
    now: int,
) -> PaymentReconciliation:
    """Track once and atomically retain only cryptographically verified success.

    The caller holds exclusive store ownership. No routing, funding inspection,
    or retry follows UNKNOWN/IN_FLIGHT or any exception. Only PAYING is eligible;
    other states require their own recovery policy rather than being rewritten.
    FAILED is only this backend's report: the store has no original-payer node
    binding, so it cannot prove failure of a payment on another configured node.
    """
    items = store.settlement_work(session_id=session_id)
    if len(items) != 1 or items[0].state != "PAYING":
        raise LiveSessionStoreError("payment reconciliation requires one retained PAYING swap")
    item = items[0]
    try:
        terms = offered_terms(Envelope.model_validate_json(item.terms_offer, strict=True))
    except Exception:  # noqa: BLE001 - never echo retained invoice or terms on corruption
        raise LiveSessionStoreError("payment reconciliation terms unavailable") from None
    payment_hash = terms.invoice_binding.payment_hash
    outcome = tracker.track(payment_hash)
    if outcome.status in ("UNKNOWN", "IN_FLIGHT", "FAILED") and outcome.preimage is None:
        return PaymentReconciliation(session_id, outcome.status, item.state, state_changed=False)
    preimage = outcome.preimage
    if (
        outcome.status != "SUCCEEDED"
        or type(preimage) is not str
        or len(preimage) != HASH_HEX_LENGTH
        or any(char not in "0123456789abcdef" for char in preimage)
        or hashlib.sha256(bytes.fromhex(preimage)).hexdigest() != payment_hash
    ):
        raise LiveSessionStoreError("payment reconciliation outcome unsupported")
    store.advance_swap(
        session_id,
        from_state="PAYING",
        to_state="PAID",
        signer=signer,
        now=now,
        preimage=preimage,
        observation={"kind": "payment_settled", "payment_preimage": preimage},
        routing_fee_msat=outcome.fee_msat,
    )
    committed_transition(
        logging.getLogger(__name__),
        session_id,
        "PAYING",
        "PAID",
        item.terms_offer,
        routing_fee_msat=outcome.fee_msat,
    )
    return PaymentReconciliation(session_id, "SUCCEEDED", "PAID", state_changed=True)
