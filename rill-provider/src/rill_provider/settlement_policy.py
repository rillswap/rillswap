"""Answer policy for every admitted BTC to LN client request (RS-003).

The live store admits a request (signature, sequence, replay, conflict) and
calls ``answer_client_request`` inside the recording transaction. Quotes go
to ``quote_policy``. ``terms_accept`` and ``funding_binding`` are checked
here and, when valid, answered with ``ack`` plus a store effect that moves
the swap forward atomically. An ``ack`` is delivery state only: accepting
terms or a binding never pays anything by itself.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from rill_core.settlement.funding import check_funding_binding_transaction
from rill_core.settlement.taproot import TaprootKeyOperations
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.hashes import FEE_POLICY_FEATURE, client_acceptance_hash, funding_binding_hash
from rill_core.wire.messages import AnyContractTerms, ContractTerms, Envelope
from rill_core.wire.quotes import TermsOfferPayload
from rill_core.wire.settlement_messages import FundingBindingPayload, TermsAcceptPayload

from rill_provider.evm_quote_policy import EVM_PROFILES, answer_evm_quote
from rill_provider.live_session_store import AcceptSwap, Answer, BindFunding
from rill_provider.quote_policy import answer_quote

if TYPE_CHECKING:
    from rill_provider.live_session_store import RequestContext
    from rill_provider.quote_policy import QuoteTerms


class SettlementCrypto(TaprootKeyOperations, Protocol):
    """BIP340 verification plus the Taproot key operations of ``rill_crypto``."""

    def schnorr_verify(self, public_key: bytes, message: bytes, signature: bytes) -> None:
        """Verify or raise."""
        ...


def _error(code: str, message: str) -> Answer:
    return Answer("error", {"code": code, "message": message})


def _ack(request: Envelope, contract: str, effect: AcceptSwap | BindFunding | None) -> Answer:
    return Answer(
        "ack",
        {"acknowledged_message_id": request.message_id},
        contract_hash=contract,
        effect=effect,
    )


def offered_any_terms(offer_envelope: Envelope) -> AnyContractTerms:
    """Return the contract terms (any profile) of one of our recorded ``terms_offer`` envelopes."""
    offer = parse_model_json(TermsOfferPayload, canonicalize(offer_envelope.payload))
    return offer.terms.contract_terms


def offered_terms(offer_envelope: Envelope) -> ContractTerms:
    """Return the Bitcoin contract terms of one of our recorded ``terms_offer`` envelopes."""
    terms = offered_any_terms(offer_envelope)
    if not isinstance(terms, ContractTerms):
        raise TypeError("recorded terms offer is not a Bitcoin profile")
    return terms


def answer_client_request(  # noqa: PLR0911 - one dispatch per message type
    request: Envelope,
    prior: tuple[Envelope, ...],
    context: RequestContext,
    terms: QuoteTerms,
    crypto: SettlementCrypto,
) -> Answer:
    """Dispatch one admitted client request to its policy."""
    if request.message_type == "quote_request":
        if request.in_reply_to is not None or request.contract_hash is not None:
            return _error("request_unacceptable", "quote requests start an exchange")
        if context.swap is not None:  # one swap per session; no new offers after it
            return _error("unsupported_request", "session already has a swap")
        if terms.profile in EVM_PROFILES:
            return answer_evm_quote(request, prior, context, terms)
        return answer_quote(request, prior, context, terms)
    if request.message_type == "terms_accept":
        return answer_acceptance(request, context, now=terms.now, crypto=crypto)
    if request.message_type == "funding_binding":
        return answer_funding(request, context, crypto=crypto)
    return _error("unsupported_request", "message type not accepted here")


def answer_acceptance(
    request: Envelope, context: RequestContext, *, now: int, crypto: SettlementCrypto
) -> Answer:
    """Admit the client's acceptance of our recorded, unexpired offer."""
    offer = context.replied_to
    if context.swap is not None or offer is None or offer.message_type != "terms_offer":
        return _error("unsupported_request", "no open terms offer to accept")
    if request.contract_hash is None or request.contract_hash != offer.contract_hash:
        return _error("request_unacceptable", "acceptance names another contract")
    try:
        payload = parse_model_json(TermsAcceptPayload, canonicalize(request.payload))
        acceptance = payload.acceptance
        terms = offered_any_terms(offer)
        if (
            acceptance.contract_hash != offer.contract_hash
            or acceptance.handshake_hash != context.handshake_hash
            or acceptance.session_id != request.session_id
            or acceptance.client_session_xonly_key != request.sender_session_key
            or acceptance.provider_session_xonly_key != offer.sender_session_key
        ):
            raise ValueError("acceptance binds another transcript")  # noqa: TRY301
        crypto.schnorr_verify(
            bytes.fromhex(request.sender_session_key),
            client_acceptance_hash(acceptance),
            bytes.fromhex(payload.client_acceptance_signature),
        )
    except Exception:  # noqa: BLE001 - no parsing or signature oracle
        return _error("request_unacceptable", "acceptance refused")
    # terms_expiry is capped at the invoice's needed remaining time when offered.
    if now > terms.terms_expiry or (
        FEE_POLICY_FEATURE in terms.required_features and now == terms.terms_expiry
    ):
        return _error("request_unacceptable", "terms expired")
    return _ack(request, offer.contract_hash, AcceptSwap(offer.contract_hash))


def answer_funding(
    request: Envelope, context: RequestContext, *, crypto: SettlementCrypto
) -> Answer:
    """Record the client's first signed binding after a static byte check.

    Only revision zero is accepted (no replacement in v1). Chain presence and
    confirmations are checked later, from the provider's own node.
    """
    swap = context.swap
    if swap is None or (
        swap.observed_funding is None
        and (swap.state != "ACCEPTED" or swap.funding_binding is not None)
    ):
        return _error("unsupported_request", "no accepted contract awaiting funding")
    if request.in_reply_to is not None or request.contract_hash != swap.contract_hash:
        return _error("request_unacceptable", "binding names another contract")
    try:
        payload = parse_model_json(FundingBindingPayload, canonicalize(request.payload))
        binding = payload.binding
        if binding.binding_revision != 0 or binding.replaces_txid is not None:
            raise ValueError("replacement bindings are not supported")  # noqa: TRY301
        crypto.schnorr_verify(
            bytes.fromhex(request.sender_session_key),
            funding_binding_hash(binding),
            bytes.fromhex(payload.funding_binding_signature),
        )
        terms = offered_terms(Envelope.model_validate_json(swap.terms_offer, strict=True))
        check_funding_binding_transaction(
            bytes.fromhex(payload.funding_transaction), binding, terms, keys=crypto
        )
        if swap.observed_funding is not None:
            selected = swap.observed_funding
            if (binding.funding_txid, binding.contract_vout) != (
                selected.binding.funding_txid,
                selected.binding.contract_vout,
            ) or bytes.fromhex(payload.funding_transaction) != selected.transaction:
                raise ValueError("binding differs from observed funding")  # noqa: TRY301 - redact
            return _ack(request, swap.contract_hash, None)
    except Exception:  # noqa: BLE001 - no parsing or signature oracle
        return _error("request_unacceptable", "funding binding refused")
    return _ack(request, swap.contract_hash, BindFunding())
