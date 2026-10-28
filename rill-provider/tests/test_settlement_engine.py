"""Restarted payment intents must not authorize new financial exposure."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest
from rill_core.wire.messages import ContractTerms, FundingBinding

from rill_provider import settlement_engine
from rill_provider.live_session_store import SettlementItem
from rill_provider.lnd_invoice_decode import InvoiceRejectedError
from rill_provider.lnd_payment_observation import LndNotSyncedError, LndUnavailableError
from rill_provider.lnd_payment_send import PaymentOutcome, PreparedPayment
from rill_provider.payment_dispatch_record import PaymentAuthority
from rill_provider.settlement_engine import SettlementEngine

INVOICE = "lnbcrt1fixture"
DOCUMENT = json.loads((Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json").read_text())
TERMS = ContractTerms.model_validate_json(json.dumps(DOCUMENT["contract_terms"]))
TERMS = TERMS.model_copy(
    update={
        "invoice_binding": TERMS.invoice_binding.model_copy(
            update={"bolt11_sha256": hashlib.sha256(INVOICE.encode()).hexdigest()}
        )
    }
)
BINDING = FundingBinding(
    contract_hash=DOCUMENT["contract_hash"],
    funding_attempt_id="31" * 32,
    binding_revision=0,
    funder_role="client",
    lineage_anchor_txid="41" * 32,
    lineage_anchor_vout=0,
    funding_txid="51" * 32,
    contract_vout=0,
    contract_value_sat=TERMS.economics.contract_amount_sat,
    contract_script_pubkey=DOCUMENT["taproot_contract"]["script_pubkey"],
    replaces_txid=None,
    created_at=DOCUMENT["created_at"],
)
ITEM = SettlementItem(
    session_id="11" * 32,
    state="PAYING",
    blocked=False,
    terms_offer=b"",
    funding_binding=b"",
    invoice=INVOICE,
    preimage=None,
    claim_tx=None,
    claim_txid=None,
    payment_dispatch="UNSENT",
)


def _backends(outcome: PaymentOutcome) -> tuple[SettlementEngine, Mock, Mock]:
    chain, lightning = Mock(), Mock()
    chain.observe_candidate_outpoint.return_value.chain_only_confirmations = 2
    chain.tip_height.return_value = 1000
    lightning.track.return_value = outcome
    lightning.prepare.return_value = PreparedPayment(
        b"exact request",
        TERMS.invoice_binding.payment_hash,
        TERMS.invoice_binding.expires_at,
        1070,
        TERMS.invoice_binding.min_final_cltv_delta,
        PaymentAuthority("03" + "ab" * 32, TERMS.network_identity),
    )
    lightning.send.return_value = PaymentOutcome("IN_FLIGHT")
    return SettlementEngine(Mock(), chain, lightning, Mock()), chain, lightning


@pytest.mark.parametrize("depth", [0, 1])
def test_restart_defers_new_payment_after_confirmation_loss(depth: int) -> None:
    engine, chain, lightning = _backends(PaymentOutcome("UNKNOWN"))
    chain.observe_candidate_outpoint.return_value.chain_only_confirmations = depth
    result = asyncio.run(engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"]))  # noqa: SLF001
    assert result == PaymentOutcome("UNKNOWN")
    chain.observe_candidate_outpoint.assert_called_once()
    lightning.send.assert_not_called()


def test_restart_does_not_send_when_funding_is_spent_or_unavailable() -> None:
    engine, chain, lightning = _backends(PaymentOutcome("UNKNOWN"))
    chain.observe_candidate_outpoint.side_effect = ValueError("outpoint is unavailable")
    with pytest.raises(ValueError, match="outpoint is unavailable"):
        asyncio.run(engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"]))  # noqa: SLF001
    lightning.send.assert_not_called()


@pytest.mark.parametrize(
    "outcome", [PaymentOutcome("IN_FLIGHT"), PaymentOutcome("SUCCEEDED", "42" * 32)]
)
@pytest.mark.parametrize("dispatch", ["UNSENT", "UNKNOWN", "SUBMITTED"])
def test_existing_payment_is_reconciled_even_if_blocked_or_funding_lost(
    outcome: PaymentOutcome,
    dispatch: str,
) -> None:
    engine, chain, lightning = _backends(outcome)
    chain.observe_candidate_outpoint.side_effect = ValueError("funding lost")
    result = asyncio.run(
        engine._pay(  # noqa: SLF001
            replace(ITEM, blocked=True, payment_dispatch=dispatch),
            TERMS,
            BINDING,
            1070,
            DOCUMENT["created_at"],
        )
    )
    assert result == outcome
    chain.observe_candidate_outpoint.assert_not_called()
    lightning.send.assert_not_called()


def test_new_payment_is_deferred_when_session_became_blocked() -> None:
    engine, _, lightning = _backends(PaymentOutcome("UNKNOWN"))
    result = asyncio.run(
        engine._pay(replace(ITEM, blocked=True), TERMS, BINDING, 1070, DOCUMENT["created_at"])  # noqa: SLF001
    )
    assert result == PaymentOutcome("UNKNOWN")
    lightning.send.assert_not_called()


def test_restart_refuses_expired_invoice() -> None:
    engine, _, lightning = _backends(PaymentOutcome("UNKNOWN"))
    result = asyncio.run(
        engine._pay(ITEM, TERMS, BINDING, 1070, TERMS.invoice_binding.expires_at)  # noqa: SLF001
    )
    assert result is None
    lightning.send.assert_not_called()


def test_restart_sends_only_after_current_funding_check() -> None:
    engine, chain, lightning = _backends(PaymentOutcome("UNKNOWN"))
    result = asyncio.run(engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"]))  # noqa: SLF001
    assert result == PaymentOutcome("IN_FLIGHT")
    chain.observe_candidate_outpoint.assert_called_once()
    lightning.prepare.assert_called_once_with(
        INVOICE,
        invoice_binding=TERMS.invoice_binding,
        fee_limit_sat=1000,
        max_expiry_height=1070,
    )
    engine._store.commit_payment_dispatch.assert_called_once_with(  # type: ignore[attr-defined]  # noqa: SLF001
        ITEM.session_id,
        TERMS.invoice_binding.payment_hash,
        lightning.prepare.return_value.dispatch_record,
    )
    lightning.send.assert_called_once_with(lightning.prepare.return_value)


def test_failed_preparation_does_not_consume_dispatch_permission() -> None:
    engine, _, lightning = _backends(PaymentOutcome("UNKNOWN"))
    lightning.prepare.side_effect = ValueError("no bounded route")
    with pytest.raises(ValueError, match="no bounded route"):
        asyncio.run(engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"]))  # noqa: SLF001
    engine._store.commit_payment_dispatch.assert_not_called()  # type: ignore[attr-defined]  # noqa: SLF001
    lightning.send.assert_not_called()


def test_pre_submission_sync_loss_retries_only_the_committed_in_memory_payment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _, lightning = _backends(PaymentOutcome("UNKNOWN"))
    outcome = PaymentOutcome("SUCCEEDED", "42" * 32)
    lightning.send.side_effect = [LndNotSyncedError(), LndNotSyncedError(), outcome]
    sleep = AsyncMock()
    monkeypatch.setattr(settlement_engine.asyncio, "sleep", sleep)

    assert (
        asyncio.run(
            engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"])  # noqa: SLF001
        )
        == outcome
    )
    lightning.prepare.assert_called_once()
    engine._store.commit_payment_dispatch.assert_called_once()  # type: ignore[attr-defined]  # noqa: SLF001
    assert len(lightning.send.call_args_list) == 3
    for attempt in lightning.send.call_args_list:
        assert attempt.args == (lightning.prepare.return_value,)
        assert not attempt.kwargs
    assert sleep.await_count == 2


@pytest.mark.parametrize("during_wait", [False, True])
@pytest.mark.parametrize("stop", ["budget", "exposure"])
def test_pre_submission_sync_retry_stops_when_authority_or_budget_ends(
    monkeypatch: pytest.MonkeyPatch,
    *,
    during_wait: bool,
    stop: str,
) -> None:
    engine, _, lightning = _backends(PaymentOutcome("UNKNOWN"))
    clock = Mock(monotonic=Mock(return_value=1000.0))
    monkeypatch.setattr(settlement_engine, "time", clock)

    def end_retry() -> None:
        if stop == "budget":
            clock.monotonic.return_value = 1011.0
        else:
            engine.disable_new_exposure()

    def unsynced(_: PreparedPayment) -> None:
        if not during_wait:
            end_retry()
        raise LndNotSyncedError

    async def sleep(_: float) -> None:
        end_retry()

    lightning.send.side_effect = unsynced
    wait = AsyncMock(side_effect=sleep)
    monkeypatch.setattr(settlement_engine.asyncio, "sleep", wait)
    with pytest.raises(LndNotSyncedError):
        asyncio.run(engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"]))  # noqa: SLF001
    lightning.send.assert_called_once_with(lightning.prepare.return_value)
    engine._store.commit_payment_dispatch.assert_called_once()  # type: ignore[attr-defined]  # noqa: SLF001
    assert wait.await_count == int(during_wait)


@pytest.mark.parametrize("after_sync_retry", [False, True])
def test_ambiguous_submission_never_retries_even_after_pre_submission_sync_loss(
    monkeypatch: pytest.MonkeyPatch,
    *,
    after_sync_retry: bool,
) -> None:
    engine, _, lightning = _backends(PaymentOutcome("UNKNOWN"))
    failures: list[Exception] = [LndUnavailableError("submission outcome unknown")]
    if after_sync_retry:
        failures.insert(0, LndNotSyncedError())
    lightning.send.side_effect = failures
    monkeypatch.setattr(settlement_engine.asyncio, "sleep", AsyncMock())
    with pytest.raises(LndUnavailableError, match="outcome unknown"):
        asyncio.run(engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"]))  # noqa: SLF001
    assert lightning.send.call_count == 1 + int(after_sync_retry)
    lightning.prepare.assert_called_once()
    engine._store.commit_payment_dispatch.assert_called_once()  # type: ignore[attr-defined]  # noqa: SLF001


def test_older_unsupported_invoice_fails_without_dispatching() -> None:
    engine, _, lightning = _backends(PaymentOutcome("UNKNOWN"))
    lightning.prepare.side_effect = InvoiceRejectedError("invoice routing features unsupported")
    assert asyncio.run(engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"])) is None  # noqa: SLF001
    engine._store.commit_payment_dispatch.assert_not_called()  # type: ignore[attr-defined]  # noqa: SLF001
    lightning.send.assert_not_called()


def test_lost_submission_response_never_sends_again_with_stale_work_item() -> None:
    engine, _, lightning = _backends(PaymentOutcome("UNKNOWN"))
    engine._store.commit_payment_dispatch.side_effect = [True, False]  # type: ignore[attr-defined]  # noqa: SLF001
    lightning.send.side_effect = OSError("lost submission response")
    with pytest.raises(OSError, match="lost submission response"):
        asyncio.run(engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"]))  # noqa: SLF001
    assert asyncio.run(
        engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"])  # noqa: SLF001
    ) == PaymentOutcome("UNKNOWN")
    lightning.send.assert_called_once()


@pytest.mark.parametrize("dispatch", ["UNKNOWN", "SUBMITTED", "unrecognized"])
def test_missing_or_consumed_grant_never_resubmits(dispatch: str) -> None:
    engine, chain, lightning = _backends(PaymentOutcome("UNKNOWN"))
    result = asyncio.run(
        engine._pay(  # noqa: SLF001 - the exposure boundary
            replace(ITEM, payment_dispatch=dispatch), TERMS, BINDING, 1070, DOCUMENT["created_at"]
        )
    )
    assert result == PaymentOutcome("UNKNOWN")
    chain.observe_candidate_outpoint.assert_not_called()
    lightning.send.assert_not_called()


def test_conflict_before_dispatch_commit_prevents_send(monkeypatch: pytest.MonkeyPatch) -> None:
    engine, _, lightning = _backends(PaymentOutcome("UNKNOWN"))
    monkeypatch.setattr(engine._store, "commit_payment_dispatch", Mock(return_value=False))  # noqa: SLF001
    result = asyncio.run(engine._pay(ITEM, TERMS, BINDING, 1070, DOCUMENT["created_at"]))  # noqa: SLF001
    assert result == PaymentOutcome("UNKNOWN")
    lightning.send.assert_not_called()


ZERO_CONF = TERMS.model_copy(update={"funding_confirmations": 0})


def test_zero_conf_restart_sends_on_a_fresh_mempool_sample_only() -> None:
    engine, chain, lightning = _backends(PaymentOutcome("UNKNOWN"))
    chain.observe_candidate_outpoint.side_effect = AssertionError("confirmed sampler used")
    result = asyncio.run(engine._pay(ITEM, ZERO_CONF, BINDING, 1070, DOCUMENT["created_at"]))  # noqa: SLF001
    assert result == PaymentOutcome("IN_FLIGHT")
    chain.observe_mempool_outpoint.assert_called_once_with(BINDING, ZERO_CONF, keys=engine._crypto)  # noqa: SLF001
    lightning.send.assert_called_once()


def test_zero_conf_never_sends_when_the_mempool_sample_fails() -> None:
    engine, chain, lightning = _backends(PaymentOutcome("UNKNOWN"))
    chain.observe_mempool_outpoint.side_effect = ValueError("output spent in the mempool")
    with pytest.raises(ValueError, match="spent in the mempool"):
        asyncio.run(engine._pay(ITEM, ZERO_CONF, BINDING, 1070, DOCUMENT["created_at"]))  # noqa: SLF001
    lightning.send.assert_not_called()


def test_funded_tip_uses_mempool_evidence_only_for_zero_conf_terms() -> None:
    engine, chain, _ = _backends(PaymentOutcome("UNKNOWN"))
    chain.observe_mempool_outpoint.return_value.tip_height = 990
    chain.observe_candidate_outpoint.return_value.tip_height = 991
    assert asyncio.run(engine._funded_tip(BINDING, ZERO_CONF)) == 990  # noqa: SLF001
    assert TERMS.funding_confirmations == 2  # the sampler reports exactly 2
    assert asyncio.run(engine._funded_tip(BINDING, TERMS)) == 991  # noqa: SLF001
    chain.observe_candidate_outpoint.return_value.chain_only_confirmations = 1
    assert asyncio.run(engine._funded_tip(BINDING, TERMS)) is None  # noqa: SLF001
    chain.observe_mempool_outpoint.assert_called_once()


@pytest.mark.parametrize("pending", [False, True])
def test_exposure_release_asks_the_tip_only_when_a_terminal_swap_holds_capacity(
    pending: bool,  # noqa: FBT001
) -> None:
    store, chain = Mock(), Mock()
    store.settlement_work.return_value = ()
    store.unfunded_swaps.return_value = ()
    store.expirable_exposure_pending.return_value = pending
    store.release_expired_exposure.return_value = 2
    chain.tip_height.return_value = 1200
    engine = SettlementEngine(store, chain, Mock(), Mock())
    assert asyncio.run(engine.tick(now=1500)) == {}
    if pending:
        store.release_expired_exposure.assert_called_once_with(1200)
    else:
        assert not chain.mock_calls
        store.release_expired_exposure.assert_not_called()
