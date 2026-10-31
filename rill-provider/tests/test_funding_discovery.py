"""Restarted provider discovery must not invent client consent or payment grants."""

from __future__ import annotations

import asyncio
import copy
import json
from dataclasses import replace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import contract_hash
from rill_core.wire.messages import ContractTerms, Envelope
from test_core_tx_bytes import GENESIS, _context, _cookie
from test_live_session_store import Harness, _envelopes
from test_payment_dispatch_store import _insert_funded_swap
from test_quote_policy import FIRM, FIRM_TERMS, _envelope
from test_quote_policy import _context as quote_context
from test_settlement_engine import BINDING, ITEM, TERMS, _backends

from rill_provider import live_session_store as live
from rill_provider import settlement_engine
from rill_provider.core_tx_bytes import CoreProtocolError, CoreTransactionReader
from rill_provider.funding_discovery import (
    MAX_RECEIPTS,
    MAX_SCAN_BLOCKS,
    WATCH_EXTENSION,
    FundingReceipt,
    FundingScan,
    FundingWatch,
    ObservedFunding,
)
from rill_provider.lnd_payment_send import PaymentOutcome
from rill_provider.quote_policy import answer_quote
from rill_provider.settlement_policy import answer_funding

if TYPE_CHECKING:
    from pathlib import Path

SCRIPT = bytes.fromhex("5120" + "ab" * 32)
BLOCK = "bb" * 32
RECEIPT = FundingReceipt(BINDING.funding_txid, BINDING.contract_vout, 10, BLOCK)


def test_serving_quotes_record_a_shallow_reorg_floor_before_funding() -> None:
    answer = answer_quote(
        _envelope(FIRM), (), quote_context(), replace(FIRM_TERMS, funding_watch=True)
    )
    marker = answer.payload["terms"]["contract_terms"]["extensions"][WATCH_EXTENSION]
    assert marker == {"version": 1, "from_height": 838}
    ordinary = answer_quote(_envelope(FIRM), (), quote_context(), FIRM_TERMS)
    assert WATCH_EXTENSION not in ordinary.payload["terms"]["contract_terms"]["extensions"]


def _watched(harness: Harness, store: live.LiveSessionStore) -> tuple[str, ContractTerms]:
    session = _insert_funded_swap(store, harness, "ACCEPTED")
    connection = store._connection  # noqa: SLF001 - durable boundary fixture
    offer = json.loads(connection.execute("SELECT terms_offer FROM swaps").fetchone()[0])
    terms = offer["payload"]["terms"]["contract_terms"]
    terms["extensions"][WATCH_EXTENSION] = {"version": 1, "from_height": 10}
    parsed = ContractTerms.model_validate_json(json.dumps(terms))
    hashed = contract_hash(parsed).hex()
    offer["contract_hash"] = hashed
    offer["payload"]["terms"]["contract_hash"] = hashed
    connection.execute(
        "UPDATE swaps SET terms_offer=?,contract_hash=?,funding_binding=NULL",
        (canonicalize(offer), hashed),
    )
    connection.execute(
        "INSERT INTO forward_funding VALUES (?,10,NULL,NULL,?,NULL,NULL,0)", (session, b"[]")
    )
    return session, parsed


def test_watch_checkpoint_and_selection_survive_restart_without_a_client_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    monkeypatch.setattr(live, "check_funding_binding_transaction", Mock())
    with harness.acquire() as store:
        session, terms = _watched(harness, store)
        watch = store.funding_watch(session)
        assert watch == FundingWatch(10, None, None, ())
        updated = store.record_funding_scan(
            session, watch, FundingScan(20, BLOCK, 20, BLOCK, (RECEIPT,), mempool_seen=False)
        )
    with harness.acquire() as store:
        assert store.funding_watch(session) == updated
        binding = BINDING.model_copy(update={"contract_hash": contract_hash(terms).hex()})
        observed = ObservedFunding(binding, b"exact discovered bytes")
        store.select_observed_funding(session, updated, observed, now=1001)
        assert not store.commit_payment_dispatch(
            session, terms.invoice_binding.payment_hash, b"not yet authorized"
        )
    with harness.acquire() as store:
        record = live._swap(store._connection, session)  # noqa: SLF001
        assert record.state == "FUNDING_SEEN"
        assert record.funding_binding is None
        assert record.observed_funding == observed
        assert store.funding_watch(session) is None
        inspected = store.inspect_swaps(session_id=session).swaps[0]
        assert inspected.funding_source == "provider-observed"
        assert not inspected.funding_binding_recorded
        assert inspected.funding_watch_recorded


def test_missing_watch_never_starts_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "ACCEPTED")
        assert store.funding_watch(session) is None


def test_reorg_rewinds_receipts_and_conflict_blocks_scan_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        session, _ = _watched(harness, store)
        initial = store.funding_watch(session)
        updated = store.record_funding_scan(
            session, initial, FundingScan(20, BLOCK, 20, BLOCK, (RECEIPT,), mempool_seen=False)
        )
        store.reset_funding_watch(session, updated)
        assert store.funding_watch(session) == initial
        store._connection.execute("UPDATE sessions SET blocked=1")  # noqa: SLF001
        with pytest.raises(live.StaleSwapError):
            store.record_funding_scan(
                session, initial, FundingScan(20, BLOCK, 20, BLOCK, (), mempool_seen=False)
            )


@pytest.mark.parametrize("receipts", [(), (RECEIPT, FundingReceipt("cc" * 32, 0, 11, BLOCK))])
def test_absent_or_ambiguous_candidates_never_select(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, receipts: tuple[FundingReceipt, ...]
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        session, _ = _watched(harness, store)
        updated = store.record_funding_scan(
            session,
            store.funding_watch(session),
            FundingScan(20, BLOCK, 20, BLOCK, receipts, mempool_seen=False),
        )
        with pytest.raises(live.StaleSwapError):
            store.select_observed_funding(
                session, updated, ObservedFunding(BINDING, b"raw"), now=1001
            )


@pytest.mark.parametrize("state", ["FUNDING_SEEN", "PAYING", "PAID", "CLAIMING", "CLAIMED"])
def test_late_matching_signed_binding_is_acknowledged_without_a_transition(state: str) -> None:
    source, envelopes = _envelopes()
    offer = copy.deepcopy(envelopes[1])
    offer.update(
        message_type="terms_offer",
        contract_hash=source["contract_hash"],
        payload={
            "terms": {
                "contract_hash": source["contract_hash"],
                "contract_terms": source["contract_terms"],
                "handshake_hash": source["verification_context"]["handshake_hash"],
            },
            "provider_terms_signature": source["verification_context"]["provider_terms_signature"],
        },
    )
    observed = ObservedFunding(BINDING, b"\x00" * 60)
    swap = live.SwapRecord(
        ITEM.session_id,
        BINDING.contract_hash,
        canonicalize(offer),
        b"accepted",
        state,
        None,
        None,
        None,
        observed,
    )
    request = copy.deepcopy(envelopes[2])
    request.update(
        message_type="funding_binding",
        in_reply_to=None,
        contract_hash=BINDING.contract_hash,
        payload={
            "binding": BINDING.model_dump(mode="json"),
            "funding_binding_signature": "00" * 64,
            "funding_transaction": observed.transaction.hex(),
        },
    )
    context = live.RequestContext("00" * 32, "02" + "00" * 32, lambda _: False, swap=swap)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("rill_provider.settlement_policy.check_funding_binding_transaction", Mock())
        answer = answer_funding(
            Envelope.model_validate_json(json.dumps(request)), context, crypto=Mock()
        )
        assert answer.message_type == "ack"
        assert answer.effect is None
        request["payload"]["binding"]["funding_txid"] = "ee" * 32
        assert (
            answer_funding(
                Envelope.model_validate_json(json.dumps(request)), context, crypto=Mock()
            ).message_type
            == "error"
        )


def test_provider_observed_zero_conf_funding_still_needs_one_confirmation() -> None:
    engine, chain, lightning = _backends(PaymentOutcome("UNKNOWN"))
    chain.observe_candidate_outpoint.return_value.chain_only_confirmations = 0
    item = replace(ITEM, observed_funding=ObservedFunding(BINDING, b"raw"))
    terms = TERMS.model_copy(update={"funding_confirmations": 0})
    assert asyncio.run(engine._pay(item, terms, BINDING, 1070, 1000)) == PaymentOutcome("UNKNOWN")  # noqa: SLF001
    chain.observe_mempool_outpoint.assert_not_called()
    lightning.send.assert_not_called()


def test_extra_unconfirmed_deposit_prevents_independent_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, chain, lightning = _backends(PaymentOutcome("UNKNOWN"))
    watch = FundingWatch(10, None, None, ())
    updated = FundingWatch(10, 20, BLOCK, (RECEIPT,))
    engine._store.funding_watch.return_value = watch  # noqa: SLF001
    engine._store.record_funding_scan.return_value = updated  # noqa: SLF001
    chain.discover_funding.return_value = FundingScan(
        20, BLOCK, 20, BLOCK, (RECEIPT,), mempool_seen=True
    )
    monkeypatch.setattr(
        settlement_engine,
        "reconstruct_taproot_contract",
        Mock(return_value=Mock(script_pubkey=SCRIPT)),
    )
    item = replace(ITEM, state="ACCEPTED")
    assert asyncio.run(engine._discover_funding(item, TERMS, 1000)) == "ACCEPTED"  # noqa: SLF001
    engine._store.select_observed_funding.assert_not_called()  # noqa: SLF001
    chain.observe_block_transaction.assert_not_called()
    lightning.send.assert_not_called()


@pytest.mark.parametrize("stop", ["saturated", "refund_height"])
def test_saturated_or_expired_watches_stop_without_selecting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stop: str
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        session, terms = _watched(harness, store)
        receipts = (
            tuple(
                FundingReceipt(f"{index + 1:064x}", 0, 10, BLOCK)
                for index in range(MAX_RECEIPTS + 1)
            )
            if stop == "saturated"
            else ()
        )
        tip = 20 if stop == "saturated" else terms.refund_lock_height
        assert (
            store.record_funding_scan(
                session,
                store.funding_watch(session),
                FundingScan(tip, BLOCK, 20, BLOCK, receipts, mempool_seen=False),
            )
            is None
        )
        assert store.funding_watch(session) is None
        assert store._connection.execute(  # noqa: SLF001
            "SELECT selected_binding,disabled FROM forward_funding WHERE session_id=?", (session,)
        ).fetchone() == (None, 1)


def test_client_binding_wins_race_with_an_inflight_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        session, _ = _watched(harness, store)
        watch = store.funding_watch(session)
        store._connection.execute(  # noqa: SLF001 - concurrent authenticated admission result
            "UPDATE swaps SET state='FUNDING_SEEN',funding_binding=? WHERE session_id=?",
            (b"original client binding", session),
        )
        with pytest.raises(live.StaleSwapError):
            store.record_funding_scan(
                session, watch, FundingScan(20, BLOCK, 20, BLOCK, (RECEIPT,), mempool_seen=False)
            )
        assert store._connection.execute(  # noqa: SLF001
            "SELECT selected_binding FROM forward_funding WHERE session_id=?", (session,)
        ).fetchone() == (None,)


def test_owner_loss_rejects_inflight_discovery_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        session, _ = _watched(harness, store)
        watch = store.funding_watch(session)
        store._connection.execute("UPDATE meta SET generation=generation+1")  # noqa: SLF001
        with pytest.raises(live.StaleOwnerError):
            store.record_funding_scan(
                session, watch, FundingScan(20, BLOCK, 20, BLOCK, (), mempool_seen=False)
            )


def test_observed_only_claim_is_rebroadcast_by_independent_restarted_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    monkeypatch.setattr(live, "check_funding_binding_transaction", Mock())
    with harness.acquire() as store:
        session, terms = _watched(harness, store)
        updated = store.record_funding_scan(
            session,
            store.funding_watch(session),
            FundingScan(20, BLOCK, 20, BLOCK, (RECEIPT,), mempool_seen=False),
        )
        observed = ObservedFunding(
            BINDING.model_copy(update={"contract_hash": contract_hash(terms).hex()}),
            b"confirmed funding bytes",
        )
        store.select_observed_funding(session, updated, observed, now=1001)
        store._connection.execute(  # noqa: SLF001 - already signed, selected claim fixture
            "UPDATE swaps SET state='CLAIMING',preimage=?,claim_tx=?,claim_txid=?",
            ("42" * 32, b"signed claim", "dd" * 32),
        )
        store._connection.execute(  # noqa: SLF001
            "INSERT INTO claim_attempts VALUES (?,0,?,?,1000,20)",
            (session, "dd" * 32, b"signed claim"),
        )
    with harness.acquire() as store:
        chain = Mock()
        engine = settlement_engine.SettlementEngine(store, chain, Mock(), Mock())
        (selected,) = engine.recorded_unilateral_claims()
        assert selected.funding_binding is None
        assert selected.observed_funding == observed
        checked = Mock()
        monkeypatch.setattr(settlement_engine, "check_funding_binding_transaction", checked)
        monkeypatch.setattr(engine, "_authorization", Mock())
        monkeypatch.setattr(
            settlement_engine,
            "validate_unilateral_spend",
            Mock(
                return_value=Mock(
                    raw_transaction=selected.raw,
                    txid=selected.txid,
                    fee_sat=selected.fee_sat,
                )
            ),
        )
        asyncio.run(engine.broadcast_recorded_unilateral(selected))
        checked.assert_called_once()
        assert checked.call_args.args[:2] == (observed.transaction, observed.binding)
        chain.broadcast.assert_called_once_with(selected.raw, selected.txid)


def test_descriptor_observation_is_bounded_and_includes_mempool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, network = _context()
    reader = CoreTransactionReader(port=18443, cookie_path=_cookie(tmp_path), network=network)
    calls = []

    def rpc(
        _client: object, method: str, params: list[object], _request_id: int, **_kwargs: object
    ) -> Any:  # noqa: ANN401 - heterogeneous Core RPC fixtures
        calls.append((method, params))
        if method == "getblockchaininfo":
            return {
                "chain": "regtest",
                "blocks": 100,
                "bestblockhash": BLOCK,
                "initialblockdownload": False,
            }
        if method == "getblockhash":
            return GENESIS if params == [0] else BLOCK
        assert method == "getdescriptoractivity"
        return {
            "activity": [
                {
                    "type": "receive",
                    "txid": "aa" * 32,
                    "vout": 0,
                    "output_spk": {"hex": SCRIPT.hex()},
                }
            ]
        }

    monkeypatch.setattr(reader, "_rpc", rpc)
    result = reader.discover_funding(SCRIPT, from_height=10)
    assert result.height == 10 + MAX_SCAN_BLOCKS - 1
    assert result.mempool_seen
    assert not result.receipts
    assert (
        "getdescriptoractivity",
        [[BLOCK] * MAX_SCAN_BLOCKS, [f"raw({SCRIPT.hex()})"], True],
    ) in calls
    with pytest.raises(CoreProtocolError, match="checkpoint"):
        reader.discover_funding(SCRIPT, from_height=10, anchor_block="ff" * 32)
