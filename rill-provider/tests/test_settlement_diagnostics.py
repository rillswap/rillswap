"""Committed diagnostics cannot create results or expose retained secrets."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import replace

import pytest
from test_lnd_invoice_decode import INVOICE, PAYEE, _payreq
from test_settlement_engine import ITEM, TERMS, _backends

from rill_provider.lnd_invoice_decode import binding_from_payreq
from rill_provider.lnd_payment_send import PaymentOutcome
from rill_provider.settlement_diagnostics import terms_facts


def test_terms_are_explicit_financial_facts_not_whole_objects() -> None:
    facts = terms_facts(TERMS)
    assert facts["payment_hash"] == TERMS.invoice_binding.payment_hash
    assert facts["amount_msat"] == TERMS.invoice_binding.amount_msat
    assert facts["success_fee_sat"] == TERMS.economics.success_fee_sat
    assert "payee_compressed_pubkey" not in facts
    assert "invoice" not in facts


def test_each_committed_intermediate_move_is_logged_without_observation_payloads(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _, _ = _backends(PaymentOutcome("UNKNOWN"))
    engine._store.settlement_work.return_value = [ITEM]  # noqa: SLF001
    engine._store.unfunded_swaps.return_value = []  # noqa: SLF001
    engine._store.expirable_exposure_pending.return_value = False  # noqa: SLF001

    async def advance(_item: object, now: int) -> str:
        engine._move(  # noqa: SLF001 - post-commit owner hook regression
            ITEM, "PAID", now, observation={"payment_preimage": "SECRET"}, routing_fee_msat=31
        )
        return engine._move(replace(ITEM, state="PAID"), "CLAIMING", now, claim_fee_sat=123)  # noqa: SLF001

    monkeypatch.setattr(engine, "_advance", advance)
    with caplog.at_level(logging.INFO):
        asyncio.run(engine.tick(1000))
    records = [
        record for record in caplog.records if getattr(record, "event", "") == "swap.transition"
    ]
    assert [record.facts["to_state"] for record in records] == ["PAID", "CLAIMING"]
    assert records[0].facts["routing_fee_msat"] == 31
    assert records[1].facts["claim_fee_sat"] == 123
    assert "SECRET" not in str([record.__dict__ for record in records])


def test_refused_commit_does_not_emit_success(caplog: pytest.LogCaptureFixture) -> None:
    engine, _, _ = _backends(PaymentOutcome("UNKNOWN"))
    engine._store.advance_swap.side_effect = ValueError("refused")  # noqa: SLF001
    with caplog.at_level(logging.INFO), pytest.raises(ValueError, match="refused"):
        engine._move(ITEM, "PAID", 1000)  # noqa: SLF001
    assert not [
        record for record in caplog.records if getattr(record, "event", "") == "swap.transition"
    ]


def test_invoice_diagnostics_do_not_include_invoice_payee_or_payment_secret(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO):
        binding_from_payreq(INVOICE, _payreq(description="Coffee\n\x1b[31m " + "c9" * 32))
    records = [
        record for record in caplog.records if getattr(record, "event", "") == "invoice.decoded"
    ]
    assert len(records) == 1
    facts = records[0].facts
    assert facts["memo"].startswith("Coffee\\n\\x1b")
    assert "c9" * 32 not in facts["memo"]
    assert facts["amount_msat"] == "50000000"
    rendered = str([record.__dict__ for record in records])
    assert INVOICE not in rendered
    assert PAYEE not in rendered
    assert (b"s" * 32).hex() not in rendered
