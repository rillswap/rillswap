"""Local diagnostics preserve financial facts, not signing material or raw errors."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import TYPE_CHECKING

from rill_provider.diagnostics import DiagnosticFormatter, diagnostic, diagnostic_context, safe_memo

if TYPE_CHECKING:
    import pytest


def _record() -> logging.LogRecord:
    record = logging.LogRecord("rill.test", logging.INFO, __file__, 1, "Payment verified", (), None)
    record.created = 1793380800.125
    return record


def test_console_and_json_are_timestamped_single_lines_with_allowlisted_financial_facts() -> None:
    record = _record()
    record.event = "payment.verified"
    record.facts = {
        "payment_hash": "ab" * 32,
        "amount_msat": "12000000",
        "success_fee_sat": "-12",
        "preimage": "SECRET",
        "invoice": "SECRET",
        "payment_secret": "SECRET",
    }
    with diagnostic_context(session_id="cd" * 32, profile="btc-to-ln/v1"):
        text = DiagnosticFormatter().format(record)
        data = json.loads(DiagnosticFormatter(json_output=True).format(record))
    assert "2026-10-30T" in text
    assert "payment.verified" in text
    assert "SECRET" not in text
    assert "\x1b" not in text
    assert len(text.splitlines()) == 1
    assert data["success_fee_sat"] == "-12"
    assert data["payment_hash"] == "ab" * 32
    assert data["session_id"] == "cd" * 32
    assert "invoice" not in data


def test_memo_is_bounded_escaped_and_does_not_become_a_secret_transport() -> None:
    memo = safe_memo("Coffee\n\x1b[31m " + "ab" * 32 + " " + "x" * 200)
    assert "\n" not in memo
    assert "\x1b" not in memo
    assert "ab" * 32 not in memo
    assert "[redacted]" in memo
    assert len(memo) <= 100


def test_reason_fields_accept_codes_not_backend_error_messages(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO):
        diagnostic(
            logging.getLogger(__name__),
            "backend.failed",
            "Backend unavailable",
            reason="secret-bearing detail https://credentials.example/token",
            operation="fee_sample",
            error_type="ValueError",
        )
    facts = caplog.records[-1].facts
    assert "reason" not in facts
    assert facts["operation"] == "fee_sample"


def test_exception_format_never_includes_exception_detail_or_source() -> None:
    try:
        raise ValueError("SECRET invoice and credentials")  # noqa: TRY301
    except ValueError:
        record = _record()
        record.exc_info = sys.exc_info()
    text = DiagnosticFormatter().format(record)
    assert "ValueError" in text
    assert "test_diagnostics.py" in text
    assert "SECRET" not in text


def test_context_is_task_local_and_restored() -> None:
    async def run() -> list[str]:
        async def one(session: str) -> str:
            with diagnostic_context(session_id=session):
                await asyncio.sleep(0)
                return DiagnosticFormatter(json_output=True).format(_record())

        return await asyncio.gather(one("one"), one("two"))

    assert [json.loads(line)["session_id"] for line in asyncio.run(run())] == ["one", "two"]
    assert "session_id" not in json.loads(DiagnosticFormatter(json_output=True).format(_record()))


def test_broken_handler_cannot_change_execution() -> None:
    class Broken(logging.Handler):
        def emit(self, _record: logging.LogRecord) -> None:
            raise RuntimeError("gone")

    logger = logging.getLogger("test.broken.diagnostic")
    handler = Broken()
    logger.addHandler(handler)
    try:
        diagnostic(logger, "swap.transition", "committed", level=logging.WARNING, preimage="SECRET")
    finally:
        logger.removeHandler(handler)
