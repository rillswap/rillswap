"""Diagnostic changes leave command results and recovery authority alone."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from rill_provider import diagnostics
from test_refund_watcher import LOCK, _watcher, _World

from rill_cli import main, swap_command
from rill_cli.refund_watcher import ChainView

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_log_options_are_explicit_and_stdout_results_are_unchanged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    args = main._parser().parse_args(  # noqa: SLF001 - command option contract
        [
            "--log-format",
            "json",
            "--log-level",
            "DEBUG",
            "providers",
            "list",
            "--network",
            "network.json",
            "--crypto-library",
            "lib.so",
            "--relay",
            "ws://127.0.0.1:7777",
        ]
    )
    assert args.log_format == "json"
    assert args.log_level == "DEBUG"
    monkeypatch.setattr(main, "_network", lambda _: object())
    monkeypatch.setattr(main.provider_directory, "run", lambda *_: '{"providers":[]}')
    assert main._providers(args) == 0  # noqa: SLF001
    assert capsys.readouterr().out == '{"providers":[]}\n'


def test_payment_invoice_display_is_not_a_diagnostic_record(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    with caplog.at_level(logging.INFO):
        swap_command._payment_prompt("lnbcrt1FULL_INVOICE")  # noqa: SLF001
    assert capsys.readouterr().err == "lnbcrt1FULL_INVOICE\n"
    assert "FULL_INVOICE" not in caplog.text


def test_progress_remains_stderr_under_an_embedding_logger_and_supports_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    import json  # noqa: PLC0415 - focused renderer assertion

    token = diagnostics._OUTPUT_FORMAT.set("json")  # noqa: SLF001 - task-local format contract
    try:
        with diagnostics.diagnostic_context(payment_hash="ab" * 32, amount_msat="1000"):
            swap_command._report("safety warning: keep your recovery file")  # noqa: SLF001
        captured = capsys.readouterr()
        assert captured.out == ""
        record = json.loads(captured.err)
        assert record["event"] == "swap.progress"
        assert record["payment_hash"] == "ab" * 32
        assert "keep your recovery file" in record["message"]
    finally:
        diagnostics._OUTPUT_FORMAT.reset(token)  # noqa: SLF001 - restore format for other commands


def test_refund_wait_progress_is_change_based_and_survives_a_throwing_reporter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = _World(view=ChainView(LOCK, unspent_on_chain=True))
    watcher = _watcher(tmp_path, world, monkeypatch)
    lines: list[str] = []
    watcher._report = lines.append  # noqa: SLF001
    assert watcher.run(max_polls=3) is None
    assert len(lines) == 1
    assert f"first eligible block {LOCK + 1}" in lines[0]
    world.invoice = None
    watcher.run(max_polls=3)
    assert len(lines) == 2
    assert "invoice state unavailable" in lines[-1]

    def broken(_line: str) -> None:
        raise RuntimeError("observer gone")

    watcher._report = broken  # noqa: SLF001
    world.invoice = "SETTLED"
    assert watcher.step()["outcome"] == "invoice_settled"
    assert world.submitted == []
