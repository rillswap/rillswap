"""Notification diagnostics do not change disclosure, history, or financial ownership."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
from types import SimpleNamespace
from typing import TYPE_CHECKING

from test_notifications import Clocks, Ledger, Sender, _notifier

from rill_provider import cli

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    import pytest


def test_supervision_gate_is_a_delayed_health_alert_and_clears_once() -> None:
    clocks = Clocks()
    notifier, sender = _notifier(Ledger(), clocks, alert_after_seconds=60)
    clocks.health = replace(clocks.health, admission_ready=False)
    asyncio.run(notifier.poll())
    assert sender.sent == []
    clocks.mono = 60
    asyncio.run(notifier.poll())
    asyncio.run(notifier.poll())
    assert len(sender.sent) == 1
    assert "settlement supervision unavailable" in sender.sent[0][1]
    clocks.health = replace(clocks.health, admission_ready=True)
    asyncio.run(notifier.poll())
    asyncio.run(notifier.poll())
    assert len(sender.sent) == 2
    assert "quotes resumed" in sender.sent[-1][0]


def test_explicit_test_uses_configured_notification_route_without_opening_store(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sender = Sender()
    routes: list[object] = []

    @asynccontextmanager
    async def notification_sender(_settings: object, proxy: object) -> AsyncIterator[Sender]:
        routes.append(proxy)
        yield sender

    monkeypatch.setattr(cli, "notification_sender", notification_sender)
    monkeypatch.setattr(
        cli, "require_relay_route", lambda *_args, **_kwargs: "http://127.0.0.1:9080"
    )
    config = SimpleNamespace(
        notifications=object(),
        network=SimpleNamespace(name="signet"),
        relay_proxy="http://127.0.0.1:9080",
        allow_direct_relays=False,
        handshake=SimpleNamespace(profile="btc-to-ln/v1"),
    )
    assert asyncio.run(cli._test_notification(config)) == 0  # noqa: SLF001
    assert routes == ["http://127.0.0.1:9080"]
    assert len(sender.sent) == 1
    assert "No swap was started" in sender.sent[0][1]
    sender.result = OSError("https://SECRET.invalid/token")
    assert asyncio.run(cli._test_notification(config)) == 2  # noqa: SLF001
    assert "SECRET" not in caplog.text
