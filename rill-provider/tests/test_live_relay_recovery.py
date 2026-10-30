"""Long outages change delivery scheduling, never contract or nonce authority."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

import pytest
from fake_relay import FakeRelay
from test_live_session_store import Harness
from test_payment_dispatch_store import _insert_funded_swap
from test_relay_client import _event
from test_transport_pow_admission import EPOCH, _service

from rill_provider.handshake_service import NIP59_BACKDATE_SECONDS, REPLAY_CLOCK_SKEW_SECONDS
from rill_provider.live_session_store import MailboxWork, OutboxEntry
from rill_provider.relay_client import SUBSCRIPTION_ID, RelayConnection

if TYPE_CHECKING:
    from pathlib import Path


def test_only_known_unfinished_economic_mailboxes_get_anchored_catchup() -> None:
    active, missing, finished = "a1" * 32, "a2" * 32, "a3" * 32
    service, _ = _service(
        8,
        (
            MailboxWork(active, 12, finished=False, reserved_at=100),
            MailboxWork(missing, None, finished=False),
            MailboxWork(finished, None, finished=True),
        ),
    )
    service._clock = lambda: 100_000  # noqa: SLF001 - hours later, including a fresh process
    rolling, anchored = service._filters()  # noqa: SLF001
    assert rolling["#p"] == sorted([EPOCH, missing, finished])
    assert anchored["#p"] == [active]
    assert anchored["since"] == 100 - NIP59_BACKDATE_SECONDS - REPLAY_CLOCK_SKEW_SECONDS
    # A wrapper backdated near the full 48 hours still falls inside the active filter.
    assert anchored["since"] <= 101 - NIP59_BACKDATE_SECONDS < rolling["since"]
    assert service._state.work[active] == 12  # noqa: SLF001 - same work, wider delivery only
    service._clock = lambda: -100_000  # noqa: SLF001
    rolling, anchored = service._filters()  # noqa: SLF001
    assert anchored["since"] <= rolling["since"]


def test_resubscription_tracks_all_filter_groups_without_replaying_every_clock_tick() -> None:
    async def exercise() -> None:
        key = "a1" * 32
        service, store = _service(0, (MailboxWork(key, None, finished=False),))
        relay = Mock(subscribe=AsyncMock(), dropped_events=0)
        await service._resubscribe([relay])  # noqa: SLF001
        store.mailbox_work.return_value = (MailboxWork(key, None, finished=False, reserved_at=100),)
        await service._resubscribe([relay])  # noqa: SLF001
        assert relay.subscribe.await_count == 2
        assert len(relay.subscribe.call_args.args[0]) == 2
        service._clock = lambda: 2000  # noqa: SLF001
        await service._resubscribe([relay])  # noqa: SLF001
        assert relay.subscribe.await_count == 2
        relay.dropped_events = 1
        await service._resubscribe([relay])  # noqa: SLF001
        assert relay.subscribe.await_count == 3
        assert len(relay.subscribe.call_args.args[0]) == 2

    asyncio.run(exercise())


def test_store_reuses_existing_reservation_and_missing_anchor_never_invents_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        session_id = _insert_funded_swap(store, harness, "LN_HELD")
        assert store.mailbox_work()[0].reserved_at == 1000
        store._connection.execute("DELETE FROM payment_hashes WHERE session_id=?", (session_id,))  # noqa: SLF001 - damaged-state read fixture only
        assert store.mailbox_work()[0].reserved_at is None


def test_session_backfill_reads_only_existing_pending_rows_without_reclassifying_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        session_id = _insert_funded_swap(store, harness, "LN_HELD")
        # Read-path fixtures only, not signed messages or financial admission.
        for sequence, state in enumerate(("PENDING", "ACKED", "RECONCILED")):
            store._connection.execute(  # noqa: SLF001
                "INSERT INTO outbox VALUES (?, ?, ?, NULL, ?, 1, ?)",
                (str(sequence), session_id, sequence, b"{}", state),
            )
        store._connection.execute(  # noqa: SLF001
            "INSERT INTO outbox VALUES ('other', 'other-session', 0, NULL, ?, 1, 'PENDING')",
            (b"{}",),
        )
        before = store._connection.execute("SELECT * FROM outbox").fetchall()  # noqa: SLF001
        assert [entry.message_id for entry in store.pending_outbox(session_id=session_id)] == ["0"]
        assert {entry.message_id for entry in store.pending_outbox()} == {"0", "other"}
        assert store._connection.execute("SELECT * FROM outbox").fetchall() == before  # noqa: SLF001


def test_urgent_delivery_preserves_deadline_and_does_not_retry_ordinary_debt() -> None:
    async def exercise() -> None:
        service, store = _service(0)
        clock = [1000]
        service._clock = lambda: clock[0]  # noqa: SLF001
        store.pending_requires_live_cooperation.return_value = False
        store.pending_sendable.return_value = True
        store.wrap_pending.return_value = b"existing archived response"
        relay = Mock(publish=AsyncMock(return_value=True))
        service._remember_urgent(  # noqa: SLF001
            json.dumps(
                {"payload": {"action": "cooperative_claim_propose", "deadline_at": 1020}}
            ).encode(),
            "reply",
        )
        service._state.attempts.update({"reply": 1000, "ordinary": 1000})  # noqa: SLF001
        clock[0] = 1001
        await service._retry_urgent([relay])  # noqa: SLF001
        relay.publish.assert_not_called()
        clock[0] = 1002
        await service._retry_urgent([relay])  # noqa: SLF001
        relay.publish.assert_awaited_once_with(b"existing archived response")
        clock[0] = 1021
        await service._retry_urgent([relay])  # noqa: SLF001
        assert relay.publish.await_count == 1
        assert service._state.urgent_until == {}  # noqa: SLF001
        store.pending_outbox.assert_not_called()  # no repeated all-history scan

    asyncio.run(exercise())


def test_cooperative_reply_prompts_ordered_backfill_of_only_the_same_pending_session() -> None:
    service, store = _service(0)
    store.pending_outbox.return_value = (
        OutboxEntry("earlier-observation", "same-session", b"existing bytes"),
        OutboxEntry("reply", "same-session", b"existing signed reply"),
    )
    service._remember_urgent(  # noqa: SLF001
        json.dumps(
            {"payload": {"action": "cooperative_claim_propose", "deadline_at": 1020}}
        ).encode(),
        "reply",
        session_id="same-session",
    )
    store.pending_outbox.assert_called_once_with(session_id="same-session")
    assert service._state.urgent_until == {"reply": 1020, "earlier-observation": 1020}  # noqa: SLF001
    # Replaying after the original deadline cannot renew the catch-up burst.
    store.pending_outbox.reset_mock()
    service._clock = lambda: 1021  # noqa: SLF001
    service._remember_urgent(  # noqa: SLF001
        json.dumps(
            {"payload": {"action": "cooperative_claim_propose", "deadline_at": 1020}}
        ).encode(),
        "reply",
        session_id="same-session",
    )
    store.pending_outbox.assert_not_called()


def test_forward_readiness_backfill_keeps_the_original_deadline() -> None:
    service, store = _service(0)
    store.pending_outbox.return_value = (
        OutboxEntry("payment-observation", "forward-session", b"existing observation"),
        OutboxEntry("readiness", "forward-session", b"existing readiness request"),
    )
    service._expedite_session_delivery("forward-session", 1020)  # noqa: SLF001
    store.pending_outbox.assert_called_once_with(session_id="forward-session")
    assert service._state.urgent_until == {  # noqa: SLF001
        "payment-observation": 1020,
        "readiness": 1020,
    }
    store.pending_outbox.reset_mock()
    service._clock = lambda: 1021  # noqa: SLF001
    service._expedite_session_delivery("forward-session", 1020)  # noqa: SLF001
    store.pending_outbox.assert_not_called()


def test_slow_relay_cannot_hide_acceptance_or_leak_a_publication_task() -> None:
    async def exercise() -> None:
        service, _ = _service(0)
        stopped = asyncio.Event()

        async def hung(_event: bytes) -> bool:
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()
            return False

        slow, healthy = Mock(publish=hung), Mock(publish=AsyncMock(return_value=True))
        assert await service._publish(b"encrypted", [slow, healthy], budget_seconds=0.01)  # noqa: SLF001
        assert stopped.is_set()

    asyncio.run(exercise())


def test_rejected_mailbox_subscription_ends_the_stream_without_logging_relay_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def exercise() -> None:
        relay = FakeRelay()
        url = await relay.start()
        recipient = "cc" * 32
        try:
            async with RelayConnection(url) as connection:
                await connection.subscribe([{"kinds": [1059], "#p": [recipient]}])
                await relay.inject(_event("07" * 32, recipient))
                events = connection.events()
                await asyncio.wait_for(anext(events), 1)
                socket = relay.subscribers[0][0]
                await socket.send_str(
                    json.dumps(["CLOSED", SUBSCRIPTION_ID, "private untrusted text"])
                )
                with pytest.raises(StopAsyncIteration):
                    await asyncio.wait_for(anext(events), 1)
                assert connection.closed
        finally:
            await relay.stop()

    asyncio.run(exercise())
    assert "subscription closed" in caplog.text
    assert "private untrusted text" not in caplog.text
