"""Live client transport repairs sockets without restarting the session caller."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Self

import pytest

from rill_cli.live_relay import LiveRelayConnection

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class Connection:
    def __init__(self) -> None:
        self.filters: list[list[dict[str, Any]]] = []
        self.sent: list[bytes] = []
        self.queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.closed = False

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        if not self.closed:
            self.closed = True
            self.queue.put_nowait(None)

    async def subscribe(self, filters: list[dict[str, Any]]) -> None:
        self.filters.append(filters)

    async def publish(self, event: bytes, *, timeout: float = 10.0) -> bool:  # noqa: ASYNC109, ARG002
        self.sent.append(event)
        return not self.closed

    async def events(self) -> AsyncIterator[bytes]:
        while not self.closed:
            event = await self.queue.get()
            if event is not None:
                yield event


async def _until(check: Any) -> None:  # noqa: ANN401 - compact fixture predicate
    async with asyncio.timeout(1):
        while not check():  # noqa: ASYNC110 - bounded fixture predicate
            await asyncio.sleep(0.001)


def test_disconnect_reopens_the_same_mailbox_with_its_original_history_floor() -> None:
    async def exercise() -> None:
        connections: list[Connection] = []

        def connect(_url: str) -> Connection:
            connection = Connection()
            connections.append(connection)
            return connection

        link = LiveRelayConnection("ws://localhost:7000", factory=connect, retry_seconds=0.001)  # type: ignore[arg-type]
        filters = [{"kinds": [1059], "#p": ["original mailbox"], "since": 1000 - 172800}]
        async with link:
            await link.subscribe(filters)
            await _until(lambda: bool(connections[0].filters))
            await connections[0].queue.put(b"before outage")
            await connections[0].__aexit__()
            await _until(lambda: len(connections) == 2 and bool(connections[1].filters))
            assert connections[1].filters == [filters]
            await connections[1].queue.put(b"after outage")
            events = link.events()
            assert await anext(events) == b"before outage"
            assert await anext(events) == b"after outage"
            await events.aclose()
            assert await link.publish(b"same encrypted event")
            assert connections[1].sent == [b"same encrypted event"]
        assert all(connection.closed for connection in connections)

    asyncio.run(exercise())


def test_explicit_alternate_delivers_after_primary_loss_and_exit_joins_workers() -> None:
    async def exercise() -> None:
        sockets: dict[str, Connection] = {}

        def connect(url: str) -> Connection:
            connection = Connection()
            sockets[url] = connection
            return connection

        link = LiveRelayConnection(
            "ws://localhost:7000",
            fallbacks=("ws://localhost:7001",),
            factory=connect,
            retry_seconds=0.01,
        )  # type: ignore[arg-type]
        async with link:
            await link.subscribe([{"kinds": [1059], "#p": ["same mailbox"]}])
            await _until(
                lambda: len(sockets) == 2 and all(value.filters for value in sockets.values())
            )
            await sockets["ws://localhost:7000"].__aexit__()
            assert await link.publish(b"unchanged signed request")
            assert sockets["ws://localhost:7001"].sent == [b"unchanged signed request"]
        assert all(task.done() for task in link._tasks)  # noqa: SLF001

    asyncio.run(exercise())


def test_immediate_context_exit_closes_a_seed_before_its_worker_starts() -> None:
    async def exercise() -> None:
        connection = Connection()
        async with LiveRelayConnection("ws://localhost:7000", factory=lambda _: connection):  # type: ignore[arg-type]
            pass
        assert connection.closed

    asyncio.run(exercise())


def test_publication_guard_is_rechecked_after_a_reconnect_wait() -> None:
    async def exercise() -> None:
        reconnecting, release = asyncio.Event(), asyncio.Event()
        first, replacement = Connection(), Connection()
        allowed = [True]
        attempts = [0]

        class DelayedConnection(Connection):
            async def __aenter__(self) -> Self:
                reconnecting.set()
                await release.wait()
                return self

        def connect(_url: str) -> Connection:
            attempts[0] += 1
            return first if attempts[0] == 1 else replacement

        replacement = DelayedConnection()
        async with LiveRelayConnection(
            "ws://localhost:7000", factory=connect, retry_seconds=0.001
        ) as link:  # type: ignore[arg-type]
            await link.subscribe([{"kinds": [1059]}])
            await _until(lambda: bool(first.filters))
            await first.__aexit__()
            await reconnecting.wait()

            def guard() -> None:
                if not allowed[0]:
                    raise RuntimeError("original window expired")

            publishing = asyncio.create_task(link.publish_guarded(b"must remain private", guard))
            allowed[0] = False
            release.set()
            with pytest.raises(RuntimeError, match="original window expired"):
                await publishing
            assert replacement.sent == []

    asyncio.run(exercise())
