"""Swap-owned reconnecting sockets. Session keys and financial effects stay with the caller."""

from __future__ import annotations

import asyncio
import copy
import logging
from typing import TYPE_CHECKING, Any, Protocol, Self

from rill_provider.diagnostics import diagnostic
from rill_provider.relay_client import RelayConnection, RelayError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

MAX_LIVE_RELAYS = 8


class RelayTransport(Protocol):
    """The existing live-session surface, also implemented by a single connection."""

    async def publish(self, event: bytes, *, timeout: float = 10.0) -> bool:  # noqa: ASYNC109 - matches the single-socket API
        """Publish existing bytes, without interpreting application effects."""
        ...

    async def subscribe(self, filters: list[dict[str, Any]]) -> None:
        """Replace the current subscription."""
        ...

    def events(self) -> AsyncIterator[bytes]:
        """Receive unverified event bytes."""
        ...


class LiveRelayConnection:
    """At most two live sockets from an explicitly permitted, immutable relay set."""

    def __init__(
        self,
        url: str,
        *,
        fallbacks: tuple[str, ...] = (),
        proxy: str | None = None,
        factory: Callable[[str], RelayConnection] | None = None,
        retry_seconds: float = 1.0,
    ) -> None:
        """Validate explicit routes; the context manager owns every opened socket."""
        self.urls = tuple(dict.fromkeys((url, *fallbacks)))
        if len(self.urls) > MAX_LIVE_RELAYS:
            raise RelayError("at most eight explicit swap relays are allowed")
        self._factory = factory or (lambda target: RelayConnection(target, proxy=proxy))
        # Preserve the caller's connection factory and its route-validation boundary.
        self._prepared = {candidate: self._factory(candidate) for candidate in self.urls}
        self._retry_seconds = retry_seconds
        self._connections: dict[str, RelayConnection] = {}
        self._opening: set[str] = set()
        self._filters: list[dict[str, Any]] = []
        self._queue: asyncio.Queue[bytes] = asyncio.Queue(1024)
        self._changed = asyncio.Event()
        self._stopped = False
        self._fault: RelayError | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self._seed: RelayConnection | None = None
        self._availability: dict[str, bool] = {}

    def _status(self, url: str, *, available: bool) -> None:
        if self._availability.get(url) == available:
            return
        self._availability[url] = available
        diagnostic(
            logging.getLogger(__name__),
            "relay.connected" if available else "relay.unavailable",
            "Swap relay connected" if available else "Swap relay unavailable; reconnecting",
            level=logging.INFO if available else logging.WARNING,
            relay=url,
            retry_seconds=None if available else int(self._retry_seconds),
        )

    async def __aenter__(self) -> Self:
        for url in self.urls:
            connection = self._take_connection(url)
            try:
                await connection.__aenter__()
            except RelayError:
                self._status(url, available=False)
                continue
            self._seed = connection
            self._tasks.append(asyncio.create_task(self._maintain((url, connection))))
            if len(self.urls) > 1:
                self._tasks.append(asyncio.create_task(self._maintain()))
            return self
        raise RelayError("no permitted relay is available")

    def _take_connection(self, url: str) -> RelayConnection:
        if url in self._prepared:
            return self._prepared.pop(url)
        return self._factory(url)

    async def __aexit__(self, *_exc: object) -> None:
        self._stopped = True
        self._changed.set()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._seed is not None:  # a worker canceled before its coroutine first ran
            await self._seed.__aexit__(None, None, None)
            self._seed = None

    async def _maintain(self, seed: tuple[str, RelayConnection] | None = None) -> None:
        if seed is not None:
            self._seed = None  # this worker now owns closing it, including on cancellation
        delay = self._retry_seconds
        cursor = 0
        while not self._stopped:
            available = [
                url
                for url in self.urls
                if url not in self._connections and url not in self._opening
            ]
            if seed is None and not available:
                await asyncio.sleep(self._retry_seconds)
                continue
            url = seed[0] if seed else available[cursor % len(available)]
            cursor += 1
            connection = seed[1] if seed else self._take_connection(url)
            entered = seed is not None
            self._opening.add(url)
            try:
                if not entered:
                    await connection.__aenter__()
                # A subscription can change while a reconnect is opening. Never install
                # an obsolete discovery filter over the current session mailbox.
                while self._filters:
                    filters = self._filters
                    await connection.subscribe(filters)
                    if filters is self._filters:
                        break
                self._connections[url] = connection
                self._opening.discard(url)
                self._changed.set()
                delay = self._retry_seconds
                self._status(url, available=True)
                async for event in connection.events():
                    try:
                        self._queue.put_nowait(event)
                    except asyncio.QueueFull:
                        self._fault = RelayError("live relay inbox overflow")
                        return
                    self._changed.set()
            except (RelayError, OSError, TimeoutError):
                pass
            finally:
                seed = None
                self._opening.discard(url)
                self._connections.pop(url, None)
                await connection.__aexit__(None, None, None)
                self._changed.set()
            if not self._stopped:
                self._status(url, available=False)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30.0)

    async def subscribe(self, filters: list[dict[str, Any]]) -> None:
        """Retain the exact filter, including its original replay floor."""
        self._filters = copy.deepcopy(filters)  # original since floor survives every reconnect
        if self._connections:
            await asyncio.gather(
                *(connection.subscribe(self._filters) for connection in self._connections.values())
            )

    async def publish(self, event: bytes, *, timeout: float = 10.0) -> bool:  # noqa: ASYNC109 - existing transport API
        """Await relay acceptance within the caller's original budget."""
        return await self._publish(event, budget_seconds=timeout)

    async def publish_guarded(self, event: bytes, guard: Callable[[], None]) -> bool:
        """Recheck application authority after reconnecting, at each actual write."""
        return await self._publish(event, budget_seconds=10.0, guard=guard)

    async def _publish(
        self,
        event: bytes,
        *,
        budget_seconds: float,
        guard: Callable[[], None] | None = None,
    ) -> bool:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + budget_seconds
        while not self._stopped:
            if self._fault:
                raise self._fault
            connections = tuple(self._connections.values())
            remaining = deadline - loop.time()
            if remaining <= 0:
                return False
            if connections:

                async def send(
                    connection: RelayConnection, budget_seconds: float = remaining
                ) -> bool:
                    if guard is not None:
                        guard()
                    return await connection.publish(event, timeout=min(budget_seconds, 2.0))

                tasks = [asyncio.create_task(send(connection)) for connection in connections]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for connection, result in zip(connections, results, strict=True):
                    if isinstance(result, BaseException) and not isinstance(
                        result, (RelayError, OSError, TimeoutError)
                    ):
                        raise result
                    if result is not True:
                        # End this socket so its owner rotates to another permitted relay.
                        await connection.__aexit__(None, None, None)
                return any(result is True for result in results)
            self._changed.clear()
            try:
                await asyncio.wait_for(self._changed.wait(), remaining)
            except TimeoutError:
                return False
        raise RelayError("live relay closed")

    async def events(self) -> AsyncIterator[bytes]:
        """Merge bounded raw ingress across socket lifetimes."""
        while not self._stopped:
            if self._fault:
                raise self._fault
            if not self._queue.empty():
                yield self._queue.get_nowait()
                continue
            self._changed.clear()
            await self._changed.wait()
