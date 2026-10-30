"""Minimal NIP-01 relay connection: publish with OK, one replaceable subscription.

Relay frames are untrusted. This module only enforces frame shape and size and
hands raw event JSON to callers, which must verify it (the NIP-59 decoders do).
Publication success means one relay stored the event, never peer delivery.

Relay routing fails closed. On public networks a connection must go through a
local HTTP CONNECT proxy (Tor's ``HTTPTunnelPort``) unless direct connections
are explicitly allowed; there is never a silent fallback to a direct socket.
The proxy receives the relay host name, so no local DNS lookup reveals it,
and every connection attempt gets its own Tor circuit (``tor_tunnel``).

Plain ``ws://`` is tunneled only to a v3 onion relay, which Tor encrypts and
authenticates end to end. Onion relays are reachable only through the proxy.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
from contextlib import suppress
from typing import TYPE_CHECKING, Any, Self
from urllib.parse import urlsplit

import aiohttp

from rill_provider.tor_tunnel import (
    ISOLATION_HEADER,
    MAX_TUNNEL_REPLY,
    connect_request,
    isolation_key,
    tunnel_established,
)

LOG = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable

    from aiohttp.client_proto import ResponseHandler
    from aiohttp.client_reqrep import ClientRequest
    from aiohttp.tracing import Trace
    from rill_core.wire.types import NetworkIdentity

MAX_FRAME_BYTES = 256 * 1024  # a 128 KiB event plus relay framing
MAX_QUEUED_EVENTS = 1024
SUBSCRIPTION_ID = "rill-provider"
OPEN_TIMEOUT = 10.0
ONION_OPEN_TIMEOUT = 60.0  # building a rendezvous circuit often takes tens of seconds
_ONION_HOST = re.compile(r"[a-z2-7]{56}\.onion")


class RelayError(RuntimeError):
    """The relay connection is unavailable; nothing about peers is implied."""


def is_onion_relay(url: str) -> bool:
    """Whether ``url`` is a ws:// or wss:// relay on a v3 onion service."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return False
    return parts.scheme in ("ws", "wss") and host is not None and bool(_ONION_HOST.fullmatch(host))


def reachable_relays(urls: Iterable[str], proxy: str | None) -> tuple[str, ...]:
    """Drop onion relays when there is no proxy to reach them; keep the order."""
    return tuple(url for url in urls if proxy is not None or not is_onion_relay(url))


def relay_proxy(proxy: str | None) -> str | None:
    """Return a checked loopback ``http://host:port`` proxy URL, or ``None``."""
    if proxy is None:
        return None
    try:
        parts = urlsplit(proxy)
        port = parts.port
    except ValueError:
        port = None
        parts = None
    if (
        parts is None
        or parts.scheme != "http"
        or parts.hostname not in ("127.0.0.1", "::1")
        or port is None
        or parts.username is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise RelayError("relay proxy must be a loopback http://host:port (Tor HTTPTunnelPort)")
    return proxy


def require_relay_route(
    network: NetworkIdentity, proxy: str | None, *, allow_direct: bool
) -> str | None:
    """Refuse direct relay sockets on public networks unless explicitly allowed.

    A direct socket reveals the operator's or user's IP address to every relay.
    Regtest is local test infrastructure and may connect directly.
    """
    checked = relay_proxy(proxy)
    if checked is None and network.name != "regtest" and not allow_direct:
        raise RelayError(
            "public networks need a relay proxy; direct relay sockets must be allowed explicitly"
        )
    return checked


def _event_json(event: object) -> bytes | None:
    if type(event) is not dict:
        return None
    try:
        return json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (UnicodeEncodeError, ValueError, TypeError):
        return None  # e.g. lone surrogates from a hostile relay


class _OnionTunnel(aiohttp.BaseConnector):
    """Open plain ws:// onion sockets through the CONNECT proxy.

    aiohttp only tunnels TLS targets with CONNECT and would forward a plain
    request in cleartext, so this connector opens the tunnel itself and hands
    the established socket to aiohttp, like ``aiohttp.UnixConnector`` does.
    """

    def __init__(self, proxy: str, isolation: str) -> None:
        super().__init__(force_close=True)
        parts = urlsplit(proxy)  # relay_proxy checked the host and port
        self._proxy_address = (parts.hostname or "", parts.port or 0)
        self._isolation = isolation

    async def _create_connection(
        self,
        req: ClientRequest,
        traces: list[Trace],
        timeout: aiohttp.ClientTimeout,  # noqa: ASYNC109 - aiohttp's connector signature
    ) -> ResponseHandler:
        del traces, timeout  # the session's connect timeout bounds the whole call
        request = connect_request(req.url.host or "", req.url.port or 80, self._isolation)
        sock = await _open_tunnel(self._loop, self._proxy_address, request)
        try:
            _, protocol = await self._loop.create_connection(self._factory, sock=sock)
        except BaseException:
            sock.close()
            raise
        return protocol


async def _open_tunnel(
    loop: asyncio.AbstractEventLoop, proxy: tuple[str, int], request: bytes
) -> socket.socket:
    """Return a non-blocking socket tunneled by the CONNECT proxy's ``request``."""
    sock = socket.socket(socket.AF_INET6 if ":" in proxy[0] else socket.AF_INET)
    try:
        sock.setblocking(False)  # noqa: FBT003 - socket API
        await loop.sock_connect(sock, proxy)
        await loop.sock_sendall(sock, request)
        reply = await _tunnel_reply(loop, sock)
    except OSError as error:
        sock.close()
        raise aiohttp.ClientConnectionError("relay proxy unavailable") from error
    except BaseException:
        sock.close()
        raise
    if not tunnel_established(reply):
        sock.close()
        raise aiohttp.ClientConnectionError("relay proxy refused the tunnel")
    return sock


async def _tunnel_reply(loop: asyncio.AbstractEventLoop, sock: socket.socket) -> bytes:
    """Read the proxy's reply one byte at a time, so no relay byte is consumed."""
    reply = b""
    while not reply.endswith(b"\r\n\r\n"):
        byte = await loop.sock_recv(sock, 1)
        if not byte or len(reply) >= MAX_TUNNEL_REPLY:
            raise aiohttp.ClientConnectionError("relay proxy closed the tunnel")
        reply += byte
    return reply


class RelayConnection:
    """One WebSocket to one relay, owned by one task."""

    def __init__(
        self, url: str, *, open_timeout: float | None = None, proxy: str | None = None
    ) -> None:
        """Prepare, but do not open, a connection to ``url``."""
        if not url.startswith(("wss://", "ws://")):
            raise RelayError("relay URL must be ws:// or wss://")
        self._proxy = relay_proxy(proxy)
        self._onion = is_onion_relay(url)
        if self._onion and self._proxy is None:
            raise RelayError("an onion relay needs the relay proxy")
        if self._proxy is not None and not url.startswith("wss://") and not self._onion:
            # Only an onion service authenticates and encrypts a plain ws:// target.
            raise RelayError("a proxied relay must use wss:// (ws:// only for an onion relay)")
        self.url = url
        if open_timeout is None:
            open_timeout = ONION_OPEN_TIMEOUT if self._onion else OPEN_TIMEOUT
        self._open_timeout = open_timeout
        self._session: aiohttp.ClientSession | None = None
        self._socket: aiohttp.ClientWebSocketResponse | None = None
        self._reader: asyncio.Task[None] | None = None
        self._events: asyncio.Queue[bytes] = asyncio.Queue(MAX_QUEUED_EVENTS)
        self._pending_ok: dict[str, asyncio.Future[bool]] = {}
        self.dropped_events = 0
        self.subscription_closed = False

    async def __aenter__(self) -> Self:
        """Open the socket and start reading frames."""
        timeout = aiohttp.ClientTimeout(total=None, connect=self._open_timeout)
        isolation = isolation_key()  # a fresh circuit per attempt, so a reconnect never reuses one
        tunnel = (
            _OnionTunnel(self._proxy, isolation)
            if self._proxy is not None and self._onion and self.url.startswith("ws://")
            else None
        )
        proxy = None if tunnel is not None else self._proxy
        # trust_env=False: environment proxies never silently reroute or bypass.
        self._session = aiohttp.ClientSession(timeout=timeout, trust_env=False, connector=tunnel)
        try:
            self._socket = await self._session.ws_connect(
                self.url,
                max_msg_size=MAX_FRAME_BYTES,
                heartbeat=30.0,
                proxy=proxy,
                # aiohttp sends proxy_headers only on its CONNECT for a wss:// target.
                proxy_headers={ISOLATION_HEADER: isolation} if proxy is not None else None,
            )
        except (aiohttp.ClientError, TimeoutError):
            await self._session.close()
            raise RelayError("relay unavailable") from None
        except BaseException:  # cancellation while opening: do not leak the session
            await self._session.close()
            raise
        self._reader = asyncio.create_task(self._read())
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Close the socket and fail any outstanding publications."""
        if self._reader is not None:
            self._reader.cancel()
            with suppress(asyncio.CancelledError, Exception):  # reader faults = closed relay
                await self._reader
        if self._socket is not None:
            await self._socket.close()
        if self._session is not None:
            await self._session.close()
        self._fail_pending()

    @property
    def closed(self) -> bool:
        """Whether the socket can no longer be used."""
        return self._socket is None or self._socket.closed or self.subscription_closed

    def _fail_pending(self) -> None:
        for future in self._pending_ok.values():
            if not future.done():
                future.set_result(False)
        self._pending_ok.clear()

    async def _send(self, frame: list[Any]) -> None:
        if self._socket is None or self._socket.closed:
            raise RelayError("relay connection closed")
        try:
            await self._socket.send_str(
                json.dumps(frame, ensure_ascii=False, separators=(",", ":"))
            )
        except (aiohttp.ClientError, ConnectionError):
            raise RelayError("relay send failed") from None

    async def _read(self) -> None:
        assert self._socket is not None  # noqa: S101 - set before the task starts
        try:
            async for message in self._socket:
                if message.type != aiohttp.WSMsgType.TEXT:
                    break
                self._dispatch(message.data)
                if self.subscription_closed:
                    LOG.warning("relay subscription closed; reconnect required")
                    break
        except (aiohttp.ClientError, ConnectionError, ValueError):
            pass  # a broken or hostile relay only ends this connection
        finally:
            self._fail_pending()

    def _dispatch(self, data: str) -> None:
        try:
            frame = json.loads(data)
        except ValueError:
            return
        if type(frame) is not list or not frame or type(frame[0]) is not str:
            return
        kind = frame[0]
        if kind == "EVENT" and len(frame) == 3 and frame[1] == SUBSCRIPTION_ID:  # noqa: PLR2004
            raw = _event_json(frame[2])
            if raw is None:
                return
            try:
                self._events.put_nowait(raw)
            except asyncio.QueueFull:
                self.dropped_events += 1  # relays replay; the store is idempotent
        elif kind == "OK" and len(frame) >= 3 and type(frame[1]) is str:  # noqa: PLR2004
            future = self._pending_ok.pop(frame[1], None)
            if future is not None and not future.done():
                future.set_result(frame[2] is True)
        elif kind == "CLOSED" and len(frame) >= 2 and frame[1] == SUBSCRIPTION_ID:  # noqa: PLR2004
            # A live WebSocket without its mailbox subscription is not a usable path.
            # Do not surface the relay's arbitrary text or attempt stable-key AUTH.
            self.subscription_closed = True

    async def publish(self, event: bytes, *, timeout: float = 10.0) -> bool:  # noqa: ASYNC109
        """Send one signed event; return True only on an explicit relay OK."""
        parsed = json.loads(event)
        event_id = parsed["id"]
        future: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
        self._pending_ok[event_id] = future
        try:
            await self._send(["EVENT", parsed])
            return await asyncio.wait_for(future, timeout)
        except TimeoutError:
            return False
        finally:
            self._pending_ok.pop(event_id, None)

    async def subscribe(self, filters: list[dict[str, Any]]) -> None:
        """Replace the single subscription (NIP-01 REQ reuses the ID)."""
        await self._send(["REQ", SUBSCRIPTION_ID, *filters])

    async def events(self) -> AsyncIterator[bytes]:
        """Yield raw, UNVERIFIED event JSON until the connection closes."""
        reader = self._reader
        if reader is None:
            return
        while True:
            getter = asyncio.ensure_future(self._events.get())
            try:
                await asyncio.wait({getter, reader}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                if not getter.done():
                    getter.cancel()
                    await asyncio.gather(getter, return_exceptions=True)
            if not getter.cancelled():
                yield getter.result()
                continue
            while not self._events.empty():
                yield self._events.get_nowait()
            return
            done, _ = await asyncio.wait({getter, reader}, return_when=asyncio.FIRST_COMPLETED)
            if getter in done:
                yield getter.result()
                continue
            getter.cancel()
            while not self._events.empty():
                yield self._events.get_nowait()
            return
