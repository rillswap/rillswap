"""Optional operator notifications through Apprise (``rill-provider[notifications]``).

The notifier follows the swap ledger (store schema v18) from where it stood
when serving started, watches the service health snapshot, and sends a daily
summary computed from the durable ledger. It only reads the store, on the
event-loop thread; delivery runs in an Apprise child process with a timeout
(``notification_worker``), through Tor when ``use_tor`` is on and a relay
proxy is set, at most once per poll (several events are combined). Failures
are logged, never with the URLs (they carry service tokens), and never affect
serving. Nothing is persisted: events while the service is down are not sent
one by one, but the next daily summary still counts them.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Protocol
from urllib.parse import urlsplit

from rill_provider.diagnostics import diagnostic
from rill_provider.notification_worker import AppriseWorker, WorkerError
from rill_provider.operator_config import OperatorConfigError, read_private_file
from rill_provider.swap_accounting import (
    ABORTED,
    ACCEPTED,
    COMPLETED,
    FAILED,
    LOST,
    MSAT_PER_SAT,
    REFUNDED,
    LedgerSummary,
    SwapResult,
    summarize,
    swap_result,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path

    from rill_provider.handshake_service import ServiceHealth
    from rill_provider.live_session_store import LiveSessionStore
    from rill_provider.operator_config import NotificationSettings

LOG = logging.getLogger(__name__)
MAX_URLS_FILE_BYTES = 16 * 1024
CLOSE_TIMEOUT_SECONDS = 30.0  # the last events at shutdown, within Compose's 1m grace
POLL_SECONDS = 15.0
MAX_EVENTS_PER_POLL = 256
DAY_SECONDS = 24 * 60 * 60
BALANCE_WAIT_SECONDS = 15.0
BALANCE_WORKERS = 4
OUTCOME_ORDER = (COMPLETED, FAILED, REFUNDED, ABORTED, LOST)


class Sender(Protocol):
    """Delivery to every configured service; True when all accepted it."""

    async def send(self, title: str, body: str, *, warning: bool) -> bool:
        """Deliver one notification."""
        ...


def read_urls(urls_file: Path) -> list[tuple[int, str]]:
    """Return the numbered URL lines of an owner-only file, never echoing them."""
    data = read_private_file(urls_file, "notification URLs file", max_bytes=MAX_URLS_FILE_BYTES)
    if len(data) > MAX_URLS_FILE_BYTES:
        raise OperatorConfigError("notification URLs file too large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise OperatorConfigError("notification URLs file must be UTF-8 text") from None
    urls = [
        (number, line.strip())
        for number, line in enumerate(text.splitlines(), start=1)
        if line.strip() and not line.strip().startswith("#")
    ]
    if not urls:
        raise OperatorConfigError("notification URLs file holds no URL")
    return urls


@contextlib.asynccontextmanager
async def notification_sender(
    settings: NotificationSettings | None, relay_proxy: str | None
) -> AsyncIterator[AppriseWorker | None]:
    """Run the Apprise worker for ``settings`` (None: no notifications), then stop it.

    The worker checks every URL before this yields; a refusal names only the
    line. Delivery goes through ``relay_proxy`` (a checked loopback Tor
    tunnel) when ``use_tor`` is on and the proxy is set, and directly otherwise.
    """
    if settings is None:
        yield None
        return
    urls = read_urls(settings.urls_file)
    proxy = None
    if settings.use_tor and relay_proxy is not None:
        parts = urlsplit(relay_proxy)
        proxy = (parts.hostname or "", parts.port or 0)
    worker = AppriseWorker(urls, proxy)
    try:
        try:
            await worker.start()
        except WorkerError as error:
            raise OperatorConfigError(str(error)) from None
        except TimeoutError:
            raise OperatorConfigError("notification worker did not start") from None
        if proxy is not None:
            LOG.info("notifications go through Tor (relay_proxy)")
        else:
            reason = "no relay_proxy" if settings.use_tor else "use_tor is off"
            LOG.info("notifications go directly, not through Tor: %s", reason)
        yield worker
    finally:
        await worker.close()


@dataclass(frozen=True)
class Message:
    """One notification before delivery; ``warning`` asks for operator action."""

    title: str
    body: str
    warning: bool = False


@dataclass
class _Condition:
    """A health alert: raised once after the grace period, cleared once on recovery."""

    since: float | None = None
    raised: bool = False

    def update(self, *, bad: bool, now: float, grace: float) -> bool | None:
        """Return True to raise the alert, False to clear it, None for no change."""
        if not bad:
            self.since = None
            if self.raised:
                self.raised = False
                return False
            return None
        if self.since is None:
            self.since = now
        if not self.raised and now - self.since >= grace:
            self.raised = True
            return True
        return None


class Notifier:
    """Turns ledger entries, health changes and the daily clock into notifications."""

    def __init__(  # noqa: PLR0913 - explicit injected resources
        self,
        settings: NotificationSettings,
        sender: Sender,
        store: LiveSessionStore,
        *,
        profile: str,
        network: str,
        health: Callable[[], ServiceHealth],
        balances: dict[str, Callable[[], str]] | None = None,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        poll_seconds: float = POLL_SECONDS,
    ) -> None:
        """Bind an acquired store; only entries appended from now on are announced."""
        self._settings = settings
        self._sender = sender
        self._store = store
        self._profile = profile
        self._prefix = f"RillSwap {profile} ({network})"
        self._health = health
        self._balances = dict(balances or {})
        self._balance_executor: ThreadPoolExecutor | None = None
        self._balance_pending: dict[str, Future[str]] = {}
        self._clock, self._monotonic = clock, monotonic
        self._poll_seconds = poll_seconds
        self._cursor = store.ledger_head()  # history is summarized, never replayed
        self._next_summary = next_summary_at(int(clock()), settings.summary_time)
        self._conditions: dict[str, _Condition] = {
            name: _Condition()
            for name in ("relays_down", "quotes_paused", "low_liquidity")
            if getattr(settings, name)
        }
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Start polling in the background, announcing the start when enabled."""
        self._task = asyncio.create_task(self._run())

    async def close(self, *, failed: bool) -> None:
        """Stop polling, send the last swap events and, when enabled, the stop."""
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        if self._balance_executor is not None:
            self._balance_executor.shutdown(wait=False, cancel_futures=True)
            self._balance_executor = None
            self._balance_pending.clear()
        messages = self._collect(self._swap_messages)
        if self._settings.service_start_stop:
            if failed:
                messages.append(
                    Message("service stopped", "Serving ended on an error.", warning=True)
                )
            else:
                messages.append(Message("service stopped", "Serving stopped."))
        try:
            await asyncio.wait_for(self._deliver(messages), CLOSE_TIMEOUT_SECONDS)
        except TimeoutError:
            LOG.warning("last notification not delivered before shutdown")

    async def poll(self) -> None:
        """Deliver what is due as one notification; never raises but cancellation."""
        messages = [*self._collect(self._swap_messages), *self._collect(self._health_messages)]
        summaries = self._collect(self._summary_messages)
        if summaries and self._settings.summary_balances and self._balances:
            balances = await asyncio.gather(
                *(self._read_balance(label, read) for label, read in self._balances.items())
            )
            message = summaries[0]
            summaries = [
                Message(
                    message.title, message.body + "\nBalances (current):\n" + "\n".join(balances)
                )
            ]
        await self._deliver([*messages, *summaries])

    async def _read_balance(self, label: str, read: Callable[[], str]) -> str:
        previous = self._balance_pending.get(label)
        if previous is not None and not previous.done():
            return f"{label}: unavailable."
        future: Future[str] | None = None
        try:
            if self._balance_executor is None:
                self._balance_executor = ThreadPoolExecutor(
                    max_workers=BALANCE_WORKERS, thread_name_prefix="rill-notifications"
                )
            future = self._balance_executor.submit(read)
            self._balance_pending[label] = future
            # Cancellation drops queued work and discards late results/errors;
            # the concurrent future still tracks an already-running backend call.
            value = await asyncio.wait_for(asyncio.wrap_future(future), BALANCE_WAIT_SECONDS)
        except Exception as error:  # noqa: BLE001 - one backend must not suppress the summary
            LOG.warning("notification balance unavailable: %s", type(error).__name__)
            value = "unavailable"
        finally:
            if future is not None and future.done():
                self._balance_pending.pop(label, None)
        return f"{label}: {value}."

    async def _run(self) -> None:
        if self._settings.service_start_stop:
            await self._deliver([Message("service started", "Serving started.")])
        while True:
            await asyncio.sleep(self._poll_seconds)
            await self.poll()

    @staticmethod
    def _collect(source: Callable[[], list[Message]]) -> list[Message]:
        try:
            return source()
        except Exception as error:  # noqa: BLE001 - notifications never affect serving
            LOG.warning("notifications skipped: %s", type(error).__name__)
            return []

    async def _deliver(self, messages: list[Message]) -> None:
        if not messages:
            return
        if len(messages) == 1:
            (message,) = messages
        else:
            message = Message(
                f"{len(messages)} notifications",
                "\n\n".join(f"{item.title}\n{item.body}" for item in messages),
                warning=any(item.warning for item in messages),
            )
        try:
            delivered = await self._sender.send(
                f"{self._prefix}: {message.title}", message.body, warning=message.warning
            )
        except Exception as error:  # noqa: BLE001 - never echo URLs or payloads
            diagnostic(
                LOG,
                "notification.failed",
                f"notification not delivered: {type(error).__name__}",
                level=logging.WARNING,
                error_type=type(error).__name__,
                event_count=len(messages),
                delivery_status="failed_best_effort",
            )
            return
        if not delivered:
            diagnostic(
                LOG,
                "notification.failed",
                "notification not delivered to every service",
                level=logging.WARNING,
                event_count=len(messages),
                delivery_status="partial_or_failed_best_effort",
            )
        else:
            diagnostic(
                LOG,
                "notification.accepted",
                "Notification accepted by configured services",
                event_count=len(messages),
                delivery_status="accepted_not_device_receipt",
            )

    def _swap_messages(self) -> list[Message]:
        settings = self._settings
        entries = self._store.ledger_after(self._cursor, limit=MAX_EVENTS_PER_POLL)
        if entries:
            self._cursor = entries[-1].entry_id
        wanted = {
            COMPLETED: settings.swap_confirmed,
            FAILED: settings.swap_failed,
            REFUNDED: settings.swap_failed,
            ABORTED: settings.swap_failed,
            LOST: settings.swap_lost,
        }
        messages: list[Message] = []
        for entry in entries:
            if entry.kind == ACCEPTED and settings.swap_request:
                amount = "" if entry.amount is None else f" for {_sat(entry.amount * MSAT_PER_SAT)}"
                messages.append(
                    Message("swap accepted", f"Swap {entry.session_id[:16]} accepted{amount}.")
                )
            elif wanted.get(entry.kind, False):
                result = swap_result(self._store.ledger_session(entry.session_id), self._profile)
                if result is not None:
                    messages.append(_outcome_message(result))
        return messages

    def _health_messages(self) -> list[Message]:
        if not self._conditions:
            return []
        health, now = self._health(), self._monotonic()
        grace = self._settings.alert_after_seconds
        paused = [
            reason
            for reason, available in (
                ("chain tip", health.tip_available),
                ("claim fee estimate", health.claim_fee_available),
                ("settlement supervision", health.admission_ready),
            )
            if not available
        ]
        checks = {
            "relays_down": (
                health.relays_connected == 0,
                Message(
                    "relays down",
                    f"No relay connected for {_duration(grace)}: clients cannot reach "
                    "this provider.",
                    warning=True,
                ),
                Message("relays back", "A relay is connected again."),
            ),
            "quotes_paused": (
                bool(paused),
                Message(
                    "quotes paused",
                    f"Quotes refused for {_duration(grace)}: {' and '.join(paused)} unavailable.",
                    warning=True,
                ),
                Message("quotes resumed", "Quotes are answered again."),
            ),
            "low_liquidity": (
                not health.announcing,
                Message(
                    "low liquidity",
                    f"Liquidity below every amount band for {_duration(grace)}: not announcing.",
                    warning=True,
                ),
                Message("liquidity back", "Liquidity covers an amount band: announcing again."),
            ),
        }
        messages: list[Message] = []
        for name, condition in self._conditions.items():
            bad, raised, cleared = checks[name]
            change = condition.update(bad=bad, now=now, grace=grace)
            if change is not None:
                messages.append(raised if change else cleared)
        return messages

    def _summary_messages(self) -> list[Message]:
        now = int(self._clock())
        if now < self._next_summary:
            return []
        until = self._next_summary
        while self._next_summary <= now:  # after a stall: the latest day, not a backlog
            until = self._next_summary
            self._next_summary += DAY_SECONDS
        if not self._settings.daily_summary:
            return []
        since = until - DAY_SECONDS
        summary = summarize(self._store.ledger_window(since, until), self._profile, since, until)
        return [Message("daily summary", summary_text(summary, self._health()))]


def next_summary_at(now: int, at: str) -> int:
    """Return the first ``HH:MM`` UTC strictly after ``now``."""
    hours, minutes = (int(part) for part in at.split(":"))
    boundary = now - now % DAY_SECONDS + hours * 3600 + minutes * 60
    return boundary if boundary > now else boundary + DAY_SECONDS


def summary_text(summary: LedgerSummary, health: ServiceHealth) -> str:
    """Render the daily summary as plain text."""
    since, until = (
        datetime.fromtimestamp(moment, UTC).strftime("%Y-%m-%d %H:%M")
        for moment in (summary.since, summary.until)
    )
    lines = [
        f"From {since} to {until} UTC.",
        (
            f"Requests: {summary.accepted} accepted "
            f"({_sat(summary.accepted_sat * MSAT_PER_SAT)}) of {summary.offered} firm offers."
        ),
    ]
    if summary.success_percent is None:
        lines.append("Closed: none.")
    else:
        outcomes = ", ".join(
            f"{summary.outcomes[kind]} {kind}" for kind in OUTCOME_ORDER if kind in summary.outcomes
        )
        lines.append(
            f"Closed: {summary.closed}, {summary.success_percent:.0f}% success ({outcomes})."
        )
        lines.append(
            f"Revenue {_sat(summary.revenue_sat * MSAT_PER_SAT)}, costs "
            f"{_sat(summary.costs_msat)}, losses {_sat(summary.lost_sat * MSAT_PER_SAT)}."
        )
        lines.append(f"Net profit: {_sat(summary.net_msat)}.")
    if summary.gas_wei or summary.gas_unmeasured:
        unmeasured = f" ({summary.gas_unmeasured} swaps not measured)" * bool(
            summary.gas_unmeasured
        )
        lines.append(f"Gas: {_gwei(summary.gas_wei)}{unmeasured}.")
    if summary.inexact:
        lines.append(
            f"Costs of {summary.inexact} swaps were not all recorded (accepted before the "
            "accounting upgrade, or not reported by a backend): the net profit is at most this."
        )
    lines.append(
        f"Now: {health.relays_connected} relays connected, "
        + ("announcing." if health.announcing else "not announcing (low liquidity).")
    )
    return "\n".join(lines)


def _outcome_message(result: SwapResult) -> Message:
    session = result.session_id[:16]
    parts = []
    if result.revenue_sat:
        parts.append(f"revenue {_sat(result.revenue_sat * MSAT_PER_SAT)}")
    if result.lost_sat:
        parts.append(f"loss {_sat(result.lost_sat * MSAT_PER_SAT)}")
    if result.costs_msat:
        parts.append(f"costs {_sat(result.costs_msat)}")
    if parts:
        parts.append(f"net {_sat(result.net_msat)}")
    if result.gas_wei:
        parts.append(f"gas {_gwei(result.gas_wei)}")
    details = f": {', '.join(parts)}" if parts else ""
    note = ""  # qualifies a net shown, never a bare outcome
    if parts and not result.exact:
        note = " Some costs were not recorded: the net is at most this."
    if result.outcome == LOST:
        body = f"Swap {session} lost{details}. Check it with inspect-swaps.{note}"
        return Message("swap lost", body, warning=True)
    title = {COMPLETED: "swap completed"}.get(result.outcome, f"swap {result.outcome}")
    return Message(title, f"Swap {session} {result.outcome}{details}.{note}")


def _sat(msat: int) -> str:
    whole, fraction = divmod(abs(msat), MSAT_PER_SAT)
    text = f"{whole:,}" + (f".{fraction:03d}".rstrip("0") if fraction else "")
    return f"{'-' * (msat < 0)}{text} sat"


def _gwei(wei: int) -> str:
    text = f"{Decimal(wei).scaleb(-9):,f}"
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return f"{text} gwei"


def _duration(seconds: int) -> str:
    if seconds % 60:
        return f"{seconds} seconds"
    minutes = seconds // 60
    return f"{minutes} minute{'s' * (minutes != 1)}"
