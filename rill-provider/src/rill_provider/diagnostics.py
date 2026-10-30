"""Local, financially sensitive diagnostics, never protocol or notification data.

Only named scalar facts are accepted. Do not pass invoices, observations, recovery
documents or exception messages here. Observers cannot grant financial authority.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import TYPE_CHECKING, override

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from types import TracebackType
    from typing import TextIO

FIELDS = frozenset(
    [
        "session_id",
        "profile",
        "network",
        "request_type",
        "message_id",
        "disposition",
        "from_state",
        "to_state",
        "payment_hash",
        "invoice_hash",
        "memo",
        "amount_msat",
        "amount_sat",
        "payout_sat",
        "contract_amount_sat",
        "success_fee_sat",
        "lightning_principal_sat",
        "nominal_payout_sat",
        "claim_fee_reserve_sat",
        "mining_prepayment_sat",
        "hold_invoice_sat",
        "success_fee_token_base",
        "lock_amount_token_base",
        "payout_token_base",
        "payout_sat_equivalent",
        "rate_token_base_per_btc",
        "claim_fee_sat",
        "funding_fee_sat",
        "refund_fee_sat",
        "timelock_block",
        "service_fee_sat",
        "network_fee_sat",
        "routing_fee_msat",
        "mining_fee_sat",
        "gas_cost_wei",
        "token_amount_base",
        "token",
        "chain_id",
        "txid",
        "funding_txid",
        "claim_txid",
        "refund_txid",
        "fee_rate_sat_kvb",
        "confirmations",
        "required_confirmations",
        "refund_height",
        "tip_height",
        "operation",
        "error_type",
        "reason",
        "retry_seconds",
        "elapsed_ms",
        "relay",
        "source",
        "delivery_status",
        "event_count",
        "state",
        "revision",
    ]
)
type Fact = str | int | bool | None
CHATTY_LIBRARY_LOGGERS = ("httpx", "httpcore", "urllib3", "web3")
_CONTEXT: ContextVar[dict[str, Fact] | None] = ContextVar("rill_diagnostics", default=None)
_OUTPUT_FORMAT: ContextVar[str] = ContextVar("rill_diagnostic_format", default="text")


def safe_text(value: str, *, limit: int = 512) -> str:
    """Keep external text on one bounded line, including terminal control codes."""
    text = "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in value[:limit]
    )
    return text + ("..." if len(value) > limit else "")


def _facts(values: dict[str, object]) -> dict[str, Fact]:
    facts: dict[str, Fact] = {}
    for key, value in values.items():
        if key not in FIELDS:
            continue
        if isinstance(value, str):
            if key in {
                "reason",
                "operation",
                "disposition",
                "delivery_status",
            } and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
                continue  # codes, never raw error text or service URLs
            facts[key] = safe_memo(value) if key == "memo" else safe_text(value)
        elif value is None or isinstance(value, (int, bool)):
            facts[key] = value
    return facts


def safe_memo(value: str) -> str:
    """Memos are untrusted local details, not a route for known secret formats."""
    redacted = re.sub(
        r"(?i)\b(?:[0-9a-f]{64}|(?:lnbc|lntb|lnbcrt|nsec1|age-secret-key-1)[a-z0-9]{20,})\b",
        "[redacted]",
        value[:512],
    )
    return safe_text(redacted, limit=80)


@contextmanager
def diagnostic_context(**fields: object) -> Iterator[None]:
    """Bind safe facts to synchronous logs in this task, not sibling swaps."""
    token = _CONTEXT.set({**(_CONTEXT.get() or {}), **_facts(fields)})
    try:
        yield
    finally:
        _CONTEXT.reset(token)


def diagnostic(
    logger: logging.Logger,
    event: str,
    message: str,
    *,
    level: int = logging.INFO,
    details: Mapping[str, object] | None = None,
    **fields: object,
) -> None:
    """Emit facts without allowing a broken handler to change settlement."""
    with suppress(Exception):  # diagnostics have no financial authority
        logger.log(
            level,
            message,
            extra={
                "event": event,
                "facts": _facts({**(_CONTEXT.get() or {}), **(details or {}), **fields}),
            },
        )


class DiagnosticFormatter(logging.Formatter):
    """UTC, Loguru-style console records or one JSON object per line."""

    def __init__(self, *, json_output: bool = False, color: bool = False) -> None:
        """Select a renderer without accessing process-global logging state."""
        super().__init__()
        self._json = json_output
        self._color = color and not json_output

    @override
    def formatException(
        self,
        ei: tuple[type[BaseException], BaseException, TracebackType | None]
        | tuple[None, None, None],
    ) -> str:
        """Report locations and type, never exception text, source lines or locals."""
        frames = []
        trace = ei[2]
        while trace is not None:
            code = trace.tb_frame.f_code
            frames.append(f"{code.co_filename.rsplit('/', 1)[-1]}:{trace.tb_lineno}:{code.co_name}")
            trace = trace.tb_next
        return f"{ei[0].__name__ if ei[0] else 'Exception'} ({' > '.join(frames[-8:])})"

    @override
    def format(self, record: logging.LogRecord) -> str:
        """Render one bounded record without exception values or source lines."""
        timestamp = datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds")
        fields = {**(_CONTEXT.get() or {}), **_facts(getattr(record, "facts", {}))}
        message = safe_text(record.getMessage(), limit=2048)
        event = safe_text(getattr(record, "event", record.name))
        if record.exc_info and record.exc_info[0] is not None:
            message += " | " + self.formatException(record.exc_info)
        if self._json:
            return json.dumps(
                {
                    "time": timestamp,
                    "level": record.levelname,
                    "component": record.name,
                    "event": event,
                    "message": message,
                    **fields,
                },
                ensure_ascii=True,
            )
        reference = fields.get("session_id")
        if isinstance(reference, str):
            fields["session_id"] = reference[:16]
        context = " ".join(
            f"{key}={json.dumps(value, ensure_ascii=True)}"
            for key, value in fields.items()
            if value is not None
        )
        level = f"{record.levelname:<7}"
        if self._color:
            color = (
                31
                if record.levelno >= logging.ERROR
                else (33 if record.levelno >= logging.WARNING else 36)
            )
            level = f"\x1b[{color}m{level}\x1b[0m"
        return f"{timestamp} | {level} | {event} | {message}" + (f" | {context}" if context else "")


def configure_logging(
    level: str,
    *,
    log_format: str = "text",
    stream: TextIO | None = None,
) -> None:
    """Configure stderr without replacing handlers installed by an embedding app."""
    output = sys.stderr if stream is None else stream
    _OUTPUT_FORMAT.set(log_format)
    handler = logging.StreamHandler(output)
    handler.setFormatter(
        DiagnosticFormatter(
            json_output=log_format == "json",
            color=output.isatty() and "NO_COLOR" not in os.environ,
        )
    )
    logging.basicConfig(level=level, handlers=[handler])
    for name in CHATTY_LIBRARY_LOGGERS:
        logging.getLogger(name).setLevel(logging.NOTSET if level == "DEBUG" else logging.WARNING)


def write_progress(message: str) -> None:
    """Render deliberate CLI progress even when an embedding app owns log handlers.

    Safety warnings and recovery waits are command stderr, not optional library
    logs. Their stream must not disappear because the root logger filters INFO.
    """
    with suppress(Exception):
        record = logging.LogRecord("rill_cli", logging.INFO, "", 0, message, (), None)
        record.event = "swap.progress"
        record.facts = _CONTEXT.get() or {}
        formatter = DiagnosticFormatter(
            json_output=_OUTPUT_FORMAT.get() == "json",
            color=sys.stderr.isatty() and "NO_COLOR" not in os.environ,
        )
        sys.stderr.write(formatter.format(record) + "\n")
        sys.stderr.flush()
