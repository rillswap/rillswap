"""Bounded own-node deposit observations, distinct from client-signed bindings.

Only an affirmative watch recorded with accepted terms permits discovery. A
mempool sighting is informational; independent selection always needs confirmed
funding and the normal fresh funding, timing, and one-shot payment checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rill_core.wire.messages import FundingBinding

WATCH_EXTENSION = "rillswap/provider-funding-watch"
MAX_SCAN_BLOCKS = 12
WATCH_REORG_MARGIN_BLOCKS = 12
MAX_RECEIPTS = 16
RECEIPT_FIELDS = 4
MAX_VOUT = 0xFFFFFFFF
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class FundingDiscoveryOverflowError(ValueError):
    """A bounded watcher is saturated; only client-signed funding may proceed."""


@dataclass(frozen=True, slots=True)
class FundingReceipt:
    """One contract-script receive in a named active block, not spend authority."""

    txid: str
    vout: int
    height: int
    block_hash: str

    def __post_init__(self) -> None:
        """Refuse partial or malformed persisted observations."""
        if not (
            type(self.txid) is str
            and _HASH.fullmatch(self.txid)
            and type(self.block_hash) is str
            and _HASH.fullmatch(self.block_hash)
            and type(self.vout) is int
            and 0 <= self.vout <= MAX_VOUT
            and type(self.height) is int
            and self.height > 0
        ):
            raise ValueError("funding receipt unsupported")


@dataclass(frozen=True, slots=True)
class FundingScan:
    """One bounded, tip-bracketed descriptor observation."""

    tip_height: int
    tip_hash: str
    height: int
    block_hash: str
    receipts: tuple[FundingReceipt, ...]
    mempool_seen: bool


@dataclass(frozen=True, slots=True)
class FundingWatch:
    """Durable affirmative floor and progress, never inferred from missing data."""

    floor_height: int
    height: int | None
    block_hash: str | None
    receipts: tuple[FundingReceipt, ...]

    def __post_init__(self) -> None:
        """Unknown progress must not invent a scan floor or hide prior receipts."""
        if not (
            type(self.floor_height) is int
            and self.floor_height > 0
            and (
                (self.height is None and self.block_hash is None and not self.receipts)
                or (
                    type(self.height) is int
                    and self.height >= self.floor_height - 1
                    and type(self.block_hash) is str
                    and _HASH.fullmatch(self.block_hash)
                )
            )
            and len(self.receipts) <= MAX_RECEIPTS
            and all(
                self.height is not None
                and type(item) is FundingReceipt
                and self.floor_height <= item.height <= self.height
                for item in self.receipts
            )
            and len({(item.txid, item.vout) for item in self.receipts}) == len(self.receipts)
        ):
            raise ValueError("funding watch unsupported")


@dataclass(frozen=True, slots=True)
class ObservedFunding:
    """Provider-selected confirmed bytes, NOT an authenticated client envelope."""

    binding: FundingBinding
    transaction: bytes
