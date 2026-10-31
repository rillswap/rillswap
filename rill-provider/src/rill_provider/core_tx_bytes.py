"""Explicit read-only local Core RPC transaction-byte and UTXO observations.

No wallet, ledger, mempool, funding, or payment action. Named-tip UTXO
samples cannot establish persistent confirmation or live action authority.
The operator supplies the full network identity; Core attests chain label,
genesis, and signet challenge, NOT deployment namespace or consensus profile.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import stat
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from decimal import Context as DecimalContext
from decimal import Decimal, InvalidOperation, localcontext
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from rill_core.errors import ValidationError
from rill_core.networks import backend_names, require_supported_network
from rill_core.settlement import (
    FundingBindingTransactionMatch,
    check_funding_binding_transaction,
    inspect_transaction_outputs,
)
from rill_core.wire.messages import ContractTerms, FundingBinding
from rill_core.wire.types import NetworkIdentity

from rill_provider.funding_discovery import (
    MAX_RECEIPTS,
    MAX_SCAN_BLOCKS,
    FundingDiscoveryOverflowError,
    FundingReceipt,
    FundingScan,
)
from rill_provider.funding_selection import INPUT_WEIGHTS, Coin, input_kind, select_funding_inputs

if TYPE_CHECKING:
    from rill_core.settlement import TaprootKeyOperations

LOG = logging.getLogger(__name__)
# One funding build at a time per process: listing coins, then locking the
# chosen ones, must not interleave with another build picking the same coins.
_FUNDING_LOCK = threading.Lock()
RPC_VERIFY_ALREADY_IN_CHAIN = -27
RPC_INVALID_ADDRESS_OR_KEY = -5  # getrawtransaction: not in mempool or txindex
MAX_COOKIE_BYTES = 512
MAX_RESPONSE_BYTES = 256 * 1024
MAX_SOURCE_SECONDS = 10
MAX_HISTORICAL_BLOCK_HEIGHT = 499_999_999
MAX_BLOCK_RESPONSE_BYTES = 32 * 1024 * 1024  # a decoded block (getblock verbosity 2)
MAX_SPEND_SCAN_BLOCKS = 12  # blocks decoded per find_spender call
# Core clamps target 1 to 2: economical two-block advice is its closest
# next-block estimate.
NEXT_BLOCK_ESTIMATE_TARGET = 2
MAX_UNSPENT_RESPONSE_BYTES = 16 * 1024 * 1024  # listunspent of a busy funding wallet
MAX_SCRIPT_BYTES = 40
_WALLET_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
SATS_PER_BTC = Decimal(100_000_000)
MAX_TRANSACTION_HEX_BYTES = 200_000
MAX_PORT = 65535
HTTP_OK = 200
CONNECT_SECONDS = 2.0
READ_SECONDS = 5.0
HASH_HEX_LENGTH = 64
MAX_ESTIMATE_TARGET = 1008  # Core's estimatesmartfee bound
MAX_FEE_ESTIMATE_CEILING_SAT_VB = 10_000
SATS_PER_BTC = Decimal(100_000_000)
MAX_SATS = 21_000_000 * 100_000_000
# Every Core RPC method the provider may call. Operators can restrict the
# provider's Core credential to exactly this list with -rpcwhitelist.
CORE_RPC_METHODS = (
    "getblockchaininfo",
    "getdescriptoractivity",
    "estimatesmartfee",
    "getmempoolinfo",
    "getblockhash",
    "getindexinfo",
    "getrawtransaction",
    "gettxout",
    "sendrawtransaction",
    # LN to BTC (RS-004): the provider funds contracts from its Core
    # wallet and looks for the client's claim spending them.
    "decodescript",
    "walletcreatefundedpsbt",
    "decodepsbt",
    "lockunspent",
    "walletprocesspsbt",
    "finalizepsbt",
    "decoderawtransaction",
    "gettxspendingprevout",
    "getblock",
    "getblockheader",
    # Caps the announced amounts by the funding wallet's balance and prices
    # balance-aware discounts.
    "getbalances",
    # Privacy-first funding: the provider picks the inputs itself.
    "listunspent",
    # Read-only operator reporting includes temporarily locked wallet outputs.
    "listlockunspent",
)
# Besides the wallet* methods.
_WALLET_RPC_METHODS = ("lockunspent", "getbalances", "listunspent", "listlockunspent")
MAX_VOUT = 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class FundedOutput:
    """A signed, not yet broadcast wallet transaction paying the contract at index 0."""

    txid: str
    vout: int
    raw: bytes
    fee_sat: int
    anchor_txid: str  # first input: the RS-003 lineage anchor
    anchor_vout: int
    selected_inputs: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class SpendObservation:
    """The transaction spending a contract output and the witness of that input."""

    txid: str
    witness: tuple[bytes, ...]
    height: int | None  # None while only in the mempool


@dataclass(frozen=True, slots=True)
class SpendScan:
    """Result of one bounded ``find_spender`` call."""

    spender: SpendObservation | None
    scanned_to: int  # last block height searched (resume from the next one)
    scanned_block: str | None = None


@dataclass(frozen=True, slots=True)
class ReverseSpendCheckpoint:
    """Immutable replay floor and a hash-anchored exclusive scan boundary."""

    floor_height: int
    floor_block: str
    height: int
    block: str

    def __post_init__(self) -> None:
        if not (
            type(self.floor_height) is int
            and type(self.height) is int
            and 0 <= self.floor_height <= self.height
            and _hash(self.floor_block)
            and _hash(self.block)
            and (self.height != self.floor_height or self.block == self.floor_block)
        ):
            raise ValueError("reverse spend checkpoint unsupported")


@dataclass(frozen=True, slots=True)
class CandidateFundingOutpoint:
    """Named-tip read-only candidate inclusion, not lineage or permission.

    A succeeding RPC is immediately staleable. It cannot authenticate the
    binding, rule out mempool spends, or prove durable funding after restart.
    """

    network_identity: NetworkIdentity
    static_match: FundingBindingTransactionMatch
    tip_hash: str
    tip_height: int
    chain_only_confirmations: int
    inclusion_height: int
    inclusion_block_hash: str


@dataclass(frozen=True, slots=True)
class MempoolFundingOutpoint:
    """Named-tip sample of the contract output, unspent in Core's mempool view.

    Evidence only for terms that pay at zero confirmations: Core knows the
    exact funding transaction and nothing in its mempool spends the output.
    The funder can still double-spend an unconfirmed transaction.
    """

    network_identity: NetworkIdentity
    static_match: FundingBindingTransactionMatch
    tip_hash: str
    tip_height: int
    confirmations: int  # 0 while only in the mempool


@dataclass(frozen=True, slots=True)
class CooperativeClaimOutpoint:
    """One named-tip UTXO sample with mempool spends considered.

    This is read-only evidence, not spending authority. A mempool spend may
    arrive immediately after the sample. It carries neither a signing time
    nor fee-policy or Lightning authorization. Only a sample that explicitly
    allowed unconfirmed funding has zero confirmations; it then names no
    inclusion block (both inclusion fields are ``None``), never an invented one.
    """

    network_identity: NetworkIdentity
    static_match: FundingBindingTransactionMatch
    funding_txid: str
    funding_vout: int
    funding_value_sat: int
    funding_script_pubkey: bytes
    tip_hash: str
    tip_height: int
    confirmations: int
    inclusion_height: int | None
    inclusion_block_hash: str | None


@dataclass(frozen=True, slots=True)
class CooperativeFeePolicy:
    """Named-tip fee advice and admission floors, not signing authority.

    The runtime must separately bound acquisition/effect age, verify the exact
    outpoint and transaction, and enforce deadlines, cap, and dust policy.
    """

    network_identity: NetworkIdentity
    tip_hash: str
    tip_height: int
    confirmation_blocks: int
    min_relay_sat_kvb: int
    mempool_min_sat_kvb: int
    estimate_sat_kvb: int | None
    estimate_blocks: int

    def fee_floor_sat(
        self, *, vsize: int, configured_floor_sat: int, pays_signed_reserve: bool = False
    ) -> int:
        """Integer ceiling for a caller's independently verified final vsize.

        ``pays_signed_reserve``: the claim pays exactly the LN to BTC claim fee
        reserve, which was priced for the next block when quoted and leaves the
        destination exactly the nominal payout, so it only has to relay.
        """
        if (
            type(vsize) is not int
            or not 0 < vsize <= MAX_TRANSACTION_HEX_BYTES
            or type(configured_floor_sat) is not int
            or not 0 < configured_floor_sat <= MAX_SATS
            or type(pays_signed_reserve) is not bool
        ):
            raise ValueError("cooperative fee inputs invalid")
        estimate = 0 if pays_signed_reserve else self.estimate_sat_kvb or 0
        rate = max(self.min_relay_sat_kvb, self.mempool_min_sat_kvb, estimate)
        return max(configured_floor_sat, (rate * vsize + 999) // 1000)


@dataclass(frozen=True, slots=True)
class NextBlockFee:
    """Economical next-block advice and the node's own admission floors, in sat/kvB.

    Advice, not a guarantee: it targets inclusion in the next block or two.
    ``estimate_sat_kvb`` is ``None`` only on regtest without an estimate.
    """

    relay_sat_kvb: int
    mempool_min_sat_kvb: int
    estimate_sat_kvb: int | None

    @property
    def floor_sat_kvb(self) -> int:
        """The lowest rate this node relays and keeps in its mempool right now."""
        return max(self.relay_sat_kvb, self.mempool_min_sat_kvb)

    @property
    def rate_sat_kvb(self) -> int:
        """The rate to pay: the estimate, never below the node floor or 1 sat/kvB."""
        return max(self.estimate_sat_kvb or 0, self.floor_sat_kvb, 1)


class CoreReadError(Exception):
    """No usable requested evidence was established; never absence proof."""


class CoreAuthError(CoreReadError):
    """RPC authentication failed or a protected cookie was not readable."""


class CoreProtocolError(CoreReadError):
    """Core RPC response or network preflight was malformed or inconsistent."""


class CoreUnavailableError(CoreReadError):
    """The requested transaction or node was unavailable, not known absent."""


@dataclass(frozen=True, slots=True)
class CoreSourceSnapshot:
    """Trusted loopback endpoint claims, not atomic state or financial authority.

    Namespace and consensus profile remain operator configuration, not observed
    daemon facts. Matching bracketing tips do not prove atomic acquisition.
    Cookie authentication authenticates the client, not the server. A trusted
    operator-controlled host/listener is required; this is not cryptographic
    daemon identity. IBD false does not prove wider-network synchronization.
    """

    configured_network: NetworkIdentity
    observed_chain: str
    genesis_hash: str
    signet_challenge: str | None
    tip_height: int
    tip_hash: str
    source_height: int
    source_block_hash: str


@dataclass(frozen=True, slots=True)
class CoreHistoricalTransaction:
    """Trusted Core historical byte observations, never financial authority.

    Explicit block coordinates are lookup hints, not proof. Configured profile,
    namespace and trusted loopback host remain operator premises. Tip/block reads
    are sampled, not atomic or continuous confirmation guarantees. No ownership,
    unspent state, funding authorization or claim validity is established here.
    """

    configured_network: NetworkIdentity
    raw_transaction: bytes
    txid: str
    block_height: int
    block_hash: str
    tip_before_height: int
    tip_before_hash: str
    tip_after_height: int
    tip_after_hash: str
    minimum_sampled_confirmations: int
    started_at: float
    completed_at: float


def _remaining_source(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining <= 0:
        raise CoreUnavailableError("Core source acquisition expired")
    return remaining


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == HASH_HEX_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _chain_tip(value: object, network: NetworkIdentity) -> tuple[str, int]:
    chain = backend_names(network).core_chain
    if (
        not isinstance(value, dict)
        or value.get("chain") != chain
        or not _hash(value.get("bestblockhash"))
        or type(value.get("blocks")) is not int
        or value["blocks"] < 0
        or value.get("initialblockdownload") is not False
        or (
            network.name == "signet"
            and (
                type(value.get("signet_challenge")) is not str
                or value["signet_challenge"] != network.signet_challenge
            )
        )
    ):
        raise CoreProtocolError("Core has no usable current tip on the configured chain")
    return value["bestblockhash"], value["blocks"]


def _exact_sats(value: object, expected: int) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        return False
    if not 0 <= expected <= MAX_SATS or not Decimal(value).is_finite():
        return False
    whole, fractional = divmod(expected, int(SATS_PER_BTC))
    # Decimal comparison is exact; arithmetic would use the ambient precision
    # and can round away a fractional satoshi or overflow on a huge exponent.
    return value == Decimal(f"{whole}.{fractional:08d}")


def _fee_rate_sat_kvb(value: object) -> int:
    """Core rates are whole satoshis per kvB, never ambient-rounded floats."""
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, Decimal))
        or not Decimal(value).is_finite()
        or not 0 <= value < 1
    ):
        raise CoreProtocolError("Core cooperative fee rate invalid")
    with localcontext(DecimalContext(prec=28)):
        rate = int(value * SATS_PER_BTC)
    if not _exact_sats(value, rate):
        raise CoreProtocolError("Core cooperative fee rate is not whole satoshis per kvB")
    return rate


def _cookie(path: Path) -> tuple[str, str]:
    try:
        result = _read_cookie(path)
    except (OSError, ValueError, UnicodeError):
        raise CoreAuthError("Core cookie unavailable; no transaction check performed") from None
    return result


def _read_cookie(path: Path) -> tuple[str, str]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb", closefd=True) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("cookie must be a private regular file")
        value = stream.read(MAX_COOKIE_BYTES + 1)
    if len(value) > MAX_COOKIE_BYTES or not value:
        raise ValueError("cookie exceeds size limit")
    text = value.removesuffix(b"\n").decode("ascii")
    username, password = text.split(":", 1)
    if username != "__cookie__" or not password or any(char in text for char in "\r\n\x00"):
        raise ValueError("unsupported cookie contents")
    return username, password


class CoreTransactionReader:
    """Fetch static bytes or a named-tip UTXO from local Bitcoin Core v30.

    A matching result does not authenticate the funder's binding signature,
    wallet prevouts or terms; it does not imply durable chain/UTXO status.
    Construction makes no RPC call and does not open or migrate any ledger.
    """

    def __init__(  # noqa: PLR0913 - keyword-only endpoint settings
        self,
        *,
        port: int,
        cookie_path: str | os.PathLike[str],
        wallet: str | None = None,
        network: NetworkIdentity,
        host: str = "127.0.0.1",
        max_fee_estimate_sat_vb: int | None = None,
    ) -> None:
        """Configure a numeric loopback endpoint without connecting to it.

        ``max_fee_estimate_sat_vb`` is an operator ceiling on Core's fee
        estimates, for chains whose estimator is skewed (signet's spam and
        empty blocks). It lowers only the estimate: relay and mempool floors,
        signed caps and every evidence check stay as they are. ``None`` keeps
        Core's estimates and every RPC request unchanged.
        """
        if host not in ("127.0.0.1", "::1") or type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError("Core RPC must be a numeric loopback host and valid port")
        if max_fee_estimate_sat_vb is not None and (
            type(max_fee_estimate_sat_vb) is not int
            or not 1 <= max_fee_estimate_sat_vb <= MAX_FEE_ESTIMATE_CEILING_SAT_VB
        ):
            raise ValueError("fee estimate ceiling out of range")
        self._max_fee_estimate_sat_vb = max_fee_estimate_sat_vb
        try:
            self._chain = backend_names(network).core_chain
        except ValidationError:
            raise ValueError("only a supported complete network identity is accepted") from None
        self._url = f"http://[{host}]:{port}/" if host == "::1" else f"http://{host}:{port}/"
        self._cookie_path = Path(cookie_path)
        self._network = network
        if wallet is not None and _WALLET_NAME.fullmatch(wallet) is None:
            raise ValueError("Core wallet name unsupported")
        self._wallet_path = "/" if wallet is None else f"/wallet/{wallet}"

    def tip_height(self) -> int:
        """Return the current height after checking chain, genesis, and signet challenge.

        Informational only (e.g. an indicative quote's reference height); a
        height read here authorizes nothing.
        """
        username, password = _cookie(self._cookie_path)
        try:
            with httpx.Client(
                base_url=self._url,
                auth=httpx.BasicAuth(username, password),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
            ) as client:
                _, height = _chain_tip(self._rpc(client, "getblockchaininfo", [], 1), self._network)
                if self._rpc(client, "getblockhash", [0], 2) != self._network.genesis_hash:
                    raise CoreProtocolError("Core genesis differs from configuration")
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        return height

    def trusted_balance_sat(self) -> int:
        """Return the funding wallet's trusted balance (``getbalances`` mine.trusted).

        Indicative only (it caps announced amounts): it includes coins locked
        for contracts being funded and authorizes nothing.
        """
        return _balance_sat(self._mine_balances(), "trusted")

    def balance_interval_sat(self) -> tuple[int, int]:
        """Return the wallet balance as (trusted, trusted plus untrusted pending).

        Indicative only (it prices balance-aware discounts) and authorizes nothing.
        """
        mine = self._mine_balances()
        trusted = _balance_sat(mine, "trusted")
        return trusted, trusted + _balance_sat(mine, "untrusted_pending")

    def _mine_balances(self) -> object:
        username, password = _cookie(self._cookie_path)
        try:
            with httpx.Client(
                base_url=self._url,
                auth=httpx.BasicAuth(username, password),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
            ) as client:
                result = self._rpc(client, "getbalances", [], 1)
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        return result.get("mine") if isinstance(result, dict) else None

    def wallet_utxo_count(self) -> int:
        """Count Core's listed wallet outputs, including locked and unconfirmed.

        Informational, not an atomic snapshot or a count of spendable funding
        inputs. Watch-only and unsafe outputs returned by Core are included;
        ``listunspent`` does not return immature coinbase outputs.
        """
        username, password = _cookie(self._cookie_path)
        try:
            with httpx.Client(
                base_url=self._url,
                auth=httpx.BasicAuth(username, password),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
            ) as client:
                unlocked = self._rpc(client, "listunspent", [0], 1)
                locked = self._rpc(client, "listlockunspent", [], 2)
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        outpoints: set[tuple[str, int]] = set()
        for outputs in (unlocked, locked):
            if not isinstance(outputs, list):
                raise CoreProtocolError("Core wallet UTXO list invalid")
            for output in outputs:
                if not isinstance(output, dict):
                    raise CoreProtocolError("Core wallet UTXO invalid")
                txid, vout = output.get("txid"), output.get("vout")
                if not (
                    isinstance(txid, str)
                    and re.fullmatch(r"[0-9a-f]{64}", txid)
                    and type(vout) is int
                    and 0 <= vout <= MAX_VOUT
                ):
                    raise CoreProtocolError("Core wallet UTXO outpoint invalid")
                outpoints.add((txid, vout))
        return len(outpoints)

    def observe_source(
        self, source_height: int, *, deadline_seconds: float = 10
    ) -> CoreSourceSnapshot:
        """Read a known source height under a setup/cleanup-inclusive acceptance budget.

        Read-only, with no wallet operation. This synchronous diagnostic refuses
        late evidence; file work and HTTP parsing can still block beyond the
        budget. It is not a hard execution deadline or suitable server-loop work.
        The caller independently binds its complete acquisition interval and LND
        observation. Neither matching tips nor active-hash reads are atomic proof.
        """
        if (
            type(source_height) is not int
            or source_height <= 0
            or type(deadline_seconds) not in (int, float)
            or not 0 < deadline_seconds <= MAX_SOURCE_SECONDS
            or not math.isfinite(deadline_seconds)
        ):
            raise CoreProtocolError("Core source observation input invalid")
        deadline = time.monotonic() + deadline_seconds
        snapshot = None
        try:
            username, password = _cookie(self._cookie_path)
            with httpx.Client(
                base_url=self._url,
                auth=httpx.BasicAuth(username, password),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(_remaining_source(deadline)),
            ) as client:
                snapshot = self._source_on_client(client, source_height, deadline)
            _remaining_source(deadline)
        except Exception:  # noqa: BLE001 - detach cookie/HTTP-bearing upstream errors
            snapshot = None
        if snapshot is None:
            raise CoreUnavailableError("Core source acquisition unavailable")
        _remaining_source(deadline)
        return snapshot

    def _source_on_client(
        self, client: httpx.Client, source_height: int, deadline: float
    ) -> CoreSourceSnapshot:
        before = self._rpc(client, "getblockchaininfo", [], 1, deadline=deadline)
        tip_hash, tip_height = _chain_tip(before, self._network)
        if source_height > tip_height:
            raise CoreProtocolError("Core source height exceeds observed tip")
        genesis = self._rpc(client, "getblockhash", [0], 2, deadline=deadline)
        if genesis != self._network.genesis_hash:
            raise CoreProtocolError("Core source genesis differs")
        source_hash = self._rpc(client, "getblockhash", [source_height], 3, deadline=deadline)
        if not _hash(source_hash):
            raise CoreProtocolError("Core source hash malformed")
        after = self._rpc(client, "getblockchaininfo", [], 4, deadline=deadline)
        if _chain_tip(after, self._network) != (tip_hash, tip_height):
            raise CoreProtocolError("Core source tip changed during acquisition")
        repeated = self._rpc(client, "getblockhash", [source_height], 5, deadline=deadline)
        if repeated != source_hash:
            raise CoreProtocolError("Core active source hash changed")
        if source_height == tip_height and source_hash != tip_hash:
            raise CoreProtocolError("Core source tip hash disagrees")
        return CoreSourceSnapshot(
            self._network,
            self._chain,
            genesis,
            self._network.signet_challenge if self._network.name == "signet" else None,
            tip_height,
            tip_hash,
            source_height,
            source_hash,
        )

    def observe_block_transaction(
        self,
        txid: str,
        *,
        block_height: int,
        block_hash: str,
        deadline_seconds: float = 10,
    ) -> CoreHistoricalTransaction:
        """Explicitly read bounded historical bytes from a known active block.

        Requires a complete explicit hint; missing/invalid hints trigger no RPC,
        discovery, scan or fallback. Works independently of wallet membership,
        txindex or whether outputs remain unspent. Bounded non-coinbase parsing
        verifies the actual txid only, not signatures or contract authorization.
        Acceptance includes cookie/client setup and cleanup, not a hard wall-time
        guarantee. Old records without hints grant no observation, payment retry,
        automatic provisioning or migration. Confirmation policy is caller-owned.
        """
        if (
            type(txid) is not str
            or not _hash(txid)
            or type(block_hash) is not str
            or not _hash(block_hash)
            or type(block_height) is not int
            or not 0 < block_height <= MAX_HISTORICAL_BLOCK_HEIGHT
            or type(deadline_seconds) not in (int, float)
            or not 0 < deadline_seconds <= MAX_SOURCE_SECONDS
            or not math.isfinite(deadline_seconds)
        ):
            raise CoreProtocolError("Core historical transaction input invalid")
        observation = None
        try:
            started_at = time.time()
            deadline = time.monotonic() + deadline_seconds
            if not math.isfinite(started_at):
                raise CoreProtocolError("Core historical transaction time unavailable")  # noqa: TRY301 - detach all setup diagnostics at public boundary
            username, password = _cookie(self._cookie_path)
            with httpx.Client(
                base_url=self._url,
                auth=httpx.BasicAuth(username, password),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(_remaining_source(deadline)),
            ) as client:
                raw, before, after = self._block_transaction_on_client(
                    client, txid, block_height, block_hash, deadline
                )
            _remaining_source(deadline)
            completed_at = time.time()
            if not math.isfinite(completed_at) or completed_at < started_at:
                raise CoreProtocolError("Core historical transaction interval unavailable")  # noqa: TRY301 - detach cleanup diagnostics at public boundary
            observation = CoreHistoricalTransaction(
                self._network,
                raw,
                txid,
                block_height,
                block_hash,
                before[1],
                before[0],
                after[1],
                after[0],
                min(before[1], after[1]) - block_height + 1,
                started_at,
                completed_at,
            )
        except Exception:  # noqa: BLE001 - detach cookie/HTTP/raw-transaction upstream errors
            observation = None
        if observation is None:
            raise CoreUnavailableError("Core historical transaction acquisition unavailable")
        _remaining_source(deadline)
        return observation

    def observe_funding_inclusion(  # noqa: PLR0912, PLR0915 - one bounded acquisition owns its sampling and cleanup invariants
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
        deadline_seconds: float = 10,
    ) -> CoreHistoricalTransaction:
        """Explicitly sample one known confirmed binding without wallet or txindex.

        Chain-only UTXO depth must refer to the sampled best block. Derive its
        inclusion height, acquire block-qualified bytes and check native contract
        correspondence. Two matching UTXO samples and unchanged bracketing tips
        are conservative admission rules, not atomic/continuous availability,
        mempool-spend exclusion or ABA-reorg protection. Unlike historical lookup,
        even ordinary tip advancement refuses this acquisition.

        Caller owns authentication of the supplied binding/terms and trust in the
        configured host/listener. Core lookup is not a Merkle inclusion proof;
        configured namespace/profile are not daemon attestations. The returned
        historical facts grant no custody, signing, payment, retry or release
        authority. Missing state installs no caller, discovery or migration work.
        Duration is checked admission through cleanup, not hard interruption.
        """
        inputs_valid = False
        try:
            if not isinstance(binding, FundingBinding) or not isinstance(terms, ContractTerms):
                raise TypeError("parsed funding inputs required")  # noqa: TRY301 - fixed public input diagnostic
            if (
                type(binding.contract_vout) is not int
                or type(terms.funding_confirmations) is not int
            ):
                raise TypeError("strict funding counters required")  # noqa: TRY301 - model serializers must not normalize bypassed booleans
            # Reject bypassed model construction as well as unsupported identities
            # before cookie access or transport. This does not authenticate events.
            binding = FundingBinding.model_validate_json(
                binding.model_dump_json(warnings="error"), strict=True
            )
            terms = ContractTerms.model_validate_json(
                terms.model_dump_json(warnings="error"), strict=True
            )
            require_supported_network(terms.network_identity)
            if terms.network_identity != self._network or (
                type(deadline_seconds) not in (int, float)
                or not math.isfinite(deadline_seconds)
                or not 0 < deadline_seconds <= MAX_SOURCE_SECONDS
            ):
                raise ValueError("funding inclusion inputs differ")  # noqa: TRY301 - fixed public input diagnostic
            inputs_valid = True
        except Exception:  # noqa: BLE001 - caller-provided model validation details never escape
            inputs_valid = False
        if not inputs_valid:
            raise CoreProtocolError("Core funding inclusion input invalid")
        observation = None
        try:
            started_at = time.time()
            deadline = time.monotonic() + deadline_seconds
            if not math.isfinite(started_at):
                raise CoreProtocolError("Core funding inclusion time unavailable")  # noqa: TRY301 - detach setup diagnostics
            username, password = _cookie(self._cookie_path)
            with httpx.Client(
                base_url=self._url,
                auth=httpx.BasicAuth(username, password),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(_remaining_source(deadline)),
            ) as client:
                request_id = 0

                def read(method: str, params: list[object]) -> Any:  # noqa: ANN401 - checked RPC result narrowing below
                    nonlocal request_id
                    request_id += 1
                    return self._rpc(client, method, params, request_id, deadline=deadline)

                before = _chain_tip(read("getblockchaininfo", []), self._network)
                if (
                    not 0 < before[1] <= MAX_HISTORICAL_BLOCK_HEIGHT
                    or read("getblockhash", [0]) != self._network.genesis_hash
                    or read("getblockhash", [before[1]]) != before[0]
                ):
                    raise CoreProtocolError("Core funding inclusion backend differs")  # noqa: TRY301 - detach backend diagnostics
                params: list[object] = [binding.funding_txid, binding.contract_vout, False]
                output = read("gettxout", params)
                depth = _checked_outpoint(output, binding, before[1])
                if output["bestblock"] != before[0] or depth < terms.funding_confirmations:
                    raise CoreProtocolError("Core funding inclusion depth differs")  # noqa: TRY301 - detach observation diagnostics
                height = before[1] - depth + 1
                block_hash = read("getblockhash", [height])
                if not _hash(block_hash):
                    raise CoreProtocolError("Core funding inclusion block unavailable")  # noqa: TRY301 - detach observation diagnostics
                raw, inner_before, inner_after = self._block_transaction_on_client(
                    client, binding.funding_txid, height, block_hash, deadline
                )
                if inner_before != before or inner_after != before:
                    raise CoreProtocolError("Core funding inclusion tip changed")  # noqa: TRY301 - additive strict policy, old historical policy unchanged
                check_funding_binding_transaction(raw, binding, terms, keys=keys)
                ending_output = read("gettxout", params)
                if (
                    _checked_outpoint(ending_output, binding, before[1]) != depth
                    or ending_output["bestblock"] != before[0]
                    or _chain_tip(read("getblockchaininfo", []), self._network) != before
                    or read("getblockhash", [height]) != block_hash
                    or read("getblockhash", [before[1]]) != before[0]
                ):
                    raise CoreProtocolError("Core funding inclusion samples contradict")  # noqa: TRY301 - detach final diagnostics
            _remaining_source(deadline)
            completed_at = time.time()
            if not math.isfinite(completed_at) or completed_at < started_at:
                raise CoreProtocolError("Core funding inclusion interval unavailable")  # noqa: TRY301 - detach cleanup diagnostics
            observation = CoreHistoricalTransaction(
                self._network,
                raw,
                binding.funding_txid,
                height,
                block_hash,
                before[1],
                before[0],
                before[1],
                before[0],
                depth,
                started_at,
                completed_at,
            )
        except Exception:  # noqa: BLE001 - detach private cookie, RPC, raw bytes and native failures
            observation = None
        if observation is None:
            raise CoreUnavailableError("Core funding inclusion acquisition unavailable")
        _remaining_source(deadline)
        return observation

    def _block_transaction_on_client(
        self,
        client: httpx.Client,
        txid: str,
        height: int,
        block_hash: str,
        deadline: float,
    ) -> tuple[bytes, tuple[str, int], tuple[str, int]]:
        request_id = 0

        def read(method: str, params: list[object]) -> Any:  # noqa: ANN401 - strict RPC results narrowed below
            nonlocal request_id
            request_id += 1
            return self._rpc(client, method, params, request_id, deadline=deadline)

        def tip() -> tuple[str, int]:
            value = _chain_tip(read("getblockchaininfo", []), self._network)
            if (
                not 0 < value[1] <= MAX_HISTORICAL_BLOCK_HEIGHT
                or read("getblockhash", [0]) != self._network.genesis_hash
                or read("getblockhash", [value[1]]) != value[0]
            ):
                raise CoreProtocolError("Core historical transaction backend differs")
            return value

        before = tip()
        if height > before[1] or read("getblockhash", [height]) != block_hash:
            raise CoreProtocolError("Core historical transaction block differs")
        value = read("getrawtransaction", [txid, False, block_hash])
        if (
            type(value) is not str
            or not value
            or len(value) > MAX_TRANSACTION_HEX_BYTES
            or re.fullmatch(r"(?:[0-9a-f]{2})+", value) is None
        ):
            raise CoreProtocolError("Core historical transaction bytes unavailable")
        raw = bytes.fromhex(value)
        if inspect_transaction_outputs(raw).txid != txid:
            raise CoreProtocolError("Core historical transaction identifier differs")
        after = tip()
        if (
            after[1] < before[1]
            or (after[1] == before[1] and after[0] != before[0])
            or read("getblockhash", [height]) != block_hash
            or read("getblockhash", [before[1]]) != before[0]
        ):
            raise CoreProtocolError("Core historical transaction samples contradict")
        return raw, before, after

    def fetch_binding_byte_match(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
    ) -> FundingBindingTransactionMatch:
        """Explicitly read bytes and run only the core static matcher.

        Synchronous operator-invoked diagnostic, not a service or
        watcher. Inactivity timeouts are NOT a total-duration bound: a
        configured listener that trickles incomplete HTTP can block this call
        indefinitely. Never use it to enforce funding/payment deadlines.
        """
        if not isinstance(terms.network_identity, NetworkIdentity) or (
            terms.network_identity != self._network
        ):
            raise ValueError("binding terms and configured full network identity differ")
        if not isinstance(binding, FundingBinding):
            raise TypeError("a parsed binding is required")
        username, password = _cookie(self._cookie_path)
        try:
            with httpx.Client(
                base_url=self._url,
                auth=httpx.BasicAuth(username, password),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
            ) as client:
                info = self._rpc(client, "getblockchaininfo", [], 1)
                if not isinstance(info, dict) or info.get("chain") != self._chain:
                    raise CoreProtocolError("Core network label differs from configuration")
                genesis = self._rpc(client, "getblockhash", [0], 2)
                if genesis != self._network.genesis_hash:
                    raise CoreProtocolError("Core genesis differs from configuration")
                raw_hex = self._rpc(client, "getrawtransaction", [binding.funding_txid, False], 3)
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        # Static mismatch remains an explicit core ValidationError, not an
        # assertion of missing/invalid live funding or a reason to retry.
        return check_funding_binding_transaction(
            _transaction_bytes(raw_hex), binding, terms, keys=keys
        )

    def observe_candidate_outpoint(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
    ) -> CandidateFundingOutpoint:
        """Sample chain-only UTXO and block-qualified bytes, with no action authority.

        This explicit synchronous diagnostic does not install a lineage view,
        rule out mempool spends, prove permanent confirmations, or satisfy
        restored-state reconciliation. It has no total-duration bound against
        a trickling local endpoint. Unknown/unstable facts fail closed without
        retry, wallet RPC, database updates, or automatic scans.
        """
        match, tip_hash, tip_height, confirmations, inclusion_height, inclusion_hash = (
            self._observe_outpoint(binding, terms, keys=keys, include_mempool=False)
        )
        if inclusion_height is None or inclusion_hash is None:
            raise CoreProtocolError("Core chain-only outpoint lacks its inclusion block")
        return CandidateFundingOutpoint(
            self._network,
            match,
            tip_hash,
            tip_height,
            confirmations,
            inclusion_height,
            inclusion_hash,
        )

    def observe_mempool_outpoint(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
    ) -> MempoolFundingOutpoint:
        """Sample the output as unspent counting mempool transactions, at any depth.

        Only zero-confirmation BTC to LN terms may act on this: the provider
        accepts that the client can still double-spend the funding. Unknown or
        unstable facts fail closed exactly like the confirmed sampler.
        """
        if terms.profile_id != "btc-to-ln/v1" or terms.funding_confirmations != 0:
            raise ValueError("mempool funding evidence is only for zero-confirmation BTC to LN")
        if not isinstance(binding, FundingBinding):
            raise TypeError("a parsed binding is required")
        if not isinstance(terms.network_identity, NetworkIdentity) or (
            terms.network_identity != self._network
        ):
            raise ValueError("binding terms and configured full network identity differ")
        try:
            with self._client() as client:
                tip_hash, tip_height = _chain_tip(
                    self._rpc(client, "getblockchaininfo", [], 1), self._network
                )
                if self._rpc(client, "getblockhash", [0], 2) != self._network.genesis_hash:
                    raise CoreProtocolError("Core genesis differs from configuration")
                raw = _transaction_bytes(
                    self._rpc(client, "getrawtransaction", [binding.funding_txid, False], 3)
                )
                match = check_funding_binding_transaction(raw, binding, terms, keys=keys)
                output = self._rpc(
                    client, "gettxout", [binding.funding_txid, binding.contract_vout, True], 4
                )
                confirmations = _checked_outpoint(output, binding, tip_height, minimum=0)
                end_hash, end_height = _chain_tip(
                    self._rpc(client, "getblockchaininfo", [], 5), self._network
                )
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if tip_hash != end_hash or tip_height != end_height or output["bestblock"] != tip_hash:
            raise CoreUnavailableError("Core chain view changed; no current outpoint proof")
        return MempoolFundingOutpoint(self._network, match, tip_hash, tip_height, confirmations)

    def observe_cooperative_claim_outpoint(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
    ) -> CooperativeClaimOutpoint:
        """Sample one outpoint, including known mempool spends.

        A positive sample is immediately staleable and grants no signing
        permission. Future runtime must independently bound total elapsed
        acquisition time, establish fee/payment/deadline policy, and ensure
        unilateral fallback. No chain-only fallback is attempted on failure.

        LN to BTC terms also accept the exact output while its transaction is
        only in the mempool (zero confirmations, no inclusion block): that is
        the provider's own funding, and a client claiming that early takes the
        double-spend risk itself. Every other profile needs a confirmed output.
        """
        match, tip_hash, tip_height, confirmations, inclusion_height, inclusion_hash = (
            self._observe_outpoint(
                binding,
                terms,
                keys=keys,
                include_mempool=True,
                minimum=0 if terms.profile_id == "ln-to-btc/v1" else 1,
            )
        )
        return CooperativeClaimOutpoint(
            self._network,
            match,
            binding.funding_txid,
            binding.contract_vout,
            int(binding.contract_value_sat),
            bytes.fromhex(binding.contract_script_pubkey),
            tip_hash,
            tip_height,
            confirmations,
            inclusion_height,
            inclusion_hash,
        )

    def _observe_outpoint(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
        include_mempool: bool,
        minimum: int = 1,
    ) -> tuple[FundingBindingTransactionMatch, str, int, int, int | None, str | None]:
        """One read-only Core session, identical checks for either fixed RPC mode.

        A zero-confirmation sample (only with ``minimum=0``) has no inclusion
        block to name or to compare block-qualified bytes against.
        """
        if not isinstance(binding, FundingBinding):
            raise TypeError("a parsed binding is required")
        if not isinstance(terms.network_identity, NetworkIdentity) or (
            terms.network_identity != self._network
        ):
            raise ValueError("binding terms and configured full network identity differ")
        username, password = _cookie(self._cookie_path)
        try:
            with httpx.Client(
                base_url=self._url,
                auth=httpx.BasicAuth(username, password),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
            ) as client:
                tip_hash, tip_height = _chain_tip(
                    self._rpc(client, "getblockchaininfo", [], 1), self._network
                )
                if self._rpc(client, "getblockhash", [0], 2) != self._network.genesis_hash:
                    raise CoreProtocolError("Core genesis differs from configuration")
                raw_hex = self._rpc(client, "getrawtransaction", [binding.funding_txid, False], 3)
                raw = _transaction_bytes(raw_hex)
                match = check_funding_binding_transaction(raw, binding, terms, keys=keys)
                output = self._rpc(
                    client,
                    "gettxout",
                    [binding.funding_txid, binding.contract_vout, include_mempool],
                    4,
                )
                confirmations = _checked_outpoint(output, binding, tip_height, minimum=minimum)
                inclusion_height: int | None = None
                inclusion_hash: str | None = None
                if confirmations > 0:
                    inclusion_height = tip_height - confirmations + 1
                    inclusion_hash = self._rpc(client, "getblockhash", [inclusion_height], 5)
                    if not _hash(inclusion_hash) or (
                        inclusion_height == tip_height and inclusion_hash != tip_hash
                    ):
                        raise CoreProtocolError(
                            "Core inclusion-height block differs from sampled tip"
                        )
                    block_raw = _transaction_bytes(
                        self._rpc(
                            client,
                            "getrawtransaction",
                            [binding.funding_txid, False, inclusion_hash],
                            6,
                        )
                    )
                    if block_raw != raw:
                        raise CoreProtocolError("Core block-qualified transaction bytes differ")
                end_hash, end_height = _chain_tip(
                    self._rpc(client, "getblockchaininfo", [], 7), self._network
                )
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if tip_hash != end_hash or tip_height != end_height or output["bestblock"] != tip_hash:
            raise CoreUnavailableError("Core chain view changed; no current outpoint proof")
        return match, tip_hash, tip_height, confirmations, inclusion_height, inclusion_hash

    def _client(self) -> httpx.Client:
        username, password = _cookie(self._cookie_path)
        return httpx.Client(
            base_url=self._url,
            auth=httpx.BasicAuth(username, password),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
        )

    def discover_funding(  # noqa: PLR0912 - bounded descriptor response validation
        self, script: bytes, *, from_height: int, anchor_block: str | None = None
    ) -> FundingScan:
        """Read at most twelve explicit blocks plus mempool, never import or rescan.

        The caller must already have a durable affirmative watch. A changed
        checkpoint or tip yields no progress and never means an empty address.
        Receives are retained even if subsequently spent, to expose duplicates.
        """
        if (
            type(script) is not bytes
            or len(script) != 34  # noqa: PLR2004 - Taproot output script
            or script[:2] != b"\x51\x20"
            or type(from_height) is not int
            or from_height < 1
            or (anchor_block is not None and not _hash(anchor_block))
        ):
            raise ValueError("funding discovery bounds unsupported")
        deadline = time.monotonic() + READ_SECONDS
        try:
            with self._client() as client:
                tip_hash, tip = _chain_tip(
                    self._rpc(client, "getblockchaininfo", [], 1, deadline=deadline), self._network
                )
                if (
                    self._rpc(client, "getblockhash", [0], 2, deadline=deadline)
                    != self._network.genesis_hash
                ):
                    raise CoreProtocolError("Core genesis differs from configuration")
                if from_height > tip + 1:
                    raise CoreProtocolError("funding discovery checkpoint above tip")
                before = self._rpc(client, "getblockhash", [from_height - 1], 3, deadline=deadline)
                if not _hash(before) or (anchor_block is not None and before != anchor_block):
                    raise CoreProtocolError("funding discovery checkpoint left active chain")
                stop = min(tip, from_height + MAX_SCAN_BLOCKS - 1)
                hashes = [
                    self._rpc(client, "getblockhash", [height], 4, deadline=deadline)
                    for height in range(from_height, stop + 1)
                ]
                if not all(_hash(value) for value in hashes):
                    raise CoreProtocolError("funding discovery block unavailable")
                result = self._rpc(
                    client,
                    "getdescriptoractivity",
                    [hashes, [f"raw({script.hex()})"], True],
                    5,
                    deadline=deadline,
                )
                if not isinstance(result, dict) or not isinstance(result.get("activity"), list):
                    raise CoreProtocolError("funding discovery activity unavailable")
                if len(result["activity"]) > MAX_RECEIPTS * 2:
                    raise FundingDiscoveryOverflowError("funding discovery saturated")
                receipts: set[FundingReceipt] = set()
                mempool_seen = False
                for event in result["activity"]:
                    if not isinstance(event, dict) or event.get("type") not in {"receive", "spend"}:
                        raise CoreProtocolError("funding discovery event unsupported")
                    if event["type"] == "spend":
                        continue
                    if (
                        not _hash(event.get("txid"))
                        or type(event.get("vout")) is not int
                        or not 0 <= event["vout"] <= MAX_VOUT
                        or not isinstance(event.get("output_spk"), dict)
                        or event["output_spk"].get("hex") != script.hex()
                    ):
                        raise CoreProtocolError("funding discovery receive unsupported")
                    height, block = event.get("height"), event.get("blockhash")
                    if height is None and block is None:
                        mempool_seen = True
                        continue
                    if (
                        type(height) is not int
                        or not from_height <= height <= stop
                        or block != hashes[height - from_height]
                    ):
                        raise CoreProtocolError("funding discovery inclusion differs")
                    receipts.add(FundingReceipt(event["txid"], event["vout"], height, block))
                end = _chain_tip(
                    self._rpc(client, "getblockchaininfo", [], 6, deadline=deadline), self._network
                )
                if end != (tip_hash, tip):
                    raise CoreUnavailableError("funding discovery chain changed")
        except httpx.HTTPError:
            raise CoreUnavailableError("funding discovery transport unavailable") from None
        return FundingScan(
            tip,
            tip_hash,
            stop,
            hashes[-1] if hashes else str(before),
            tuple(sorted(receipts, key=lambda item: (item.height, item.txid, item.vout))),
            mempool_seen,
        )

    def broadcast(self, raw: bytes, txid: str) -> str:
        """Submit exact transaction bytes (the only mutating call); return the txid.

        ``txid`` comes from the caller's validated build. Idempotent: a
        transaction already in the chain counts as broadcast.
        The caller records the exact bytes durably before calling.
        """
        try:
            with self._client() as client:
                result = self._rpc(client, "sendrawtransaction", [raw.hex()], 1)
        except CoreRpcError as error:
            if error.code != RPC_VERIFY_ALREADY_IN_CHAIN:
                raise
            return txid
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if result != txid:
            raise CoreProtocolError("Core reported another transaction ID")
        return txid

    def fund_output(  # noqa: PLR0912 - one cleanup scope owns every identified input
        self, script_pubkey: bytes, value_sat: int, *, max_fee_sat: int
    ) -> FundedOutput:
        """Build and sign (never broadcast) a wallet transaction paying ``value_sat`` to the script.

        The paid output is always index 0 (change, if any, is index 1); inputs
        are locked in the wallet so a second build cannot double-spend them.
        The fee must not exceed ``max_fee_sat`` or nothing is signed. The
        caller records the exact bytes durably, then ``broadcast``s them.

        The rate is economical next-block advice (``next_block_fee``). The
        provider picks the inputs itself for privacy: the fewest coins, then
        the least excess (``funding_selection``); Core never adds more, and it
        drops change not worth keeping into the fee. A Core credential whose
        ``rpcwhitelist`` predates ``listunspent`` keeps Core's own selection
        at the same explicit rate.
        """
        if not (
            type(script_pubkey) is bytes
            and 0 < len(script_pubkey) <= MAX_SCRIPT_BYTES
            and type(value_sat) is int
            and value_sat > 0
            and type(max_fee_sat) is int
            and max_fee_sat >= 0
        ):
            raise ValueError("funding request unsupported")
        amount = f"{Decimal(value_sat) / SATS_PER_BTC:.8f}"
        selected_inputs: tuple[tuple[str, int], ...] = ()
        try:
            # Listing and locking must not interleave with another build.
            with _FUNDING_LOCK, self._client() as client:
                rate = self._next_block_fee(client).rate_sat_kvb
                described = self._rpc(client, "decodescript", [script_pubkey.hex()], 3)
                address = described.get("address") if isinstance(described, dict) else None
                if type(address) is not str:
                    raise CoreProtocolError("contract script has no address")  # noqa: TRY301 - cleanup scope
                chosen = self._choose_funding_inputs(
                    client, len(script_pubkey), value_sat, rate, max_fee_sat
                )
                options: dict[str, object] = {
                    "changePosition": 1,
                    "lockUnspents": True,
                    "replaceable": False,
                    "fee_rate": f"{rate // 1000}.{rate % 1000:03d}",  # sat/vB
                }
                if chosen is not None:
                    options["add_inputs"] = False
                inputs = [{"txid": txid, "vout": vout} for txid, vout in chosen or ()]
                created = self._rpc(
                    client, "walletcreatefundedpsbt", [inputs, [{address: amount}], 0, options], 5
                )
                if not isinstance(created, dict) or type(created.get("psbt")) is not str:
                    raise CoreProtocolError("Core wallet returned no PSBT")  # noqa: TRY301 - cleanup scope
                psbt = self._rpc(client, "decodepsbt", [created["psbt"]], 6)
                selected_inputs = _funding_inputs(
                    psbt.get("tx") if isinstance(psbt, dict) else None
                )
                if chosen is not None and sorted(selected_inputs) != sorted(chosen):
                    raise CoreProtocolError("Core wallet funded other inputs than selected")  # noqa: TRY301
                fee = _fee_sat(created)
                if fee > max_fee_sat:
                    raise CoreProtocolError("funding fee exceeds the signed maximum")  # noqa: TRY301
                signed = self._rpc(client, "walletprocesspsbt", [created["psbt"], True], 7)
                if not isinstance(signed, dict) or type(signed.get("psbt")) is not str:
                    raise CoreProtocolError("Core wallet could not sign the funding")  # noqa: TRY301
                final = self._rpc(client, "finalizepsbt", [signed["psbt"], True], 8)
                if not isinstance(final, dict) or final.get("complete") is not True:
                    raise CoreProtocolError("Core wallet could not sign every funding input")  # noqa: TRY301
                raw = _transaction_bytes(final.get("hex"))
                decoded = self._rpc(client, "decoderawtransaction", [raw.hex()], 9)
            txid = decoded.get("txid") if isinstance(decoded, dict) else None
            outputs = decoded.get("vout") if isinstance(decoded, dict) else None
            if (
                type(txid) is not str
                or not _hash(txid)
                or not isinstance(outputs, list)
                or not outputs
                or not isinstance(outputs[0], dict)
                or outputs[0].get("scriptPubKey", {}).get("hex") != script_pubkey.hex()
                or _btc_to_sat(outputs[0].get("value")) != value_sat
                or _funding_inputs(decoded) != selected_inputs
            ):
                raise CoreProtocolError("Core wallet signed a different funding than requested")  # noqa: TRY301
            return FundedOutput(
                txid=txid,
                vout=0,
                raw=raw,
                fee_sat=fee,
                anchor_txid=selected_inputs[0][0],
                anchor_vout=selected_inputs[0][1],
                selected_inputs=selected_inputs,
            )
        except Exception as error:  # builder owns identified inputs until successful return
            refusal = (
                CoreUnavailableError("Core RPC transport unavailable")
                if isinstance(error, httpx.HTTPError)
                else error
            )
            if selected_inputs:
                try:
                    self.release_funding_inputs(selected_inputs)
                except Exception:  # noqa: BLE001 - preserve original refusal, never claim cleanup
                    refusal.add_note(
                        "Funding input cleanup failed; inspect this wallet's locked coins."
                    )
            if refusal is not error:
                raise refusal from None
            raise

    def next_block_fee(self) -> NextBlockFee:
        """Sample economical next-block advice with this node's relay and mempool floors.

        Core's ``estimatesmartfee(2, "ECONOMICAL")`` (target 1 is clamped to
        2), capped by the operator ceiling. Without an estimate, public
        networks refuse rather than guess: the ceiling is never a fallback.
        Regtest alone falls back to the node's own minimums.
        """
        try:
            with self._client() as client:
                return self._next_block_fee(client)
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None

    def _next_block_fee(self, client: httpx.Client) -> NextBlockFee:
        mempool = self._rpc(client, "getmempoolinfo", [], 1)
        if not isinstance(mempool, dict):
            raise CoreProtocolError("Core mempool policy unavailable")
        relay = _fee_rate_sat_kvb(mempool.get("minrelaytxfee"))
        minimum = _fee_rate_sat_kvb(mempool.get("mempoolminfee"))
        try:
            advice = self._rpc(
                client, "estimatesmartfee", [NEXT_BLOCK_ESTIMATE_TARGET, "ECONOMICAL"], 2
            )
        except CoreRpcError:
            advice = None
        estimate = (
            _fee_rate_sat_kvb(advice["feerate"])
            if isinstance(advice, dict) and "feerate" in advice and not advice.get("errors")
            else 0
        )
        if estimate > 0:
            return NextBlockFee(relay, minimum, self._capped_estimate_sat_kvb(estimate))
        if self._network.name != "regtest":
            raise CoreUnavailableError("Core next-block fee estimate unavailable")
        return NextBlockFee(relay, minimum, None)

    def _choose_funding_inputs(
        self,
        client: httpx.Client,
        script_length: int,
        value_sat: int,
        rate_sat_kvb: int,
        max_fee_sat: int,
    ) -> tuple[tuple[str, int], ...] | None:
        """Explicit inputs, or ``None`` when the credential may not list coins."""
        try:
            listed = self._rpc(client, "listunspent", [0], 4)
        except CoreAuthError:
            LOG.warning(
                "Core credential lacks listunspent; funding falls back to Core's own coin "
                "selection. Add listunspent to the provider's rpcwhitelist."
            )
            return None
        selection = select_funding_inputs(
            _wallet_coins(listed),
            value_sat=value_sat,
            script_len=script_length,
            rate_sat_kvb=rate_sat_kvb,
            max_fee_sat=max_fee_sat,
        )
        if selection is None:
            raise CoreUnavailableError("funding wallet cannot pay the contract at this fee rate")
        return tuple((coin.txid, coin.vout) for coin in selection.coins)

    def release_funding_inputs(self, inputs: tuple[tuple[str, int], ...]) -> None:
        """Release exactly this invocation's identified inputs, never all wallet locks."""
        _funding_inputs({"vin": [{"txid": txid, "vout": vout} for txid, vout in inputs]})
        try:
            with self._client() as client:
                released = self._rpc(
                    client,
                    "lockunspent",
                    [True, [{"txid": txid, "vout": vout} for txid, vout in inputs]],
                    1,
                )
        except httpx.HTTPError:
            raise CoreUnavailableError("Core funding input cleanup unavailable") from None
        if released is not True:
            raise CoreProtocolError("Core did not release the selected funding inputs")

    def funding_scan_boundary(self, txid: str, required_depth: int) -> tuple[int, str]:
        """Canonical parent of a confirmed funding block, not a sampled tip minus depth."""
        if not _hash(txid) or type(required_depth) is not int or required_depth < 1:
            raise ValueError("funding scan boundary request unsupported")
        try:
            with self._client() as client:
                tx = self._rpc(client, "getrawtransaction", [txid, True], 1)
                block = tx.get("blockhash") if isinstance(tx, dict) else None
                if not _hash(block) or not isinstance(tx, dict) or tx.get("txid") != txid:
                    raise CoreProtocolError("funding inclusion unavailable")
                header = self._rpc(client, "getblockheader", [block, True], 2)
                height = header.get("height") if isinstance(header, dict) else None
                if (
                    type(height) is not int
                    or height < 1
                    or not isinstance(header, dict)
                    or header.get("hash") != block
                    or type(header.get("confirmations")) is not int
                    or header["confirmations"] < required_depth
                    or not _hash(header.get("previousblockhash"))
                    or self._rpc(client, "getblockhash", [height], 3) != block
                ):
                    raise CoreProtocolError(
                        "funding inclusion is not canonical at settlement depth"
                    )
                return height - 1, header["previousblockhash"]
        except httpx.HTTPError:
            raise CoreUnavailableError("Core funding inclusion unavailable") from None

    def find_spender(  # noqa: PLR0912 - bounded scan and branch authentication stay together
        self,
        txid: str,
        vout: int,
        *,
        from_height: int,
        to_height: int,
        anchor_block: str | None = None,
    ) -> SpendScan:
        """Look for the transaction spending ``txid:vout``: mempool first, then blocks.

        Blocks ``from_height`` through ``to_height`` are decoded oldest first,
        at most ``MAX_SPEND_SCAN_BLOCKS`` per call; ``scanned_to`` tells the
        caller where to resume. A mempool spender has ``height`` ``None``.
        """
        if not (
            type(txid) is str
            and len(txid) == HASH_HEX_LENGTH
            and type(vout) is int
            and vout >= 0
            and type(from_height) is int
            and type(to_height) is int
            and from_height > 0
        ):
            raise ValueError("spend scan bounds unsupported")
        if anchor_block is not None and not _hash(anchor_block):
            raise ValueError("scan anchor unsupported")
        scanned_block = anchor_block
        try:
            with self._client() as client:
                (entry,) = _list(
                    self._rpc(client, "gettxspendingprevout", [[{"txid": txid, "vout": vout}]], 1),
                    1,
                )
                spender = entry.get("spendingtxid") if isinstance(entry, dict) else None
                if type(spender) is str and len(spender) == HASH_HEX_LENGTH:
                    decoded = self._rpc(client, "getrawtransaction", [spender, True], 2)
                    witness = _spending_witness(decoded, txid, vout)
                    if witness is not None:
                        return SpendScan(
                            SpendObservation(spender, witness, None), from_height - 1, anchor_block
                        )
                scanned_to = from_height - 1
                last = min(to_height, from_height + MAX_SPEND_SCAN_BLOCKS - 1)
                for height in range(from_height, last + 1):
                    block_hash = self._rpc(client, "getblockhash", [height], 3)
                    block = self._rpc(client, "getblock", [block_hash, 2], 4)
                    continuous = anchor_block is None or not (
                        not isinstance(block, dict)
                        or not _hash(block_hash)
                        or block.get("hash") != block_hash
                        or type(block.get("height")) is not int
                        or block.get("height") != height
                        or block.get("previousblockhash") != scanned_block
                    )
                    transactions = block.get("tx") if isinstance(block, dict) else None
                    for transaction in _list(transactions):
                        witness = _spending_witness(transaction, txid, vout)
                        if witness is not None:
                            spender = transaction.get("txid")
                            if type(spender) is not str or len(spender) != HASH_HEX_LENGTH:
                                raise CoreProtocolError("Core reported a malformed spender")
                            observation = SpendObservation(spender, witness, height)
                            if anchor_block is not None:
                                # Reorganizations cannot retract knowledge of a valid
                                # preimage. Preserve the witness without progress
                                # authority if its branch cannot be authenticated.
                                canonical = False
                                if continuous:
                                    with suppress(CoreReadError):
                                        canonical = (
                                            self._rpc(client, "getblockhash", [height], 5)
                                            == block_hash
                                        )
                                if not canonical:
                                    return SpendScan(observation, from_height - 1, None)
                            return SpendScan(
                                observation,
                                height,
                                block_hash if anchor_block is not None else None,
                            )
                    if not continuous:
                        raise CoreProtocolError("spend scan chain continuity unavailable")
                    scanned_to = height
                    if anchor_block is not None:
                        scanned_block = block_hash
                if (
                    anchor_block is not None
                    and self._rpc(client, "getblockhash", [scanned_to], 5) != scanned_block
                ):
                    raise CoreProtocolError("spend scan branch changed")
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        return SpendScan(None, scanned_to, scanned_block)

    def outpoint_unspent(self, txid: str, vout: int) -> bool:
        """Whether ``txid:vout`` is unspent on the confirmed chain (mempool ignored).

        ``False`` means Core answered that the confirmed chain has no such
        unspent output: spent, or never existed. Transport failure raises.
        """
        if not (type(txid) is str and len(txid) == HASH_HEX_LENGTH and type(vout) is int):
            raise ValueError("outpoint must be a txid and index")
        try:
            with self._client() as client:
                output = self._rpc(client, "gettxout", [txid, vout, False], 1)
        except CoreRpcError:
            raise CoreUnavailableError("Core outpoint status unavailable") from None
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if output is None:
            return False
        if not isinstance(output, dict):
            raise CoreProtocolError("Core outpoint status is inconsistent")
        return True

    def transaction_inputs(self, raw: bytes) -> tuple[str, tuple[tuple[str, int], ...]]:
        """Decode exact transaction bytes into their txid and spent outpoints.

        Decoding says nothing about the chain or validity; it only names inputs.
        """
        if not isinstance(raw, bytes) or not raw:
            raise ValueError("transaction bytes required")
        try:
            with self._client() as client:
                decoded = self._rpc(client, "decoderawtransaction", [raw.hex()], 1)
        except CoreRpcError:
            raise CoreUnavailableError("Core transaction decoding unavailable") from None
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        txid = decoded.get("txid") if isinstance(decoded, dict) else None
        if not _hash(txid):
            raise CoreProtocolError("Core decoded a malformed transaction")
        return str(txid), _funding_inputs(decoded)

    def observe_cooperative_fee_policy(
        self, target_blocks: int, *, allow_regtest_fixed_fee: bool = False
    ) -> CooperativeFeePolicy:
        """Sample strict fee evidence without changing fallback fee advice.

        Public networks require an affirmative conservative estimate whose
        returned horizon fits the signed confirmation budget. Only explicit
        regtest configuration permits an explicitly unavailable estimate.
        Missing/malformed evidence never selects that exemption.
        """
        if type(target_blocks) is not int or not 1 <= target_blocks <= MAX_ESTIMATE_TARGET:
            raise ValueError("estimate target out of range")
        if type(allow_regtest_fixed_fee) is not bool or (
            allow_regtest_fixed_fee and self._network.name != "regtest"
        ):
            raise ValueError("fixed cooperative fee policy requires explicit regtest configuration")
        try:
            with self._client() as client:
                tip_hash, tip_height = _chain_tip(
                    self._rpc(client, "getblockchaininfo", [], 1), self._network
                )
                if self._rpc(client, "getblockhash", [0], 2) != self._network.genesis_hash:
                    raise CoreProtocolError("Core genesis differs from configuration")
                mempool = self._rpc(client, "getmempoolinfo", [], 3)
                if not isinstance(mempool, dict):
                    raise CoreProtocolError("Core cooperative mempool policy unavailable")
                relay = _fee_rate_sat_kvb(mempool.get("minrelaytxfee"))
                minimum = _fee_rate_sat_kvb(mempool.get("mempoolminfee"))
                estimate = self._rpc(client, "estimatesmartfee", [target_blocks, "CONSERVATIVE"], 4)
                if not isinstance(estimate, dict) or (
                    type(estimate.get("blocks")) is not int
                    or not 0 <= estimate["blocks"] <= MAX_ESTIMATE_TARGET
                ):
                    raise CoreProtocolError("Core cooperative estimate malformed")
                errors = estimate.get("errors")
                if "errors" in estimate:
                    if (
                        not isinstance(errors, list)
                        or not errors
                        or any(type(error) is not str or not error for error in errors)
                        or "feerate" in estimate
                    ):
                        raise CoreProtocolError("Core cooperative estimate malformed")
                    if not allow_regtest_fixed_fee:
                        raise CoreUnavailableError("Core cooperative estimate unavailable")
                    rate = None
                else:
                    rate = _fee_rate_sat_kvb(estimate.get("feerate"))
                    if rate <= 0 or not 1 <= estimate["blocks"] <= target_blocks:
                        raise CoreProtocolError(
                            "Core cooperative estimate exceeds confirmation budget"
                        )
                    rate = self._capped_estimate_sat_kvb(rate)
                end_hash, end_height = _chain_tip(
                    self._rpc(client, "getblockchaininfo", [], 5), self._network
                )
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if (tip_hash, tip_height) != (end_hash, end_height):
            raise CoreUnavailableError("Core chain view changed; no current fee evidence")
        return CooperativeFeePolicy(
            self._network,
            tip_hash,
            tip_height,
            target_blocks,
            relay,
            minimum,
            rate,
            estimate["blocks"],
        )

    def _capped_estimate_sat_kvb(self, rate: int) -> int:
        """Lower only the estimate; relay and mempool floors still bind cooperation."""
        if self._max_fee_estimate_sat_vb is None:
            return rate
        return min(rate, self._max_fee_estimate_sat_vb * 1000)

    def fee_rate_sat_vb(self, target_blocks: int) -> float | None:
        """Return Core's conservative feerate estimate in sat/vB, or ``None``.

        An estimate is advice, not evidence: any failure, an answer with
        ``errors``, or a non-positive rate yields ``None`` and the caller
        falls back to its configured fee.
        """
        if type(target_blocks) is not int or not 1 <= target_blocks <= MAX_ESTIMATE_TARGET:
            raise ValueError("estimate target out of range")
        try:
            with self._client() as client:
                result = self._rpc(client, "estimatesmartfee", [target_blocks, "CONSERVATIVE"], 1)
        except (CoreRpcError, httpx.HTTPError):
            return None
        if not isinstance(result, dict) or result.get("errors"):
            return None
        rate = result.get("feerate")
        if (
            not isinstance(rate, (int, float, Decimal))
            or isinstance(rate, bool)
            or not 0 < rate < 1
        ):
            return None  # BTC per kvB; anything at or above 1 BTC/kvB is nonsense
        estimate = float(Decimal(str(rate)) * 100_000)  # 1e8 sat per BTC over 1000 vB per kvB
        if self._max_fee_estimate_sat_vb is None:
            return estimate
        return min(estimate, float(self._max_fee_estimate_sat_vb))

    def block_hash(self, height: int) -> str:
        """Return the active-chain block hash at ``height``; failures raise."""
        if type(height) is not int or height < 0:
            raise ValueError("block height must be a non-negative integer")
        try:
            with self._client() as client:
                result = self._rpc(client, "getblockhash", [height], 1)
        except CoreRpcError:
            raise CoreUnavailableError("Core block hash unavailable") from None
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if not _hash(result):
            raise CoreProtocolError("Core block hash is malformed")
        return str(result)

    def confirmations(self, txid: str) -> int:
        """Return best-chain confirmations of a transaction (0 in mempool).

        Needs ``txindex=1`` for confirmed transactions. Raises
        ``CoreTransactionUnknownError`` when Core has neither a mempool nor an
        indexed copy (e.g. never broadcast or evicted); other failures are not
        evidence about the transaction at all.
        """
        try:
            with self._client() as client:
                result = self._rpc(client, "getrawtransaction", [txid, True], 1)
        except CoreRpcError as error:
            if error.code != RPC_INVALID_ADDRESS_OR_KEY:
                raise
            # Only a synced txindex turns "not found" into usable absence
            # evidence; a disabled or catching-up index says nothing.
            try:
                with self._client() as client:
                    indexes = self._rpc(client, "getindexinfo", ["txindex"], 2)
            except (CoreRpcError, httpx.HTTPError):
                raise CoreUnavailableError("Core index status unavailable") from None
            index = indexes.get("txindex") if isinstance(indexes, dict) else None
            if not (isinstance(index, dict) and index.get("synced") is True):
                raise CoreUnavailableError("Core txindex is not synced; no absence claim") from None
            raise CoreTransactionUnknownError(error.code) from None
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        count = result.get("confirmations", 0) if isinstance(result, dict) else None
        if not isinstance(result, dict) or result.get("txid") != txid or type(count) is not int:
            raise CoreProtocolError("Core transaction status is inconsistent")
        return count

    def _rpc(  # noqa: PLR0912 - cohesive bounded JSON-RPC parser and optional acceptance checks
        self,
        client: httpx.Client,
        method: str,
        params: list[object],
        request_id: int,
        *,
        deadline: float | None = None,
    ) -> Any:  # noqa: ANN401
        if method not in CORE_RPC_METHODS:
            raise CoreProtocolError("unsupported Core RPC method")
        wallet = method.startswith("wallet") or method in _WALLET_RPC_METHODS
        path = self._wallet_path if wallet else "/"
        max_bytes = {
            "getblock": MAX_BLOCK_RESPONSE_BYTES,
            "listunspent": MAX_UNSPENT_RESPONSE_BYTES,
            "listlockunspent": MAX_UNSPENT_RESPONSE_BYTES,
        }.get(method, MAX_RESPONSE_BYTES)
        try:
            with client.stream(
                "POST",
                path,
                headers={"Accept-Encoding": "identity"},
                json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
                timeout=(
                    httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS)
                    if deadline is None
                    else httpx.Timeout(_remaining_source(deadline))
                ),
            ) as response:
                if deadline is not None:
                    _remaining_source(deadline)
                if response.status_code in (401, 403):
                    raise CoreAuthError("Core RPC authentication rejected")
                if response.status_code != HTTP_OK:
                    raise CoreUnavailableError(
                        "Core RPC failed without usable transaction evidence"
                    )
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise CoreProtocolError("compressed Core RPC responses are unsupported")
                chunks = bytearray()
                for part in response.iter_raw():
                    if deadline is not None:
                        _remaining_source(deadline)
                    if len(chunks) + len(part) > max_bytes:
                        raise CoreProtocolError("Core RPC response exceeded resource limit")
                    chunks.extend(part)
            if deadline is not None:
                _remaining_source(deadline)
            envelope = json.loads(
                chunks,
                object_pairs_hook=_unique_pairs,
                parse_float=Decimal,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-JSON number")),
            )
        except (ValueError, UnicodeError, InvalidOperation):
            raise CoreProtocolError("Core RPC response is not strict JSON") from None
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if (
            not isinstance(envelope, dict)
            or envelope.get("jsonrpc") != "2.0"
            or type(envelope.get("id")) is not int
            or envelope["id"] != request_id
            or ("result" in envelope) == ("error" in envelope)
        ):
            raise CoreProtocolError("Core RPC response envelope is inconsistent")
        if "error" in envelope:
            error = envelope["error"]
            if (
                not isinstance(error, dict)
                or type(error.get("code")) is not int
                or not isinstance(error.get("message"), str)
            ):
                raise CoreProtocolError("Core RPC error envelope is malformed")
            raise CoreRpcError(error["code"])
        return envelope["result"]


class CoreRpcError(CoreUnavailableError):
    """Core answered with a JSON-RPC error; only the numeric code is kept."""

    def __init__(self, code: int) -> None:
        """Keep the code, never the (possibly data-bearing) message."""
        super().__init__("Core RPC result unavailable; no absence claim")
        self.code = code


class CoreTransactionUnknownError(CoreRpcError):
    """Core has no mempool or indexed copy of the transaction right now."""


def _transaction_bytes(raw_hex: object) -> bytes:
    if (
        not isinstance(raw_hex, str)
        or len(raw_hex) > MAX_TRANSACTION_HEX_BYTES
        or (len(raw_hex) % 2 or any(char not in "0123456789abcdef" for char in raw_hex))
    ):
        raise CoreProtocolError("Core transaction response is not bounded lowercase hex")
    return bytes.fromhex(raw_hex)


def _checked_outpoint(
    output: object, binding: FundingBinding, tip_height: int, *, minimum: int = 1
) -> int:
    if output is None:
        raise CoreUnavailableError("contract outpoint unavailable; not proof of absence")
    count = output.get("confirmations") if isinstance(output, dict) else None
    if (
        not isinstance(output, dict)
        or isinstance(count, bool)
        or not isinstance(count, int)
        or not minimum <= count <= tip_height
        or not _hash(output.get("bestblock"))
        or output.get("coinbase") is not False
        or not isinstance(output.get("scriptPubKey"), dict)
        or output["scriptPubKey"].get("hex") != binding.contract_script_pubkey
        or not _exact_sats(output.get("value"), int(binding.contract_value_sat))
    ):
        raise CoreProtocolError("Core contract outpoint evidence is inconsistent")
    return count


def _funding_inputs(decoded: object) -> tuple[tuple[str, int], ...]:
    inputs = decoded.get("vin") if isinstance(decoded, dict) else None
    if (
        not isinstance(inputs, list)
        or not inputs
        or any(
            not isinstance(item, dict)
            or not _hash(item.get("txid"))
            or type(item.get("vout")) is not int
            or not 0 <= item["vout"] <= MAX_VOUT
            for item in inputs
        )
    ):
        raise CoreProtocolError("Core funding input identities unavailable")
    outpoints = tuple((item["txid"], item["vout"]) for item in inputs)
    if len(set(outpoints)) != len(outpoints):
        raise CoreProtocolError("Core funding input identities are duplicated")
    return outpoints


def _wallet_coins(listed: object) -> list[Coin]:
    """Safe, solvable single-key wallet coins; anything else stays out of selection."""
    coins = []
    for entry in _list(listed):
        if (
            not isinstance(entry, dict)
            or not _hash(entry.get("txid"))
            or type(entry.get("vout")) is not int
            or not 0 <= entry["vout"] <= MAX_VOUT
            or type(entry.get("confirmations")) is not int
            or entry["confirmations"] < 0
        ):
            raise CoreProtocolError("Core wallet coin list is malformed")
        value = _btc_to_sat(entry.get("amount"))
        script, descriptor = entry.get("scriptPubKey"), entry.get("desc")
        kind = (
            input_kind(script, descriptor)
            if type(script) is str and type(descriptor) is str
            else None
        )
        if (
            kind is None
            or value <= 0
            or entry.get("solvable") is not True
            or entry.get("safe") is not True
            or entry.get("reused") is True  # avoid_reuse wallets skip dirty coins too
        ):
            continue
        confirmed = entry["confirmations"] > 0
        coins.append(Coin(entry["txid"], entry["vout"], value, INPUT_WEIGHTS[kind], confirmed))
    return coins


def _fee_sat(created: object) -> int:
    fee = created.get("fee") if isinstance(created, dict) else None
    if type(created) is not dict or type(created.get("psbt")) is not str:
        raise CoreProtocolError("Core wallet returned no PSBT")
    return _btc_to_sat(fee)


def _btc_to_sat(value: object) -> int:
    if not isinstance(value, Decimal):
        raise CoreProtocolError("Core reported a non-decimal amount")
    sats = value * SATS_PER_BTC
    if sats != sats.to_integral_value() or sats < 0:
        raise CoreProtocolError("Core reported a non-integral satoshi amount")
    return int(sats)


def _list(value: object, exact: int | None = None) -> list[Any]:
    if not isinstance(value, list) or (exact is not None and len(value) != exact):
        raise CoreProtocolError("Core reported a malformed list")
    return value


def _spending_witness(decoded: object, txid: str, vout: int) -> tuple[bytes, ...] | None:
    """Return the witness of the input of ``decoded`` spending ``txid:vout``, if any."""
    inputs = decoded.get("vin") if isinstance(decoded, dict) else None
    for entry in _list(inputs):
        if not isinstance(entry, dict) or entry.get("txid") != txid or entry.get("vout") != vout:
            continue
        items = entry.get("txinwitness", [])
        if not isinstance(items, list) or not all(type(item) is str for item in items):
            raise CoreProtocolError("Core reported a malformed witness")
        try:
            return tuple(bytes.fromhex(item) for item in items)
        except ValueError:
            raise CoreProtocolError("Core reported a malformed witness") from None
    return None


def _balance_sat(mine: object, field: str) -> int:
    """Return one ``getbalances`` mine field in sat, refusing anything implausible."""
    value = mine.get(field) if isinstance(mine, dict) else None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, Decimal))
        or not Decimal(value).is_finite()
        or not 0 <= value <= MAX_SATS / SATS_PER_BTC
    ):
        raise CoreProtocolError("Core wallet balance invalid")
    with localcontext(DecimalContext(prec=28)):
        return int(value * SATS_PER_BTC)
