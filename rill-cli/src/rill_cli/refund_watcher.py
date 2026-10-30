"""``rill recover watch-refund``: refund a failed BTC-to-LN swap with fee escalation.

The watcher never refunds a swap the provider paid: the client's own LND must
report the invoice as not SETTLED before every attempt. Only an explicit
operator choice (``invoice_state=None``, the CLI's ``--chain-only``) skips that
check for an invoice no local LND holds; the contract's refund lock and an
unspent funding output then decide alone, and the outcome says so. Every signed attempt
is written to a create-only file before its broadcast; those files are the
durable state, so a restart continues from the highest recorded fee and
never signs a lower one. Any recorded attempt may confirm.
"""

from __future__ import annotations

import hashlib
import logging
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

import httpx
from rill_core.settlement.unilateral import SchnorrVerifier, validate_unilateral_spend
from rill_core.wire.canonical import canonicalize, parse_json_strict

from rill_cli.claim_watcher import ClaimSubmission
from rill_cli.recovery_core_observation import CONNECT_SECONDS, READ_SECONDS, _cookie, _outpoint
from rill_cli.refund_publication import MAX_INTENT_BYTES, publish_new_broadcast_intent

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from rill_core.settlement.unilateral import UnilateralAuthorization
    from rill_core.wire.messages import FundingBinding
    from rill_provider.lnd_invoice_observation import LndInvoiceObserver

    from rill_cli.recovery_core_observation import RecoveryCoreReader

LOG = logging.getLogger(__name__)
ATTEMPT_KIND = "btc-to-ln-refund-attempt/v1"
MAX_ATTEMPTS = 32
INCREMENTAL_RELAY_SAT_VB = 1  # BIP125 rule 4 at Core's default incremental relay fee
MAX_ATTEMPT_FILES = 64

type Outcome = Literal["refund_confirmed", "invoice_settled", "outpoint_spent_elsewhere"]


class RefundWatchError(ValueError):
    """The watcher refused to continue; nothing was signed by this call."""


@dataclass(frozen=True, slots=True)
class RefundAttempt:
    """One signed, durably recorded refund; ``None`` height means unknown."""

    attempt: int
    txid: str
    raw: bytes
    fee_sat: int
    vsize: int
    height: int | None


@dataclass(frozen=True, slots=True)
class ChainView:
    """One chain-only sample: tip and whether the contract output is unspent."""

    tip_height: int
    unspent_on_chain: bool


def refund_fee_target(  # noqa: PLR0913 - explicit schedule inputs
    *,
    initial: int,
    maximum: int,
    start_height: int,
    escalate_blocks: int,
    tip: int,
    latest: RefundAttempt | None,
) -> int | None:
    """Return the fee of the next attempt, or ``None`` when none is due.

    The fee rises linearly from ``initial`` at ``start_height`` (the first
    block a refund can be mined in) to ``maximum`` ``escalate_blocks`` later,
    then stays at ``maximum``. A replacement needs a new block since the
    latest attempt and must beat its fee by the incremental relay fee.
    """
    maximum = max(initial, maximum)
    if latest is None:
        return initial
    if latest.attempt + 1 >= MAX_ATTEMPTS or (latest.height is not None and tip <= latest.height):
        return None
    elapsed = max(0, tip - start_height)
    target = (
        maximum
        if elapsed >= escalate_blocks
        else (initial + (maximum - initial) * elapsed // max(1, escalate_blocks))
    )
    increment = latest.vsize * INCREMENTAL_RELAY_SAT_VB
    if maximum - target < increment:
        target = maximum  # never strand the final replacement below the maximum
    if target < latest.fee_sat + increment:
        return None
    return target


def attempt_document(attempt: RefundAttempt, *, funding_txid: str, contract_vout: int) -> bytes:
    """Canonical public record of one signed attempt (no secrets)."""
    return canonicalize(
        {
            "kind": ATTEMPT_KIND,
            "attempt": attempt.attempt,
            "funding_txid": funding_txid,
            "contract_vout": contract_vout,
            "refund_txid": attempt.txid,
            "fee_sat": attempt.fee_sat,
            "tip_height": attempt.height,
            "signed_refund_hex": attempt.raw.hex(),
            "signed_refund_sha256": hashlib.sha256(attempt.raw).hexdigest(),
        }
    )


def load_attempts(
    directory: Path, authorization: UnilateralAuthorization, *, verifier: SchnorrVerifier
) -> list[RefundAttempt]:
    """Rebuild the attempt history from ``refund-*.json``; every file must verify."""
    files = sorted(directory.glob("refund-*.json"))
    if len(files) > MAX_ATTEMPT_FILES:
        raise RefundWatchError("too many attempt files in the intent directory")
    attempts: list[RefundAttempt] = []
    for path in files:
        parsed = parse_json_strict(path.read_bytes(), max_bytes=MAX_INTENT_BYTES)
        if not isinstance(parsed, dict) or parsed.get("kind") != ATTEMPT_KIND:
            raise RefundWatchError("attempt file is not a refund attempt record")
        raw_hex, height = parsed.get("signed_refund_hex"), parsed.get("tip_height")
        if not isinstance(raw_hex, str) or (height is not None and type(height) is not int):
            raise RefundWatchError("attempt file is malformed")
        raw = bytes.fromhex(raw_hex)
        checked = validate_unilateral_spend(raw, authorization, verifier=verifier)
        if checked.txid != parsed.get("refund_txid") or checked.fee_sat != parsed.get("fee_sat"):
            raise RefundWatchError("attempt file differs from its signed transaction")
        if parsed.get("attempt") != len(attempts):
            raise RefundWatchError("attempt files are not a contiguous history")
        attempts.append(
            RefundAttempt(len(attempts), checked.txid, raw, checked.fee_sat, checked.vsize, height)
        )
    return attempts


class RefundWatcher:
    """Poll until the refund confirms, the invoice settles, or the output is gone.

    The chain, invoice, signing, and submission functions are explicit so the
    policy is testable without Core or LND. ``sign`` returns exact refund bytes
    for a fee; ``submit`` preflights and sends them and returns ``True`` when
    the node accepted (``False`` when it did not); ``confirmations`` returns
    ``None`` for a transaction the node cannot see.
    """

    def __init__(  # noqa: PLR0913 - explicit collaborators
        self,
        *,
        attempts: list[RefundAttempt],
        intent_dir: Path,
        funding_txid: str,
        contract_vout: int,
        refund_lock_height: int,
        initial_fee_sat: int,
        max_fee_sat: int,
        escalate_blocks: int,
        chain: Callable[[], ChainView | None],
        invoice_state: Callable[[], str | None] | None,
        sign: Callable[[int, int], tuple[bytes, str, int, int]],
        submit: Callable[[bytes, str], bool],
        confirmations: Callable[[str], int | None],
        authorization: UnilateralAuthorization,
        verifier: SchnorrVerifier,
        poll_seconds: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
        report: Callable[[str], None] = LOG.info,
    ) -> None:
        """Take the recorded history and the explicit collaborators."""
        if initial_fee_sat < 0 or max_fee_sat < initial_fee_sat or escalate_blocks < 1:
            raise RefundWatchError("fee schedule must be non-negative and rising")
        self.attempts = attempts
        self._dir = intent_dir
        self._funding = (funding_txid, contract_vout)
        self._lock_height = refund_lock_height
        self._fees = (initial_fee_sat, max_fee_sat, escalate_blocks)
        self._chain, self._invoice_state = chain, invoice_state
        self._sign, self._submit, self._confirmations = sign, submit, confirmations
        self._authorization, self._verifier = authorization, verifier
        self._poll, self._sleep = poll_seconds, sleep
        self._report = report
        self._last_progress: str | None = None

    def _progress(self, line: str) -> None:
        if line == self._last_progress:
            return
        self._last_progress = line
        with suppress(Exception):  # progress cannot change signing or submission
            self._report(line)

    def run(self, *, max_polls: int | None = None) -> dict[str, Any] | None:
        """Poll until an outcome; ``None`` only when ``max_polls`` ran out."""
        polls = 0
        while max_polls is None or polls < max_polls:
            polls += 1
            outcome = self.step()
            if outcome is not None:
                return outcome
            self._sleep(self._poll)
        return None

    def step(self) -> dict[str, Any] | None:  # noqa: PLR0911, PLR0912 - one rule per branch
        """One poll: refuse, finish, wait, rebroadcast, or record and send a bump."""
        if self._invoice_state is not None:
            invoice = self._invoice_state()
            if invoice is None:
                self._progress("invoice state unavailable; not refunding without it")
                return None
            if invoice == "SETTLED":
                return self._outcome("invoice_settled", refund="refused: the provider paid")
        view = self._chain()
        if view is None or not view.unspent_on_chain:
            for attempt in reversed(self.attempts):
                depth = self._confirmations(attempt.txid)
                # A negative depth is a conflicted transaction, not our refund.
                if depth is not None and depth > 0:
                    return self._outcome(
                        "refund_confirmed", refund_txid=attempt.txid, confirmations=depth
                    )
            if view is None:
                self._progress("chain data unavailable; keeping the recorded refund attempts")
                return None
            return self._outcome("outpoint_spent_elsewhere")
        if view.tip_height <= self._lock_height:
            self._progress(
                f"waiting for refund maturity: block {view.tip_height}, "
                f"first eligible block {self._lock_height + 1}"
            )
            return None
        latest = self.attempts[-1] if self.attempts else None
        initial, maximum, blocks = self._fees
        fee = refund_fee_target(
            initial=initial,
            maximum=maximum,
            start_height=self._lock_height + 1,
            escalate_blocks=blocks,
            tip=view.tip_height,
            latest=latest,
        )
        if fee is None:
            if latest is not None:
                self._submit(latest.raw, latest.txid)  # rebroadcast; a replacement is fine
            return None
        raw, txid, checked_fee, vsize = self._sign(fee, view.tip_height)
        if checked_fee != fee:
            raise RefundWatchError("signed refund fee differs from the scheduled fee")
        attempt = RefundAttempt(len(self.attempts), txid, raw, fee, vsize, view.tip_height)
        self._record(attempt)  # durable before the send
        self.attempts.append(attempt)
        self._progress(f"refund attempt {attempt.attempt} recorded: txid {txid}, fee {fee} sat")
        if not self._submit(raw, txid):
            self._progress(f"refund attempt {attempt.attempt} not accepted yet; recorded")
        else:
            self._progress(f"refund submitted: {txid}; waiting for chain confirmation")
        return None

    def _record(self, attempt: RefundAttempt) -> None:
        document = attempt_document(
            attempt, funding_txid=self._funding[0], contract_vout=self._funding[1]
        )

        def verify(stored: bytes) -> None:
            if stored != document:
                raise RefundWatchError("attempt record readback differs")
            checked = validate_unilateral_spend(
                attempt.raw, self._authorization, verifier=self._verifier
            )
            if checked.txid != attempt.txid or checked.fee_sat != attempt.fee_sat:
                raise RefundWatchError("attempt record differs from the signed refund")

        publish_new_broadcast_intent(
            self._dir / f"refund-{attempt.attempt:02d}-{attempt.txid}.json",
            document,
            verify_from_disk=verify,
        )

    def _outcome(self, outcome: Outcome, **extra: Any) -> dict[str, Any]:  # noqa: ANN401
        self._progress(f"refund watch outcome: {outcome}")
        return {
            "kind": "btc-to-ln-refund-watch/v1",
            "outcome": outcome,
            "invoice_check": "lnd" if self._invoice_state is not None else "skipped-chain-only",
            "attempts": [
                {"attempt": a.attempt, "refund_txid": a.txid, "fee_sat": a.fee_sat}
                for a in self.attempts
            ],
            **extra,
        }


def core_collaborators(
    reader: RecoveryCoreReader, *, binding: FundingBinding
) -> tuple[
    Callable[[], ChainView | None], Callable[[str], int | None], Callable[[bytes, str], bool]
]:
    """Chain view, confirmations, and submission over the recovery Core reader.

    Every call opens one short loopback session. Failures are never evidence:
    the chain view and confirmations return ``None`` and submission ``False``.
    """
    chain, confirmations, submit = core_claim_collaborators(reader, binding=binding)
    return chain, confirmations, lambda raw, txid: submit(raw, txid) is ClaimSubmission.ACCEPTED


def core_claim_collaborators(
    reader: RecoveryCoreReader, *, binding: FundingBinding
) -> tuple[
    Callable[[], ChainView | None],
    Callable[[str], int | None],
    Callable[[bytes, str], ClaimSubmission],
]:
    """Claim submission distinguishes local refusal from potentially disclosed bytes."""

    def client() -> httpx.Client:
        username, password = _cookie(reader._cookie_path)  # noqa: SLF001 - CLI-local RPC boundary
        return httpx.Client(
            base_url=reader._url,  # noqa: SLF001 - same explicit loopback endpoint
            auth=httpx.BasicAuth(username, password),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
        )

    def chain() -> ChainView | None:
        try:
            with client() as session:
                tip_hash, height = reader._attest_session(session)  # noqa: SLF001 - same RPC boundary
                if height == 0:
                    return None
                # Chain-only: our own unconfirmed refund must not look like a spend.
                out = reader._rpc(  # noqa: SLF001
                    session, "gettxout", [binding.funding_txid, binding.contract_vout, False], 3
                )
                if out is None:
                    return None  # absence does not identify a spender or a missing funding tx
                outpoint_tip, _ = _outpoint(out, binding, height)
                if outpoint_tip != tip_hash:
                    return None  # the output sample differs from the attested tip
        except Exception:  # noqa: BLE001 - transport or node failure is not evidence
            LOG.info("Core chain view unavailable; waiting")
            return None
        return ChainView(height, unspent_on_chain=True)

    def confirmations(txid: str) -> int | None:
        try:
            with client() as session:
                reader._attest_session(session)  # noqa: SLF001 - no unauthenticated Core reads
                result = reader._rpc(session, "getrawtransaction", [txid, True], 3)  # noqa: SLF001
        except Exception:  # noqa: BLE001 - unknown or unavailable: no evidence
            return None
        depth = result.get("confirmations") if isinstance(result, dict) else None
        return depth if type(depth) is int and result.get("txid") == txid else None

    def submit(raw: bytes, txid: str) -> ClaimSubmission:
        broadcast_invoked = False
        try:
            with client() as session:
                reader._attest_session(session)  # noqa: SLF001 - before leaking spend bytes
                preflight = reader._rpc(  # noqa: SLF001
                    session, "testmempoolaccept", [[raw.hex()]], 4, submission=True
                )
                if not (
                    isinstance(preflight, list)
                    and len(preflight) == 1
                    and isinstance(preflight[0], dict)
                    and preflight[0].get("allowed") is True
                    and preflight[0].get("txid") == txid
                ):
                    return ClaimSubmission.NOT_BROADCAST
                broadcast_invoked = True
                returned = reader._rpc(  # noqa: SLF001
                    session, "sendrawtransaction", [raw.hex()], 5, submission=True
                )
        except Exception:  # noqa: BLE001 - the attempt is recorded; the next poll retries
            return ClaimSubmission.UNKNOWN if broadcast_invoked else ClaimSubmission.NOT_BROADCAST
        return ClaimSubmission.ACCEPTED if returned == txid else ClaimSubmission.UNKNOWN

    return chain, confirmations, submit


def lnd_invoice_state(observer: LndInvoiceObserver, payment_hash: str) -> Callable[[], str | None]:
    """Report the client's own invoice state, or ``None`` when LND cannot say."""
    hashed = bytes.fromhex(payment_hash)

    def state() -> str | None:
        try:
            return observer.lookup(hashed).state
        except Exception:  # noqa: BLE001 - never refund on missing evidence
            return None

    return state
