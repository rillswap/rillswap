"""Authoritative single-owner RS-001 handshake session store.

This is the only provider store whose rows may authorize exposing a
handshake_accept or admitting a handshake_confirm. Its guarantees are
conditional on a deployment fact it cannot verify: the database and its owner
lock live on an explicitly provisioned volume OUTSIDE the application's backup
and restore domain, used by exactly one host. The operator attests to that at
provisioning time.

What it enforces locally:
- explicit provisioning only; absent, partial, foreign, or newer files refuse;
- one lifetime exclusive owner (flock on a stable lock inode, no takeover);
- a generation counter bumped per owner and checked in every write;
- copied or file-restored databases (different inode) refuse to open;
- the exact accept bytes are durably committed before they may be exposed;
- confirm admission requires the full static transcript over those bytes.

It does NOT detect an in-place rollback of the authoritative volume, a clone
on another host, or authorize any economic effect. Confirmation grants no
funding, payment, or claim authority.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import stat
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol, Self, cast

import pyrage  # type: ignore[import-untyped]
from pyrage import x25519
from rill_core.settlement import (
    CooperativeClaimPlan,
    FundingOutput,
    UnilateralAuthorization,
    build_cooperative_claim,
    finalize_cooperative_claim,
    reconstruct_taproot_contract,
    verify_cooperative_claim_proposal,
)
from rill_core.settlement.funding import (
    FundingBindingTransactionMatch,
    check_funding_binding_transaction,
)
from rill_core.settlement.unilateral import validate_unilateral_spend
from rill_core.wire import verify_static_handshake_accept, verify_static_handshake_transcript
from rill_core.wire.canonical import canonicalize, parse_json_strict, parse_model_json
from rill_core.wire.cooperative_messages import (
    CooperativeClaimComplete,
    CooperativeClaimDeclined,
    CooperativeClaimPropose,
    CooperativeClaimReady,
    CooperativeClaimReadyRequest,
    CooperativeClaimSigned,
    CooperativeClaimVerified,
    check_cooperative_action_context,
    parse_cooperative_payload,
)
from rill_core.wire.envelope_authentication import verify_static_signed_envelope
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_FEATURE,
    FEE_POLICY_FEATURE,
    client_acceptance_hash,
    contract_hash,
    funding_binding_hash,
    handshake_hash,
    handshake_init_hash,
    provider_terms_hash,
    unsigned_envelope_hash,
)
from rill_core.wire.messages import (
    AnyContractTerms,
    ContractTerms,
    Envelope,
    EvmContractTerms,
    FundingBinding,
    HandshakeAccept,
    HandshakeAcceptPayload,
    HandshakeInit,
    InvoiceBinding,
    LnToBtcEconomics,
    require_supported_contract_features,
)
from rill_core.wire.quotes import TermsOfferPayload
from rill_core.wire.settlement_messages import FundingBindingPayload, TermsAcceptPayload
from rill_core.wire.types import NetworkIdentity

from rill_provider import _nip01_event as nip01
from rill_provider import _transport_pow as transport_pow
from rill_provider._nip59_receive import OUTER_KIND, _decode_gift_wrap_candidate
from rill_provider._nip59_send import _wrap_envelope
from rill_provider.core_tx_bytes import (
    MAX_ESTIMATE_TARGET,
    MAX_SATS,
    MAX_VOUT,
    SATS_PER_BTC,
    CooperativeClaimOutpoint,
    CooperativeFeePolicy,
    ReverseSpendCheckpoint,
)
from rill_provider.handshake_store import HandshakePolicy, _expected, _features, _require_policy
from rill_provider.issuance_reservation import _policy_bytes
from rill_provider.lnd_hold_invoice import BoundHoldInvoiceObservation, HeldHtlc, HoldInvoiceStatus
from rill_provider.payment_dispatch_record import PaymentAuthority, bound_payer
from rill_provider.reverse_cooperation import ReverseCooperationWindow
from rill_provider.swap_accounting import (
    ACCEPTED,
    CLAIM_FEE,
    COMPLETED,
    FUNDING_FEE,
    GAS,
    LEDGER_KINDS,
    LEDGER_UNITS,
    LOST,
    OFFERED,
    REBATE,
    REBATE_WINDOW_SECONDS,
    REFUND_FEE,
    ROUTING_FEE,
    TERMINAL_KIND_BY_STATE,
    TERMINAL_KINDS,
    LedgerEntry,
    SwapEconomics,
    ledger_amount,
    signed_ledger_amount,
    swap_economics,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from os import PathLike

    from rill_core.settlement.taproot import TaprootKeyOperations
    from rill_core.wire.envelope_authentication import EnvelopeSchnorrVerifier
    from rill_crypto import Context
    from rill_crypto.binding import MusigAttempt

    from rill_provider.handshake_custody_offline import CustodyPublicKeys
    from rill_provider.provider_identity import ProviderIdentity
    from rill_provider.reverse_operations import ReverseOperation, ReverseOperations

APPLICATION_ID = 0x524C5331  # RLS1, distinct from all diagnostic stores.
SCHEMA_VERSION = 21  # every other version is refused: recreate with provision-store
CONTRACT_KEY_RECORD_KIND = "rillswap-provider-contract-key"
OPEN_PHASES = ("CONFIRMED", "ACCEPTED")  # sessions that may still send requests
SWAP_TRANSITIONS = frozenset(
    {
        ("ACCEPTED", "FAILED"),  # never funded before the payment deadline
        ("FUNDING_SEEN", "PAYING"),
        ("FUNDING_SEEN", "FAILED"),
        ("PAYING", "PAID"),
        ("PAYING", "FAILED"),
        ("PAID", "CLAIMING"),
        ("CLAIMING", "CLAIMED"),
        ("CLAIMING", "LOST"),  # the client's refund spent the contract; no claim confirmed
    }
)
# LN to BTC (RS-004): the provider funds after the hold invoice is accepted and
# settles it with the preimage the client's claim reveals, or refunds.
REVERSE_SWAP_TRANSITIONS = frozenset(
    {
        ("ACCEPTED", "LN_HELD"),  # every HTLC accepted, amount and expiry checked
        ("ACCEPTED", "ABORTED"),  # hold canceled or expired before funding
        ("LN_HELD", "FUNDING_SENT"),  # the one funding grant: signed funding recorded
        ("LN_HELD", "ABORTED"),  # hold no longer accepted, or the window closed
        ("FUNDING_SENT", "FUNDED"),
        ("FUNDING_SENT", "SETTLED"),  # a claim revealed the preimage before our depth check
        ("FUNDED", "SETTLED"),
        ("FUNDED", "REFUNDING"),  # past the refund lock, still unspent: refund broadcast
        ("REFUNDING", "SETTLED"),  # the claim won the race: settle, the hold pays for it
        ("REFUNDING", "REFUNDED"),  # refund at depth, hold canceled
    }
)
# RS-010: EVM swaps reuse the Bitcoin state names. Evidence is HTLC ``Lockup`` /
# ``Claim`` logs and transaction hashes instead of outpoints and raw transactions.
EVM_SWAP_TRANSITIONS = frozenset(
    {
        # erc20-to-ln: the client locks tokens, we pay the invoice and claim.
        ("ACCEPTED", "FUNDING_SEEN"),  # the exact Lockup observed at funding depth
        ("ACCEPTED", "FAILED"),  # terms expired before any lock
        ("FUNDING_SEEN", "PAYING"),  # the one payment grant
        ("FUNDING_SEEN", "FAILED"),  # lock no longer payable (timing) before any dispatch
        ("PAYING", "PAID"),
        ("PAYING", "FAILED"),
        ("PAID", "CLAIMING"),  # our claim sent
        ("CLAIMING", "CLAIMED"),  # our claim at settlement depth
        ("CLAIMING", "LOST"),  # the lock is gone without our claim (client refund)
        # ln-to-erc20: we lock tokens after the hold is accepted, the client claims.
        ("ACCEPTED", "LN_HELD"),
        ("ACCEPTED", "ABORTED"),
        ("LN_HELD", "FUNDING_SENT"),  # the one lock grant: reservation DISPATCHED
        ("LN_HELD", "ABORTED"),
        ("FUNDING_SENT", "FUNDED"),  # our lock at funding depth
        ("FUNDING_SENT", "SETTLED"),  # the client's Claim appeared before our depth check
        ("FUNDED", "SETTLED"),  # Claim log revealed the preimage: hold settled
        ("FUNDED", "REFUNDING"),  # timelock passed, still locked: refund sent
        ("REFUNDING", "SETTLED"),  # the claim won the race
        ("REFUNDING", "REFUNDED"),  # refund at settlement depth, hold canceled
    }
)
EVM_TERMINAL_STATES = ("FAILED", "CLAIMED", "LOST", "ABORTED", "SETTLED", "REFUNDED")
REVERSE_STATES = (
    "LN_HELD",
    "FUNDING_SENT",
    "FUNDED",
    "SETTLED",
    "REFUNDING",
    "REFUNDED",
    "ABORTED",
)
CLIENT_REQUEST_TYPES = ("quote_request", "terms_accept", "funding_binding")
SWAP_COLUMNS = (
    "session_id, contract_hash, terms_offer, terms_accept, state, funding_binding, "
    "preimage, claim_txid"
)
FIRST_REQUEST_SEQUENCE = 2  # RS-001: first client message after the confirm
MAX_REQUESTS_PER_SESSION = 16  # further requests are refused unanswered
DEFAULT_MAX_SESSIONS = 1000  # live (unexpired) sessions
DEFAULT_MAX_TOMBSTONES = 1_000_000  # permanent expired-session IDs (~100 bytes each)
DEFAULT_MAX_ACTIVE_RESERVATIONS = 4  # unreleased firm offers and swaps (financial exposure)
DEFAULT_NEW_SESSIONS_PER_MINUTE = 60  # global admission rate; known sessions exempt
MAX_DOCUMENT_BYTES = 65_536
MAX_CHALLENGE_TRIES = 4
MAX_LABEL_CHARS = 256
HEX32 = re.compile(r"[0-9a-f]{64}\Z")
LOCK_SUFFIX = ".owner-lock"
MAX_OUTER_EVENT_BYTES = 128 * 1024
COMPRESSED_KEY_BYTES = 33
KEY_RECORD_KIND = "rill-provider/live-session-key/v1"
EPOCH_RECORD_KIND = "rill-provider/epoch-inbox-key/v1"
MAX_ADVERTISED_EPOCHS = 4  # RS-005 epoch_inbox_xonly_keys maximum
MAX_INSPECTION_PAGE = 1000
# LOST is terminal for a CLAIMING swap whose contract output was spent on
# the confirmed chain by something other than a recorded claim attempt (the
# client's refund) and stayed spent for refund_resolution_confirmations
# blocks. outpoint_spent_height/block are the tip height and hash at which
# that spend was first observed (the anchor must stay on the active chain);
# NULL while the output is unspent or a recorded attempt is mined.
# funding_* is the signed LN to BTC funding the provider broadcast and
# refund_* its refund spend (RS-004).
SWAPS_SCHEMA = (
    "CREATE TABLE swaps (session_id TEXT PRIMARY KEY, contract_hash TEXT NOT NULL UNIQUE, "
    "terms_offer BLOB NOT NULL, terms_accept BLOB NOT NULL, state TEXT NOT NULL CHECK "
    "(state IN ('ACCEPTED', 'FUNDING_SEEN', 'PAYING', 'PAID', 'FAILED', 'CLAIMING', "
    "'CLAIMED', 'LOST', 'LN_HELD', 'FUNDING_SENT', 'FUNDED', 'SETTLED', 'REFUNDING', "
    "'REFUNDED', 'ABORTED')), funding_binding BLOB, preimage TEXT, claim_txid TEXT, "
    "claim_tx BLOB, updated_at INTEGER NOT NULL, outpoint_spent_height INTEGER "
    "CHECK (outpoint_spent_height > 0), outpoint_spent_block TEXT "
    "CHECK ((outpoint_spent_block IS NULL) = (outpoint_spent_height IS NULL)), "
    "funding_txid TEXT, funding_vout INTEGER CHECK (funding_vout >= 0), funding_tx BLOB, "
    "refund_txid TEXT, refund_tx BLOB, "
    "CHECK ((funding_txid IS NULL) = (funding_tx IS NULL) AND "
    "(funding_txid IS NULL) = (funding_vout IS NULL)), "
    "CHECK ((refund_txid IS NULL) = (refund_tx IS NULL)))"
)
PAYMENT_DISPATCH_SCHEMA = (
    "CREATE TABLE payment_dispatch (session_id TEXT PRIMARY KEY, "
    "payment_hash TEXT NOT NULL UNIQUE, "
    "state TEXT NOT NULL CHECK (state IN ('UNSENT', 'SUBMITTED')), request BLOB)"
)
EPOCH_ADMISSION_SCHEMA = (
    "CREATE TABLE epoch_admissions (session_id TEXT PRIMARY KEY, epoch_key TEXT NOT NULL, "
    "retire_after INTEGER NOT NULL, expired INTEGER NOT NULL CHECK (expired IN (0, 1)))"
)
EPOCH_RETIREMENT_SCHEMA = (
    "CREATE TABLE epoch_retirement (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
    "retired_through INTEGER NOT NULL CHECK (retired_through >= 0))"
)
EPOCH_KEY_HISTORY_SCHEMA = "CREATE TABLE epoch_key_history (epoch_key TEXT PRIMARY KEY)"
# One row per payment-hash reservation, kept forever. Only RELEASED rows stop
# counting against financial capacity, and only with versioned closure evidence.
ECONOMIC_RESERVATION_SCHEMA = (
    "CREATE TABLE economic_reservations (payment_hash TEXT PRIMARY KEY, "
    "session_id TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN "
    "('UNSENT', 'DISPATCHED', 'RELEASED')), release_evidence BLOB, "
    "CHECK ((state = 'RELEASED') = (release_evidence IS NOT NULL)))"
)
# Every signed claim a CLAIMING swap may have broadcast, kept forever: any of
# them can confirm. swaps.claim_tx/claim_txid mirror the latest attempt until
# CLAIMED, then the attempt that confirmed. A NULL fee or height is not yet
# validated or observed; neither authorizes a bump.
CLAIM_ATTEMPT_SCHEMA = (
    "CREATE TABLE claim_attempts (session_id TEXT NOT NULL, "
    "attempt INTEGER NOT NULL CHECK (attempt >= 0), txid TEXT NOT NULL UNIQUE, "
    "raw BLOB NOT NULL, fee_sat INTEGER CHECK (fee_sat >= 0), "
    "first_seen_height INTEGER CHECK (first_seen_height > 0), "
    "PRIMARY KEY (session_id, attempt))"
)
COOPERATION_ATTEMPT_SCHEMA = (
    "CREATE TABLE cooperation_attempts (cooperation_id BLOB PRIMARY KEY NOT NULL CHECK "
    "(typeof(cooperation_id)='blob' AND length(cooperation_id)=32), session_id TEXT NOT NULL, "
    "owner_generation INTEGER NOT NULL CHECK (typeof(owner_generation)='integer' AND "
    "owner_generation > 0), binding BLOB NOT NULL "
    "CHECK (typeof(binding)='blob' AND length(binding) BETWEEN 1 AND 65536), "
    "created_at INTEGER NOT NULL CHECK (typeof(created_at)='integer' AND created_at >= 0), "
    "deadline_at INTEGER NOT NULL CHECK (typeof(deadline_at)='integer' AND "
    "deadline_at > created_at), state TEXT NOT NULL CHECK "
    "(state IN ('BURNED','NONCE_READY','SIGNING','COMPLETE','ABANDONED')), "
    "local_nonce BLOB CHECK (local_nonce IS NULL OR (typeof(local_nonce)='blob' AND "
    "length(local_nonce)=66)), peer_nonce BLOB CHECK (peer_nonce IS NULL OR "
    "(typeof(peer_nonce)='blob' AND length(peer_nonce)=66)), partial_signature BLOB CHECK "
    "(partial_signature IS NULL OR (typeof(partial_signature)='blob' AND "
    "length(partial_signature)=32)), nonce_response_id TEXT, partial_response_id TEXT, "
    "CHECK ((local_nonce IS NULL)=(nonce_response_id IS NULL)), "
    "CHECK ((partial_signature IS NULL)=(partial_response_id IS NULL)), "
    "CHECK ((state='BURNED' AND local_nonce IS NULL AND peer_nonce IS NULL) OR "
    "(state='NONCE_READY' AND local_nonce IS NOT NULL AND peer_nonce IS NULL) OR "
    "(state='SIGNING' AND local_nonce IS NOT NULL AND peer_nonce IS NOT NULL) OR "
    "(state='COMPLETE' AND local_nonce IS NOT NULL AND peer_nonce IS NOT NULL AND "
    "partial_signature IS NOT NULL) OR "
    "(state='ABANDONED' AND partial_signature IS NULL)), "
    "CHECK (state='COMPLETE' OR partial_signature IS NULL))"
)
# Arbitration is distinct from nonce custody: an affirmative admission row
# alone grants no waiting period or signing authority. A complete presigned
# unilateral bundle is required before any future runtime can open a window.
CLAIM_ARBITRATION_SCHEMA = (
    "CREATE TABLE claim_arbitration (session_id TEXT PRIMARY KEY NOT NULL, "
    "contract_hash TEXT NOT NULL CHECK (typeof(contract_hash)='text' AND "
    "length(contract_hash)=64), version INTEGER NOT NULL CHECK "
    "(typeof(version)='integer' AND version=1), state TEXT NOT NULL CHECK "
    "(state IN ('ADMITTED','WAITING','CLOSED')), owner_generation INTEGER "
    "CHECK (owner_generation IS NULL OR (typeof(owner_generation)='integer' AND "
    "owner_generation>0)), prepared_at INTEGER CHECK (prepared_at IS NULL OR "
    "(typeof(prepared_at)='integer' AND prepared_at>=0)), deadline_at INTEGER "
    "CHECK (deadline_at IS NULL OR (typeof(deadline_at)='integer' AND "
    "deadline_at>prepared_at)), deadline_height INTEGER CHECK "
    "(deadline_height IS NULL OR (typeof(deadline_height)='integer' AND "
    "deadline_height>0)), fallback_raw BLOB CHECK (fallback_raw IS NULL OR "
    "(typeof(fallback_raw)='blob' AND length(fallback_raw)>0)), fallback_txid TEXT "
    "CHECK (fallback_txid IS NULL OR (typeof(fallback_txid)='text' AND "
    "length(fallback_txid)=64)), fallback_fee_sat INTEGER CHECK "
    "(fallback_fee_sat IS NULL OR (typeof(fallback_fee_sat)='integer' AND "
    "fallback_fee_sat>=0)), cooperative_raw BLOB CHECK (cooperative_raw IS NULL OR "
    "(typeof(cooperative_raw)='blob' AND length(cooperative_raw)>0)), "
    "cooperative_txid TEXT CHECK (cooperative_txid IS NULL OR "
    "(typeof(cooperative_txid)='text' AND length(cooperative_txid)=64)), "
    "CHECK ((owner_generation IS NULL)=(prepared_at IS NULL) AND "
    "(owner_generation IS NULL)=(deadline_at IS NULL) AND "
    "(owner_generation IS NULL)=(deadline_height IS NULL) AND "
    "(owner_generation IS NULL)=(fallback_raw IS NULL) AND "
    "(owner_generation IS NULL)=(fallback_txid IS NULL) AND "
    "(owner_generation IS NULL)=(fallback_fee_sat IS NULL)), "
    "CHECK ((cooperative_raw IS NULL)=(cooperative_txid IS NULL) AND "
    "(cooperative_raw IS NULL OR owner_generation IS NOT NULL)), "
    "CHECK ((state='ADMITTED' AND owner_generation IS NULL AND "
    "cooperative_raw IS NULL) OR (state='WAITING' AND owner_generation IS NOT NULL "
    "AND cooperative_raw IS NULL) OR state='CLOSED'))"
)
REVERSE_PREIMAGE_EVIDENCE_SCHEMA = (
    "CREATE TABLE reverse_preimage_evidence (session_id TEXT PRIMARY KEY NOT NULL, "
    "document BLOB NOT NULL CHECK (typeof(document)='blob' AND "
    "length(document) BETWEEN 1 AND 65536), received_at INTEGER NOT NULL CHECK "
    "(typeof(received_at)='integer' AND received_at>=0))"
)
# RS-010: EVM HTLC evidence for erc20-to-ln and ln-to-erc20 swaps. A row
# exists for every EVM-profile swap from acceptance, and its presence routes
# the swap to the EVM lifecycle (``evm_settlement_work``) instead of the
# Bitcoin one. lock_* is the counterparty's observed ``Lockup`` log (forward
# swaps); provider_tx_hash is our own lock (reverse swaps); claim_tx_hash is
# our claim (forward, with its signed bytes) or the observed client claim
# (reverse, hash only); refund_tx_hash is our refund (reverse). Signed bytes
# are retained so an interrupted broadcast can be repeated after a restart.
# Hashes are lowercase hex without ``0x``.
EVM_SWAP_SCHEMA = (
    "CREATE TABLE evm_swaps (session_id TEXT PRIMARY KEY NOT NULL, "
    "lock_tx_hash TEXT, lock_log_index INTEGER CHECK (lock_log_index >= 0), "
    "lock_block INTEGER CHECK (lock_block >= 0), provider_tx_hash TEXT, provider_tx BLOB, "
    "claim_tx_hash TEXT, claim_tx BLOB, refund_tx_hash TEXT, refund_tx BLOB, "
    "CHECK ((lock_tx_hash IS NULL) = (lock_log_index IS NULL) AND "
    "(lock_tx_hash IS NULL) = (lock_block IS NULL)), "
    "CHECK ((provider_tx_hash IS NULL) = (provider_tx IS NULL)), "
    "CHECK ((refund_tx_hash IS NULL) = (refund_tx IS NULL)))"
)
REVERSE_SPEND_SCAN_SCHEMA = (
    "CREATE TABLE reverse_spend_scans (session_id TEXT PRIMARY KEY NOT NULL "
    "REFERENCES swaps(session_id), "
    "floor_height INTEGER NOT NULL CHECK (typeof(floor_height)='integer' AND floor_height>=0), "
    "floor_block TEXT NOT NULL CHECK (length(floor_block)=64 "
    "AND floor_block NOT GLOB '*[^0-9a-f]*'), "
    "cursor_height INTEGER NOT NULL CHECK (typeof(cursor_height)='integer' "
    "AND cursor_height>=floor_height), "
    "cursor_block TEXT NOT NULL CHECK (length(cursor_block)=64 "
    "AND cursor_block NOT GLOB '*[^0-9a-f]*'), "
    "CHECK (cursor_height!=floor_height OR cursor_block=floor_block))"
)
# Append-only per-swap accounting, written in each event's own transaction
# (swap_accounting.py). Only ``completed`` revenue may be negative (a rebate).
SWAP_LEDGER_SCHEMA = (
    "CREATE TABLE swap_ledger (entry_id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "session_id TEXT NOT NULL, "
    "recorded_at INTEGER NOT NULL CHECK (typeof(recorded_at)='integer'), "
    "kind TEXT NOT NULL CHECK (kind IN ("
    + ", ".join(f"'{kind}'" for kind in LEDGER_KINDS)
    + ")), amount INTEGER CHECK (amount IS NULL OR (typeof(amount)='integer' "
    f"AND (amount>=0 OR kind='{COMPLETED}'))), "
    "unit TEXT CHECK (unit IS NULL OR unit IN ("
    + ", ".join(f"'{unit}'" for unit in LEDGER_UNITS)
    + ")), CHECK ((amount IS NULL) = (unit IS NULL)))"
)
SCHEMA = (
    (
        "CREATE TABLE meta (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
        "schema_version INTEGER NOT NULL, store_uuid TEXT NOT NULL, network_jcs BLOB NOT NULL, "
        "provider_identity TEXT NOT NULL, policy_jcs BLOB NOT NULL, authority_jcs BLOB NOT NULL, "
        "db_inode INTEGER NOT NULL, lock_inode INTEGER NOT NULL, generation INTEGER NOT NULL, "
        "custody_recipient TEXT NOT NULL)"
    ),
    (
        "CREATE TABLE sessions (session_id TEXT PRIMARY KEY, init_bytes BLOB NOT NULL, "
        "init_message_id TEXT NOT NULL, client_key TEXT NOT NULL, "
        "provider_challenge TEXT NOT NULL UNIQUE, provider_session_key TEXT NOT NULL UNIQUE, "
        "session_secret_age BLOB NOT NULL, key_state TEXT NOT NULL CHECK "
        "(key_state IN ('LIVE', 'RETIRED')), accept_bytes BLOB, accept_message_id TEXT, "
        "transcript_digest TEXT, phase TEXT NOT NULL CHECK "
        "(phase IN ('RESERVED', 'ACCEPT_COMMITTED', 'CONFIRMED', 'ACCEPTED')), "
        "blocked INTEGER NOT NULL CHECK (blocked IN (0, 1)), revision INTEGER NOT NULL, "
        "next_client_seq INTEGER NOT NULL, next_provider_seq INTEGER NOT NULL, "
        "active_at INTEGER NOT NULL)"
    ),
    (
        "CREATE TABLE inbox (session_id TEXT NOT NULL, sender_key TEXT NOT NULL, "
        "message_id TEXT NOT NULL, seq INTEGER NOT NULL, unsigned_digest TEXT NOT NULL, "
        "canonical_bytes BLOB NOT NULL, admitted_revision INTEGER NOT NULL, "
        "PRIMARY KEY (session_id, sender_key, message_id), "
        "UNIQUE (session_id, sender_key, seq))"
    ),
    (
        "CREATE TABLE outbox (message_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, "
        "seq INTEGER NOT NULL, in_reply_to TEXT, canonical_bytes BLOB NOT NULL, "
        "committed_revision INTEGER NOT NULL, delivery_state TEXT NOT NULL CHECK "
        "(delivery_state IN ('PENDING', 'ACKED', 'RECONCILED')), UNIQUE (session_id, seq))"
    ),
    (
        "CREATE TABLE conflicts (session_id TEXT NOT NULL, kind TEXT NOT NULL CHECK "
        "(kind IN ('init', 'confirm', 'request')), evidence_bytes BLOB NOT NULL, "
        "PRIMARY KEY (session_id, kind))"
    ),
    (
        "CREATE TABLE epochs (epoch_key TEXT PRIMARY KEY, secret_age BLOB NOT NULL, "
        "created_at INTEGER NOT NULL, retire_after INTEGER NOT NULL)"
    ),
    (
        "CREATE TABLE announcements (slot INTEGER PRIMARY KEY CHECK (slot = 1), "
        "created_at INTEGER NOT NULL)"
    ),
    (
        "CREATE TABLE contract_keys (session_id TEXT PRIMARY KEY, "
        "compressed_key TEXT NOT NULL UNIQUE, secret_age BLOB NOT NULL)"
    ),
    # Accepted contracts are never idle-expired (RS-003 acceptance).
    SWAPS_SCHEMA,
    # Never deleted: a payment hash is offered at most once, forever (RS-003).
    (
        "CREATE TABLE payment_hashes (payment_hash TEXT PRIMARY KEY, "
        "session_id TEXT NOT NULL, reserved_at INTEGER NOT NULL)"
    ),
    PAYMENT_DISPATCH_SCHEMA,
    EPOCH_ADMISSION_SCHEMA,
    EPOCH_RETIREMENT_SCHEMA,
    EPOCH_KEY_HISTORY_SCHEMA,
    ECONOMIC_RESERVATION_SCHEMA,
    CLAIM_ATTEMPT_SCHEMA,
    COOPERATION_ATTEMPT_SCHEMA,
    CLAIM_ARBITRATION_SCHEMA,
    REVERSE_PREIMAGE_EVIDENCE_SCHEMA,
    EVM_SWAP_SCHEMA,
    REVERSE_SPEND_SCAN_SCHEMA,
    SWAP_LEDGER_SCHEMA,
)
MAX_CLAIM_ATTEMPTS = 32
COOPERATION_BUDGET_SECONDS = 30
COOPERATION_OBSERVATION_MAX_AGE_SECONDS = 5
INDEXES = (
    "CREATE INDEX epoch_admissions_expiry ON epoch_admissions (expired, retire_after)",
    "CREATE INDEX economic_reservations_state ON economic_reservations (state, session_id)",
    (
        "CREATE UNIQUE INDEX cooperation_unfinished_session ON cooperation_attempts (session_id) "
        "WHERE state IN ('BURNED','NONCE_READY','SIGNING')"
    ),
    "CREATE INDEX swap_ledger_session ON swap_ledger (session_id)",
    "CREATE INDEX swap_ledger_time ON swap_ledger (recorded_at)",
)


@dataclass(frozen=True, slots=True)
class EpochInitiation:
    """Canonical init and authenticated recipient provenance from open_epoch_frame()."""

    document: bytes
    epoch_key: str


@dataclass(frozen=True, slots=True)
class MailboxWork:
    """One subscribed session mailbox and its RS-006 transport work terms."""

    mailbox_key: str
    declared_bits: int | None
    finished: bool
    # A delivery hint, not a change to this mailbox's proof-of-work identity.
    reserved_at: int | None = field(default=None, compare=False)


# Terminal across every profile (forward, reverse and EVM swaps share them).
FINISHED_SWAP_STATES = frozenset(EVM_TERMINAL_STATES)
REPLAY_ACTIVE_SWAP_STATES = frozenset(
    {
        "ACCEPTED",
        "FUNDING_SEEN",
        "PAYING",
        "PAID",
        "CLAIMING",
        "LN_HELD",
        "FUNDING_SENT",
        "FUNDED",
        "REFUNDING",
    }
)


def _declared_work(init_bytes: bytes) -> int | None:
    """Return the transport work an admitted init declared, or None.

    Admission refuses malformed declarations, so an unreadable one means
    damaged bytes; it is treated as undeclared, which never makes a session
    require work its client did not promise.
    """
    try:
        return transport_pow.requirement(json.loads(init_bytes)["payload"]["extensions"])
    except (ValueError, KeyError, TypeError):
        return None


class LiveSessionStoreError(ValueError):
    """No authoritative session fact was established; nothing may be exposed."""


class StaleOwnerError(LiveSessionStoreError):
    """The handle no longer owns the store; stop all exposure immediately."""


class SessionCapacityError(LiveSessionStoreError):
    """No new session fits; existing sessions and replays are unaffected."""


class SessionExpiredError(LiveSessionStoreError):
    """The session expired; its recorded result is final and keys are gone."""


class SessionBlockedError(LiveSessionStoreError):
    """Durable conflict evidence blocks new risk for this session."""


@dataclass(frozen=True, slots=True)
class AuthorityDeclaration:
    """Operator attestation of the deployment boundary this store relies on."""

    volume_label: str
    outside_restore_domain: bool
    single_host: bool

    def jcs(self) -> bytes:
        """Return canonical attestation bytes, refusing anything not explicit."""
        if not (
            type(self.volume_label) is str
            and 0 < len(self.volume_label) <= MAX_LABEL_CHARS
            and self.volume_label.isprintable()
            and self.outside_restore_domain is True
            and self.single_host is True
        ):
            raise LiveSessionStoreError("explicit authority attestation required")
        return canonicalize(
            {
                "volume_label": self.volume_label,
                "outside_restore_domain": True,
                "single_host": True,
            }
        )


@dataclass(frozen=True, slots=True)
class SessionReservation:
    """A reserved challenge; permits only building and committing one accept."""

    session_id: str
    init_message_id: str
    provider_challenge: str
    provider_session_key: str
    revision: int


@dataclass(frozen=True, slots=True)
class AcceptCommit:
    """Exact accept bytes durably committed; only now may they be published."""

    session_id: str
    message_id: str
    canonical_bytes: bytes
    transcript_digest: str
    revision: int


@dataclass(frozen=True, slots=True)
class _ReverseNegotiationOrigin:
    """Acquired-owner-local provenance, never payment or signing permission."""

    accept_document: bytes
    handshake_hash: str
    contract_hash: str | None = None
    acceptance_document: bytes | None = None


@dataclass(frozen=True, slots=True)
class _ReverseProposalAttempt:
    message_id: str
    unsigned_digest: str
    cooperation_id: str
    window: ReverseCooperationWindow | None


@dataclass(frozen=True, slots=True)
class _ReverseLiveProposalContext:
    """Original live read context, never debt, nonce, or signing permission."""

    terms: ContractTerms
    binding: FundingBinding
    window: ReverseCooperationWindow
    static_match: FundingBindingTransactionMatch
    plan: CooperativeClaimPlan


@dataclass(frozen=True, slots=True)
class _ReversePaidProposalEvidence:
    """Same-operation observations, not provenance or a signing capability.

    Only trusted runtime actually collecting the stronger original-invoice
    query and Core evidence can establish acquisition provenance and clock
    origin. Structural data and matching timestamps cannot prove either.
    Never serialize, reconstruct, or transfer this record to another operation.
    """

    operation: ReverseOperation
    context: _ReverseLiveProposalContext
    core: CooperativeClaimOutpoint
    policy: CooperativeFeePolicy
    invoice: BoundHoldInvoiceObservation
    started_at: float
    completed_at: float
    configured_floor_sat: int
    allow_regtest_fixed_fee: bool


@dataclass(frozen=True, slots=True)
class ReverseProposalAdmission:
    """Reservation receipt only, never settlement, nonce, or signing authority."""

    session_id: str
    message_id: str
    cooperation_id: str
    replay: bool


@dataclass(frozen=True, slots=True)
class ReversePreimageEvidenceReceipt:
    """Knowledge retained privately, not payment, debt, or current authority."""

    session_id: str
    message_id: str
    received_at: int
    replay: bool


@dataclass(frozen=True, slots=True)
class ConfirmAdmission:
    """Client confirmation admitted; grants no economic authority."""

    session_id: str
    message_id: str
    transcript_digest: str
    revision: int
    replay: bool


@dataclass(frozen=True, slots=True)
class RequestAnswer:
    """A client request admitted with its recorded, signed answer (not yet sent)."""

    session_id: str
    request_message_id: str
    response_message_id: str
    replay: bool


@dataclass(frozen=True, slots=True)
class CooperativeResultAdmission:
    """Durable peer disposition, never permission to produce our partial."""

    session_id: str
    message_id: str
    status: str
    replay: bool


@dataclass(frozen=True, slots=True)
class CooperativeClaimObservation:
    """Trusted runtime's fresh, mempool-aware claim sample, not a wire model.

    The store cannot independently acquire chain or LND facts. Trusted runtime
    must obtain these from its configured Core and payment backends, bound to
    one named tip immediately before invoking the signer. The engine coordinator
    constructs this only after fresh authenticated signed-result admission.
    This type must never be deserialized from a peer message.
    """

    network: NetworkIdentity
    funding_txid: str
    funding_vout: int
    funding_value_sat: int
    funding_script_pubkey: bytes
    tip_height: int
    tip_hash: str
    confirmations: int
    sampled_at: int
    mempool_unspent: bool
    fee_floor_sat: int


class EnvelopeSigner(Protocol):
    """BIP-340 signing, e.g. ``rill_crypto.Context``."""

    def schnorr_sign(self, secret_key: bytes, message: bytes, auxiliary_random: bytes) -> bytes:
        """Sign a 32-byte digest."""
        ...


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Session facts a responder may bind into its answer."""

    handshake_hash: str
    provider_contract_key: str  # compressed; fresh per session, sealed like the session key
    is_payment_hash_reserved: Callable[[str], bool]
    replied_to: Envelope | None = None  # our outbox message named by in_reply_to
    swap: SwapRecord | None = None
    # False when a new firm offer would exceed unreleased economic capacity.
    economic_capacity_available: bool = True
    # Whether both handshakes committed cooperative claims; new terms match it.
    cooperative: bool = False
    network_fees: bool = False
    # Rebates granted by open firm offers plus those paid in the last 24 h,
    # from this store alone. None (unknown) must grant no new rebate.
    rebates_committed_sat: int | None = None


@dataclass(frozen=True, slots=True)
class PricingCommitments:
    """What this store's open offers already commit, for balance-aware pricing."""

    open_volume_sat: int | None  # None: an open offer's volume was not measured
    rebates_committed_sat: int


@dataclass(frozen=True, slots=True)
class SwapRecord:
    """Durable accepted-swap state; byte fields are exact canonical envelopes."""

    session_id: str
    contract_hash: str
    terms_offer: bytes
    terms_accept: bytes
    state: str
    funding_binding: bytes | None
    preimage: str | None
    claim_txid: str | None


@dataclass(frozen=True, slots=True)
class EvmSettlementItem:
    """One accepted EVM-profile swap (RS-010) the EVM settlement engine still has to move."""

    session_id: str
    state: str
    blocked: bool
    terms_offer: bytes
    invoice: str  # erc20-to-ln: the client's bolt11 from its firm request; "" for reverse
    preimage: str | None
    dispatch_state: str  # payment_dispatch state or UNKNOWN (forward only)
    payer: PaymentAuthority | None
    lock_tx_hash: str | None
    lock_log_index: int | None
    lock_block: int | None
    provider_tx_hash: str | None
    provider_tx: bytes | None
    claim_tx_hash: str | None
    claim_tx: bytes | None
    refund_tx_hash: str | None
    refund_tx: bytes | None

    def terms(self) -> EvmContractTerms:
        """Return the signed EVM terms this swap was accepted under."""
        return _evm_offer_terms(self.terms_offer)


@dataclass(frozen=True, slots=True)
class SettlementItem:
    """One funded swap the settlement engine still has to move forward."""

    session_id: str
    state: str
    blocked: bool
    terms_offer: bytes
    funding_binding: bytes | None  # None before the client's binding (or for LN to BTC)
    invoice: str
    preimage: str | None
    claim_tx: bytes | None
    claim_txid: str | None
    payment_dispatch: str = "UNKNOWN"
    # Provenance of a committed version 1 dispatch record, never send permission.
    payment_payer: PaymentAuthority | None = None
    # Tip (height, hash) at which the contract output was first seen spent by
    # a non-attempt; the hash anchors the wait to the active chain.
    outpoint_spent_height: int | None = None
    outpoint_spent_block: str | None = None
    # LN to BTC (RS-004): the provider's own funding and refund.
    funding_txid: str | None = None
    funding_vout: int | None = None
    funding_tx: bytes | None = None
    refund_txid: str | None = None
    refund_tx: bytes | None = None


@dataclass(frozen=True, slots=True)
class ClaimAttempt:
    """One recorded signed claim; ``None`` fee or height is not yet observed."""

    attempt: int
    txid: str
    raw: bytes
    fee_sat: int | None
    first_seen_height: int | None


@dataclass(frozen=True, slots=True)
class FundingConflict:
    """Proof that a paid BTC to LN deposit that never confirmed can no longer confirm.

    ``conflict_txid``, a transaction other than the deposit, spends the
    deposit's own input ``conflict_input_txid:conflict_input_vout`` in the
    active-chain block ``conflict_block`` at ``conflict_height``, at least
    ``required_confirmations`` deep at ``tip_height``.
    """

    funding_txid: str
    conflict_txid: str
    conflict_input_txid: str
    conflict_input_vout: int
    conflict_height: int
    conflict_block: str
    tip_height: int
    required_confirmations: int


@dataclass(frozen=True, slots=True)
class RecordedUnilateralClaim:
    """Affirmatively selected attempt whose exact bytes can be redispatched."""

    session_id: str
    contract_hash: str
    raw: bytes
    txid: str
    fee_sat: int | None
    terms_offer: bytes
    funding_binding: bytes
    preimage: str


@dataclass(frozen=True, slots=True)
class PreparedFallback:
    """Persisted claim candidate; enumeration alone never authorizes spending."""

    session_id: str
    contract_hash: str
    state: str
    owner_generation: int
    deadline_at: int
    deadline_height: int
    raw: bytes
    txid: str
    fee_sat: int
    terms_offer: bytes
    funding_binding: bytes
    preimage: str


@dataclass(frozen=True, slots=True, repr=False)
class CooperativeCompletionCandidate:
    """Non-authorizing read snapshot for independent completion preflight.

    No native handle, nonce, or peer partial is exposed. The runtime must
    validate the fallback and exact burned plan within its original evidence
    budget; the atomic completion entry point rechecks all live authority.
    """

    fallback: PreparedFallback
    burned_binding: bytes


@dataclass(frozen=True, slots=True)
class ReadinessChallenge:
    """A newly issued request, not an admission or restartable authority."""

    session_id: str
    request_id: str
    challenge: str
    contract_hash: str
    owner_generation: int
    started_at: int
    deadline_at: int
    deadline_height: int


@dataclass(frozen=True, slots=True)
class CooperativeWinner:
    """Affirmative, selected key-path bytes with the accepted authority snapshot."""

    session_id: str
    contract_hash: str
    state: str
    raw: bytes
    txid: str
    terms_offer: bytes
    funding_binding: bytes
    preimage: str


@dataclass(frozen=True, slots=True)
class SwapInspection:
    """Offline custody summary, never live chain evidence or dispatch authority."""

    session_id: str
    contract_hash: str
    state: str
    session_present: bool
    blocked: bool | None
    dispatch_state: str
    dispatch_recorded: bool
    funding_binding_recorded: bool
    preimage_recorded: bool
    claim_recorded: bool
    claim_txid: str | None


@dataclass(frozen=True, slots=True)
class SwapInspectionPage:
    """Bounded keyset page; cursor does not claim a snapshot across invocations."""

    swaps: tuple[SwapInspection, ...]
    next_after: str | None


class StaleSwapError(LiveSessionStoreError):
    """The swap is no longer in the state the caller observed."""


@dataclass(frozen=True, slots=True)
class AcceptSwap:
    """Effect: record acceptance of the replied-to terms offer."""

    contract_hash: str


@dataclass(frozen=True, slots=True)
class BindFunding:
    """Effect: record the client's funding binding for the accepted swap."""


@dataclass(frozen=True, slots=True)
class Answer:
    """A responder's answer; ``payment_hash`` is reserved forever with it."""

    message_type: str
    payload: dict[str, Any]
    payment_hash: str | None = None
    contract_hash: str | None = None  # envelope binding, e.g. for terms_offer
    effect: AcceptSwap | BindFunding | None = None
    # The service-fee rebate a firm terms_offer grants (sat); zero otherwise.
    rebate_sat: int = 0


if TYPE_CHECKING:
    from collections.abc import Callable

    # Policy: (request, earlier admitted requests, session context) -> answer.
    Responder = Callable[[Envelope, tuple[Envelope, ...], RequestContext], Answer]


@dataclass(frozen=True, slots=True)
class OutboxEntry:
    """Committed provider bytes awaiting application acknowledgment."""

    message_id: str
    session_id: str
    canonical_bytes: bytes


def _canonical_envelope(document: bytes) -> Envelope:
    if type(document) is not bytes or not 0 < len(document) <= MAX_DOCUMENT_BYTES:
        raise LiveSessionStoreError("envelope size unsupported")
    if canonicalize(parse_json_strict(document, max_bytes=MAX_DOCUMENT_BYTES)) != document:
        raise LiveSessionStoreError("canonical envelope bytes required")
    return parse_model_json(Envelope, document)


def _stable_file(directory: int, name: str, *, create: bool) -> int:
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor = os.open(name, flags, 0o600, dir_fd=directory)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise LiveSessionStoreError("store path is not a regular file")
    return descriptor


class LiveSessionStore:
    """Single owner of authoritative handshake sessions for one provider."""

    def __init__(  # noqa: PLR0913 - explicit owned resources
        self,
        *,
        path: Path,
        lock_fd: int,
        connection: sqlite3.Connection,
        generation: int,
        network: NetworkIdentity,
        identity: str,
        policy: HandshakePolicy,
        crypto: EnvelopeSchnorrVerifier,
        store_uuid: str,
        custody_identity: x25519.Identity,
        public_keys: CustodyPublicKeys,
        max_sessions: int,
        max_tombstones: int,
        new_sessions_per_minute: int,
        max_active_reservations: int,
    ) -> None:
        """Use provision() or acquire(); never construct directly."""
        self.path = path
        self._lock_fd: int | None = lock_fd
        self._owner_pins = 0
        self._retained_lock_fd: int | None = None
        self._reverse_operations: ReverseOperations | None = None
        self._reverse_negotiations: dict[str, _ReverseNegotiationOrigin] = {}
        self._reverse_proposals: dict[str, _ReverseProposalAttempt] = {}
        self._connection = connection
        self._generation = generation
        self._network = network
        self._identity = identity
        self._policy = policy
        self._crypto = crypto
        self._store_uuid = store_uuid
        self._custody_identity = custody_identity
        self._public_keys = public_keys
        self._max_sessions = max_sessions
        self._max_tombstones = max_tombstones
        self._max_active_reservations = max_active_reservations
        self._admission = _TokenBucket(new_sessions_per_minute)
        self._pid = os.getpid()
        # Allocation IDs outlive failures for this owner. Native handles and
        # the secret nonce itself never cross a process or storage boundary.
        self._allocated_cooperation_ids: set[bytes] = set()
        self._cooperation_handles: dict[bytes, MusigAttempt] = {}

    @staticmethod
    def provision(  # noqa: PLR0913 - independent provisioning facts explicit
        path: str | PathLike[str],
        network: NetworkIdentity,
        provider_identity: str,
        policy: HandshakePolicy,
        authority: AuthorityDeclaration,
        *,
        custody_recipient: str,
    ) -> None:
        """Explicitly create a new empty store and owner lock; never overwrite.

        Session secrets are age-encrypted to ``custody_recipient``. Its identity
        must be kept outside this volume's images, or encryption adds nothing.
        """
        network_jcs, identity = _expected(network, provider_identity)
        recipient = _recipient(custody_recipient)
        policy_jcs = _epoch_policy_bytes(policy)
        authority_jcs = authority.jcs()
        location = Path(path).absolute()
        directory = os.open(location.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            lock_fd = _stable_file(directory, location.name + LOCK_SUFFIX, create=True)
            try:
                db_fd = _stable_file(directory, location.name, create=True)
                db_inode = os.fstat(db_fd).st_ino
                os.close(db_fd)
                lock_inode = os.fstat(lock_fd).st_ino
                os.fsync(lock_fd)
            finally:
                os.close(lock_fd)
            connection = sqlite3.connect(
                location.as_uri() + "?mode=rw", uri=True, isolation_level=None
            )
            try:
                _configure(connection)
                connection.execute("BEGIN IMMEDIATE")
                for statement in (*SCHEMA, *INDEXES):
                    connection.execute(statement)
                connection.execute("INSERT INTO epoch_retirement VALUES (1, 0)")
                connection.execute(
                    "INSERT INTO meta VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                    (
                        SCHEMA_VERSION,
                        str(uuid.uuid4()),
                        network_jcs,
                        identity,
                        policy_jcs,
                        authority_jcs,
                        db_inode,
                        lock_inode,
                        recipient,
                    ),
                )
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                connection.execute("COMMIT")
            finally:
                connection.close()
            os.fsync(directory)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - partial files are left for the operator
            raise LiveSessionStoreError("live session store provisioning refused") from None
        finally:
            os.close(directory)

    @classmethod
    def acquire(  # noqa: PLR0912, PLR0913, PLR0915 - independent custody guards explicit
        cls,
        path: str | PathLike[str],
        network: NetworkIdentity,
        provider_identity: str,
        policy: HandshakePolicy,
        *,
        crypto: EnvelopeSchnorrVerifier,
        custody_identity: str,
        public_keys: CustodyPublicKeys,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        max_tombstones: int = DEFAULT_MAX_TOMBSTONES,
        new_sessions_per_minute: int = DEFAULT_NEW_SESSIONS_PER_MINUTE,
        max_active_reservations: int = DEFAULT_MAX_ACTIVE_RESERVATIONS,
    ) -> Self:
        """Take lifetime exclusive ownership; refuse any unknown or copied state.

        ``max_sessions`` caps pre-acceptance sessions, which ``expire_idle``
        reclaims. ``max_active_reservations`` caps unreleased economic
        reservations (firm offers and accepted swaps); only evidenced closure
        releases one. A store of any other schema version is refused with its
        contents unchanged: there is no upgrade path.
        """
        if not all(
            type(limit) is int and limit >= 1
            for limit in (
                max_sessions,
                max_tombstones,
                new_sessions_per_minute,
                max_active_reservations,
            )
        ):
            raise LiveSessionStoreError("session capacity unsupported")
        network_jcs, identity = _expected(network, provider_identity)
        try:
            unlocking = x25519.Identity.from_str(custody_identity)
        except Exception:  # noqa: BLE001 - never echo credential material
            raise LiveSessionStoreError("custody identity malformed") from None
        policy_jcs = _epoch_policy_bytes(policy)
        location = Path(path).absolute()
        lock_fd = -1
        connection: sqlite3.Connection | None = None
        try:
            directory = os.open(location.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                lock_fd = _stable_file(directory, location.name + LOCK_SUFFIX, create=False)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise LiveSessionStoreError("store owned by another process") from None
                db_fd = _stable_file(directory, location.name, create=False)
                db_inode = os.fstat(db_fd).st_ino
                os.close(db_fd)
            finally:
                os.close(directory)
            connection = sqlite3.connect(
                location.as_uri() + "?mode=rw", uri=True, isolation_level=None
            )
            connection.execute("PRAGMA busy_timeout=5000")
            _check_schema(connection)
            _configure(connection)
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT schema_version, network_jcs, provider_identity, policy_jcs, "
                "db_inode, lock_inode, generation, store_uuid, authority_jcs, custody_recipient "
                "FROM meta"
            ).fetchall()
            if len(row) != 1 or row[0][:4] != (SCHEMA_VERSION, network_jcs, identity, policy_jcs):
                raise LiveSessionStoreError("store namespace or policy mismatch")  # noqa: TRY301
            _check_provisioning(row[0][7], row[0][8])
            if row[0][9] != str(unlocking.to_public()):
                raise LiveSessionStoreError("custody identity does not match store")  # noqa: TRY301
            if row[0][4:6] != (db_inode, os.fstat(lock_fd).st_ino):
                raise LiveSessionStoreError(  # noqa: TRY301 - copied or restored file
                    "store files are not the provisioned authoritative copy"
                )
            _epoch_watermark(connection)
            if connection.execute(
                "SELECT 1 FROM epochs e LEFT JOIN epoch_key_history h "
                "ON h.epoch_key=e.epoch_key WHERE h.epoch_key IS NULL LIMIT 1"
            ).fetchone():
                raise LiveSessionStoreError("epoch key history unavailable")  # noqa: TRY301
            # Native one-shot nonce handles never survive process ownership.
            # Abandon every unfinished burn before this generation is usable;
            # absence of a live handle never authorizes recreating one.
            # A signed readiness request is historical evidence, not a live
            # token. This prefilter avoids loading an ordinary outbox backlog;
            # only the parsed exact action is reconciled on reacquisition.
            for request_id, document in connection.execute(
                "SELECT message_id,canonical_bytes FROM outbox WHERE delivery_state='PENDING' "
                "AND instr(canonical_bytes,?)>0",
                (b'"action":"cooperative_claim_ready"',),
            ).fetchall():
                try:
                    outgoing = _canonical_envelope(document)
                except Exception:  # noqa: BLE001 - unrelated malformed outbox needs its own review
                    logging.getLogger(__name__).warning(
                        "pending outbox envelope malformed; retained for operator review"
                    )
                    continue
                if (
                    outgoing.message_type == "action_request"
                    and outgoing.payload.get("action") == "cooperative_claim_ready"
                ):
                    connection.execute(
                        "UPDATE outbox SET delivery_state='RECONCILED' "
                        "WHERE message_id=? AND delivery_state='PENDING'",
                        (request_id,),
                    )
            connection.execute(
                "UPDATE outbox SET delivery_state='RECONCILED' "
                "WHERE delivery_state='PENDING' AND EXISTS "
                "(SELECT 1 FROM cooperation_attempts a "
                "JOIN claim_arbitration c ON c.session_id=a.session_id "
                "WHERE c.state IN ('WAITING','CLOSED') "
                "AND c.owner_generation=a.owner_generation "
                "AND a.session_id=outbox.session_id "
                "AND a.nonce_response_id=outbox.message_id "
                "AND a.state IN ('BURNED','NONCE_READY','SIGNING'))"
            )
            connection.execute(
                "UPDATE cooperation_attempts SET state='ABANDONED' "
                "WHERE state IN ('BURNED','NONCE_READY','SIGNING')"
            )
            # No process-local deadline worker or native handle survives owner
            # change. Closing eligibility does not itself dispatch or spend.
            connection.execute("UPDATE claim_arbitration SET state='CLOSED' WHERE state='WAITING'")
            generation = row[0][6] + 1
            connection.execute("UPDATE meta SET generation=?", (generation,))
            connection.execute("COMMIT")
            owned = cls(
                path=location,
                lock_fd=lock_fd,
                connection=connection,
                generation=generation,
                network=NetworkIdentity.model_validate_json(network_jcs, strict=True),
                identity=identity,
                policy=policy,
                crypto=crypto,
                store_uuid=row[0][7],
                custody_identity=unlocking,
                public_keys=public_keys,
                max_sessions=max_sessions,
                max_tombstones=max_tombstones,
                new_sessions_per_minute=new_sessions_per_minute,
                max_active_reservations=max_active_reservations,
            )
        except LiveSessionStoreError:
            _discard(connection, lock_fd)
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            _discard(connection, lock_fd)
            raise LiveSessionStoreError("live session store unavailable") from None
        return owned

    def close(self) -> None:
        """Fence the handle immediately; pinned physical exclusion ends later."""
        lock_fd, self._lock_fd = self._lock_fd, None
        self._reverse_negotiations.clear()
        for proposal in self._reverse_proposals.values():
            if proposal.window is not None:
                proposal.window.abandon()
        self._reverse_proposals.clear()
        if os.getpid() != self._pid:
            # Inherited across fork: never touch the parent's SQLite connection.
            # Closing our descriptor copy does not release the parent's flock.
            retained, self._retained_lock_fd = self._retained_lock_fd, None
            self._owner_pins = 0
            for inherited in (lock_fd, retained):
                if inherited is not None:
                    os.close(inherited)
            return
        if lock_fd is not None and self._owner_pins:
            # Transfer before native/SQLite cleanup, which may raise or reenter.
            self._retained_lock_fd, lock_fd = lock_fd, None
        handles, self._cooperation_handles = self._cooperation_handles, {}
        try:
            for attempt in handles.values():
                attempt.close()
        finally:
            _discard(self._connection, -1 if lock_fd is None else lock_fd)

    @contextmanager
    def retain_owner(self) -> Iterator[None]:
        """Pin physical exclusion, not usable authority, on the owning thread.

        External economic RPC workers must not access SQLite or native handles,
        which close() still destroys immediately. Their caller must retain this
        pin until actual execution finishes, including cancellation drainage.
        No new pin or effect is permitted after logical closure. This in-memory
        mechanism neither resumes cooperation nor protects against process death.
        """
        if os.getpid() != self._pid:
            raise StaleOwnerError("store handle inherited across fork; reacquire")
        if self._lock_fd is None:
            raise StaleOwnerError("store handle closed")
        self._owner_pins += 1
        try:
            yield
        finally:
            # Do not return in a forked child: that suppresses an exception
            # thrown through this generator's context-manager exit.
            if os.getpid() == self._pid:
                self._owner_pins -= 1
                if self._owner_pins == 0:
                    retained, self._retained_lock_fd = self._retained_lock_fd, None
                    if retained is not None:
                        os.close(retained)

    def __enter__(self) -> Self:
        """Own the store for the block."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Release ownership."""
        self.close()

    @property
    def generation(self) -> int:
        """Owner generation; increases on every acquire."""
        return self._generation

    @property
    def owner_is_open(self) -> bool:
        """Local lifecycle fence only, not generation or financial authority.

        External RPC queue guards may read this without using SQLite or crypto.
        Physical retention handles an effect already starting when close races
        the guard. Authoritative state still requires the normal store checks.
        """
        return os.getpid() == self._pid and self._lock_fd is not None

    @property
    def reverse_operations(self) -> ReverseOperations:
        """One reverse execution boundary shared by every caller of this owner."""
        if self._reverse_operations is None:
            # Lifecycle-local import avoids a store/token runtime import cycle.
            from rill_provider.reverse_operations import ReverseOperations  # noqa: PLC0415

            self._reverse_operations = ReverseOperations(self)
        return self._reverse_operations

    @property
    def network_identity(self) -> NetworkIdentity:
        """The pinned network authority of this acquired store."""
        return self._network

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        if os.getpid() != self._pid:
            raise StaleOwnerError("store handle inherited across fork; reacquire")
        if self._lock_fd is None:
            raise StaleOwnerError("store handle closed")
        connection = self._connection
        try:
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error:
            raise LiveSessionStoreError("live session store busy or unavailable") from None
        try:
            if connection.execute("SELECT generation FROM meta").fetchone() != (self._generation,):
                raise StaleOwnerError("store owned by a newer generation")  # noqa: TRY301
            yield connection
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                self.close()  # transaction state unknown; this handle may not continue
            raise
        try:
            connection.execute("COMMIT")
        except sqlite3.Error:
            # Outcome unknown: the write may or may not be durable. Release
            # ownership so the caller must reacquire and re-read the truth.
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            self.close()
            raise StaleOwnerError("commit outcome uncertain; ownership released") from None

    def burn_selected_cooperative_claim(  # noqa: PLR0913 - frozen live attempt identity
        self,
        session_id: str,
        cooperation_id: bytes,
        plan: CooperativeClaimPlan,
        *,
        now: Callable[[], int],
        tip_height: int,
        deadline_at: int,
        deadline_height: int,
    ) -> None:
        """Burn a live attempt only inside this owner's prepared window.

        The clock is refreshed under write authority; time spent acquiring
        SQLite or validating the plan never renews the retained deadline.
        """
        if type(tip_height) is not int:
            raise LiveSessionStoreError("cooperative window height unavailable")
        if not callable(now):
            raise LiveSessionStoreError("cooperative clock unavailable")
        self._burn_cooperative_claim_impl(
            session_id,
            cooperation_id,
            plan,
            now=_cooperative_now(0, now),
            deadline_at=deadline_at,
            deadline_height=deadline_height,
            window_tip=tip_height,
            clock=now,
        )

    def _burn_cooperative_claim(  # noqa: PLR0913 - retained internal primitive
        self,
        session_id: str,
        cooperation_id: bytes,
        plan: CooperativeClaimPlan,
        *,
        now: int,
        deadline_at: int,
        deadline_height: int,
    ) -> None:
        self._burn_cooperative_claim_impl(
            session_id,
            cooperation_id,
            plan,
            now=now,
            deadline_at=deadline_at,
            deadline_height=deadline_height,
            window_tip=None,
        )

    def _burn_cooperative_claim_impl(  # noqa: PLR0912, PLR0913, PLR0915 - one custody transition
        self,
        session_id: str,
        cooperation_id: bytes,
        plan: CooperativeClaimPlan,
        *,
        now: int,
        deadline_at: int,
        deadline_height: int,
        window_tip: int | None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        """Reserve one immutable ID before any native MuSig nonce allocation.

        INTERNAL ONLY. A committed burn is not permission to allocate a nonce,
        sign, send a message, or act on a supplied chain view. Future callers
        must independently validate current chain and Lightning facts and use
        separate durable response/outbox methods. Uncertain commits never
        return an authorization. Existing swaps without the signed feature
        cannot reach this path, and abandoned IDs are never reused.
        """
        if (
            not isinstance(cooperation_id, bytes)
            or len(cooperation_id) != 32  # noqa: PLR2004 - BIP327 context length
            or cooperation_id == bytes(32)
            or not isinstance(plan, CooperativeClaimPlan)
            or type(now) is not int
            or type(deadline_at) is not int
            or type(deadline_height) is not int
            or now < 0
            or not now < deadline_at <= now + COOPERATION_BUDGET_SECONDS
            or deadline_height <= 0
        ):
            raise LiveSessionStoreError("cooperative attempt parameters refused")
        try:
            with self._write() as connection:
                now = _cooperative_now(now, clock)
                row = connection.execute(
                    "SELECT s.init_bytes, s.accept_bytes, s.transcript_digest, s.phase, "
                    "s.blocked, w.contract_hash, w.terms_offer, w.terms_accept, w.state, "
                    "w.funding_binding, w.funding_txid, w.funding_vout, w.preimage "
                    "FROM sessions s JOIN swaps w ON s.session_id=w.session_id "
                    "WHERE s.session_id=?",
                    (session_id,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("no accepted cooperative swap")  # noqa: TRY301
                (
                    init_bytes,
                    accept_bytes,
                    transcript,
                    phase,
                    blocked,
                    recorded_hash,
                    offer,
                    accepted,
                    state,
                    binding_bytes,
                    funding_txid,
                    funding_vout,
                    preimage,
                ) = row
                if (
                    phase != "ACCEPTED"
                    or blocked
                    or accept_bytes is None
                    or COOPERATIVE_CLAIM_FEATURE not in self._policy.features
                    or connection.execute(
                        "SELECT 1 FROM cooperation_attempts WHERE session_id=? LIMIT 1",
                        (session_id,),
                    ).fetchone()
                    is not None
                ):
                    raise LiveSessionStoreError("cooperative attempt unavailable")  # noqa: TRY301
                init_envelope = _canonical_envelope(init_bytes)
                accept_envelope = _canonical_envelope(accept_bytes)
                initiation = parse_model_json(HandshakeInit, canonicalize(init_envelope.payload))
                acceptance = parse_model_json(
                    HandshakeAccept, canonicalize(accept_envelope.payload["accept"])
                )
                terms = _offer_terms(offer)
                client_acceptance = parse_model_json(
                    TermsAcceptPayload, canonicalize(_canonical_envelope(accepted).payload)
                ).acceptance
                digest = contract_hash(terms).hex()
                transcript_hash = handshake_hash(initiation, acceptance).hex()
                require_supported_contract_features(terms, initiation, acceptance)
                acceptance.validate_against(initiation, supported_features=self._policy.features)
                if (
                    COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                    or session_id != initiation.session_id
                    or transcript_hash != transcript
                    or digest != recorded_hash
                    or terms.network_identity != self._network
                    or terms.profile_id != self._policy.profile
                    or client_acceptance.contract_hash != digest
                    or client_acceptance.handshake_hash != transcript_hash
                    or client_acceptance.session_id != session_id
                    or client_acceptance.client_session_xonly_key
                    != initiation.client_session_xonly_key
                    or client_acceptance.provider_session_xonly_key
                    != acceptance.provider_session_xonly_key
                    or deadline_height > terms.refund_lock_height
                    or not isinstance(preimage, str)
                    or re.fullmatch(r"[0-9a-f]{64}", preimage) is None
                    or hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
                    != terms.invoice_binding.payment_hash
                ):
                    raise LiveSessionStoreError("cooperative authority unavailable")  # noqa: TRY301
                if window_tip is not None:
                    _require_waiting_cooperation(
                        connection,
                        session_id,
                        recorded_hash,
                        self._generation,
                        now=now,
                        deadline_at=deadline_at,
                        deadline_height=deadline_height,
                        tip_height=window_tip,
                    )
                funding = plan.authorization.funding
                if terms.profile_id == "btc-to-ln/v1":
                    if state not in ("PAID", "CLAIMING") or binding_bytes is None:
                        raise LiveSessionStoreError("payment not claimable")  # noqa: TRY301
                    signed_binding = parse_model_json(
                        FundingBindingPayload,
                        canonicalize(_canonical_envelope(binding_bytes).payload),
                    ).binding
                    if (
                        signed_binding.contract_hash != digest
                        or signed_binding.funding_txid != funding.txid.hex()
                        or signed_binding.contract_vout != funding.output_index
                        or int(signed_binding.contract_value_sat) != funding.value_sat
                        or signed_binding.contract_script_pubkey != funding.script_pubkey.hex()
                    ):
                        raise LiveSessionStoreError("funding binding mismatch")  # noqa: TRY301
                elif (
                    state != "SETTLED"
                    or funding_txid != funding.txid.hex()
                    or funding_vout != funding.output_index
                ):
                    # Reverse SETTLED currently follows a witnessed claim. A
                    # pre-spend settle path must be separately designed first.
                    raise LiveSessionStoreError("reverse claim not settled")  # noqa: TRY301
                keys = cast("TaprootKeyOperations", self._public_keys)
                authorization = UnilateralAuthorization.from_terms(
                    terms, funding, "claim", keys=keys
                )
                frozen = build_cooperative_claim(authorization, fee_sat=plan.fee_sat)
                if plan != frozen:
                    raise LiveSessionStoreError("cooperative transaction differs")  # noqa: TRY301
                taproot = reconstruct_taproot_contract(terms, keys=keys)
                immutable = canonicalize(
                    {
                        "version": 1,
                        "session_id": session_id,
                        "cooperation_id": cooperation_id.hex(),
                        "contract_hash": digest,
                        "network_identity": terms.network_identity.model_dump(mode="json"),
                        "claimant": terms.claimant,
                        "user_key": terms.client_contract_compressed_key,
                        "provider_key": terms.provider_contract_compressed_key,
                        "tap_tweak": taproot.tap_tweak.hex(),
                        "funding_txid": funding.txid.hex(),
                        "funding_vout": funding.output_index,
                        "funding_value_sat": funding.value_sat,
                        "funding_script_pubkey": funding.script_pubkey.hex(),
                        "unsigned_transaction": frozen.base_transaction.hex(),
                        "signature_hash": frozen.signature_hash.hex(),
                        "fee_sat": frozen.fee_sat,
                        "deadline_at": deadline_at,
                        "deadline_height": deadline_height,
                    }
                )
                now = _cooperative_now(now, clock)
                if now >= deadline_at:
                    raise LiveSessionStoreError("cooperative deadline elapsed")  # noqa: TRY301
                connection.execute(
                    "INSERT INTO cooperation_attempts "
                    "(cooperation_id, session_id, owner_generation, binding, "
                    "created_at, deadline_at, state) VALUES (?, ?, ?, ?, ?, ?, 'BURNED')",
                    (
                        cooperation_id,
                        session_id,
                        self._generation,
                        immutable,
                        now,
                        deadline_at,
                    ),
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo stored credentials or wire data
            raise LiveSessionStoreError("cooperative attempt refused") from None

    def _commit_cooperative_proposal_nonce(
        self,
        session_id: str,
        cooperation_id: bytes,
        public_nonce: bytes,
        *,
        signer: EnvelopeSigner,
        now: int,
    ) -> str:
        return self._commit_cooperative_proposal_nonce_impl(
            session_id, cooperation_id, public_nonce, signer=signer, now=now, window_tip=None
        )

    def _commit_cooperative_proposal_nonce_impl(  # noqa: PLR0913 - exact nonce custody inputs
        self,
        session_id: str,
        cooperation_id: bytes,
        public_nonce: bytes,
        *,
        signer: EnvelopeSigner,
        now: int,
        window_tip: int | None,
        clock: Callable[[], int] | None = None,
    ) -> str:
        """Commit a native public nonce and signed BTC-to-LN proposal before exposure.

        INTERNAL ONLY. The native handle must have been allocated AFTER the
        durable burn. On failure/uncertain commit destroy it and fall back; do
        not regenerate for this ID. The returned ID names a committed outbox
        message, not delivery or permission to disclose a partial signature.
        """
        if (
            not isinstance(cooperation_id, bytes)
            or len(cooperation_id) != 32  # noqa: PLR2004 - BIP327 context length
            or not isinstance(public_nonce, bytes)
            or len(public_nonce) != 66  # noqa: PLR2004 - BIP327 public nonce length
            or type(now) is not int
            or now < 0
        ):
            raise LiveSessionStoreError("cooperative nonce parameters refused")
        try:
            with self._write() as connection:
                now = _cooperative_now(now, clock)
                row = connection.execute(
                    "SELECT a.binding,a.owner_generation,a.created_at,a.deadline_at,a.state,"
                    "s.phase,s.blocked,w.state,w.preimage,w.contract_hash,"
                    "w.terms_offer,w.funding_binding "
                    "FROM cooperation_attempts a JOIN sessions s ON s.session_id=a.session_id "
                    "JOIN swaps w ON w.session_id=a.session_id "
                    "WHERE a.session_id=? AND a.cooperation_id=?",
                    (session_id, cooperation_id),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("cooperative burn unavailable")  # noqa: TRY301
                (
                    binding_bytes,
                    generation,
                    created_at,
                    deadline_at,
                    state,
                    phase,
                    blocked,
                    swap_state,
                    preimage,
                    recorded_hash,
                    offer_bytes,
                    funding_binding_bytes,
                ) = row
                binding = parse_json_strict(binding_bytes)
                if not isinstance(binding, dict) or (
                    generation != self._generation
                    or state != "BURNED"
                    or phase != "ACCEPTED"
                    or blocked
                    or swap_state not in ("PAID", "CLAIMING")
                    or not created_at <= now < deadline_at
                    or binding.get("version") != 1
                    or binding.get("session_id") != session_id
                    or binding.get("cooperation_id") != cooperation_id.hex()
                    or binding.get("contract_hash") != recorded_hash
                    or binding.get("claimant") != "provider"
                    or binding.get("deadline_at") != deadline_at
                    or not isinstance(preimage, str)
                    or re.fullmatch(r"[0-9a-f]{64}", preimage) is None
                    or funding_binding_bytes is None
                    or COOPERATIVE_CLAIM_FEATURE not in self._policy.features
                ):
                    raise LiveSessionStoreError("cooperative nonce unavailable")  # noqa: TRY301
                terms = _offer_terms(offer_bytes)
                retained_funding = parse_model_json(
                    FundingBindingPayload,
                    canonicalize(_canonical_envelope(funding_binding_bytes).payload),
                ).binding
                if (
                    contract_hash(terms).hex() != recorded_hash
                    or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                    or hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
                    != terms.invoice_binding.payment_hash
                    or retained_funding.contract_hash != recorded_hash
                    or retained_funding.funding_txid != binding.get("funding_txid")
                    or retained_funding.contract_vout != binding.get("funding_vout")
                    or int(retained_funding.contract_value_sat) != binding.get("funding_value_sat")
                    or retained_funding.contract_script_pubkey
                    != binding.get("funding_script_pubkey")
                ):
                    raise LiveSessionStoreError("cooperative nonce binding changed")  # noqa: TRY301
                if window_tip is not None:
                    window_deadline = binding.get("deadline_height")
                    if type(window_deadline) is not int:
                        raise LiveSessionStoreError(  # noqa: TRY301
                            "cooperative window deadline unavailable"
                        )
                    _require_waiting_cooperation(
                        connection,
                        session_id,
                        recorded_hash,
                        self._generation,
                        now=now,
                        deadline_at=deadline_at,
                        deadline_height=window_deadline,
                        tip_height=window_tip,
                    )
                # Production supplies native rill-crypto.Context and checks both
                # nonce points before any signed envelope can leave the store.
                cast("Context", self._crypto).musig_public_nonce_validate(public_nonce)
                proposal = CooperativeClaimPropose.model_validate_json(
                    canonicalize(
                        {
                            "action": "cooperative_claim_propose",
                            "cooperation_id": cooperation_id.hex(),
                            "unsigned_transaction": binding["unsigned_transaction"],
                            "payment_preimage": preimage,
                            "public_nonce": public_nonce.hex(),
                            "deadline_at": deadline_at,
                            "deadline_height": binding["deadline_height"],
                        }
                    ),
                    strict=True,
                )
                now = _cooperative_now(now, clock)
                if now >= deadline_at:
                    raise LiveSessionStoreError("cooperative deadline elapsed")  # noqa: TRY301
                message_id = self._record_observation(
                    connection,
                    session_id,
                    proposal.model_dump(mode="json"),
                    signer,
                    now,
                    message_type="action_request",
                    required_features=(COOPERATIVE_CLAIM_FEATURE,),
                )
                if (
                    connection.execute(
                        "UPDATE cooperation_attempts SET state='NONCE_READY',local_nonce=?,"
                        "nonce_response_id=? WHERE cooperation_id=? AND session_id=? "
                        "AND state='BURNED' AND owner_generation=?",
                        (public_nonce, message_id, cooperation_id, session_id, self._generation),
                    ).rowcount
                    != 1
                ):
                    raise LiveSessionStoreError("cooperative nonce state changed")  # noqa: TRY301
                now = _cooperative_now(now, clock)
                if now >= deadline_at:
                    # Roll back the local outbox and NONCE_READY update if
                    # signing/storage consumed the remainder of the budget.
                    raise LiveSessionStoreError("cooperative deadline elapsed")  # noqa: TRY301
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo nonce or stored state
            raise LiveSessionStoreError("cooperative nonce commit refused") from None
        return message_id

    def begin_selected_cooperative_proposal(
        self,
        session_id: str,
        cooperation_id: bytes,
        *,
        now: Callable[[], int],
        tip_height: int,
    ) -> str:
        """Allocate and persist a nonce while this owner's window is open.

        Refresh the irreversible clock after SQLite acquisition, just before
        native allocation, and around proposal persistence. Delivery must
        still independently recheck time and height through pending_sendable.
        """
        if type(tip_height) is not int:
            raise LiveSessionStoreError("cooperative window height unavailable")
        if not callable(now):
            raise LiveSessionStoreError("cooperative clock unavailable")
        return self._begin_cooperative_proposal_impl(
            session_id,
            cooperation_id,
            now=_cooperative_now(0, now),
            window_tip=tip_height,
            clock=now,
        )

    def _begin_and_commit_cooperative_proposal(
        self, session_id: str, cooperation_id: bytes, *, now: int
    ) -> str:
        """Retained internal custody primitive; never call for live arbitration."""
        return self._begin_cooperative_proposal_impl(
            session_id, cooperation_id, now=now, window_tip=None
        )

    def _begin_cooperative_proposal_impl(  # noqa: PLR0912, PLR0915 - one custody transition
        self,
        session_id: str,
        cooperation_id: bytes,
        *,
        now: int,
        window_tip: int | None,
        clock: Callable[[], int] | None = None,
    ) -> str:
        """Allocate one store-owned native handle after burn, then commit its nonce.

        INTERNAL ONLY. The caller must already have durably burned the exact
        claim, verified current chain state, and planned independent fallback.
        The scalar stays inside the store; neither it nor the opaque signing
        handle is returned. A failed begin/commit permanently prevents another
        native allocation for this ID in this owner process. A new owner
        abandons the BURNED row before it can allocate anything.
        """
        from rill_crypto import Context  # noqa: PLC0415 - native boundary is opt-in

        if (
            not isinstance(self._crypto, Context)
            or self._public_keys is not self._crypto
            or not isinstance(cooperation_id, bytes)
            or len(cooperation_id) != 32  # noqa: PLR2004 - unique BIP327 ID
            or type(now) is not int
            or now < 0
        ):
            raise LiveSessionStoreError("native cooperative custody unavailable")
        crypto = self._crypto
        if cooperation_id in self._allocated_cooperation_ids:
            raise LiveSessionStoreError("cooperative nonce allocation already attempted")
        try:
            with self._write() as connection:
                now = _cooperative_now(now, clock)
                row = connection.execute(
                    "SELECT a.binding,a.owner_generation,a.created_at,a.deadline_at,a.state,"
                    "s.phase,s.blocked,w.state,w.contract_hash,w.terms_offer,"
                    "k.compressed_key,k.secret_age "
                    "FROM cooperation_attempts a "
                    "JOIN sessions s ON s.session_id=a.session_id "
                    "JOIN swaps w ON w.session_id=a.session_id "
                    "LEFT JOIN contract_keys k ON k.session_id=a.session_id "
                    "WHERE a.session_id=? AND a.cooperation_id=?",
                    (session_id, cooperation_id),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("cooperative burn unavailable")  # noqa: TRY301
                (
                    binding_bytes,
                    generation,
                    created_at,
                    deadline_at,
                    state,
                    phase,
                    blocked,
                    swap_state,
                    recorded_hash,
                    offer_bytes,
                    compressed,
                    sealed,
                ) = row
                binding = parse_json_strict(binding_bytes)
                if not isinstance(binding, dict) or (
                    cooperation_id in self._allocated_cooperation_ids
                    or generation != self._generation
                    or state != "BURNED"
                    or phase != "ACCEPTED"
                    or blocked
                    or swap_state not in ("PAID", "CLAIMING")
                    or not created_at <= now < deadline_at
                    or binding.get("version") != 1
                    or binding.get("cooperation_id") != cooperation_id.hex()
                    or binding.get("session_id") != session_id
                    or binding.get("deadline_at") != deadline_at
                    or binding.get("contract_hash") != recorded_hash
                    or binding.get("claimant") != "provider"
                    or compressed != binding.get("provider_key")
                    or sealed is None
                    or COOPERATIVE_CLAIM_FEATURE not in self._policy.features
                ):
                    raise LiveSessionStoreError("cooperative nonce allocation unavailable")  # noqa: TRY301
                terms = _offer_terms(offer_bytes)
                if (
                    contract_hash(terms).hex() != recorded_hash
                    or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                    or terms.client_contract_compressed_key != binding.get("user_key")
                    or terms.provider_contract_compressed_key != compressed
                    or terms.network_identity.model_dump(mode="json")
                    != binding.get("network_identity")
                ):
                    raise LiveSessionStoreError("cooperative signer terms changed")  # noqa: TRY301
                if window_tip is not None:
                    window_deadline = binding.get("deadline_height")
                    if type(window_deadline) is not int:
                        raise LiveSessionStoreError(  # noqa: TRY301
                            "cooperative window deadline unavailable"
                        )
                    _require_waiting_cooperation(
                        connection,
                        session_id,
                        recorded_hash,
                        self._generation,
                        now=now,
                        deadline_at=deadline_at,
                        deadline_height=window_deadline,
                        tip_height=window_tip,
                    )
                user_key = binding.get("user_key")
                tweak = binding.get("tap_tweak")
                message = binding.get("signature_hash")
                if (
                    not isinstance(user_key, str)
                    or re.fullmatch(r"(02|03)[0-9a-f]{64}", user_key) is None
                    or not isinstance(tweak, str)
                    or re.fullmatch(r"[0-9a-f]{64}", tweak) is None
                    or not isinstance(message, str)
                    or re.fullmatch(r"[0-9a-f]{64}", message) is None
                ):
                    raise LiveSessionStoreError("cooperative signing context malformed")  # noqa: TRY301
                plaintext = pyrage.decrypt(sealed, [self._custody_identity])
                key_record = parse_json_strict(plaintext)
                if not isinstance(key_record, dict):
                    raise LiveSessionStoreError("cooperative contract custody differs")  # noqa: TRY301
                scalar_hex = key_record.get("secret_scalar")
                if (
                    key_record.get("kind") != CONTRACT_KEY_RECORD_KIND
                    or key_record.get("store_uuid") != self._store_uuid
                    or key_record.get("session_id") != session_id
                    or key_record.get("compressed_public_key") != compressed
                    or not isinstance(scalar_hex, str)
                    or re.fullmatch(r"[0-9a-f]{64}", scalar_hex) is None
                ):
                    raise LiveSessionStoreError("cooperative contract custody differs")  # noqa: TRY301
                scalar = bytes.fromhex(scalar_hex)
                del plaintext, key_record, scalar_hex
                try:
                    if crypto.public_key(scalar).hex() != compressed:
                        raise LiveSessionStoreError("cooperative contract key differs")
                    now = _cooperative_now(now, clock)
                    if now >= deadline_at:
                        raise LiveSessionStoreError("cooperative deadline elapsed")
                    # The burn committed in an earlier transaction. Never
                    # remove this tombstone, including if native begin raises.
                    self._allocated_cooperation_ids.add(cooperation_id)
                    attempt, public_nonce = crypto.musig_begin(
                        secret_key=scalar,
                        user_public_key=bytes.fromhex(user_key),
                        provider_public_key=bytes.fromhex(compressed),
                        tap_tweak=bytes.fromhex(tweak),
                        message=bytes.fromhex(message),
                        cooperation_id=cooperation_id,
                    )
                    self._cooperation_handles[cooperation_id] = attempt
                finally:
                    del scalar
            # The private storage primitive rechecks the current owner, state,
            # funding, preimage and deadline in its own durable write. It may
            # only publish the exact nonce bound to the live handle above.
            if window_tip is None:
                return self._commit_cooperative_proposal_nonce(
                    session_id, cooperation_id, public_nonce, signer=crypto, now=now
                )
            return self._commit_cooperative_proposal_nonce_impl(
                session_id,
                cooperation_id,
                public_nonce,
                signer=crypto,
                now=now,
                window_tip=window_tip,
                clock=clock,
            )
        except BaseException as error:
            live = self._cooperation_handles.pop(cooperation_id, None)
            if live is not None:
                with suppress(Exception):
                    live.close()
            if isinstance(error, Exception) and not isinstance(error, LiveSessionStoreError):
                raise LiveSessionStoreError("cooperative native proposal refused") from None
            raise

    def _expectations(self) -> dict[str, object]:
        return {
            "expected_provider_identity": self._identity,
            "expected_profile": self._policy.profile,
            "expected_network": self._network,
            "supported_features": _features(self._policy.features),
            "supported_encryption_suites": _features(self._policy.encryption_suites),
            "supported_capabilities": _features(self._policy.capabilities),
            "crypto": self._crypto,
        }

    def _init(self, document: bytes) -> tuple[Envelope, HandshakeInit]:
        outer = _canonical_envelope(document)
        init = HandshakeInit.model_validate_json(canonicalize(outer.payload), strict=True)
        policy = self._policy
        if not (
            outer.message_type == "handshake_init"
            and outer.sequence == 0
            and outer.in_reply_to is None
            and outer.contract_hash is None
            and outer.signature is None
            and outer.session_id == init.session_id
            and outer.sender_session_key == init.client_session_xonly_key
            and outer.profile_id == init.profile_id == policy.profile
            and outer.network_identity == init.network_identity == self._network
            and init.expected_provider_identity_xonly_key == self._identity
            and set(outer.required_features).issubset(policy.features)
            and set(init.required_features).issubset(policy.features)
            and bool(set(init.requested_encryption_suites) & policy.encryption_suites)
        ):
            raise LiveSessionStoreError("untrusted or unsupported handshake initiation")
        return outer, init

    def reserve(  # noqa: PLR0912, PLR0915 - replay, provenance, capacity share one transaction
        self, initiation: EpochInitiation, *, now: int | None = None
    ) -> SessionReservation:
        """Reserve one fresh provider challenge per session; replay is stable.

        The init is unsigned, so different bytes for a known session may come
        from a stranger. They are kept as bounded conflict evidence and block
        new risk for that session (an availability cost, never exposure).
        Every session is epoch-bound: an idle session keeps a tombstone until
        its epoch has durably retired, after which its ID is never admissible.
        """
        now = int(time.time()) if now is None else now
        if not isinstance(initiation, EpochInitiation):
            raise LiveSessionStoreError("epoch admission provenance unavailable")
        init_document = initiation.document
        try:
            outer, init = self._init(init_document)
            with self._write() as connection:
                if _session_expired(connection, init.session_id):
                    raise SessionExpiredError("session expired")  # noqa: TRY301
                epoch = init.epoch_inbox_xonly_key  # Core refuses an unbound init
                if initiation.epoch_key != epoch:
                    raise LiveSessionStoreError("epoch admission provenance unavailable")  # noqa: TRY301
                epoch_row = connection.execute(
                    "SELECT retire_after FROM epochs WHERE epoch_key=? AND retire_after > ?",
                    (epoch, max(now, _epoch_watermark(connection))),
                ).fetchone()
                if epoch_row is None:
                    raise SessionExpiredError("admission epoch retired")  # noqa: TRY301
                retire_after = epoch_row[0]
                admission = connection.execute(
                    "SELECT epoch_key, retire_after FROM epoch_admissions WHERE session_id=?",
                    (init.session_id,),
                ).fetchone()
                row = connection.execute(
                    "SELECT init_bytes, provider_challenge, blocked, revision FROM sessions "
                    "WHERE session_id=?",
                    (init.session_id,),
                ).fetchone()
                if admission is not None and (row is None or admission != (epoch, retire_after)):
                    # A differently bound init must not poison a known session
                    # through the conflict path.
                    raise LiveSessionStoreError("epoch admission custody unavailable")  # noqa: TRY301
                if row is not None and admission is None:
                    raise LiveSessionStoreError("epoch admission custody unavailable")  # noqa: TRY301
                if row is not None:
                    if row[0] == init_document and not row[2]:
                        # Replay reuses the key; broken custody is never replaced.
                        key = self._require_custody(connection, init.session_id)
                        return SessionReservation(
                            init.session_id, outer.message_id, row[1], key, row[3]
                        )
                    if row[0] != init_document:
                        _record_conflict(connection, init.session_id, "init", init_document)
                    blocked = True
                else:
                    blocked = False
                    if (
                        FEE_POLICY_FEATURE in self._policy.features
                        and FEE_POLICY_FEATURE not in init.required_features
                    ):
                        raise LiveSessionStoreError("new session requires network fee policy")  # noqa: TRY301
                    if (
                        COOPERATIVE_CLAIM_FEATURE in self._policy.features
                        and COOPERATIVE_CLAIM_FEATURE not in init.required_features
                        and init.profile_id != "ln-to-btc/v1"
                    ):
                        # Mandatory for new forward business; recorded sessions
                        # (including unfeatured ones) replay above unchanged.
                        raise LiveSessionStoreError("new session requires cooperative claims")  # noqa: TRY301
                    # Accepted sessions are retained forever but hold economic
                    # reservations instead; only pre-acceptance sessions count here.
                    (live,) = connection.execute(
                        "SELECT COUNT(*) FROM sessions WHERE phase IN "
                        "('RESERVED', 'ACCEPT_COMMITTED', 'CONFIRMED')"
                    ).fetchone()
                    (dead,) = connection.execute(
                        "SELECT COUNT(*) FROM epoch_admissions WHERE expired=1"
                    ).fetchone()
                    if live >= self._max_sessions or dead >= self._max_tombstones:
                        raise SessionCapacityError("session capacity reached")  # noqa: TRY301
                    if not self._admission.take(now):
                        raise SessionCapacityError("session admission rate exceeded")  # noqa: TRY301
                    challenge = _fresh_challenge(connection, init)
                    key, sealed = self._new_session_key(init, challenge)
                    connection.execute(
                        "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, 'LIVE', "
                        "NULL, NULL, NULL, 'RESERVED', 0, 0, 1, 0, ?)",
                        (
                            init.session_id,
                            init_document,
                            outer.message_id,
                            init.client_session_xonly_key,
                            challenge,
                            key,
                            sealed,
                            now,
                        ),
                    )
                    connection.execute(
                        "INSERT INTO epoch_admissions VALUES (?, ?, ?, 0)",
                        (init.session_id, epoch, retire_after),
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents
            raise LiveSessionStoreError("session reservation refused") from None
        if blocked:
            raise SessionBlockedError("session initiation conflict is durable")
        return SessionReservation(init.session_id, outer.message_id, challenge, key, 0)

    def _key_record(
        self, session_id: str, init_digest: str, challenge: str, scalar: bytes, xonly: str
    ) -> bytes:
        return canonicalize(
            {
                "kind": KEY_RECORD_KIND,
                "secret_scalar": scalar.hex(),
                "xonly_public_key": xonly,
                "store_uuid": self._store_uuid,
                "network_identity": self._network.model_dump(mode="json"),
                "provider_identity": self._identity,
                "session_id": session_id,
                "handshake_init_digest": init_digest,
                "provider_challenge": challenge,
            }
        )

    def _new_session_key(self, init: HandshakeInit, challenge: str) -> tuple[str, bytes]:
        scalar = _new_session_scalar()
        xonly = _xonly(self._public_keys, scalar)
        record = self._key_record(
            init.session_id, handshake_init_hash(init).hex(), challenge, scalar, xonly
        )
        sealed = pyrage.encrypt(record, [self._custody_identity.to_public()])
        if type(sealed) is not bytes or pyrage.decrypt(sealed, [self._custody_identity]) != record:
            raise LiveSessionStoreError("session key custody not verifiable")
        return xonly, sealed

    def _require_custody(self, connection: sqlite3.Connection, session_id: str) -> str:
        """Return the bound public key only if its sealed secret is intact and usable."""
        _, xonly = self._unseal(connection, session_id)
        return xonly

    def _unseal(self, connection: sqlite3.Connection, session_id: str) -> tuple[bytes, str]:
        row = connection.execute(
            "SELECT init_bytes, provider_challenge, provider_session_key, session_secret_age, "
            "key_state FROM sessions WHERE session_id=?",
            (session_id,),
        ).fetchone()
        try:
            init_bytes, challenge, xonly, sealed, state = row
            _, init = self._init(init_bytes)
            plaintext = pyrage.decrypt(sealed, [self._custody_identity])
            record = json.loads(plaintext)
            scalar = bytes.fromhex(record["secret_scalar"])
            valid = (
                state == "LIVE"
                and plaintext
                == self._key_record(
                    session_id, handshake_init_hash(init).hex(), challenge, scalar, xonly
                )
                and _xonly(self._public_keys, scalar) == xonly
            )
        except Exception:  # noqa: BLE001 - never echo secret material or library errors
            valid = False
        if not valid:
            raise LiveSessionStoreError("session key custody unavailable")
        return scalar, str(xonly)

    def wrap_pending(self, message_id: str, *, transport: Context) -> bytes:
        """Return a fresh NIP-59 wrap of one committed, still-owed outbox message.

        Each call re-randomizes seal and wrapper around the unchanged logical
        message. The recipient is the peer's session mailbox from the
        committed transcript, never a caller-chosen key.
        """
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT o.session_id, o.canonical_bytes, s.client_key FROM outbox o "
                    "JOIN sessions s ON s.session_id = o.session_id "
                    "WHERE o.message_id=? AND o.delivery_state='PENDING'",
                    (message_id,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("no pending outbox message")  # noqa: TRY301
                session_id, document, recipient = row
                scalar, _ = self._unseal(connection, session_id)
                try:
                    return _wrap_envelope(
                        document,
                        sender_session_secret=scalar,
                        recipient_xonly_key=recipient,
                        crypto=transport,
                    )
                finally:
                    del scalar
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo secret material or library errors
            raise LiveSessionStoreError("outbox wrap refused") from None

    def pending_requires_live_cooperation(self, message_id: str) -> bool | None:
        """Classify a retained request, not its window or delivery authority.

        Only new readiness/proposal requests need live service availability.
        Ordinary settlement and already-owed completion remain deliverable.
        None means no pending record, never permission to recreate one.
        """
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT canonical_bytes FROM outbox "
                    "WHERE message_id=? AND delivery_state='PENDING'",
                    (message_id,),
                ).fetchone()
                if row is None:
                    return None
                envelope = _canonical_envelope(row[0])
                return envelope.message_type == "action_request" and envelope.payload.get(
                    "action"
                ) in (
                    "cooperative_claim_ready",
                    "cooperative_claim_propose",
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - malformed retained state grants no disclosure
            raise LiveSessionStoreError("pending request classification unavailable") from None

    def pending_sendable(  # noqa: PLR0911 - one fail-closed proposal authorization
        self,
        message_id: str,
        *,
        now: int,
        tip_height: int | None = None,
        readiness: ReadinessChallenge | None = None,
    ) -> bool:
        """Allow ordinary outbox replay; proposal replay needs a live window.

        The caller must sample an independent fresh Core tip for a proposal.
        A completion is distinct: its selected cooperative winner stays owed
        even after the deadline or a new owner takes over.
        """
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT session_id,canonical_bytes FROM outbox "
                    "WHERE message_id=? AND delivery_state='PENDING'",
                    (message_id,),
                ).fetchone()
                if row is None:
                    return False
                session_id, document = row
                envelope = _canonical_envelope(document)
                if (
                    envelope.message_type == "action_request"
                    and envelope.payload.get("action") == "cooperative_claim_ready"
                ):
                    if (
                        readiness is None
                        or not isinstance(readiness, ReadinessChallenge)
                        or readiness.request_id != message_id
                        or readiness.session_id != session_id
                        or readiness.owner_generation != self._generation
                        or type(now) is not int
                        or type(tip_height) is not int
                        or tip_height <= 0
                        or tip_height >= readiness.deadline_height
                        or not readiness.started_at <= now < readiness.deadline_at
                    ):
                        return False
                    payload = parse_cooperative_payload(
                        "action_request", canonicalize(envelope.payload)
                    )
                    if not isinstance(payload, CooperativeClaimReadyRequest) or (
                        payload.challenge != readiness.challenge
                        or payload.deadline_at != readiness.deadline_at
                        or payload.deadline_height != readiness.deadline_height
                        or envelope.contract_hash != readiness.contract_hash
                    ):
                        return False
                    row = connection.execute(
                        "SELECT a.state,a.version,a.contract_hash,s.phase,s.blocked,"
                        "w.state,w.contract_hash,w.preimage,w.claim_tx,w.claim_txid "
                        "FROM claim_arbitration a JOIN swaps w ON w.session_id=a.session_id "
                        "JOIN sessions s ON s.session_id=a.session_id WHERE a.session_id=?",
                        (session_id,),
                    ).fetchone()
                    return (
                        row
                        == (
                            "ADMITTED",
                            1,
                            readiness.contract_hash,
                            "ACCEPTED",
                            0,
                            "PAID",
                            readiness.contract_hash,
                            payload.payment_preimage,
                            None,
                            None,
                        )
                        and not connection.execute(
                            "SELECT 1 FROM claim_attempts WHERE session_id=? LIMIT 1",
                            (session_id,),
                        ).fetchone()
                    )
                if (
                    envelope.message_type != "action_request"
                    or envelope.payload.get("action") != "cooperative_claim_propose"
                ):
                    return True
                if type(now) is not int or type(tip_height) is not int:
                    return False
                attempt = connection.execute(
                    "SELECT a.owner_generation,a.deadline_at,a.state,a.binding,"
                    "s.phase,s.blocked,w.state,w.contract_hash "
                    "FROM cooperation_attempts a "
                    "JOIN sessions s ON s.session_id=a.session_id "
                    "JOIN swaps w ON w.session_id=a.session_id "
                    "WHERE a.session_id=? AND a.nonce_response_id=?",
                    (session_id, message_id),
                ).fetchone()
                if attempt is None:
                    return False
                generation, deadline_at, state, bound, phase, blocked, swap_state, digest = attempt
                binding = parse_json_strict(bound)
                deadline_height = (
                    binding.get("deadline_height") if isinstance(binding, dict) else None
                )
                if (
                    generation != self._generation
                    or state not in ("NONCE_READY", "SIGNING")
                    or phase != "ACCEPTED"
                    or blocked
                    or swap_state != "PAID"
                    or not isinstance(binding, dict)
                    or binding.get("contract_hash") != digest
                    or binding.get("deadline_at") != deadline_at
                    or type(deadline_height) is not int
                ):
                    return False
                try:
                    _require_waiting_cooperation(
                        connection,
                        session_id,
                        digest,
                        self._generation,
                        now=now,
                        deadline_at=deadline_at,
                        deadline_height=deadline_height,
                        tip_height=tip_height,
                    )
                except LiveSessionStoreError:
                    return False
                return True
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - malformed proposal is not dispatch permission
            return False

    def reconcile_expired_cooperative_proposals(self, now: int) -> int:
        """Retire only linked live proposals whose original window has expired."""
        if type(now) is not int or now < 0:
            raise LiveSessionStoreError("cooperative deadline unavailable")
        try:
            with self._write() as connection:
                return connection.execute(
                    "UPDATE outbox SET delivery_state='RECONCILED' "
                    "WHERE delivery_state='PENDING' AND EXISTS "
                    "(SELECT 1 FROM cooperation_attempts a "
                    "JOIN claim_arbitration c ON c.session_id=a.session_id "
                    "WHERE a.session_id=outbox.session_id "
                    "AND a.nonce_response_id=outbox.message_id "
                    "AND a.state IN ('NONCE_READY','SIGNING') "
                    "AND c.state='WAITING' AND c.version=1 "
                    "AND c.owner_generation=a.owner_generation AND c.deadline_at<=?)",
                    (now,),
                ).rowcount
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo stored message details
            raise LiveSessionStoreError("cooperative proposal reconciliation refused") from None

    def open_mailbox_frame(self, outer_event: bytes, *, transport: Context) -> bytes:
        """Decode a gift wrap sent to one of our session mailboxes.

        Returns the exact canonical envelope bytes only if the seal author is
        that session's client key and the envelope names that session. This is
        NOT admission: the caller must still pass the bytes to the matching
        admission method (for example ``admit_confirm``).
        """
        try:
            recipient = _routing_recipient(outer_event, transport)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT session_id, client_key FROM sessions WHERE provider_session_key=?",
                    (recipient,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("mailbox frame for unknown session")  # noqa: TRY301
                session_id, client = row
                scalar, mailbox = self._unseal(connection, session_id)
                try:
                    candidate = _decode_gift_wrap_candidate(
                        outer_event,
                        recipient_mailbox_secret=scalar,
                        expected_recipient_xonly_key=mailbox,
                        expected_network=self._network,
                        expected_profile_id=self._policy.profile,
                        crypto=transport,
                    )
                finally:
                    del scalar
            if not (
                candidate.seal_author_xonly_key == client
                and candidate.envelope.sender_session_key == client
                and candidate.envelope.session_id == session_id
            ):
                raise LiveSessionStoreError("mailbox frame sender not bound to session")  # noqa: TRY301
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - uniform, redacted refusal (RS-006)
            raise LiveSessionStoreError("mailbox frame refused") from None
        return candidate.envelope_bytes

    def create_accept(
        self,
        session_id: str,
        *,
        identity: ProviderIdentity,
        transport_endpoints: tuple[str, ...],
    ) -> AcceptCommit:
        """Build, identity-sign, and durably commit this session's one accept.

        Negotiation picks the client's most preferred supported suite and the
        requested capabilities we support, in the client's order. A session
        that already committed an accept returns that record, never a new one.
        Nothing is exposed here; publish only via ``wrap_pending``.
        """
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT init_bytes, provider_challenge, accept_bytes, blocked "
                    "FROM sessions WHERE session_id=?",
                    (session_id,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("no reservation for session")  # noqa: TRY301
                init_bytes, challenge, stored, blocked = row
                key = (
                    None
                    if stored is not None or blocked
                    else self._require_custody(connection, session_id)
                )
            if stored is not None:
                return self.commit_accept(stored)
            if blocked or key is None:
                raise SessionBlockedError("session blocked by conflict evidence")  # noqa: TRY301
            outer, init = self._init(init_bytes)
            if identity.xonly_public_key != self._identity:
                raise LiveSessionStoreError("identity is not this store's provider")  # noqa: TRY301
            policy = self._policy
            suites = [s for s in init.requested_encryption_suites if s in policy.encryption_suites]
            capabilities = tuple(c for c in init.requested_capabilities if c in policy.capabilities)
            if not suites or not capabilities:
                raise LiveSessionStoreError("no mutually supported selection")  # noqa: TRY301
            cooperative = COOPERATIVE_CLAIM_FEATURE in init.required_features
            network_fees = FEE_POLICY_FEATURE in init.required_features
            if FEE_POLICY_FEATURE in policy.features and not network_fees:
                raise LiveSessionStoreError("new session requires network fee policy")  # noqa: TRY301
            if (
                COOPERATIVE_CLAIM_FEATURE in policy.features
                and not cooperative
                and init.profile_id != "ln-to-btc/v1"
            ):
                # reserve() already refuses these; never sign an accept for one.
                raise LiveSessionStoreError("new session requires cooperative claims")  # noqa: TRY301
            selection = HandshakeAccept(
                handshake_init_hash=handshake_init_hash(init).hex(),
                protocol="rillswap",
                wire_version="1",
                profile_id=init.profile_id,
                network_identity=init.network_identity,
                session_id=init.session_id,
                client_challenge=init.client_challenge,
                provider_challenge=challenge,
                client_session_xonly_key=init.client_session_xonly_key,
                provider_session_xonly_key=key,
                provider_identity_xonly_key=self._identity,
                selected_encryption_suite=suites[0],
                selected_capabilities=capabilities,
                transport_endpoints=tuple(transport_endpoints),
                required_features=tuple(
                    sorted(
                        {EPOCH_SESSION_FEATURE}
                        | ({COOPERATIVE_CLAIM_FEATURE} if cooperative else set())
                        | ({FEE_POLICY_FEATURE} if network_fees else set())
                    )
                ),
                extensions={},
            )
            payload: dict[str, Any] = {
                "accept": selection.model_dump(mode="json"),
                "provider_identity_signature": identity.sign_handshake_accept(selection),
            }
            document = canonicalize(
                {
                    "protocol": "rillswap",
                    "wire_version": "1",
                    "profile_id": init.profile_id,
                    "network_identity": init.network_identity.model_dump(mode="json"),
                    "session_id": init.session_id,
                    "message_id": _new_message_id(),
                    "sender_session_key": key,
                    "sequence": 0,
                    "in_reply_to": outer.message_id,
                    "contract_hash": None,
                    "message_type": "handshake_accept",
                    "payload": payload,
                    "required_features": [],
                    "extensions": {},
                    "signature": None,
                }
            )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo secret material or library errors
            raise LiveSessionStoreError("accept construction refused") from None
        # A concurrent identical build is impossible (single owner); a crash
        # before this commit leaves nothing exposed and simply rebuilds.
        return self.commit_accept(document)

    def commit_accept(self, accept_document: bytes) -> AcceptCommit:
        """Durably commit exact accept bytes BEFORE any publication.

        Only after this returns may the bytes be exposed. At most one accept is
        ever committed per session; identical resubmission returns the record.
        """
        try:
            outer = _canonical_envelope(accept_document)
            accepted = HandshakeAcceptPayload.model_validate_json(
                canonicalize(outer.payload), strict=True
            )
            with self._write() as connection:
                row = connection.execute(
                    "SELECT init_bytes, provider_challenge, accept_bytes, accept_message_id, "
                    "transcript_digest, phase, blocked, revision FROM sessions "
                    "WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("no reservation for session")  # noqa: TRY301
                init_bytes, challenge, stored, stored_id, digest, phase, blocked, revision = row
                if phase != "RESERVED":
                    if stored != accept_document:
                        raise LiveSessionStoreError(  # noqa: TRY301
                            "a different accept is already committed"
                        )
                    return AcceptCommit(
                        outer.session_id,
                        stored_id,
                        stored,
                        digest,
                        _accept_revision(connection, stored_id),
                    )
                if blocked:
                    raise SessionBlockedError("session blocked by conflict evidence")  # noqa: TRY301
                transcript = verify_static_handshake_accept(
                    init_bytes,
                    accept_document,
                    **self._expectations(),  # type: ignore[arg-type]
                ).hex()
                if accepted.accept.provider_challenge != challenge:
                    raise LiveSessionStoreError("accept challenge not reserved")  # noqa: TRY301
                custody_key = self._require_custody(connection, outer.session_id)
                if accepted.accept.provider_session_xonly_key != custody_key:
                    raise LiveSessionStoreError(  # noqa: TRY301
                        "accept session key is not the reserved custody key"
                    )
                committed = revision + 1
                connection.execute(
                    "INSERT INTO outbox VALUES (?, ?, 0, ?, ?, ?, 'PENDING')",
                    (
                        outer.message_id,
                        outer.session_id,
                        outer.in_reply_to,
                        accept_document,
                        committed,
                    ),
                )
                connection.execute(
                    "UPDATE sessions SET accept_bytes=?, accept_message_id=?, "
                    "transcript_digest=?, phase='ACCEPT_COMMITTED', revision=?, "
                    "next_provider_seq=1 WHERE session_id=?",
                    (accept_document, outer.message_id, transcript, committed, outer.session_id),
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents or crypto details
            raise LiveSessionStoreError("accept commit refused") from None
        if (
            self._policy.profile == "ln-to-btc/v1"
            and COOPERATIVE_CLAIM_FEATURE in accepted.accept.required_features
        ):
            # Only this fresh path reaches here, after successful COMMIT. An
            # inherited reservation may finish a new handshake, but an already
            # committed accept or restored accepted session supplies no origin.
            self._reverse_negotiations[outer.session_id] = _ReverseNegotiationOrigin(
                accept_document, transcript
            )
        return AcceptCommit(
            outer.session_id, outer.message_id, accept_document, transcript, committed
        )

    def admit_confirm(self, confirm_document: bytes, *, now: int | None = None) -> ConfirmAdmission:
        """Atomically admit the signed confirm over the committed transcript.

        Unverifiable documents are refused without any record. A second,
        different, validly signed confirm is client equivocation: it is kept
        as evidence and blocks the session.
        """
        try:
            outer = _canonical_envelope(confirm_document)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT init_bytes, accept_bytes, accept_message_id, transcript_digest, "
                    "client_key, phase, blocked, revision FROM sessions WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None and _session_expired(connection, outer.session_id):
                    raise SessionExpiredError("session expired")  # noqa: TRY301
                if row is None or row[5] == "RESERVED":
                    raise LiveSessionStoreError("no committed accept for session")  # noqa: TRY301
                init_bytes, accept_bytes, accept_id, digest, client, phase, blocked, revision = row
                admitted = None
                if phase in OPEN_PHASES:
                    admitted = connection.execute(
                        "SELECT message_id, canonical_bytes, admitted_revision, unsigned_digest "
                        "FROM inbox WHERE session_id=? AND sender_key=? AND seq=1",
                        (outer.session_id, client),
                    ).fetchone()
                    if admitted is not None and admitted[1] == confirm_document and not blocked:
                        return ConfirmAdmission(
                            outer.session_id, admitted[0], digest, admitted[2], replay=True
                        )
                if blocked:
                    raise SessionBlockedError("session blocked by conflict evidence")  # noqa: TRY301
                transcript = verify_static_handshake_transcript(
                    init_bytes,
                    accept_bytes,
                    confirm_document,
                    **self._expectations(),  # type: ignore[arg-type]
                ).hex()
                if transcript != digest:
                    raise LiveSessionStoreError("confirm transcript differs")  # noqa: TRY301
                # RS-001 conflicts are defined over unsigned canonical bytes: a
                # different valid signature over the same content is a replay,
                # answered with the originally recorded result.
                if admitted is not None and unsigned_envelope_hash(outer).hex() == admitted[3]:
                    return ConfirmAdmission(
                        outer.session_id, admitted[0], digest, admitted[2], replay=True
                    )
                equivocation = phase in OPEN_PHASES
                if equivocation:
                    _record_conflict(connection, outer.session_id, "confirm", confirm_document)
                else:
                    admitted_revision = revision + 1
                    connection.execute(
                        "INSERT INTO inbox VALUES (?, ?, ?, 1, ?, ?, ?)",
                        (
                            outer.session_id,
                            client,
                            outer.message_id,
                            unsigned_envelope_hash(outer).hex(),
                            confirm_document,
                            admitted_revision,
                        ),
                    )
                    connection.execute(
                        "UPDATE sessions SET phase='CONFIRMED', revision=?, next_client_seq=2, "
                        "active_at=? WHERE session_id=?",
                        (
                            admitted_revision,
                            int(time.time()) if now is None else now,
                            outer.session_id,
                        ),
                    )
                    # The confirm is the application acknowledgment of the accept.
                    connection.execute(
                        "UPDATE outbox SET delivery_state='ACKED' "
                        "WHERE message_id=? AND delivery_state='PENDING'",
                        (accept_id,),
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents or crypto details
            raise LiveSessionStoreError("confirm admission refused") from None
        if equivocation:
            raise SessionBlockedError("conflicting signed confirm is durable")
        return ConfirmAdmission(
            outer.session_id, outer.message_id, digest, admitted_revision, replay=False
        )

    def rotate_epochs(
        self, *, now: int, period: int, retention: int, advertise_for: int
    ) -> tuple[str, ...]:
        """Ensure a current epoch inbox key; return keys to advertise, newest first.

        A new epoch starts when the newest is ``period`` seconds old. Each key
        keeps decoding until ``created_at + period + retention``; set
        ``retention`` to at least the announcement lifetime so late inits
        still decode. Only keys that stay decodable for ``advertise_for``
        more seconds are returned (announcement lifetime plus delivery grace),
        so a valid announcement never names a key about to retire. Epoch keys
        only receive public inits (availability, not authority), and their
        sealed secrets bind this store.
        """
        if not (
            type(now) is int
            and type(period) is int
            and type(retention) is int
            and type(advertise_for) is int
            and 0 <= advertise_for <= retention
            and now > 0
            and period > 0
            and retention >= 0
        ):
            raise LiveSessionStoreError("epoch schedule unsupported")
        try:
            with self._write() as connection:
                newest = connection.execute("SELECT MAX(created_at) FROM epochs").fetchone()[0]
                if now < _epoch_watermark(connection) or (newest is not None and now < newest):
                    raise LiveSessionStoreError("clock is behind the newest epoch")  # noqa: TRY301
                _retire_epochs(connection, now)
                if newest is None or now >= newest + period:
                    xonly, sealed = self._new_epoch_key(now)
                    connection.execute("INSERT INTO epoch_key_history VALUES (?)", (xonly,))
                    connection.execute(
                        "INSERT INTO epochs VALUES (?, ?, ?, ?)",
                        (xonly, sealed, now, now + period + retention),
                    )
                rows = connection.execute(
                    "SELECT epoch_key FROM epochs WHERE retire_after > ? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (now + advertise_for, MAX_ADVERTISED_EPOCHS),
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo secret material or library errors
            raise LiveSessionStoreError("epoch rotation refused") from None
        return tuple(row[0] for row in rows)

    def _epoch_record(self, scalar: bytes, xonly: str, created_at: int) -> bytes:
        return canonicalize(
            {
                "kind": EPOCH_RECORD_KIND,
                "secret_scalar": scalar.hex(),
                "xonly_public_key": xonly,
                "store_uuid": self._store_uuid,
                "created_at": created_at,
            }
        )

    def _new_epoch_key(self, created_at: int) -> tuple[str, bytes]:
        scalar = _new_epoch_scalar()
        xonly = _xonly(self._public_keys, scalar)
        if xonly == self._identity:
            raise LiveSessionStoreError("epoch key collides with identity")
        record = self._epoch_record(scalar, xonly, created_at)
        sealed = pyrage.encrypt(record, [self._custody_identity.to_public()])
        if type(sealed) is not bytes or pyrage.decrypt(sealed, [self._custody_identity]) != record:
            raise LiveSessionStoreError("epoch key custody not verifiable")
        return xonly, sealed

    def open_epoch_frame(
        self, outer_event: bytes, *, now: int, transport: Context
    ) -> EpochInitiation:
        """Decode a gift-wrapped handshake_init sent to an unretired epoch inbox.

        Returns exact canonical init bytes whose envelope sender is the seal
        author, plus its recipient epoch. Pass this result to ``reserve``,
        which applies every init rule. Refusals are uniform and redacted.
        """
        try:
            recipient = _routing_recipient(outer_event, transport)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT secret_age, created_at FROM epochs "
                    "WHERE epoch_key=? AND retire_after > ?",
                    (recipient, max(now, _epoch_watermark(connection))),
                ).fetchone()
            if row is None:
                raise LiveSessionStoreError("frame for unknown or retired epoch")  # noqa: TRY301
            plaintext = pyrage.decrypt(row[0], [self._custody_identity])
            scalar = bytes.fromhex(json.loads(plaintext)["secret_scalar"])
            try:
                if not (
                    plaintext == self._epoch_record(scalar, recipient, row[1])
                    and _xonly(self._public_keys, scalar) == recipient
                ):
                    raise LiveSessionStoreError("epoch key custody unavailable")
                candidate = _decode_gift_wrap_candidate(
                    outer_event,
                    recipient_mailbox_secret=scalar,
                    expected_recipient_xonly_key=recipient,
                    expected_network=self._network,
                    expected_profile_id=self._policy.profile,
                    crypto=transport,
                )
            finally:
                del scalar
            if not (
                candidate.envelope.message_type == "handshake_init"
                and candidate.envelope.sender_session_key == candidate.seal_author_xonly_key
            ):
                raise LiveSessionStoreError("epoch frame is not a sender-bound init")  # noqa: TRY301
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - uniform, redacted refusal (RS-006)
            raise LiveSessionStoreError("epoch frame refused") from None
        return EpochInitiation(candidate.envelope_bytes, recipient)

    def expire_idle(self, *, now: int, idle_timeout: int) -> int:
        """Expire idle pre-economic sessions without discarding replay protection.

        A session idle for ``idle_timeout`` (reserved, accepted, or confirmed
        with nothing after the confirm) loses its key, messages, and conflict
        evidence (SQLite ``secure_delete``). Its ID stays in ``epoch_admissions``
        until its recipient epoch has durably retired. Accepted contracts never
        enter this deletion path. Returns how many sessions expired.
        """
        if not (type(now) is int and type(idle_timeout) is int and idle_timeout > 0):
            raise LiveSessionStoreError("expiry schedule unsupported")
        try:
            with self._write() as connection:
                _retire_epochs(connection, now)
                idle = [
                    (row[0],)
                    for row in connection.execute(
                        "SELECT session_id FROM sessions WHERE phase IN "
                        "('RESERVED', 'ACCEPT_COMMITTED', 'CONFIRMED') AND active_at <= ?",
                        (now - idle_timeout,),
                    )
                ]
                # Release before deletion: an idle session's open offer can never
                # be accepted again. Its payment hash stays reserved forever.
                connection.executemany(
                    "UPDATE economic_reservations SET state='RELEASED', release_evidence=? "
                    "WHERE session_id=? AND state='UNSENT' "
                    "AND session_id NOT IN (SELECT session_id FROM swaps)",
                    [(_release_evidence("expired-offer", expired_at=now), sid) for (sid,) in idle],
                )
                marked = connection.executemany(
                    "UPDATE epoch_admissions SET expired=1 WHERE session_id=?", idle
                ).rowcount
                if marked != len(idle):
                    # Deleting a session without its tombstone would make its
                    # ID admissible again; refuse rather than lose replay safety.
                    raise LiveSessionStoreError("epoch admission custody unavailable")  # noqa: TRY301
                for table in ("inbox", "outbox", "conflicts", "contract_keys", "sessions"):
                    connection.executemany(
                        f"DELETE FROM {table} WHERE session_id=?",  # noqa: S608 - fixed names
                        idle,
                    )
                connection.execute(
                    "DELETE FROM epoch_admissions WHERE expired=1 AND retire_after <= ?",
                    (_epoch_watermark(connection),),
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("session expiry refused") from None
        for (session_id,) in idle:
            self._reverse_negotiations.pop(session_id, None)
            attempt = self._reverse_proposals.pop(session_id, None)
            if attempt is not None and attempt.window is not None:
                attempt.window.abandon()
        return len(idle)

    def receiving_epochs(self, *, now: int) -> tuple[str, ...]:
        """Return every still-decodable epoch key, advertised or not."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT epoch_key FROM epochs WHERE retire_after > ? ORDER BY created_at DESC",
                    (max(now, _epoch_watermark(connection)),),
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("epoch keys unavailable") from None
        return tuple(row[0] for row in rows)

    def record_announcement(self, created_at: int) -> None:
        """Durably order an RS-005 announcement revision before publishing it.

        Revisions equal ``created_at`` and must strictly increase across
        restarts; a clock rollback is refused rather than published lower.
        """
        if type(created_at) is not int or created_at <= 0:
            raise LiveSessionStoreError("announcement time unsupported")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT created_at FROM announcements WHERE slot=1"
                ).fetchone()
                if row is not None and created_at <= row[0]:
                    raise LiveSessionStoreError("announcement revision would not increase")  # noqa: TRY301
                connection.execute(
                    "INSERT OR REPLACE INTO announcements VALUES (1, ?)", (created_at,)
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("announcement ordering refused") from None

    def answer_request(  # noqa: PLR0912, PLR0915 - one admission transaction
        self,
        request_document: bytes,
        *,
        responder: Responder,
        signer: EnvelopeSigner,
        now: int | None = None,
    ) -> RequestAnswer:
        """Admit one signed client request and durably record its signed answer.

        One transaction checks the client session-key signature and the
        contiguous sequence, calls the pure ``responder`` for the answer
        payload, signs it with the session key, and records both. Only then may
        the answer be published (via ``pending_outbox``). An exact replay,
        even with a fresh signature, returns the recorded answer. A different
        validly signed message reusing a message ID or sequence is kept as
        evidence and blocks the session. Anything unverifiable, out of order,
        or over budget is refused with no record and no reply.
        """
        now = int(time.time()) if now is None else now
        conflict = False
        reverse_origin: _ReverseNegotiationOrigin | None = None
        try:
            outer = _canonical_envelope(request_document)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT client_key, provider_session_key, phase, blocked, revision, "
                    "next_client_seq, next_provider_seq, transcript_digest "
                    "FROM sessions WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None and _session_expired(connection, outer.session_id):
                    raise SessionExpiredError("session expired")  # noqa: TRY301
                if row is None or row[2] not in OPEN_PHASES:
                    raise LiveSessionStoreError("no confirmed session")  # noqa: TRY301
                client, key, _, blocked, revision, client_seq, provider_seq, transcript = row
                if blocked:
                    raise SessionBlockedError("session blocked by conflict evidence")  # noqa: TRY301
                digest = verify_static_signed_envelope(
                    request_document,
                    expected_session_id=outer.session_id,
                    expected_profile=self._policy.profile,
                    expected_network=self._network,
                    expected_sender_key=client,
                    supported_features=self._policy.features,
                    crypto=self._crypto,
                ).hex()
                # Unlike a request, a cooperative result has no response
                # outbox and has its own conflict admission boundary.
                if outer.message_type == "action_result":
                    raise LiveSessionStoreError("request not admissible")  # noqa: TRY301
                seen = connection.execute(
                    "SELECT message_id, seq, unsigned_digest FROM inbox "
                    "WHERE session_id=? AND sender_key=? AND (message_id=? OR seq=?)",
                    (outer.session_id, client, outer.message_id, outer.sequence),
                ).fetchall()
                if seen:
                    if seen == [(outer.message_id, outer.sequence, digest)]:
                        if outer.message_type not in CLIENT_REQUEST_TYPES:
                            raise LiveSessionStoreError("request not admissible")  # noqa: TRY301
                        answer = connection.execute(
                            "SELECT message_id FROM outbox WHERE session_id=? AND in_reply_to=?",
                            (outer.session_id, outer.message_id),
                        ).fetchone()
                        return RequestAnswer(
                            outer.session_id, outer.message_id, answer[0], replay=True
                        )
                    _record_conflict(connection, outer.session_id, "request", request_document)
                    connection.execute(
                        "UPDATE sessions SET blocked=1, revision=revision + 1 WHERE session_id=?",
                        (outer.session_id,),
                    )
                    conflict = True
                else:
                    replied = None
                    if outer.in_reply_to is not None:
                        replied = connection.execute(
                            "SELECT canonical_bytes FROM outbox "
                            "WHERE session_id=? AND message_id=?",
                            (outer.session_id, outer.in_reply_to),
                        ).fetchone()
                    if not (
                        outer.sequence == client_seq
                        and outer.message_type in CLIENT_REQUEST_TYPES
                        and (outer.in_reply_to is None or replied is not None)
                        and client_seq - FIRST_REQUEST_SEQUENCE < MAX_REQUESTS_PER_SESSION
                    ):
                        raise LiveSessionStoreError("request not admissible")  # noqa: TRY301
                    (accept_bytes,) = connection.execute(
                        "SELECT accept_bytes FROM sessions WHERE session_id=?",
                        (outer.session_id,),
                    ).fetchone()
                    negotiated = HandshakeAcceptPayload.model_validate_json(
                        canonicalize(_canonical_envelope(accept_bytes).payload), strict=True
                    ).accept.required_features
                    cooperative = COOPERATIVE_CLAIM_FEATURE in negotiated
                    if (
                        outer.message_type == "quote_request"
                        and COOPERATIVE_CLAIM_FEATURE in self._policy.features
                        and not cooperative
                        and outer.profile_id != "ln-to-btc/v1"
                    ):
                        # Forward contracts remain cooperative. Reverse clients
                        # may explicitly negotiate a unilateral claim instead.
                        raise LiveSessionStoreError("request not admissible")  # noqa: TRY301
                    prior = tuple(
                        _canonical_envelope(document)
                        for (document,) in connection.execute(
                            "SELECT canonical_bytes FROM inbox WHERE session_id=? "
                            "AND sender_key=? AND seq>=? ORDER BY seq",
                            (outer.session_id, client, FIRST_REQUEST_SEQUENCE),
                        )
                    )
                    context = RequestContext(
                        handshake_hash=transcript,
                        provider_contract_key=self._contract_key(connection, outer.session_id),
                        replied_to=None if replied is None else _canonical_envelope(replied[0]),
                        swap=_swap(connection, outer.session_id),
                        economic_capacity_available=self._economic_capacity(
                            connection, outer.session_id
                        ),
                        is_payment_hash_reserved=lambda digest: (
                            connection.execute(
                                "SELECT 1 FROM payment_hashes WHERE payment_hash=?", (digest,)
                            ).fetchone()
                            is not None
                        ),
                        cooperative=cooperative,
                        network_fees=FEE_POLICY_FEATURE in negotiated,
                        rebates_committed_sat=_rebates_committed(connection, now),
                    )
                    reply = responder(outer, prior, context)
                    if ledger_amount(reply.rebate_sat) is None or (
                        reply.rebate_sat
                        and (reply.message_type != "terms_offer" or reply.payment_hash is None)
                    ):
                        raise LiveSessionStoreError("request refused")  # noqa: TRY301
                    if reply.effect is not None:
                        _apply_effect(connection, outer, reply.effect, replied, now)
                        if isinstance(reply.effect, AcceptSwap):
                            self._admit_claim_arbitration(connection, outer, reply, replied, now)
                            origin = self._reverse_negotiations.get(outer.session_id)
                            if (
                                origin is not None
                                and origin.contract_hash is None
                                and replied is not None
                                and outer.message_type == "terms_accept"
                                and reply.message_type == "ack"
                                and origin.handshake_hash == transcript
                            ):
                                terms = _offer_terms(replied[0])
                                if (
                                    terms.profile_id == "ln-to-btc/v1"
                                    and COOPERATIVE_CLAIM_FEATURE in terms.required_features
                                    and contract_hash(terms).hex() == reply.effect.contract_hash
                                ):
                                    initiation_bytes = connection.execute(
                                        "SELECT init_bytes FROM sessions WHERE session_id=?",
                                        (outer.session_id,),
                                    ).fetchone()[0]
                                    initiation = parse_model_json(
                                        HandshakeInit,
                                        canonicalize(_canonical_envelope(initiation_bytes).payload),
                                    )
                                    accepted = parse_model_json(
                                        HandshakeAcceptPayload,
                                        canonicalize(
                                            _canonical_envelope(origin.accept_document).payload
                                        ),
                                    )
                                    require_supported_contract_features(
                                        terms, initiation, accepted.accept
                                    )
                                    reverse_origin = replace(
                                        origin,
                                        contract_hash=reply.effect.contract_hash,
                                        acceptance_document=request_document,
                                    )
                    if reply.payment_hash is not None:
                        connection.execute(
                            "INSERT INTO payment_hashes VALUES (?, ?, ?)",
                            (reply.payment_hash, outer.session_id, now),
                        )
                        self._reserve_offer(connection, outer.session_id, reply.payment_hash)
                    scalar, _ = self._unseal(connection, outer.session_id)
                    try:
                        response = self._signed_envelope(
                            outer, key, provider_seq, reply, scalar, signer, outer.message_id
                        )
                    finally:
                        del scalar
                    admitted = revision + 1
                    connection.execute(
                        "INSERT INTO inbox VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            outer.session_id,
                            client,
                            outer.message_id,
                            outer.sequence,
                            digest,
                            request_document,
                            admitted,
                        ),
                    )
                    connection.execute(
                        "INSERT INTO outbox VALUES (?, ?, ?, ?, ?, ?, 'PENDING')",
                        (
                            response.message_id,
                            outer.session_id,
                            provider_seq,
                            outer.message_id,
                            canonicalize(response.model_dump(mode="json")),
                            admitted,
                        ),
                    )
                    connection.execute(
                        "UPDATE sessions SET revision=?, next_client_seq=?, "
                        "next_provider_seq=?, active_at=? WHERE session_id=?",
                        (admitted, client_seq + 1, provider_seq + 1, now, outer.session_id),
                    )
                    if reply.payment_hash is not None and reply.message_type == "terms_offer":
                        economics = _offer_economics(canonicalize(response.model_dump(mode="json")))
                        _record_ledger(
                            connection,
                            outer.session_id,
                            now,
                            OFFERED,
                            None if economics is None else economics.volume_sat,
                        )
                        if reply.rebate_sat:
                            _record_ledger(
                                connection, outer.session_id, now, REBATE, reply.rebate_sat
                            )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents or crypto details
            raise LiveSessionStoreError("request refused") from None
        if conflict:
            raise SessionBlockedError("conflicting signed request is durable")
        if reverse_origin is not None:
            # Native allocation, deadlines, LND settlement, chain evidence, and
            # proposal admission remain separate requirements. Do not publish a
            # provenance transition inside the potentially uncertain transaction.
            self._reverse_negotiations[outer.session_id] = reverse_origin
        return RequestAnswer(outer.session_id, outer.message_id, response.message_id, replay=False)

    def _has_original_reverse_negotiation(self, session_id: str, digest: str) -> bool:
        """Check only this owner's uninterrupted negotiation provenance.

        No signed session expiry exists. This supplies no deadline, payment,
        nonce, chain, or signing authority. Missing process memory (including
        after restart) denies provenance without initiating any work.
        The future admission must independently enforce original cooperation
        deadlines and every other financial prerequisite under the shared gate.
        """
        origin = self._reverse_negotiations.get(session_id)
        if (
            not self.owner_is_open
            or origin is None
            or origin.contract_hash != digest
            or origin.acceptance_document is None
        ):
            return False
        with self._write() as connection:
            row = connection.execute(
                "SELECT s.accept_bytes, s.transcript_digest, s.blocked, w.contract_hash, "
                "w.terms_accept FROM sessions s JOIN swaps w ON w.session_id=s.session_id "
                "WHERE s.session_id=?",
                (session_id,),
            ).fetchone()
            return self._matches_reverse_negotiation(session_id, digest, row)

    def _matches_reverse_negotiation(
        self, session_id: str, digest: str, retained: tuple[bytes, str, int, str, bytes] | None
    ) -> bool:
        origin = self._reverse_negotiations.get(session_id)
        return bool(
            self.owner_is_open
            and origin is not None
            and origin.contract_hash == digest
            and origin.acceptance_document is not None
            and retained
            == (
                origin.accept_document,
                origin.handshake_hash,
                0,
                digest,
                origin.acceptance_document,
            )
        )

    def _admit_claim_arbitration(
        self,
        connection: sqlite3.Connection,
        request: Envelope,
        reply: Answer,
        replied: tuple[bytes] | None,
        now: int,
    ) -> None:
        """Authenticate a newly featured acceptance; mark only BTC to LN claims.

        This runs in the same write transaction as first acceptance. An
        ADMITTED row alone can never delay the existing unilateral claim,
        allocate a nonce or infer eligibility for an older accepted swap.
        """
        if replied is None:
            return  # existing _apply_effect rejects this before returning
        offer = _canonical_envelope(replied[0])
        if offer.message_type != "terms_offer":
            return  # existing unfeatured acceptance behavior is unchanged
        payload = parse_model_json(TermsOfferPayload, canonicalize(offer.payload))
        offered = payload.terms
        terms = offered.contract_terms
        try:
            row = connection.execute(
                "SELECT init_bytes,accept_bytes,transcript_digest,client_key,"
                "provider_session_key FROM sessions WHERE session_id=?",
                (request.session_id,),
            ).fetchone()
            if row is None or row[1] is None:
                raise ValueError("featured session transcript unavailable")  # noqa: TRY301
            init_bytes, accept_bytes, transcript, client_key, provider_key = row
            initiation = parse_model_json(
                HandshakeInit, canonicalize(_canonical_envelope(init_bytes).payload)
            )
            acceptance = parse_model_json(
                HandshakeAccept,
                canonicalize(_canonical_envelope(accept_bytes).payload["accept"]),
            )
            if not any(
                COOPERATIVE_CLAIM_FEATURE in feature_set
                for feature_set in (
                    initiation.required_features,
                    acceptance.required_features,
                    terms.required_features,
                )
            ):
                return  # the previously accepted, fully unfeatured contract
            accepted = parse_model_json(TermsAcceptPayload, canonicalize(request.payload))
            signed = accepted.acceptance
            acceptance.validate_against(initiation, supported_features=self._policy.features)
            require_supported_contract_features(terms, initiation, acceptance)
            digest = contract_hash(terms).hex()
            transcript_hash = handshake_hash(initiation, acceptance).hex()
            if (
                COOPERATIVE_CLAIM_FEATURE not in self._policy.features
                or request.message_type != "terms_accept"
                or request.in_reply_to != offer.message_id
                or request.session_id != initiation.session_id
                or offer.session_id != initiation.session_id
                or request.profile_id != self._policy.profile
                or offer.profile_id != request.profile_id
                or terms.profile_id != request.profile_id
                or initiation.profile_id != request.profile_id
                or acceptance.profile_id != request.profile_id
                or terms.network_identity != self._network
                or initiation.network_identity != self._network
                or acceptance.network_identity != self._network
                or request.sender_session_key != client_key
                or request.sender_session_key != initiation.client_session_xonly_key
                or offer.sender_session_key != provider_key
                or offer.sender_session_key != acceptance.provider_session_xonly_key
                or offered.handshake_hash != transcript_hash
                or transcript != transcript_hash
                or offered.contract_hash != digest
                or offer.contract_hash != digest
                or request.contract_hash != digest
                or reply.effect != AcceptSwap(digest)
                or reply.message_type != "ack"
                or reply.contract_hash != digest
                or reply.payment_hash is not None
                or reply.payload != {"acknowledged_message_id": request.message_id}
                or signed.contract_hash != digest
                or signed.handshake_hash != transcript_hash
                or signed.session_id != request.session_id
                or signed.client_session_xonly_key != client_key
                or signed.provider_session_xonly_key != provider_key
                or now > terms.terms_expiry
            ):
                raise ValueError("featured acceptance differs")  # noqa: TRY301
            self._crypto.schnorr_verify(
                bytes.fromhex(acceptance.provider_identity_xonly_key),
                provider_terms_hash(offered),
                bytes.fromhex(payload.provider_terms_signature),
            )
            self._crypto.schnorr_verify(
                bytes.fromhex(client_key),
                client_acceptance_hash(signed),
                bytes.fromhex(accepted.client_acceptance_signature),
            )
            if request.profile_id == "btc-to-ln/v1":
                # Only the provider claims BTC to LN swaps. The LN to BTC
                # client claims, so its acceptance is authenticated here but
                # has no provider claim to arbitrate.
                connection.execute(
                    "INSERT INTO claim_arbitration (session_id,contract_hash,version,state) "
                    "VALUES (?,?,1,'ADMITTED')",
                    (request.session_id, digest),
                )
        except Exception:  # noqa: BLE001 - no signed acceptance or local policy oracle
            raise LiveSessionStoreError("cooperative admission refused") from None

    def _authenticated_reverse_agreement(
        self, row: tuple[Any, ...], session_id: str
    ) -> tuple[HandshakeInit, HandshakeAccept, ContractTerms]:
        """Authenticate archived agreement without proposal, time, or fresh authority."""
        (
            client,
            provider,
            phase,
            init_bytes,
            accept_bytes,
            transcript,
            digest,
            offer_bytes,
            accepted_bytes,
        ) = row
        if phase != "ACCEPTED" or self._policy.profile != "ln-to-btc/v1":
            raise LiveSessionStoreError("no accepted reverse context")
        initiation = parse_model_json(
            HandshakeInit, canonicalize(_canonical_envelope(init_bytes).payload)
        )
        acceptance = parse_model_json(
            HandshakeAcceptPayload, canonicalize(_canonical_envelope(accept_bytes).payload)
        ).accept
        offer = _canonical_envelope(offer_bytes)
        offered = parse_model_json(TermsOfferPayload, canonicalize(offer.payload))
        terms = offered.terms.contract_terms
        accepted = _canonical_envelope(accepted_bytes)
        signed_acceptance = parse_model_json(TermsAcceptPayload, canonicalize(accepted.payload))
        acceptance.validate_against(initiation, supported_features=self._policy.features)
        require_supported_contract_features(terms, initiation, acceptance)
        signed = signed_acceptance.acceptance
        if (
            terms.profile_id != "ln-to-btc/v1"
            or initiation.session_id != session_id
            or initiation.profile_id != terms.profile_id
            or initiation.network_identity != terms.network_identity
            or terms.network_identity != self._network
            or client != initiation.client_session_xonly_key
            or provider != acceptance.provider_session_xonly_key
            or handshake_hash(initiation, acceptance).hex() != transcript
            or offered.terms.handshake_hash != transcript
            or contract_hash(terms).hex() != digest
            or offered.terms.contract_hash != digest
            or offer.contract_hash != digest
            or accepted.message_type != "terms_accept"
            or accepted.in_reply_to != offer.message_id
            or accepted.contract_hash != digest
            or signed.contract_hash != digest
            or signed.handshake_hash != transcript
            or signed.session_id != session_id
            or signed.client_session_xonly_key != client
            or signed.provider_session_xonly_key != provider
        ):
            raise LiveSessionStoreError("reverse agreement context differs")
        for retained, sender in ((offer_bytes, provider), (accepted_bytes, client)):
            verify_static_signed_envelope(
                retained,
                expected_session_id=session_id,
                expected_profile=self._policy.profile,
                expected_network=self._network,
                expected_sender_key=sender,
                supported_features=self._policy.features,
                crypto=self._crypto,
            )
        self._crypto.schnorr_verify(
            bytes.fromhex(acceptance.provider_identity_xonly_key),
            provider_terms_hash(offered.terms),
            bytes.fromhex(offered.provider_terms_signature),
        )
        self._crypto.schnorr_verify(
            bytes.fromhex(client),
            client_acceptance_hash(signed),
            bytes.fromhex(signed_acceptance.client_acceptance_signature),
        )
        return initiation, acceptance, terms

    def _reverse_repayment_binding(self, session_id: str) -> InvoiceBinding | None:
        """Return repayment classification/data, never proof that any debt exists.

        Only exact epoch-only commitments retain legacy routing.
        Their opaque client acceptance stays outside legacy classification.
        All other contexts require fully authenticated featured agreement;
        partial, inconsistent, unknown, or unsupported context never downgrades.
        No Core, live proposal/window, sequence, or knowledge backfill is needed.
        """
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT s.client_key,s.provider_session_key,s.phase,s.init_bytes,"
                    "s.accept_bytes,s.transcript_digest,w.contract_hash,w.terms_offer,"
                    "w.terms_accept FROM sessions s JOIN swaps w ON w.session_id=s.session_id "
                    "WHERE s.session_id=?",
                    (session_id,),
                ).fetchone()
                if row is None:
                    raise ValueError("repayment context absent")  # noqa: TRY301
                initiation = _canonical_envelope(row[3])
                acceptance = _canonical_envelope(row[4])
                offer = _canonical_envelope(row[7])
                inner_init = initiation.payload["required_features"]
                accepted_payload = acceptance.payload["accept"]
                offered_payload = offer.payload["terms"]
                if not isinstance(accepted_payload, dict) or not isinstance(offered_payload, dict):
                    raise TypeError("repayment feature context unsupported")  # noqa: TRY301
                contract_payload = offered_payload["contract_terms"]
                if not isinstance(contract_payload, dict):
                    raise TypeError("repayment contract context unsupported")  # noqa: TRY301
                inner_accept = accepted_payload["required_features"]
                inner_terms = contract_payload["required_features"]
                # Parse the closed terms object without introducing historical
                # signature or relationship checks into trusted legacy repayment.
                terms = _offer_terms(row[7])
                if (
                    type(inner_terms) is list
                    and inner_terms == []
                    and type(inner_init) is list
                    and type(inner_accept) is list
                    and inner_init == inner_accept
                    and inner_init == [EPOCH_SESSION_FEATURE]
                    and initiation.required_features == ()
                    and acceptance.required_features == ()
                    and offer.required_features == ()
                ):
                    return None
                _, _, terms = self._authenticated_reverse_agreement(row, session_id)
                if COOPERATIVE_CLAIM_FEATURE not in terms.required_features:
                    raise ValueError("repayment feature unsupported")  # noqa: TRY301
                return terms.invoice_binding
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001, S110 - no archived signature or private-context oracle
            pass
        raise LiveSessionStoreError("reverse repayment context refused")

    def _authenticated_reverse_preimage(
        self, connection: sqlite3.Connection, document: bytes
    ) -> tuple[Envelope, CooperativeClaimPropose, ContractTerms]:
        """Authenticate historical knowledge, never current economic permission.

        No sequence, blocked state, process-local negotiation, attempt, time,
        height, funding, or native-plan eligibility is inferred. This validates
        archived signatures and original roles independently of prior admission.
        """
        outer = _canonical_envelope(document)
        row = connection.execute(
            "SELECT s.client_key,s.provider_session_key,s.phase,s.init_bytes,"
            "s.accept_bytes,s.transcript_digest,w.contract_hash,w.terms_offer,"
            "w.terms_accept FROM sessions s JOIN swaps w ON w.session_id=s.session_id "
            "WHERE s.session_id=?",
            (outer.session_id,),
        ).fetchone()
        if row is None or row[2] != "ACCEPTED" or self._policy.profile != "ln-to-btc/v1":
            raise LiveSessionStoreError("no accepted reverse context")
        client = row[0]
        verify_static_signed_envelope(
            document,
            expected_session_id=outer.session_id,
            expected_profile=self._policy.profile,
            expected_network=self._network,
            expected_sender_key=client,
            supported_features=self._policy.features,
            crypto=self._crypto,
        )
        initiation, acceptance, terms = self._authenticated_reverse_agreement(row, outer.session_id)
        payload = check_cooperative_action_context(outer, terms, initiation, acceptance)
        if (
            not isinstance(payload, CooperativeClaimPropose)
            or hashlib.sha256(bytes.fromhex(payload.payment_preimage)).hexdigest()
            != terms.invoice_binding.payment_hash
        ):
            raise LiveSessionStoreError("reverse preimage context differs")
        return outer, payload, terms

    def _retain_reverse_preimage_evidence(
        self, document: bytes, *, operation: ReverseOperation, now: int
    ) -> ReversePreimageEvidenceReceipt:
        """Commit first authenticated knowledge independently of later admission.

        No inbox/outbox, burn, revision, refund blocking, debt, RPC, or signing
        mutation occurs. Expiry and an invalid native plan do not erase matching
        preimage knowledge. Audit time is not proof of timely disclosure. Retained
        evidence is reauthenticated before returning an immutable old receipt.
        """
        self.reverse_operations.check(operation)
        if type(now) is not int or now < 0:
            raise LiveSessionStoreError("reverse evidence audit time unsupported")
        try:
            with self._write() as connection:
                outer, payload, _ = self._authenticated_reverse_preimage(connection, document)
                prior = connection.execute(
                    "SELECT document,received_at FROM reverse_preimage_evidence WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if prior is None:
                    self.reverse_operations.check(operation)
                    connection.execute(
                        "INSERT INTO reverse_preimage_evidence VALUES (?,?,?)",
                        (outer.session_id, document, now),
                    )
                    receipt = ReversePreimageEvidenceReceipt(
                        outer.session_id, outer.message_id, now, replay=False
                    )
                else:
                    retained, known, _ = self._authenticated_reverse_preimage(connection, prior[0])
                    if (
                        retained.session_id != outer.session_id
                        or known.payment_preimage != payload.payment_preimage
                    ):
                        raise ValueError("retained reverse evidence differs")  # noqa: TRY301
                    receipt = ReversePreimageEvidenceReceipt(
                        retained.session_id, retained.message_id, prior[1], replay=True
                    )
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001, S110 - sanitized refusal, never log private input
            pass
        else:
            return receipt
        raise LiveSessionStoreError("reverse preimage evidence refused")

    def _reverse_preimage_evidence(self, session_id: str) -> bytes | None:
        """Read reauthenticated private knowledge, not a financial permission.

        Missing evidence is unknown. Unsupported or malformed evidence is
        retained for operator review; ordinary recovery and debt do not query it.
        No scan, lookup, settlement, payment retry, or native work is scheduled.
        """
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT document FROM reverse_preimage_evidence WHERE session_id=?",
                    (session_id,),
                ).fetchone()
                if row is None:
                    return None
                outer, _, _ = self._authenticated_reverse_preimage(connection, row[0])
                if outer.session_id != session_id:
                    raise ValueError("retained reverse evidence names another session")  # noqa: TRY301
                return bytes(row[0])
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001, S110 - sanitized refusal, never log private input
            pass
        raise LiveSessionStoreError("reverse preimage evidence unavailable")

    def _reverse_reservation_binding(  # noqa: PLR0913 - one exact signed funding/proposal association
        self,
        connection: sqlite3.Connection,
        outer: Envelope,
        payload: CooperativeClaimPropose,
        terms: ContractTerms,
        *,
        provider: str,
        txid: str,
        vout: int,
        raw: bytes,
    ) -> tuple[bytes, FundingBindingTransactionMatch, FundingBinding, CooperativeClaimPlan]:
        """Rebuild immutable reservation bytes inside an authenticated owner write.

        Native static funding/plan verification is not publication, current
        unspentness, payment, nonce custody, or permission to sign or settle.
        """
        digest = contract_hash(terms).hex()
        funding_messages = [
            _canonical_envelope(item[0])
            for item in connection.execute(
                "SELECT canonical_bytes FROM outbox WHERE session_id=?", (outer.session_id,)
            )
        ]
        funding_messages = [
            item for item in funding_messages if item.message_type == "funding_binding"
        ]
        if len(funding_messages) != 1:
            raise LiveSessionStoreError("reverse funding association ambiguous")
        funding_message = funding_messages[0]
        funding_bytes = canonicalize(funding_message.model_dump(mode="json"))
        funding_digest = verify_static_signed_envelope(
            funding_bytes,
            expected_session_id=outer.session_id,
            expected_profile=self._policy.profile,
            expected_network=self._network,
            expected_sender_key=provider,
            supported_features=self._policy.features,
            crypto=self._crypto,
        ).hex()
        funding_payload = parse_model_json(
            FundingBindingPayload, canonicalize(funding_message.payload)
        )
        binding = funding_payload.binding
        if (
            funding_message.contract_hash != digest
            or binding.contract_hash != digest
            or binding.binding_revision != 0
            or binding.replaces_txid is not None
            or binding.funder_role != "provider"
            or binding.funding_txid != txid
            or binding.contract_vout != vout
            or bytes.fromhex(funding_payload.funding_transaction) != raw
        ):
            raise LiveSessionStoreError("reverse funding association differs")
        self._crypto.schnorr_verify(
            bytes.fromhex(provider),
            funding_binding_hash(binding),
            bytes.fromhex(funding_payload.funding_binding_signature),
        )
        keys = cast("TaprootKeyOperations", self._public_keys)
        match = check_funding_binding_transaction(raw, binding, terms, keys=keys)
        funding = FundingOutput(
            bytes.fromhex(txid),
            vout,
            int(binding.contract_value_sat),
            bytes.fromhex(binding.contract_script_pubkey),
        )
        authorization = UnilateralAuthorization.from_terms(terms, funding, "claim", keys=keys)
        plan = verify_cooperative_claim_proposal(
            bytes.fromhex(payload.unsigned_transaction), authorization
        )
        taproot = reconstruct_taproot_contract(terms, keys=keys)
        immutable = canonicalize(
            {
                "version": 2,
                "kind": "reverse-proposal-reservation",
                "session_id": outer.session_id,
                "cooperation_id": payload.cooperation_id,
                "contract_hash": digest,
                "proposal_message_id": outer.message_id,
                "proposal_unsigned_digest": unsigned_envelope_hash(outer).hex(),
                "funding_message_id": funding_message.message_id,
                "funding_unsigned_digest": funding_digest,
                "funding_binding_hash": funding_binding_hash(binding).hex(),
                "network_identity": terms.network_identity.model_dump(mode="json"),
                "claimant": terms.claimant,
                "user_key": terms.client_contract_compressed_key,
                "provider_key": terms.provider_contract_compressed_key,
                "tap_tweak": taproot.tap_tweak.hex(),
                "funding_txid": txid,
                "funding_vout": vout,
                "funding_value_sat": funding.value_sat,
                "funding_script_pubkey": funding.script_pubkey.hex(),
                "unsigned_transaction": plan.base_transaction.hex(),
                "signature_hash": plan.signature_hash.hex(),
                "fee_sat": plan.fee_sat,
                "deadline_at": payload.deadline_at,
                "deadline_height": payload.deadline_height,
            }
        )
        return immutable, match, binding, plan

    def _reverse_live_proposal_context(
        self,
        document: bytes,
        *,
        operation: ReverseOperation,
        purpose: Literal["acquisition", "repayment", "paid-signing"],
    ) -> _ReverseLiveProposalContext:
        """Preflight original read inputs, never financial or signing authority.

        Require original owner memory and exact native-valid burned reservation.
        Acquisition requires FUNDED without debt. Paid-signing requires local
        SETTLED with the exact retained preimage, but proves neither independent
        repayment provenance nor current Own-LND payment or signing permission.
        Fresh real positive bound settlement, chain, fees, and original-window
        evidence remain mandatory before any future signing effect.
        No RPC or lifecycle write occurs.
        Failure after identifying the original attempt abandons its window.
        """
        self.reverse_operations.check(operation)
        if type(purpose) is not str or purpose not in ("acquisition", "repayment", "paid-signing"):
            raise LiveSessionStoreError("reverse proposal context purpose refused")
        context: _ReverseLiveProposalContext | None = None
        try:
            with self._write() as connection:
                context = self._reverse_live_context_in_connection(
                    connection, document, operation=operation, purpose=purpose
                )
        except StaleOwnerError:
            if context is not None:
                context.window.abandon()
            raise
        except Exception:  # noqa: BLE001 - no connection or archived-context oracle
            if context is not None:
                context.window.abandon()
        else:
            return context
        raise LiveSessionStoreError("reverse proposal live context refused")

    def _reverse_live_context_in_connection(
        self,
        connection: sqlite3.Connection,
        document: bytes,
        *,
        operation: ReverseOperation,
        purpose: Literal["acquisition", "repayment", "paid-signing"],
    ) -> _ReverseLiveProposalContext:
        """Check original context inside the caller's explicit owner transaction."""
        self.reverse_operations.check(operation)
        if type(purpose) is not str or purpose not in ("acquisition", "repayment", "paid-signing"):
            raise LiveSessionStoreError("reverse proposal context purpose refused")
        if connection is not self._connection or not connection.in_transaction:
            raise LiveSessionStoreError("reverse proposal context connection refused")
        attempt: _ReverseProposalAttempt | None = None
        try:
            outer, payload, terms = self._authenticated_reverse_preimage(connection, document)
            candidate = self._reverse_proposals.get(outer.session_id)
            if (
                candidate is None
                or candidate.window is None
                or candidate.message_id != outer.message_id
                or candidate.unsigned_digest != unsigned_envelope_hash(outer).hex()
                or candidate.cooperation_id != payload.cooperation_id
            ):
                raise ValueError("original reverse reservation absent")  # noqa: TRY301
            attempt = candidate
            row = connection.execute(
                "SELECT s.accept_bytes,s.transcript_digest,s.blocked,w.contract_hash,"
                "w.terms_accept,s.provider_session_key,w.state,w.preimage,"
                "w.funding_txid,w.funding_vout,w.funding_tx,w.refund_txid,w.refund_tx "
                "FROM sessions s JOIN swaps w ON w.session_id=s.session_id "
                "WHERE s.session_id=?",
                (outer.session_id,),
            ).fetchone()
            if (
                row is None
                or not self._matches_reverse_negotiation(outer.session_id, row[3], row[:5])
                # A client may claim before the provider's own funding reaches
                # the signed depth: FUNDING_SENT cooperates like FUNDED.
                or (
                    purpose == "acquisition"
                    and (row[6] not in ("FUNDING_SENT", "FUNDED") or row[7] is not None)
                )
                or (
                    purpose == "repayment"
                    and (
                        row[6] not in ("FUNDING_SENT", "FUNDED", "SETTLED")
                        or row[7] != payload.payment_preimage
                    )
                )
                or (
                    purpose == "paid-signing"
                    and (row[6] != "SETTLED" or row[7] != payload.payment_preimage)
                )
                or type(row[8]) is not str
                or type(row[9]) is not int
                or type(row[10]) is not bytes
                or row[11] is not None
                or row[12] is not None
            ):
                raise ValueError("reverse acquisition lifecycle refused")  # noqa: TRY301
            expected, match, binding, plan = self._reverse_reservation_binding(
                connection,
                outer,
                payload,
                terms,
                provider=row[5],
                txid=row[8],
                vout=row[9],
                raw=row[10],
            )
            burned = connection.execute(
                "SELECT session_id,owner_generation,binding,state,deadline_at,local_nonce,"
                "peer_nonce,partial_signature,nonce_response_id,partial_response_id "
                "FROM cooperation_attempts WHERE cooperation_id=?",
                (bytes.fromhex(payload.cooperation_id),),
            ).fetchone()
            if burned != (
                outer.session_id,
                self._generation,
                expected,
                "BURNED",
                payload.deadline_at,
                None,
                None,
                None,
                None,
                None,
            ):
                raise ValueError("reverse acquisition reservation differs")  # noqa: TRY301
            self.reverse_operations.check(operation)
            candidate.window.evidence_time()
            return _ReverseLiveProposalContext(terms, binding, candidate.window, match, plan)
        except StaleOwnerError:
            if attempt is not None and attempt.window is not None:
                attempt.window.abandon()
            raise
        except Exception:  # noqa: BLE001 - no archived preimage or native-context oracle
            if attempt is not None and attempt.window is not None:
                attempt.window.abandon()
        raise LiveSessionStoreError("reverse proposal live context refused")

    def _check_reverse_paid_evidence(
        self,
        connection: sqlite3.Connection,
        document: bytes,
        *,
        operation: ReverseOperation,
        evidence: _ReversePaidProposalEvidence,
    ) -> _ReverseLiveProposalContext:
        """Revalidate same-operation paid observations inside an explicit transaction.

        This does not prove stronger-query provenance, clock-domain origin, or
        atomicity. Trusted runtime must collect the actual batch itself. No RPC,
        nonce, partial signature, reply, or lifecycle update occurs here.
        Final native context validation is charged to the original interval.
        """
        self.reverse_operations.check(operation)
        if (
            type(evidence) is not _ReversePaidProposalEvidence
            or evidence.operation is not operation
            or type(evidence.context) is not _ReverseLiveProposalContext
            or connection is not self._connection
            or not connection.in_transaction
        ):
            raise LiveSessionStoreError("reverse paid evidence operation refused")
        original_window = evidence.context.window
        try:
            configured_floor_sat = evidence.configured_floor_sat
            allow_regtest_fixed_fee = evidence.allow_regtest_fixed_fee
            if (
                type(configured_floor_sat) is not int
                or not 0 < configured_floor_sat <= MAX_SATS
                or type(allow_regtest_fixed_fee) is not bool
                or (allow_regtest_fixed_fee and self._network.name != "regtest")
            ):
                raise ValueError("reverse cooperative fee configuration refused")  # noqa: TRY301
            final_context = self._reverse_live_context_in_connection(
                connection, document, operation=operation, purpose="paid-signing"
            )
            binding, terms = final_context.binding, final_context.terms
            core, invoice, policy = evidence.core, evidence.invoice, evidence.policy
            if (
                final_context != evidence.context
                or type(core) is not CooperativeClaimOutpoint
                or type(core.static_match) is not type(final_context.static_match)
                or core.static_match != final_context.static_match
                or core.network_identity != terms.network_identity
                or core.funding_txid != binding.funding_txid
                or type(core.funding_vout) is not int
                or core.funding_vout != binding.contract_vout
                or type(core.funding_value_sat) is not int
                or core.funding_value_sat != int(binding.contract_value_sat)
                or type(core.funding_script_pubkey) is not bytes
                or core.funding_script_pubkey != bytes.fromhex(binding.contract_script_pubkey)
                or _reverse_funding_sample_refused(core, terms)
                or type(invoice) is not BoundHoldInvoiceObservation
                or invoice.network != terms.network_identity
                or invoice.payment_hash != terms.invoice_binding.payment_hash
                or invoice.bolt11_sha256 != terms.invoice_binding.bolt11_sha256
                or invoice.node_pubkey != terms.invoice_binding.payee_compressed_pubkey
                or invoice.status.state != "SETTLED"
                or type(invoice.last_lnd_height) is not int
                or (invoice.last_lnd_height, invoice.last_lnd_block_hash)
                != (core.tip_height, core.tip_hash)
                or type(policy) is not CooperativeFeePolicy
                or policy.network_identity != terms.network_identity
                or type(policy.tip_height) is not int
                or (policy.tip_height, policy.tip_hash) != (core.tip_height, core.tip_hash)
                or type(policy.confirmation_blocks) is not int
                or policy.confirmation_blocks != terms.timing_policy.claim_confirmation_blocks
                or any(
                    type(rate) is not int or not 0 <= rate < SATS_PER_BTC
                    for rate in (policy.min_relay_sat_kvb, policy.mempool_min_sat_kvb)
                )
                or type(policy.estimate_blocks) is not int
                or not 0 <= policy.estimate_blocks <= MAX_ESTIMATE_TARGET
                or (policy.estimate_sat_kvb is None and not allow_regtest_fixed_fee)
                or (
                    policy.estimate_sat_kvb is not None
                    and (
                        type(policy.estimate_sat_kvb) is not int
                        or not 0 < policy.estimate_sat_kvb < SATS_PER_BTC
                        or not 1 <= policy.estimate_blocks <= policy.confirmation_blocks
                    )
                )
            ):
                raise ValueError("reverse paid evidence differs")  # noqa: TRY301
            plan = final_context.plan
            vsize = (4 * len(plan.base_transaction) + 68 + 3) // 4
            economics = terms.economics
            floor = policy.fee_floor_sat(
                vsize=vsize,
                configured_floor_sat=configured_floor_sat,
                pays_signed_reserve=isinstance(economics, LnToBtcEconomics)
                and plan.fee_sat == int(economics.claim_fee_reserve_sat),
            )
            if plan.fee_sat < floor:
                raise ValueError("reverse cooperative fee below floor")  # noqa: TRY301
            self.reverse_operations.check(operation)
            original_window.check(tip_height=core.tip_height)
            original_window.check_evidence_interval(
                started_at=evidence.started_at, completed_at=evidence.completed_at
            )
        except StaleOwnerError:
            original_window.abandon()
            raise
        except Exception:  # noqa: BLE001 - no archived preimage, plan, or backend oracle
            original_window.abandon()
        else:
            return final_context
        raise LiveSessionStoreError("reverse paid proposal preflight refused")

    def _reverse_signed_reply_replay(
        self,
        document: bytes,
        *,
        operation: ReverseOperation,
        transaction: sqlite3.Connection | None = None,
    ) -> bytes | None:
        """Return exact authenticated archived bytes, never delivery or signing authority.

        Recognized unfinished/absent attempts yield no artifact and authorize
        no repair, regeneration, backend work, or clock/window reconstruction.
        Completed replay authenticates historical association, not independent
        native-plan or partial correctness. The original committing writer
        established those invariants before signing and archiving the response.
        """
        self.reverse_operations.check(operation)
        try:
            with self._write() if transaction is None else nullcontext(transaction) as connection:
                outer, proposal, terms = self._authenticated_reverse_preimage(connection, document)
                digest = unsigned_envelope_hash(outer).hex()
                admitted = connection.execute(
                    "SELECT sender_key,seq,unsigned_digest,canonical_bytes FROM inbox "
                    "WHERE session_id=? AND message_id=?",
                    (outer.session_id, outer.message_id),
                ).fetchone()
                if (
                    admitted is None
                    or admitted[:3] != (outer.sender_session_key, outer.sequence, digest)
                    or unsigned_envelope_hash(_canonical_envelope(admitted[3])).hex() != digest
                ):
                    raise ValueError("reverse replay request differs")  # noqa: TRY301
                row = connection.execute(
                    "SELECT session_id,binding,state,local_nonce,peer_nonce,partial_signature,"
                    "nonce_response_id,partial_response_id FROM cooperation_attempts "
                    "WHERE cooperation_id=?",
                    (bytes.fromhex(proposal.cooperation_id),),
                ).fetchone()
                if row is None:
                    return None
                if row[0] != outer.session_id:
                    raise ValueError("reverse replay attempt differs")  # noqa: TRY301
                if row[2] in ("BURNED", "NONCE_READY", "SIGNING", "ABANDONED"):
                    return None
                if row[2] != "COMPLETE":
                    raise ValueError("reverse replay state unsupported")  # noqa: TRY301
                bound = parse_json_strict(row[1])
                fields = {
                    "version",
                    "kind",
                    "session_id",
                    "cooperation_id",
                    "contract_hash",
                    "proposal_message_id",
                    "proposal_unsigned_digest",
                    "funding_message_id",
                    "funding_unsigned_digest",
                    "funding_binding_hash",
                    "network_identity",
                    "claimant",
                    "user_key",
                    "provider_key",
                    "tap_tweak",
                    "funding_txid",
                    "funding_vout",
                    "funding_value_sat",
                    "funding_script_pubkey",
                    "unsigned_transaction",
                    "signature_hash",
                    "fee_sat",
                    "deadline_at",
                    "deadline_height",
                }
                if (
                    not isinstance(bound, dict)
                    or set(bound) != fields
                    or canonicalize(bound) != row[1]
                    or type(bound["version"]) is not int
                    or bound["version"] != 2  # noqa: PLR2004 - immutable reverse reservation version
                    or bound["kind"] != "reverse-proposal-reservation"
                    or bound["session_id"] != outer.session_id
                    or bound["cooperation_id"] != proposal.cooperation_id
                    or bound["contract_hash"] != contract_hash(terms).hex()
                    or bound["proposal_message_id"] != outer.message_id
                    or bound["proposal_unsigned_digest"] != digest
                    or bound["network_identity"] != terms.network_identity.model_dump(mode="json")
                    or bound["claimant"] != terms.claimant
                    or bound["user_key"] != terms.client_contract_compressed_key
                    or bound["provider_key"] != terms.provider_contract_compressed_key
                    or bound["unsigned_transaction"] != proposal.unsigned_transaction
                    or type(bound["deadline_at"]) is not int
                    or bound["deadline_at"] != proposal.deadline_at
                    or type(bound["deadline_height"]) is not int
                    or bound["deadline_height"] != proposal.deadline_height
                    or any(
                        type(bound[name]) is not str
                        or re.fullmatch("[0-9a-f]{64}", cast("str", bound[name])) is None
                        for name in (
                            "funding_message_id",
                            "funding_unsigned_digest",
                            "funding_binding_hash",
                            "tap_tweak",
                            "funding_txid",
                            "signature_hash",
                        )
                    )
                    or type(bound["funding_vout"]) is not int
                    or bound["funding_vout"] < 0
                    or type(bound["funding_value_sat"]) is not int
                    or not 0 < bound["funding_value_sat"] <= MAX_SATS
                    or bound["funding_value_sat"]
                    != int(terms.economics.model_dump()["contract_amount_sat"])
                    or type(bound["funding_script_pubkey"]) is not str
                    or re.fullmatch("5120[0-9a-f]{64}", bound["funding_script_pubkey"]) is None
                    or type(bound["fee_sat"]) is not int
                    or not 0 <= bound["fee_sat"] <= int(terms.max_claim_fee_sat)
                    or any(
                        type(value) is not bytes or len(value) != length
                        for value, length in (
                            (row[3], 66),
                            (row[4], 66),
                            (row[5], 32),
                        )
                    )
                    or row[4].hex() != proposal.public_nonce
                    or type(row[6]) is not str
                    or row[6] != row[7]
                ):
                    raise ValueError("reverse completed replay binding differs")  # noqa: TRY301
                replies = connection.execute(
                    "SELECT message_id,session_id,seq,in_reply_to,canonical_bytes FROM outbox "
                    "WHERE session_id=? AND in_reply_to=?",
                    (outer.session_id, outer.message_id),
                ).fetchall()
                provider = connection.execute(
                    "SELECT provider_session_key FROM sessions WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if len(replies) != 1 or provider is None:
                    raise ValueError("reverse archived reply ambiguous or absent")  # noqa: TRY301
                stored = replies[0]
                reply = _canonical_envelope(stored[4])
                verify_static_signed_envelope(
                    stored[4],
                    expected_session_id=outer.session_id,
                    expected_profile=self._policy.profile,
                    expected_network=self._network,
                    expected_sender_key=provider[0],
                    supported_features=self._policy.features,
                    crypto=self._crypto,
                )
                payload = parse_cooperative_payload("action_result", canonicalize(reply.payload))
                if (
                    reply.message_type != "action_result"
                    or reply.message_id != row[6]
                    or stored[:4]
                    != (reply.message_id, reply.session_id, reply.sequence, reply.in_reply_to)
                    or reply.in_reply_to != outer.message_id
                    or reply.contract_hash != outer.contract_hash
                    or reply.required_features != (COOPERATIVE_CLAIM_FEATURE,)
                    or not isinstance(payload, CooperativeClaimSigned)
                    or payload.cooperation_id != proposal.cooperation_id
                    or payload.public_nonce != row[3].hex()
                    or payload.partial_signature != row[5].hex()
                ):
                    raise ValueError("reverse archived reply differs")  # noqa: TRY301
                result = bytes(stored[4])
                self.reverse_operations.check(operation)
            self.reverse_operations.check(operation)
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - no archived private-proposal or signature oracle
            refused = True
        else:
            refused = False
        if refused:
            raise LiveSessionStoreError("reverse archived contribution replay refused")
        return result

    def _admit_reverse_cooperative_completion(  # noqa: PLR0912, PLR0915 - atomic signed transcript receipt
        self,
        document: bytes,
        *,
        operation: ReverseOperation,
        crypto: Context,
        now: int,
    ) -> RequestAnswer:
        """Verify public archived contributions, never renew signing or economic authority.

        The completed contribution can predate this process or its signing window.
        Only the existing inbox/outbox change; COMPLETE remains provider participation,
        not a claim broadcast, chain confirmation, or new settlement obligation.
        """
        self.reverse_operations.check(operation)
        if type(now) is not int or now < 0:
            raise LiveSessionStoreError("reverse completion audit time refused")
        conflict = False
        try:
            outer = _canonical_envelope(document)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT client_key,provider_session_key,phase,blocked,revision,"
                    "next_client_seq,next_provider_seq FROM sessions WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None or row[2] != "ACCEPTED" or self._policy.profile != "ln-to-btc/v1":
                    raise ValueError("no accepted reverse session")  # noqa: TRY301
                client, provider, _, blocked, revision, client_seq, provider_seq = row
                if blocked:
                    raise SessionBlockedError("session blocked by conflict evidence")  # noqa: TRY301
                digest = verify_static_signed_envelope(
                    document,
                    expected_session_id=outer.session_id,
                    expected_profile=self._policy.profile,
                    expected_network=self._network,
                    expected_sender_key=client,
                    supported_features=self._policy.features,
                    crypto=self._crypto,
                ).hex()
                payload = parse_cooperative_payload("action_request", canonicalize(outer.payload))
                if outer.message_type != "action_request" or not isinstance(
                    payload, CooperativeClaimComplete
                ):
                    raise ValueError("not a reverse completion")  # noqa: TRY301
                seen = connection.execute(
                    "SELECT message_id,seq,unsigned_digest FROM inbox WHERE session_id=? "
                    "AND sender_key=? AND (message_id=? OR seq=?)",
                    (outer.session_id, client, outer.message_id, outer.sequence),
                ).fetchall()
                if seen:
                    if seen == [(outer.message_id, outer.sequence, digest)]:
                        replies = connection.execute(
                            "SELECT message_id,seq,canonical_bytes FROM outbox "
                            "WHERE session_id=? AND in_reply_to=?",
                            (outer.session_id, outer.message_id),
                        ).fetchall()
                        if len(replies) != 1:
                            raise ValueError("completion receipt absent or ambiguous")  # noqa: TRY301
                        receipt = _canonical_envelope(replies[0][2])
                        verify_static_signed_envelope(
                            replies[0][2],
                            expected_session_id=outer.session_id,
                            expected_profile=self._policy.profile,
                            expected_network=self._network,
                            expected_sender_key=provider,
                            supported_features=self._policy.features,
                            crypto=self._crypto,
                        )
                        verified = parse_cooperative_payload(
                            "action_result", canonicalize(receipt.payload)
                        )
                        if (
                            receipt.message_type != "action_result"
                            or receipt.message_id != replies[0][0]
                            or receipt.sequence != replies[0][1]
                            or receipt.in_reply_to != outer.message_id
                            or receipt.contract_hash != outer.contract_hash
                            or receipt.required_features != (COOPERATIVE_CLAIM_FEATURE,)
                            or not isinstance(verified, CooperativeClaimVerified)
                            or verified.cooperation_id != payload.cooperation_id
                        ):
                            raise ValueError("completion receipt differs")  # noqa: TRY301
                        return RequestAnswer(
                            outer.session_id, outer.message_id, replies[0][0], replay=True
                        )
                    _record_conflict(connection, outer.session_id, "request", document)
                    connection.execute(
                        "UPDATE cooperation_attempts SET state='ABANDONED' WHERE session_id=? "
                        "AND state IN ('BURNED','NONCE_READY','SIGNING')",
                        (outer.session_id,),
                    )
                    conflict = True
                else:
                    if (
                        outer.sequence != client_seq
                        or client_seq - FIRST_REQUEST_SEQUENCE >= MAX_REQUESTS_PER_SESSION
                    ):
                        raise ValueError("completion sequence refused")  # noqa: TRY301
                    attempt = connection.execute(
                        "SELECT binding,local_nonce,peer_nonce,state FROM cooperation_attempts "
                        "WHERE cooperation_id=? AND session_id=?",
                        (bytes.fromhex(payload.cooperation_id), outer.session_id),
                    ).fetchone()
                    if attempt is None or attempt[3] != "COMPLETE":
                        raise ValueError("no completed provider contribution")  # noqa: TRY301
                    bound = parse_json_strict(attempt[0])
                    if not isinstance(bound, dict):
                        raise ValueError("completion transcript absent")  # noqa: TRY301
                    prior = connection.execute(
                        "SELECT canonical_bytes FROM inbox WHERE session_id=? AND message_id=?",
                        (outer.session_id, bound.get("proposal_message_id")),
                    ).fetchone()
                    if prior is None:
                        raise ValueError("completion transcript unavailable")  # noqa: TRY301
                    archived = self._reverse_signed_reply_replay(
                        prior[0], operation=operation, transaction=connection
                    )
                    if archived is None:
                        raise ValueError("completion transcript unavailable")  # noqa: TRY301
                    proposal, _, terms = self._authenticated_reverse_preimage(connection, prior[0])
                    agreement = connection.execute(
                        "SELECT s.client_key,s.provider_session_key,s.phase,s.init_bytes,"
                        "s.accept_bytes,s.transcript_digest,w.contract_hash,w.terms_offer,"
                        "w.terms_accept FROM sessions s "
                        "JOIN swaps w ON w.session_id=s.session_id WHERE s.session_id=?",
                        (outer.session_id,),
                    ).fetchone()
                    if agreement is None:
                        raise ValueError("completion agreement unavailable")  # noqa: TRY301
                    initiation, acceptance, _ = self._authenticated_reverse_agreement(
                        agreement, outer.session_id
                    )
                    check_cooperative_action_context(
                        outer, terms, initiation, acceptance, prior_request=proposal
                    )
                    for (stored,) in connection.execute(
                        "SELECT canonical_bytes FROM inbox WHERE session_id=? AND sender_key=?",
                        (outer.session_id, client),
                    ):
                        previous = _canonical_envelope(stored)
                        if (
                            previous.message_type == "action_request"
                            and previous.payload.get("action") == "cooperative_claim_complete"
                            and previous.payload.get("cooperation_id") == payload.cooperation_id
                        ):
                            raise ValueError("completion already admitted")  # noqa: TRY301
                    transcript = {
                        "user_public_key": bytes.fromhex(terms.client_contract_compressed_key),
                        "provider_public_key": bytes.fromhex(
                            terms.provider_contract_compressed_key
                        ),
                        "tap_tweak": bytes.fromhex(cast("str", bound["tap_tweak"])),
                        "message": bytes.fromhex(cast("str", bound["signature_hash"])),
                        "user_public_nonce": attempt[2],
                        "provider_public_nonce": attempt[1],
                    }
                    # Recheck both public partials so corruption of derived binding data
                    # cannot make the receipt attest to a different aggregate transcript.
                    signed_reply = CooperativeClaimSigned.model_validate_json(
                        canonicalize(_canonical_envelope(archived).payload), strict=True
                    )
                    crypto.musig_partial_verify(
                        **transcript,
                        signer_index=1,
                        partial_signature=bytes.fromhex(signed_reply.partial_signature),
                    )
                    crypto.musig_partial_verify(
                        **transcript,
                        signer_index=0,
                        partial_signature=bytes.fromhex(payload.partial_signature),
                    )
                    verified = CooperativeClaimVerified(
                        action="cooperative_claim_complete",
                        cooperation_id=payload.cooperation_id,
                        status="verified",
                    )
                    scalar, key = self._unseal(connection, outer.session_id)
                    try:
                        response = self._signed_envelope(
                            outer,
                            key,
                            provider_seq,
                            Answer(
                                "action_result",
                                verified.model_dump(mode="json"),
                                contract_hash=outer.contract_hash,
                            ),
                            scalar,
                            crypto,
                            outer.message_id,
                            required_features=(COOPERATIVE_CLAIM_FEATURE,),
                        )
                    finally:
                        del scalar
                    encoded = canonicalize(response.model_dump(mode="json"))
                    _canonical_envelope(encoded)
                    connection.execute(
                        "INSERT INTO inbox VALUES (?,?,?,?,?,?,?)",
                        (
                            outer.session_id,
                            client,
                            outer.message_id,
                            outer.sequence,
                            digest,
                            document,
                            revision + 1,
                        ),
                    )
                    connection.execute(
                        "INSERT INTO outbox VALUES (?,?,?,?,?,?,'PENDING')",
                        (
                            response.message_id,
                            outer.session_id,
                            provider_seq,
                            outer.message_id,
                            encoded,
                            revision + 1,
                        ),
                    )
                    connection.execute(
                        "UPDATE sessions SET revision=?,next_client_seq=?,next_provider_seq=?,"
                        "active_at=? WHERE session_id=?",
                        (revision + 1, client_seq + 1, provider_seq + 1, now, outer.session_id),
                    )
                    self.reverse_operations.check(operation)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - no signature, proposal, or private context oracle
            raise LiveSessionStoreError("reverse completion refused") from None
        if conflict:
            pending = self._reverse_proposals.get(outer.session_id)
            if pending is not None and pending.window is not None:
                pending.window.abandon()
            raise SessionBlockedError("conflicting signed request is durable")
        return RequestAnswer(outer.session_id, outer.message_id, response.message_id, replay=False)

    def _commit_reverse_signed_reply(  # noqa: PLR0912, PLR0915 - one custody/consumption/response boundary
        self,
        document: bytes,
        *,
        operation: ReverseOperation,
        evidence: _ReversePaidProposalEvidence,
        crypto: Context,
        now: int,
    ) -> bytes:
        """Consume one provider nonce and archive its correlated contribution.

        INTERNAL ONLY. Trusted runtime must collect actual same-operation paid
        evidence and keep this original gate/window through the effect. The
        previously durable unique burn and permanent allocation tombstone
        forbid regeneration, even after native failure or transaction rollback.
        No contract scalar or native handle leaves the store, and no nonce or
        partial leaves this method before its exact signed reply commits.
        COMPLETE proves archived provider participation, not client broadcast
        or chain disposition. Settlement debt and capacity are not changed.
        """
        __tracebackhide__ = True
        self.reverse_operations.check(operation)
        if type(now) is not int or now < 0:
            raise LiveSessionStoreError("reverse signed reply audit time refused")
        cooperation_id: bytes | None = None
        window: ReverseCooperationWindow | None = None
        attempt: MusigAttempt | None = None
        try:
            with self._write() as connection:
                context = self._check_reverse_paid_evidence(
                    connection, document, operation=operation, evidence=evidence
                )
                window = context.window
                outer, proposal, terms = self._authenticated_reverse_preimage(connection, document)
                cooperation_id = bytes.fromhex(proposal.cooperation_id)
                if (
                    cooperation_id in self._allocated_cooperation_ids
                    or cooperation_id in self._cooperation_handles
                    or connection.execute(
                        "SELECT 1 FROM outbox WHERE session_id=? AND in_reply_to=? LIMIT 1",
                        (outer.session_id, outer.message_id),
                    ).fetchone()
                    is not None
                ):
                    raise ValueError("reverse native contribution already unavailable")  # noqa: TRY301
                row = connection.execute(
                    "SELECT compressed_key,secret_age FROM contract_keys WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None or row[0] != terms.provider_contract_compressed_key:
                    raise ValueError("reverse contract custody differs")  # noqa: TRY301
                plaintext = key_record = scalar_hex = scalar = None
                try:
                    plaintext = pyrage.decrypt(row[1], [self._custody_identity])
                    key_record = parse_json_strict(plaintext)
                    if not isinstance(key_record, dict):
                        raise TypeError("reverse contract custody differs")
                    scalar_hex = key_record.get("secret_scalar")
                    if (
                        key_record.get("kind") != CONTRACT_KEY_RECORD_KIND
                        or key_record.get("store_uuid") != self._store_uuid
                        or key_record.get("session_id") != outer.session_id
                        or key_record.get("compressed_public_key") != row[0]
                        or type(scalar_hex) is not str
                        or re.fullmatch("[0-9a-f]{64}", scalar_hex) is None
                    ):
                        raise ValueError("reverse contract custody differs")
                    scalar = bytes.fromhex(scalar_hex)
                    if crypto.public_key(scalar).hex() != row[0]:
                        raise ValueError("reverse contract key differs")
                    self._check_reverse_paid_evidence(
                        connection, document, operation=operation, evidence=evidence
                    )
                    taproot = reconstruct_taproot_contract(terms, keys=crypto)
                    self._check_reverse_paid_evidence(
                        connection, document, operation=operation, evidence=evidence
                    )
                    # Never remove this tombstone, including when begin raises.
                    self._allocated_cooperation_ids.add(cooperation_id)
                    attempt, public_nonce = crypto.musig_begin(
                        secret_key=scalar,
                        user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
                        provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
                        tap_tweak=taproot.tap_tweak,
                        message=context.plan.signature_hash,
                        cooperation_id=cooperation_id,
                    )
                    self._cooperation_handles[cooperation_id] = attempt
                finally:
                    del plaintext, key_record, scalar_hex, scalar
                self._check_reverse_paid_evidence(
                    connection, document, operation=operation, evidence=evidence
                )
                retained = self._cooperation_handles.pop(cooperation_id, None)
                if retained is not attempt:
                    raise ValueError("reverse native custody unavailable")  # noqa: TRY301
                peer_nonce = bytes.fromhex(proposal.public_nonce)
                try:
                    partial = attempt.partial_sign_once(peer_nonce)
                finally:
                    attempt.close()
                crypto.musig_partial_verify(
                    user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
                    provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
                    tap_tweak=taproot.tap_tweak,
                    message=context.plan.signature_hash,
                    user_public_nonce=peer_nonce,
                    provider_public_nonce=public_nonce,
                    signer_index=1,
                    partial_signature=partial,
                )
                self._check_reverse_paid_evidence(
                    connection, document, operation=operation, evidence=evidence
                )
                session = connection.execute(
                    "SELECT revision,next_provider_seq FROM sessions WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if session is None:
                    raise ValueError("reverse signed response context absent")  # noqa: TRY301
                payload = CooperativeClaimSigned(
                    action="cooperative_claim_propose",
                    cooperation_id=proposal.cooperation_id,
                    status="signed",
                    public_nonce=public_nonce.hex(),
                    partial_signature=partial.hex(),
                )
                reply = Answer(
                    "action_result",
                    payload.model_dump(mode="json"),
                    contract_hash=outer.contract_hash,
                )
                session_scalar, key = self._unseal(connection, outer.session_id)
                try:
                    response = self._signed_envelope(
                        outer,
                        key,
                        session[1],
                        reply,
                        session_scalar,
                        crypto,
                        outer.message_id,
                        required_features=(COOPERATIVE_CLAIM_FEATURE,),
                    )
                finally:
                    del session_scalar
                response_bytes = canonicalize(response.model_dump(mode="json"))
                _canonical_envelope(response_bytes)  # Closed schema and canonical size bound.
                self._check_reverse_paid_evidence(
                    connection, document, operation=operation, evidence=evidence
                )
                connection.execute(
                    "INSERT INTO outbox VALUES (?,?,?,?,?,?,'PENDING')",
                    (
                        response.message_id,
                        outer.session_id,
                        session[1],
                        outer.message_id,
                        response_bytes,
                        session[0] + 1,
                    ),
                )
                changed = connection.execute(
                    "UPDATE cooperation_attempts SET state='COMPLETE',local_nonce=?,peer_nonce=?,"
                    "partial_signature=?,nonce_response_id=?,partial_response_id=? "
                    "WHERE cooperation_id=? AND session_id=? AND owner_generation=? "
                    "AND state='BURNED'",
                    (
                        public_nonce,
                        peer_nonce,
                        partial,
                        response.message_id,
                        response.message_id,
                        cooperation_id,
                        outer.session_id,
                        self._generation,
                    ),
                )
                if changed.rowcount != 1:
                    raise ValueError("reverse signed contribution state changed")  # noqa: TRY301
                connection.execute(
                    "UPDATE sessions SET revision=?,next_provider_seq=?,active_at=? "
                    "WHERE session_id=?",
                    (session[0] + 1, session[1] + 1, now, outer.session_id),
                )
                self.reverse_operations.check(operation)
                window.check(tip_height=evidence.core.tip_height)
                window.check_evidence_interval(
                    started_at=evidence.started_at, completed_at=evidence.completed_at
                )
        except BaseException as error:
            if cooperation_id is not None:
                live = self._cooperation_handles.pop(cooperation_id, None)
                if live is not None:
                    with suppress(Exception):
                        live.close()
            if attempt is not None:
                with suppress(Exception):
                    attempt.close()
            if window is not None:
                window.abandon()
            if cooperation_id is not None and self.owner_is_open:
                try:
                    with self._write() as connection:
                        connection.execute(
                            "UPDATE cooperation_attempts SET state='ABANDONED' "
                            "WHERE cooperation_id=? AND owner_generation=? AND state='BURNED'",
                            (cooperation_id, self._generation),
                        )
                except Exception:  # noqa: BLE001 - uncertain custody cannot retain an open owner
                    self.close()
            if not isinstance(error, Exception) or isinstance(error, StaleOwnerError):
                raise
        else:
            return response_bytes
        raise LiveSessionStoreError("reverse signed contribution refused")

    def _admit_reverse_cooperative_proposal(  # noqa: PLR0912, PLR0915 - one authenticated reservation
        self,
        document: bytes,
        *,
        operation: ReverseOperation,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> ReverseProposalAdmission:
        """Reserve exact reverse proposal evidence without replying or settling.

        INTERNAL ONLY. No debt, preimage knowledge, nonce allocation, signing,
        network effects, or financial permission are created. Retained funding
        bytes prove neither publication nor current unspent confirmation. Later
        economic admission must independently prove those facts and recheck this
        ORIGINAL window, not instantiate another. Replay returns a receipt only,
        including after restart. Production featured acceptance stays gated.
        """
        self.reverse_operations.check(operation)
        attempt: _ReverseProposalAttempt | None = None
        conflict = False
        abandoned: tuple[bytes, ...] = ()
        refusal: LiveSessionStoreError | None = None
        receipt: ReverseProposalAdmission | None = None
        try:
            outer = _canonical_envelope(document)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT s.client_key,s.provider_session_key,s.phase,s.blocked,s.revision,"
                    "s.next_client_seq,s.init_bytes,s.accept_bytes,s.transcript_digest,"
                    "w.contract_hash,w.terms_offer,w.terms_accept,w.state,"
                    "w.funding_txid,w.funding_vout,w.funding_tx FROM sessions s "
                    "JOIN swaps w ON w.session_id=s.session_id WHERE s.session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None or row[2] != "ACCEPTED" or self._policy.profile != "ln-to-btc/v1":
                    raise LiveSessionStoreError("no accepted reverse session")  # noqa: TRY301
                (
                    client,
                    provider,
                    _,
                    blocked,
                    revision,
                    client_seq,
                    _init_bytes,
                    accept_bytes,
                    transcript,
                    digest,
                    _offer_bytes,
                    accepted_bytes,
                    state,
                    txid,
                    vout,
                    raw,
                ) = row
                unsigned_digest = verify_static_signed_envelope(
                    document,
                    expected_session_id=outer.session_id,
                    expected_profile=self._policy.profile,
                    expected_network=self._network,
                    expected_sender_key=client,
                    supported_features=self._policy.features,
                    crypto=self._crypto,
                ).hex()
                if outer.message_type != "action_request":
                    raise LiveSessionStoreError("reverse proposal type unsupported")  # noqa: TRY301
                payload = parse_cooperative_payload("action_request", canonicalize(outer.payload))
                if not isinstance(payload, CooperativeClaimPropose):
                    raise LiveSessionStoreError("reverse proposal type unsupported")  # noqa: TRY301
                seen = connection.execute(
                    "SELECT message_id,seq,unsigned_digest FROM inbox WHERE session_id=? "
                    "AND sender_key=? AND (message_id=? OR seq=?)",
                    (outer.session_id, client, outer.message_id, outer.sequence),
                ).fetchall()
                if seen:
                    if seen == [(outer.message_id, outer.sequence, unsigned_digest)]:
                        return ReverseProposalAdmission(
                            outer.session_id,
                            outer.message_id,
                            payload.cooperation_id,
                            replay=True,
                        )
                    _record_conflict(connection, outer.session_id, "request", document)
                    abandoned = tuple(
                        item[0]
                        for item in connection.execute(
                            "SELECT cooperation_id FROM cooperation_attempts WHERE session_id=?",
                            (outer.session_id,),
                        )
                    )
                    connection.execute(
                        "UPDATE cooperation_attempts SET state='ABANDONED' "
                        "WHERE session_id=? AND state IN ('BURNED','NONCE_READY','SIGNING')",
                        (outer.session_id,),
                    )
                    conflict = True
                else:
                    if (
                        blocked
                        or outer.sequence != client_seq
                        or client_seq - FIRST_REQUEST_SEQUENCE >= MAX_REQUESTS_PER_SESSION
                        or payload.cooperation_id == "00" * 32
                        or outer.session_id in self._reverse_proposals
                        or connection.execute(
                            "SELECT 1 FROM cooperation_attempts WHERE session_id=? LIMIT 1",
                            (outer.session_id,),
                        ).fetchone()
                        is not None
                        or not self._matches_reverse_negotiation(
                            outer.session_id,
                            digest,
                            (accept_bytes, transcript, blocked, digest, accepted_bytes),
                        )
                    ):
                        raise LiveSessionStoreError("reverse proposal unavailable")  # noqa: TRY301
                    _, _, terms = self._authenticated_reverse_preimage(connection, document)
                    # Keep this first anchor even when the transaction later
                    # rolls back. Corrected/new-ID retries cannot renew it.
                    attempt = _ReverseProposalAttempt(
                        outer.message_id,
                        unsigned_digest,
                        payload.cooperation_id,
                        None,
                    )
                    self._reverse_proposals[outer.session_id] = attempt
                    window = ReverseCooperationWindow(
                        signed_deadline_at=payload.deadline_at,
                        signed_deadline_height=payload.deadline_height,
                        claim_height_cutoff=terms.refund_lock_height
                        - terms.timing_policy.claim_confirmation_blocks,
                        wall_clock=wall_clock,
                        monotonic_clock=monotonic_clock,
                    )
                    attempt = replace(attempt, window=window)
                    self._reverse_proposals[outer.session_id] = attempt
                    if state not in ("FUNDING_SENT", "FUNDED") or raw is None:
                        raise LiveSessionStoreError("reverse funding unavailable")  # noqa: TRY301
                    immutable, _, _, _ = self._reverse_reservation_binding(
                        connection,
                        outer,
                        payload,
                        terms,
                        provider=provider,
                        txid=txid,
                        vout=vout,
                        raw=raw,
                    )
                    self.reverse_operations.check(operation)
                    now = int(wall_clock())
                    if not window.time_allowed():
                        raise LiveSessionStoreError("reverse proposal deadline elapsed")  # noqa: TRY301
                    connection.execute(
                        "INSERT INTO cooperation_attempts "
                        "(cooperation_id,session_id,owner_generation,binding,"
                        "created_at,deadline_at,state) "
                        "VALUES (?,?,?,?,?,?,'BURNED')",
                        (
                            bytes.fromhex(payload.cooperation_id),
                            outer.session_id,
                            self._generation,
                            immutable,
                            now,
                            payload.deadline_at,
                        ),
                    )
                    connection.execute(
                        "INSERT INTO inbox VALUES (?,?,?,?,?,?,?)",
                        (
                            outer.session_id,
                            client,
                            outer.message_id,
                            outer.sequence,
                            unsigned_digest,
                            document,
                            revision + 1,
                        ),
                    )
                    connection.execute(
                        "UPDATE sessions SET next_client_seq=?,revision=?,active_at=? "
                        "WHERE session_id=?",
                        (client_seq + 1, revision + 1, now, outer.session_id),
                    )
                    receipt = ReverseProposalAdmission(
                        outer.session_id, outer.message_id, payload.cooperation_id, replay=False
                    )
        except LiveSessionStoreError as error:
            if attempt is not None and attempt.window is not None:
                attempt.window.abandon()
            refusal = type(error)(str(error))
        except Exception:  # noqa: BLE001 - no preimage, nonce, binding, or signature oracle
            if attempt is not None and attempt.window is not None:
                attempt.window.abandon()
            refusal = LiveSessionStoreError("reverse proposal refused")
        if refusal is not None:
            # Exit the handler before raising: parser errors can retain private
            # proposal bytes in __context__ even with ``raise ... from None``.
            raise refusal
        if conflict:
            previous = self._reverse_proposals.get(outer.session_id)
            if previous is not None and previous.window is not None:
                previous.window.abandon()
            for cooperation_id in abandoned:
                handle = self._cooperation_handles.pop(cooperation_id, None)
                if handle is not None:
                    handle.close()
            raise SessionBlockedError("conflicting signed reverse proposal is durable")
        if receipt is None:
            raise LiveSessionStoreError("reverse proposal receipt unavailable")
        return receipt

    def _admit_cooperative_result(  # noqa: PLR0912, PLR0915 - one signed admission transaction
        self,
        document: bytes,
        *,
        now: int,
        readiness: ReadinessChallenge | None = None,
        tip_height: int | None = None,
    ) -> CooperativeResultAdmission:
        """Record one authenticated client disposition without signing or replying.

        INTERNAL ONLY. An admitted partial is not permission to sign: the
        process-local native handle, current chain facts, deadline, and exact
        spending policy must be checked again by a later signing operation.
        Exact signed replays, even after restart, return a receipt only.
        Invalid replies are rejected without consuming sequence or changing
        the attempt. A future runtime must independently trigger unilateral
        fallback on refusal, invalid response, or the bounded timeout.
        """
        if type(now) is not int or now < 0:
            raise LiveSessionStoreError("cooperative result time unsupported")
        if readiness is not None and (
            not isinstance(readiness, ReadinessChallenge)
            or readiness.owner_generation != self._generation
            or type(tip_height) is not int
            or tip_height <= 0
            or tip_height >= readiness.deadline_height
            or not readiness.started_at <= now < readiness.deadline_at
        ):
            raise LiveSessionStoreError("readiness token unavailable")
        abandon: bytes | None = None
        conflict = False
        status = ""
        try:
            outer = _canonical_envelope(document)
            with self._write() as connection:
                session = connection.execute(
                    "SELECT client_key,phase,blocked,revision,next_client_seq,"
                    "init_bytes,accept_bytes FROM sessions WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if session is None or session[1] != "ACCEPTED":
                    raise LiveSessionStoreError("no accepted cooperative session")  # noqa: TRY301
                client, _, blocked, revision, client_seq, init_bytes, accept_bytes = session
                digest = verify_static_signed_envelope(
                    document,
                    expected_session_id=outer.session_id,
                    expected_profile=self._policy.profile,
                    expected_network=self._network,
                    expected_sender_key=client,
                    supported_features=self._policy.features,
                    crypto=self._crypto,
                ).hex()
                if outer.message_type != "action_result":
                    raise LiveSessionStoreError("cooperative result type unsupported")  # noqa: TRY301
                seen = connection.execute(
                    "SELECT message_id,seq,unsigned_digest FROM inbox "
                    "WHERE session_id=? AND sender_key=? AND (message_id=? OR seq=?)",
                    (outer.session_id, client, outer.message_id, outer.sequence),
                ).fetchall()
                if seen:
                    if seen == [(outer.message_id, outer.sequence, digest)]:
                        replay = parse_cooperative_payload(
                            "action_result", canonicalize(outer.payload)
                        )
                        if readiness is not None and (
                            not isinstance(replay, CooperativeClaimReady)
                            or outer.session_id != readiness.session_id
                            or outer.in_reply_to != readiness.request_id
                            or replay.challenge != readiness.challenge
                        ):
                            raise LiveSessionStoreError("readiness replay not correlated")  # noqa: TRY301
                        if readiness is None and not isinstance(
                            replay,
                            (
                                CooperativeClaimSigned,
                                CooperativeClaimDeclined,
                                CooperativeClaimVerified,
                            ),
                        ):
                            raise LiveSessionStoreError("cooperative replay type unsupported")  # noqa: TRY301
                        if not isinstance(
                            replay,
                            (
                                CooperativeClaimReady,
                                CooperativeClaimSigned,
                                CooperativeClaimDeclined,
                                CooperativeClaimVerified,
                            ),
                        ):
                            raise LiveSessionStoreError("cooperative replay type unsupported")  # noqa: TRY301
                        return CooperativeResultAdmission(
                            outer.session_id, outer.message_id, replay.status, replay=True
                        )
                    _record_conflict(connection, outer.session_id, "request", document)
                    connection.execute(
                        "UPDATE cooperation_attempts SET state='ABANDONED' "
                        "WHERE session_id=? AND state IN ('BURNED','NONCE_READY','SIGNING')",
                        (outer.session_id,),
                    )
                    attempt = connection.execute(
                        "SELECT cooperation_id FROM cooperation_attempts WHERE session_id=?",
                        (outer.session_id,),
                    ).fetchone()
                    abandon = None if attempt is None else attempt[0]
                    conflict = True
                else:
                    if (
                        blocked
                        or outer.sequence != client_seq
                        or client_seq - FIRST_REQUEST_SEQUENCE >= MAX_REQUESTS_PER_SESSION
                    ):
                        raise LiveSessionStoreError("cooperative result out of sequence")  # noqa: TRY301
                    payload = parse_cooperative_payload(
                        "action_result", canonicalize(outer.payload)
                    )
                    if isinstance(payload, CooperativeClaimReady):
                        if readiness is None:
                            raise LiveSessionStoreError(  # noqa: TRY301
                                "readiness token unavailable"
                            )
                        self._check_readiness_echo(connection, outer, readiness, now=now)
                        connection.execute(
                            "INSERT INTO inbox VALUES (?,?,?,?,?,?,?)",
                            (
                                outer.session_id,
                                client,
                                outer.message_id,
                                outer.sequence,
                                digest,
                                document,
                                revision + 1,
                            ),
                        )
                        connection.execute(
                            "UPDATE sessions SET next_client_seq=?,revision=?,active_at=? "
                            "WHERE session_id=?",
                            (client_seq + 1, revision + 1, now, outer.session_id),
                        )
                        connection.execute(
                            "UPDATE outbox SET delivery_state='RECONCILED' "
                            "WHERE session_id=? AND message_id=? AND delivery_state='PENDING'",
                            (outer.session_id, readiness.request_id),
                        )
                        return CooperativeResultAdmission(
                            outer.session_id, outer.message_id, payload.status, replay=False
                        )
                    if readiness is not None:
                        raise LiveSessionStoreError("readiness reply unsupported")  # noqa: TRY301
                    if isinstance(payload, CooperativeClaimVerified):
                        self._check_completion_receipt(
                            connection, outer, payload, init_bytes, accept_bytes
                        )
                        connection.execute(
                            "INSERT INTO inbox VALUES (?,?,?,?,?,?,?)",
                            (
                                outer.session_id,
                                client,
                                outer.message_id,
                                outer.sequence,
                                digest,
                                document,
                                revision + 1,
                            ),
                        )
                        connection.execute(
                            "UPDATE sessions SET next_client_seq=?,revision=?,active_at=? "
                            "WHERE session_id=?",
                            (client_seq + 1, revision + 1, now, outer.session_id),
                        )
                        return CooperativeResultAdmission(
                            outer.session_id, outer.message_id, payload.status, replay=False
                        )
                    if not isinstance(payload, (CooperativeClaimSigned, CooperativeClaimDeclined)):
                        raise LiveSessionStoreError("cooperative result status unsupported")  # noqa: TRY301
                    status = payload.status
                    cooperation_id = bytes.fromhex(payload.cooperation_id)
                    row = connection.execute(
                        "SELECT a.binding,a.owner_generation,a.created_at,a.deadline_at,a.state,"
                        "a.local_nonce,a.nonce_response_id,w.contract_hash,w.terms_offer,"
                        "w.funding_binding,w.preimage,w.state "
                        "FROM cooperation_attempts a JOIN swaps w ON w.session_id=a.session_id "
                        "WHERE a.session_id=? AND a.cooperation_id=?",
                        (outer.session_id, cooperation_id),
                    ).fetchone()
                    if row is None:
                        raise LiveSessionStoreError("cooperative proposal unavailable")  # noqa: TRY301
                    (
                        binding_bytes,
                        generation,
                        created_at,
                        deadline_at,
                        state,
                        local_nonce,
                        proposal_id,
                        recorded_hash,
                        offer_bytes,
                        funding_bytes,
                        preimage,
                        swap_state,
                    ) = row
                    binding = parse_json_strict(binding_bytes)
                    if not isinstance(binding, dict) or (
                        generation != self._generation
                        or state != "NONCE_READY"
                        or not created_at <= now < deadline_at
                        or swap_state not in ("PAID", "CLAIMING")
                        or not isinstance(local_nonce, bytes)
                        or not isinstance(proposal_id, str)
                        or binding.get("version") != 1
                        or binding.get("session_id") != outer.session_id
                        or binding.get("cooperation_id") != payload.cooperation_id
                        or binding.get("contract_hash") != recorded_hash
                        or binding.get("deadline_at") != deadline_at
                        or funding_bytes is None
                        or not isinstance(preimage, str)
                        or re.fullmatch(r"[0-9a-f]{64}", preimage) is None
                    ):
                        raise LiveSessionStoreError("cooperative proposal no longer current")  # noqa: TRY301
                    arbitration = connection.execute(
                        "SELECT state,owner_generation,contract_hash,deadline_at,"
                        "deadline_height FROM claim_arbitration WHERE session_id=? AND version=1",
                        (outer.session_id,),
                    ).fetchone()
                    if arbitration is not None and (
                        arbitration
                        != (
                            "WAITING",
                            self._generation,
                            recorded_hash,
                            deadline_at,
                            binding.get("deadline_height"),
                        )
                        or swap_state != "PAID"
                    ):
                        raise LiveSessionStoreError(  # noqa: TRY301 - old internal tests have no window
                            "cooperative proposal no longer current"
                        )
                    terms = _offer_terms(offer_bytes)
                    funding = parse_model_json(
                        FundingBindingPayload,
                        canonicalize(_canonical_envelope(funding_bytes).payload),
                    ).binding
                    if (
                        contract_hash(terms).hex() != recorded_hash
                        or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                        or hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
                        != terms.invoice_binding.payment_hash
                        or funding.contract_hash != recorded_hash
                        or funding.funding_txid != binding.get("funding_txid")
                        or funding.contract_vout != binding.get("funding_vout")
                        or int(funding.contract_value_sat) != binding.get("funding_value_sat")
                        or funding.contract_script_pubkey != binding.get("funding_script_pubkey")
                    ):
                        raise LiveSessionStoreError("cooperative funding differs")  # noqa: TRY301
                    saved = connection.execute(
                        "SELECT canonical_bytes FROM outbox WHERE session_id=? AND message_id=?",
                        (outer.session_id, proposal_id),
                    ).fetchone()
                    if saved is None:
                        raise LiveSessionStoreError("cooperative proposal transcript missing")  # noqa: TRY301
                    proposal = _canonical_envelope(saved[0])
                    original = parse_cooperative_payload(
                        "action_request", canonicalize(proposal.payload)
                    )
                    if not isinstance(original, CooperativeClaimPropose) or (
                        proposal.message_id != proposal_id
                        or original.cooperation_id != payload.cooperation_id
                        or original.public_nonce != local_nonce.hex()
                        or original.unsigned_transaction != binding.get("unsigned_transaction")
                        or original.payment_preimage != preimage
                        or original.deadline_at != deadline_at
                        or original.deadline_height != binding.get("deadline_height")
                    ):
                        raise LiveSessionStoreError("cooperative proposal differs")  # noqa: TRY301
                    initiation = parse_model_json(
                        HandshakeInit,
                        canonicalize(_canonical_envelope(init_bytes).payload),
                    )
                    acceptance = parse_model_json(
                        HandshakeAccept,
                        canonicalize(_canonical_envelope(accept_bytes).payload["accept"]),
                    )
                    checked = check_cooperative_action_context(
                        outer, terms, initiation, acceptance, prior_request=proposal
                    )
                    if checked != payload:
                        raise LiveSessionStoreError("cooperative result context differs")  # noqa: TRY301
                    if isinstance(payload, CooperativeClaimSigned):
                        from rill_crypto import Context  # noqa: PLC0415 - native partial boundary

                        if (
                            not isinstance(self._crypto, Context)
                            or cooperation_id not in self._cooperation_handles
                        ):
                            raise LiveSessionStoreError("cooperative signer custody lost")  # noqa: TRY301
                        crypto = self._crypto
                        peer_nonce = bytes.fromhex(payload.public_nonce)
                        crypto.musig_public_nonce_validate(local_nonce)
                        crypto.musig_public_nonce_validate(peer_nonce)
                        crypto.musig_partial_verify(
                            user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
                            provider_public_key=bytes.fromhex(
                                terms.provider_contract_compressed_key
                            ),
                            tap_tweak=bytes.fromhex(str(binding["tap_tweak"])),
                            message=bytes.fromhex(str(binding["signature_hash"])),
                            user_public_nonce=peer_nonce,
                            provider_public_nonce=local_nonce,
                            signer_index=0,
                            partial_signature=bytes.fromhex(payload.partial_signature),
                        )
                        update: tuple[str, bytes | None] = ("SIGNING", peer_nonce)
                    else:
                        update = ("ABANDONED", None)
                        abandon = cooperation_id
                    connection.execute(
                        "INSERT INTO inbox VALUES (?,?,?,?,?,?,?)",
                        (
                            outer.session_id,
                            client,
                            outer.message_id,
                            outer.sequence,
                            digest,
                            document,
                            revision + 1,
                        ),
                    )
                    if (
                        connection.execute(
                            "UPDATE cooperation_attempts SET state=?,peer_nonce=? "
                            "WHERE session_id=? AND cooperation_id=? AND state='NONCE_READY' "
                            "AND owner_generation=?",
                            (*update, outer.session_id, cooperation_id, self._generation),
                        ).rowcount
                        != 1
                    ):
                        raise LiveSessionStoreError("cooperative attempt changed")  # noqa: TRY301
                    connection.execute(
                        "UPDATE sessions SET next_client_seq=?,revision=?,active_at=? "
                        "WHERE session_id=?",
                        (client_seq + 1, revision + 1, now, outer.session_id),
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo nonce, partial or signed documents
            raise LiveSessionStoreError("cooperative result refused") from None
        if abandon is not None:
            live = self._cooperation_handles.pop(abandon, None)
            if live is not None:
                live.close()
        if conflict:
            raise SessionBlockedError("conflicting signed cooperative result is durable")
        return CooperativeResultAdmission(outer.session_id, outer.message_id, status, replay=False)

    def _check_completion_receipt(
        self,
        connection: sqlite3.Connection,
        outer: Envelope,
        payload: CooperativeClaimVerified,
        init_bytes: bytes,
        accept_bytes: bytes,
    ) -> None:
        """Correlate a client's verified receipt with this provider's archived completion.

        The receipt grants nothing (no signing, settlement, broadcast or reply).
        It is admitted only so the session's client sequence matches what the
        client sent. RS-002 lets the client send it late, so neither the signing
        window, owner generation nor native handle is required: only a COMPLETE
        attempt of this session whose authenticated completion it answers.
        """
        if self._policy.profile != "btc-to-ln/v1":
            raise LiveSessionStoreError("cooperative result status unsupported")
        row = connection.execute(
            "SELECT a.state,a.partial_response_id,w.terms_offer,s.provider_session_key "
            "FROM cooperation_attempts a JOIN swaps w ON w.session_id=a.session_id "
            "JOIN sessions s ON s.session_id=a.session_id "
            "WHERE a.cooperation_id=? AND a.session_id=?",
            (bytes.fromhex(payload.cooperation_id), outer.session_id),
        ).fetchone()
        if row is None or row[0] != "COMPLETE" or not isinstance(row[1], str):
            raise LiveSessionStoreError("cooperative completion no longer current")
        _, completion_id, offer_bytes, provider = row
        saved = connection.execute(
            "SELECT canonical_bytes FROM outbox WHERE session_id=? AND message_id=?",
            (outer.session_id, completion_id),
        ).fetchone()
        if saved is None:
            raise LiveSessionStoreError("cooperative completion transcript missing")
        verify_static_signed_envelope(
            saved[0],
            expected_session_id=outer.session_id,
            expected_profile=self._policy.profile,
            expected_network=self._network,
            expected_sender_key=provider,
            supported_features=self._policy.features,
            crypto=self._crypto,
        )
        completion = _canonical_envelope(saved[0])
        original = parse_cooperative_payload("action_request", canonicalize(completion.payload))
        if (
            not isinstance(original, CooperativeClaimComplete)
            or completion.message_id != completion_id
            or original.cooperation_id != payload.cooperation_id
        ):
            raise LiveSessionStoreError("cooperative completion differs")
        initiation = parse_model_json(
            HandshakeInit, canonicalize(_canonical_envelope(init_bytes).payload)
        )
        acceptance = parse_model_json(
            HandshakeAccept, canonicalize(_canonical_envelope(accept_bytes).payload["accept"])
        )
        checked = check_cooperative_action_context(
            outer, _offer_terms(offer_bytes), initiation, acceptance, prior_request=completion
        )
        if checked != payload:
            raise LiveSessionStoreError("cooperative result context differs")

    def admit_cooperative_readiness(
        self,
        document: bytes,
        challenge: ReadinessChallenge,
        *,
        now: int,
        tip_height: int,
    ) -> CooperativeResultAdmission:
        """Record a signed echo only for a current in-memory owner's challenge.

        The caller must consume its challenge after the first non-replay result.
        This inbox receipt itself never authorizes nonce exposure or waiting.
        """
        return self._admit_cooperative_result(
            document, now=now, readiness=challenge, tip_height=tip_height
        )

    def _check_readiness_echo(
        self,
        connection: sqlite3.Connection,
        outer: Envelope,
        challenge: ReadinessChallenge,
        *,
        now: int,
    ) -> None:
        """Require a paid feature-bound swap and the exact signed owner request."""
        if outer.session_id != challenge.session_id or outer.in_reply_to != challenge.request_id:
            raise LiveSessionStoreError("readiness reply not correlated")
        row = connection.execute(
            "SELECT a.state,a.version,a.contract_hash,w.state,w.contract_hash,"
            "w.terms_offer,w.funding_binding,w.preimage,w.claim_tx,w.claim_txid,"
            "s.init_bytes,s.accept_bytes FROM claim_arbitration a "
            "JOIN swaps w ON w.session_id=a.session_id "
            "JOIN sessions s ON s.session_id=a.session_id WHERE a.session_id=?",
            (challenge.session_id,),
        ).fetchone()
        if row is None or row[:3] != ("ADMITTED", 1, challenge.contract_hash):
            raise LiveSessionStoreError("readiness admission unavailable")
        (
            _,
            _,
            _,
            state,
            contract,
            offer,
            funding_bytes,
            preimage,
            claim_tx,
            claim_txid,
            init_bytes,
            accept_bytes,
        ) = row
        if (
            state != "PAID"
            or contract != challenge.contract_hash
            or funding_bytes is None
            or claim_tx is not None
            or claim_txid is not None
            or not isinstance(preimage, str)
            or re.fullmatch(r"[0-9a-f]{64}", preimage) is None
            or connection.execute(
                "SELECT 1 FROM claim_attempts WHERE session_id=? LIMIT 1",
                (challenge.session_id,),
            ).fetchone()
        ):
            raise LiveSessionStoreError("readiness swap unavailable")
        terms = _offer_terms(offer)
        if (
            contract_hash(terms).hex() != contract
            or terms.network_identity != self._network
            or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
            or hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
            != terms.invoice_binding.payment_hash
        ):
            raise LiveSessionStoreError("readiness terms unavailable")
        retained = connection.execute(
            "SELECT canonical_bytes,delivery_state FROM outbox WHERE session_id=? AND message_id=?",
            (challenge.session_id, challenge.request_id),
        ).fetchone()
        if retained is None or retained[1] != "PENDING":
            raise LiveSessionStoreError("readiness request missing")
        request = _canonical_envelope(retained[0])
        original = parse_cooperative_payload("action_request", canonicalize(request.payload))
        if not isinstance(original, CooperativeClaimReadyRequest) or (
            original.challenge != challenge.challenge
            or original.payment_preimage != preimage
            or original.deadline_at != challenge.deadline_at
            or original.deadline_height != challenge.deadline_height
            or challenge.deadline_at > challenge.started_at + COOPERATION_BUDGET_SECONDS
            or now >= challenge.deadline_at
        ):
            raise LiveSessionStoreError("readiness request changed")
        initiation = parse_model_json(
            HandshakeInit, canonicalize(_canonical_envelope(init_bytes).payload)
        )
        acceptance = parse_model_json(
            HandshakeAccept, canonicalize(_canonical_envelope(accept_bytes).payload["accept"])
        )
        checked = check_cooperative_action_context(
            outer, terms, initiation, acceptance, prior_request=request
        )
        if (
            not isinstance(checked, CooperativeClaimReady)
            or checked.challenge != challenge.challenge
        ):
            raise LiveSessionStoreError("readiness reply changed")

    def commit_selected_cooperative_claim(
        self,
        session_id: str,
        cooperation_id: bytes,
        observation: CooperativeClaimObservation,
        *,
        now: Callable[[], int],
    ) -> str:
        """Select the exact key-path winner atomically before exposing our partial.

        This checked live entry point requires the current owner's prepared
        WAITING window. Only a verified completion may close that window.
        Refresh the owner clock around lock acquisition, native consumption,
        and persistence; acquisition never renews the sample or deadline.
        """
        if not callable(now):
            raise LiveSessionStoreError("cooperative clock unavailable")
        return self._complete_cooperative_claim(
            session_id,
            cooperation_id,
            observation,
            now=_cooperative_now(0, now),
            select_winner=True,
            clock=now,
        )

    def cooperative_completion_candidate(
        self, session_id: str, cooperation_id: bytes
    ) -> CooperativeCompletionCandidate | None:
        """Read only a current, affirmatively prepared SIGNING candidate.

        This is not a clock, chain, fee, native-plan, or signing verifier. A
        missing/older/nonqualifying record or absent process-local custody
        selects no candidate. Malformed storage raises a sanitized error.
        Restart never recreates custody from these bytes. Start
        the runtime's monotonic budget before acquiring this snapshot.
        """
        if type(cooperation_id) is not bytes or len(cooperation_id) != 32:  # noqa: PLR2004 - exact burned ID
            raise LiveSessionStoreError("cooperative completion identifier invalid")
        try:
            with self._write() as connection:
                if cooperation_id not in self._cooperation_handles:
                    return None
                row = connection.execute(
                    "SELECT a.session_id,a.contract_hash,a.state,a.owner_generation,"
                    "a.deadline_at,a.deadline_height,a.fallback_raw,a.fallback_txid,"
                    "a.fallback_fee_sat,w.terms_offer,w.funding_binding,w.preimage,c.binding "
                    "FROM cooperation_attempts c "
                    "JOIN claim_arbitration a ON a.session_id=c.session_id "
                    "JOIN swaps w ON w.session_id=c.session_id "
                    "JOIN sessions s ON s.session_id=c.session_id "
                    "WHERE c.session_id=? AND c.cooperation_id=? AND c.state='SIGNING' "
                    "AND c.owner_generation=? AND a.state='WAITING' AND a.version=1 "
                    "AND a.owner_generation=c.owner_generation AND a.deadline_at=c.deadline_at "
                    "AND a.cooperative_raw IS NULL AND a.cooperative_txid IS NULL "
                    "AND a.fallback_raw IS NOT NULL AND a.fallback_txid IS NOT NULL "
                    "AND a.fallback_fee_sat IS NOT NULL AND w.state='PAID' "
                    "AND w.contract_hash=a.contract_hash AND w.preimage IS NOT NULL "
                    "AND w.terms_offer IS NOT NULL AND w.funding_binding IS NOT NULL "
                    "AND w.claim_tx IS NULL AND w.claim_txid IS NULL "
                    "AND s.phase='ACCEPTED' AND s.blocked=0 "
                    "AND NOT EXISTS (SELECT 1 FROM claim_attempts t "
                    "WHERE t.session_id=w.session_id)",
                    (session_id, cooperation_id, self._generation),
                ).fetchone()
                if row is None:
                    return None
                fallback, burned_bytes = PreparedFallback(*row[:-1]), row[-1]
                binding = parse_json_strict(burned_bytes)
                if (
                    not isinstance(binding, dict)
                    or canonicalize(binding) != burned_bytes
                    or type(binding.get("version")) is not int
                    or binding["version"] != 1
                    or binding.get("session_id") != session_id
                    or binding.get("cooperation_id") != cooperation_id.hex()
                    or binding.get("contract_hash") != fallback.contract_hash
                    or type(binding.get("deadline_at")) is not int
                    or type(binding.get("deadline_height")) is not int
                    or binding.get("deadline_at") != fallback.deadline_at
                    or binding.get("deadline_height") != fallback.deadline_height
                ):
                    return None
                return CooperativeCompletionCandidate(fallback, burned_bytes)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - no stored failure grants sampling or signer authority
            raise LiveSessionStoreError("cooperative completion candidate unavailable") from None

    def _commit_cooperative_claim_partial(
        self,
        session_id: str,
        cooperation_id: bytes,
        observation: CooperativeClaimObservation,
        *,
        now: int,
    ) -> str:
        """Retained internal custody primitive; never call for live arbitration."""
        return self._complete_cooperative_claim(
            session_id, cooperation_id, observation, now=now, select_winner=False
        )

    def _complete_cooperative_claim(  # noqa: PLR0912, PLR0913, PLR0915 - one-shot custody transition
        self,
        session_id: str,
        cooperation_id: bytes,
        observation: CooperativeClaimObservation,
        *,
        now: int,
        select_winner: bool,
        clock: Callable[[], int] | None = None,
    ) -> str:
        """Consume one live handle and commit the signed completion before exposure.

        The live wrapper requires a fresh, named-tip, mempool-aware sample
        immediately before invocation. This method never broadcasts.
        """
        from rill_crypto import Context  # noqa: PLC0415 - native signer only

        if (
            not isinstance(self._crypto, Context)
            or self._public_keys is not self._crypto
            or not isinstance(cooperation_id, bytes)
            or len(cooperation_id) != 32  # noqa: PLR2004 - burned ID length
            or not isinstance(observation, CooperativeClaimObservation)
            or type(now) is not int
            or now < 0
            or observation.network != self._network
            or type(observation.sampled_at) is not int
            or not 0 <= observation.sampled_at <= now
            or now - observation.sampled_at > COOPERATION_OBSERVATION_MAX_AGE_SECONDS
            or type(observation.tip_height) is not int
            or observation.tip_height <= 0
            or type(observation.confirmations) is not int
            or observation.confirmations < 0
            or type(observation.fee_floor_sat) is not int
            or observation.fee_floor_sat < 0
            or type(observation.funding_vout) is not int
            or observation.funding_vout < 0
            or type(observation.funding_value_sat) is not int
            or observation.funding_value_sat <= 0
            or type(observation.funding_script_pubkey) is not bytes
            or observation.mempool_unspent is not True
            or type(observation.tip_hash) is not str
            or HEX32.fullmatch(observation.tip_hash) is None
            or type(observation.funding_txid) is not str
            or HEX32.fullmatch(observation.funding_txid) is None
        ):
            raise LiveSessionStoreError("cooperative signing observation unavailable")
        crypto = self._crypto
        consumed = False
        try:
            with self._write() as connection:
                now = _cooperative_completion_now(now, clock, observation)
                row = connection.execute(
                    "SELECT a.binding,a.owner_generation,a.created_at,a.deadline_at,a.state,"
                    "a.local_nonce,a.peer_nonce,a.nonce_response_id,s.phase,s.blocked,"
                    "s.client_key,w.state,w.contract_hash,w.terms_offer,w.funding_binding,"
                    "w.preimage,w.claim_tx,w.claim_txid FROM cooperation_attempts a "
                    "JOIN sessions s ON s.session_id=a.session_id "
                    "JOIN swaps w ON w.session_id=a.session_id "
                    "WHERE a.session_id=? AND a.cooperation_id=?",
                    (session_id, cooperation_id),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("cooperative signer attempt unavailable")  # noqa: TRY301
                (
                    binding_bytes,
                    generation,
                    created_at,
                    deadline_at,
                    state,
                    local_nonce,
                    peer_nonce,
                    proposal_id,
                    phase,
                    blocked,
                    client_key,
                    swap_state,
                    recorded_hash,
                    offer_bytes,
                    funding_bytes,
                    preimage,
                    claim_tx,
                    claim_txid,
                ) = row
                binding = parse_json_strict(binding_bytes)
                if not isinstance(binding, dict) or (
                    generation != self._generation
                    or state != "SIGNING"
                    or phase != "ACCEPTED"
                    or blocked
                    or swap_state not in ("PAID", "CLAIMING")
                    or cooperation_id not in self._cooperation_handles
                    or not created_at <= now < deadline_at
                    or binding.get("version") != 1
                    or binding.get("session_id") != session_id
                    or binding.get("cooperation_id") != cooperation_id.hex()
                    or binding.get("contract_hash") != recorded_hash
                    or binding.get("claimant") != "provider"
                    or binding.get("deadline_at") != deadline_at
                    or not isinstance(local_nonce, bytes)
                    or not isinstance(peer_nonce, bytes)
                    or not isinstance(proposal_id, str)
                    or funding_bytes is None
                    or not isinstance(preimage, str)
                    or re.fullmatch(r"[0-9a-f]{64}", preimage) is None
                ):
                    raise LiveSessionStoreError("cooperative signing custody unavailable")  # noqa: TRY301
                terms = _offer_terms(offer_bytes)
                fee_sat = binding.get("fee_sat")
                deadline_height = binding.get("deadline_height")
                if (
                    type(fee_sat) is not int
                    or fee_sat < 0
                    or type(deadline_height) is not int
                    or deadline_height <= 0
                ):
                    raise LiveSessionStoreError("cooperative signing plan malformed")  # noqa: TRY301
                if select_winner:
                    arbitration = connection.execute(
                        "SELECT state,owner_generation,contract_hash,deadline_at,"
                        "deadline_height,cooperative_raw,cooperative_txid "
                        "FROM claim_arbitration WHERE session_id=? AND version=1",
                        (session_id,),
                    ).fetchone()
                    if (
                        arbitration
                        != (
                            "WAITING",
                            self._generation,
                            recorded_hash,
                            deadline_at,
                            deadline_height,
                            None,
                            None,
                        )
                        or swap_state != "PAID"
                        or claim_tx is not None
                        or claim_txid is not None
                        or connection.execute(
                            "SELECT 1 FROM claim_attempts WHERE session_id=? LIMIT 1", (session_id,)
                        ).fetchone()
                    ):
                        raise LiveSessionStoreError(  # noqa: TRY301
                            "cooperative arbitration unavailable"
                        )
                retained = parse_model_json(
                    FundingBindingPayload,
                    canonicalize(_canonical_envelope(funding_bytes).payload),
                ).binding
                if (
                    contract_hash(terms).hex() != recorded_hash
                    or terms.network_identity != self._network
                    or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                    or hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
                    != terms.invoice_binding.payment_hash
                    or retained.contract_hash != recorded_hash
                    or retained.funding_txid != binding.get("funding_txid")
                    or retained.contract_vout != binding.get("funding_vout")
                    or int(retained.contract_value_sat) != binding.get("funding_value_sat")
                    or retained.contract_script_pubkey != binding.get("funding_script_pubkey")
                    or observation.funding_txid != retained.funding_txid
                    or observation.funding_vout != retained.contract_vout
                    or observation.funding_value_sat != int(retained.contract_value_sat)
                    or observation.funding_script_pubkey.hex() != retained.contract_script_pubkey
                    or observation.confirmations < terms.funding_confirmations
                    or observation.tip_height >= terms.refund_lock_height
                    or observation.tip_height >= deadline_height
                    or fee_sat < observation.fee_floor_sat
                ):
                    raise LiveSessionStoreError("cooperative signing facts changed")  # noqa: TRY301
                funding = FundingOutput(
                    txid=bytes.fromhex(retained.funding_txid),
                    output_index=retained.contract_vout,
                    value_sat=int(retained.contract_value_sat),
                    script_pubkey=bytes.fromhex(retained.contract_script_pubkey),
                )
                authorization = UnilateralAuthorization.from_terms(
                    terms, funding, "claim", keys=crypto
                )
                plan = build_cooperative_claim(authorization, fee_sat=fee_sat)
                taproot = reconstruct_taproot_contract(terms, keys=crypto)
                if (
                    plan.base_transaction.hex() != binding.get("unsigned_transaction")
                    or plan.signature_hash.hex() != binding.get("signature_hash")
                    or terms.client_contract_compressed_key != binding.get("user_key")
                    or terms.provider_contract_compressed_key != binding.get("provider_key")
                    or taproot.tap_tweak.hex() != binding.get("tap_tweak")
                ):
                    raise LiveSessionStoreError("cooperative claim plan differs")  # noqa: TRY301
                saved = connection.execute(
                    "SELECT canonical_bytes FROM outbox WHERE session_id=? AND message_id=?",
                    (session_id, proposal_id),
                ).fetchone()
                if saved is None:
                    raise LiveSessionStoreError("cooperative proposal missing")  # noqa: TRY301
                proposal = _canonical_envelope(saved[0])
                original = parse_cooperative_payload(
                    "action_request", canonicalize(proposal.payload)
                )
                if not isinstance(original, CooperativeClaimPropose) or (
                    original.cooperation_id != cooperation_id.hex()
                    or original.public_nonce != local_nonce.hex()
                    or original.unsigned_transaction != plan.base_transaction.hex()
                ):
                    raise LiveSessionStoreError("cooperative proposal differs")  # noqa: TRY301
                matches: list[CooperativeClaimSigned] = []
                for (admitted,) in connection.execute(
                    "SELECT canonical_bytes FROM inbox WHERE session_id=? AND sender_key=? "
                    "AND seq>=? ORDER BY seq",
                    (session_id, client_key, FIRST_REQUEST_SEQUENCE),
                ):
                    candidate = _canonical_envelope(admitted)
                    if (
                        candidate.message_type != "action_result"
                        or candidate.in_reply_to != proposal_id
                    ):
                        continue
                    verify_static_signed_envelope(
                        admitted,
                        expected_session_id=session_id,
                        expected_profile=self._policy.profile,
                        expected_network=self._network,
                        expected_sender_key=client_key,
                        supported_features=self._policy.features,
                        crypto=crypto,
                    )
                    result = parse_cooperative_payload(
                        "action_result", canonicalize(candidate.payload)
                    )
                    if isinstance(result, CooperativeClaimSigned) and (
                        result.cooperation_id == cooperation_id.hex()
                        and result.public_nonce == peer_nonce.hex()
                    ):
                        matches.append(result)
                if len(matches) != 1:
                    raise LiveSessionStoreError("cooperative admitted partial unavailable")  # noqa: TRY301
                result = matches[0]
                crypto.musig_public_nonce_validate(peer_nonce)
                crypto.musig_partial_verify(
                    user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
                    provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
                    tap_tweak=taproot.tap_tweak,
                    message=plan.signature_hash,
                    user_public_nonce=peer_nonce,
                    provider_public_nonce=local_nonce,
                    signer_index=0,
                    partial_signature=bytes.fromhex(result.partial_signature),
                )
                now = _cooperative_completion_now(now, clock, observation)
                if not created_at <= now < deadline_at:
                    raise LiveSessionStoreError("cooperative deadline elapsed")  # noqa: TRY301
                # Popping BEFORE native consumption makes every failure one-shot.
                handle = self._cooperation_handles.pop(cooperation_id)
                consumed = True
                try:
                    partial = handle.partial_sign_once(peer_nonce)
                finally:
                    handle.close()
                crypto.musig_partial_verify(
                    user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
                    provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
                    tap_tweak=taproot.tap_tweak,
                    message=plan.signature_hash,
                    user_public_nonce=peer_nonce,
                    provider_public_nonce=local_nonce,
                    signer_index=1,
                    partial_signature=partial,
                )
                signature = crypto.musig_aggregate(
                    user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
                    provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
                    tap_tweak=taproot.tap_tweak,
                    message=plan.signature_hash,
                    user_public_nonce=peer_nonce,
                    provider_public_nonce=local_nonce,
                    user_partial_signature=bytes.fromhex(result.partial_signature),
                    provider_partial_signature=partial,
                )
                completed = finalize_cooperative_claim(plan, signature, verifier=crypto)
                now = _cooperative_completion_now(now, clock, observation)
                if not created_at <= now < deadline_at:
                    raise LiveSessionStoreError("cooperative deadline elapsed")  # noqa: TRY301
                if (
                    select_winner
                    and connection.execute(
                        "UPDATE claim_arbitration SET state='CLOSED',cooperative_raw=?,"
                        "cooperative_txid=? WHERE session_id=? AND version=1 "
                        "AND state='WAITING' AND owner_generation=? AND contract_hash=? "
                        "AND cooperative_raw IS NULL AND cooperative_txid IS NULL",
                        (
                            completed.raw_transaction,
                            completed.txid,
                            session_id,
                            self._generation,
                            recorded_hash,
                        ),
                    ).rowcount
                    != 1
                ):
                    raise LiveSessionStoreError("cooperative selection refused")  # noqa: TRY301
                if select_winner:
                    _reconcile_cooperative_proposal(connection, session_id)
                if select_winner:
                    if (
                        connection.execute(
                            "UPDATE swaps SET state='CLAIMING',claim_tx=?,claim_txid=?,"
                            "updated_at=? "
                            "WHERE session_id=? AND state='PAID' AND claim_tx IS NULL "
                            "AND claim_txid IS NULL",
                            (completed.raw_transaction, completed.txid, now, session_id),
                        ).rowcount
                        != 1
                    ):
                        raise StaleSwapError("cooperative claim changed")  # noqa: TRY301
                    connection.execute(
                        "INSERT INTO claim_attempts VALUES (?,0,?,?,?,?)",
                        (
                            session_id,
                            completed.txid,
                            completed.raw_transaction,
                            completed.fee_sat,
                            observation.tip_height,
                        ),
                    )
                    self._record_observation(
                        connection,
                        session_id,
                        {"kind": "claim_broadcast", "claim_txid": completed.txid},
                        crypto,
                        now,
                    )
                completion = {
                    "action": "cooperative_claim_complete",
                    "cooperation_id": cooperation_id.hex(),
                    "partial_signature": partial.hex(),
                }
                message_id = self._record_observation(
                    connection,
                    session_id,
                    completion,
                    crypto,
                    now,
                    message_type="action_request",
                    required_features=(COOPERATIVE_CLAIM_FEATURE,),
                )
                if (
                    connection.execute(
                        "UPDATE cooperation_attempts SET state='COMPLETE',"
                        "partial_signature=?,partial_response_id=? "
                        "WHERE session_id=? AND cooperation_id=? AND state='SIGNING' "
                        "AND owner_generation=?",
                        (partial, message_id, session_id, cooperation_id, self._generation),
                    ).rowcount
                    != 1
                ):
                    raise LiveSessionStoreError("cooperative signing state changed")  # noqa: TRY301
                now = _cooperative_completion_now(now, clock, observation)
                if not created_at <= now < deadline_at:
                    raise LiveSessionStoreError("cooperative deadline elapsed")  # noqa: TRY301
        except BaseException as error:
            if consumed and os.getpid() == self._pid and self._lock_fd is not None:
                # A rollback cannot restore a consumed native handle.
                with suppress(Exception), self._write() as connection:
                    connection.execute(
                        "UPDATE cooperation_attempts SET state='ABANDONED' "
                        "WHERE session_id=? AND cooperation_id=? AND state='SIGNING' "
                        "AND owner_generation=?",
                        (session_id, cooperation_id, self._generation),
                    )
            if isinstance(error, Exception) and not isinstance(error, LiveSessionStoreError):
                raise LiveSessionStoreError("cooperative signing refused") from None
            raise
        return message_id

    def _signed_envelope(  # noqa: PLR0913, PLR0917 - one envelope's explicit parts
        self,
        request: Envelope,
        key: str,
        sequence: int,
        reply: Answer,
        scalar: bytes,
        signer: EnvelopeSigner,
        in_reply_to: str | None,
        *,
        required_features: tuple[str, ...] = (),
    ) -> Envelope:
        unsigned = Envelope.model_validate_json(
            canonicalize(
                {
                    "protocol": "rillswap",
                    "wire_version": "1",
                    "profile_id": request.profile_id,
                    "network_identity": request.network_identity.model_dump(mode="json"),
                    "session_id": request.session_id,
                    "message_id": _new_message_id(),
                    "sender_session_key": key,
                    "sequence": sequence,
                    "in_reply_to": in_reply_to,
                    "contract_hash": reply.contract_hash,
                    "message_type": reply.message_type,
                    "payload": reply.payload,
                    "required_features": list(required_features),
                    "extensions": {},
                    "signature": None,
                }
            ),
            strict=True,
        )
        digest = unsigned_envelope_hash(unsigned)
        signature = signer.schnorr_sign(scalar, digest, secrets.token_bytes(32))
        self._crypto.schnorr_verify(bytes.fromhex(key), digest, signature)
        return unsigned.model_copy(update={"signature": signature.hex()})

    def _contract_key(self, connection: sqlite3.Connection, session_id: str) -> str:
        """Return this session's provider contract key, creating it once."""
        row = connection.execute(
            "SELECT compressed_key FROM contract_keys WHERE session_id=?", (session_id,)
        ).fetchone()
        if row is not None:
            return str(row[0])
        scalar = _new_session_scalar()
        compressed = bytes(self._public_keys.public_key(scalar)).hex()
        record = canonicalize(
            {
                "kind": CONTRACT_KEY_RECORD_KIND,
                "secret_scalar": scalar.hex(),
                "compressed_public_key": compressed,
                "session_id": session_id,
                "store_uuid": self._store_uuid,
            }
        )
        del scalar
        sealed = pyrage.encrypt(record, [self._custody_identity.to_public()])
        if type(sealed) is not bytes or pyrage.decrypt(sealed, [self._custody_identity]) != record:
            raise LiveSessionStoreError("contract key custody not verifiable")
        connection.execute(
            "INSERT INTO contract_keys VALUES (?, ?, ?)", (session_id, compressed, sealed)
        )
        return compressed

    def classify_request(self, request_document: bytes) -> str:
        """Read-only preflight: ``"new"``, ``"replay"``, or ``"conflict"``.

        Lets the caller skip expensive work (e.g. invoice decoding) for
        replays and unadmissible messages. ``answer_request`` rechecks
        everything; this grants nothing and records nothing.
        """
        try:
            outer = _canonical_envelope(request_document)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT client_key, phase, blocked, next_client_seq FROM sessions "
                    "WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None or row[1] not in OPEN_PHASES or row[2]:
                    raise LiveSessionStoreError("no open confirmed session")  # noqa: TRY301
                client, _, _, client_seq = row
                digest = verify_static_signed_envelope(
                    request_document,
                    expected_session_id=outer.session_id,
                    expected_profile=self._policy.profile,
                    expected_network=self._network,
                    expected_sender_key=client,
                    supported_features=self._policy.features,
                    crypto=self._crypto,
                ).hex()
                seen = connection.execute(
                    "SELECT message_id, seq, unsigned_digest FROM inbox "
                    "WHERE session_id=? AND sender_key=? AND (message_id=? OR seq=?)",
                    (outer.session_id, client, outer.message_id, outer.sequence),
                ).fetchall()
                if outer.message_type not in CLIENT_REQUEST_TYPES:
                    raise LiveSessionStoreError("request not admissible")  # noqa: TRY301
                if not seen and (
                    outer.sequence != client_seq
                    or client_seq - FIRST_REQUEST_SEQUENCE >= MAX_REQUESTS_PER_SESSION
                    or (
                        outer.in_reply_to is not None
                        and connection.execute(
                            "SELECT 1 FROM outbox WHERE session_id=? AND message_id=?",
                            (outer.session_id, outer.in_reply_to),
                        ).fetchone()
                        is None
                    )
                ):
                    raise LiveSessionStoreError("request not admissible")  # noqa: TRY301
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents or crypto details
            raise LiveSessionStoreError("request refused") from None
        if seen:
            return "replay" if seen == [(outer.message_id, outer.sequence, digest)] else "conflict"
        if outer.sequence != client_seq:
            raise LiveSessionStoreError("request not admissible")
        return "new"

    def settlement_work(self, *, session_id: str | None = None) -> tuple[SettlementItem, ...]:
        """Return funded work, optionally restricted to one exact retained session."""
        if session_id is not None and (
            type(session_id) is not str or HEX32.fullmatch(session_id) is None
        ):
            raise LiveSessionStoreError("settlement session ID unsupported")
        selected = "AND w.session_id=? " if session_id is not None else ""
        parameters = (
            (FIRST_REQUEST_SEQUENCE, session_id)
            if session_id is not None
            else (FIRST_REQUEST_SEQUENCE,)
        )
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT w.session_id, w.state, s.blocked, w.terms_offer, w.funding_binding, "  # noqa: S608 - only static SQL fragments; bound session ID
                    "i.canonical_bytes, w.preimage, w.claim_tx, w.claim_txid, "
                    "COALESCE(p.state, 'UNKNOWN'), p.payment_hash, p.request, "
                    "w.outpoint_spent_height, w.outpoint_spent_block, w.funding_txid, "
                    "w.funding_vout, w.funding_tx, w.refund_txid, w.refund_tx FROM swaps w "
                    "JOIN sessions s ON s.session_id = w.session_id "
                    "LEFT JOIN payment_dispatch p ON p.session_id = w.session_id "
                    "JOIN inbox i ON i.session_id = w.session_id AND i.sender_key = s.client_key "
                    "AND i.seq = ? LEFT JOIN evm_swaps e ON e.session_id = w.session_id "
                    "WHERE e.session_id IS NULL AND w.state IN ('ACCEPTED', 'FUNDING_SEEN', "
                    "'PAYING', 'PAID', 'CLAIMING', 'LN_HELD', 'FUNDING_SENT', 'FUNDED', "
                    "'REFUNDING') " + selected + "ORDER BY w.updated_at, w.session_id",
                    parameters,
                ).fetchall()
                items = tuple(
                    SettlementItem(
                        session_id,
                        state,
                        bool(blocked),
                        offer,
                        binding,
                        # LN to BTC requests carry a payment hash, not an invoice.
                        str(_canonical_envelope(request).payload.get("invoice", "")),
                        preimage,
                        claim_tx,
                        claim_txid,
                        payment_dispatch,
                        bound_payer(record, payment_hash=hashed, network=self._network)
                        if payment_dispatch == "SUBMITTED"
                        else None,
                        spent_height,
                        spent_block,
                        *provider_transactions,
                    )
                    for (
                        session_id,
                        state,
                        blocked,
                        offer,
                        binding,
                        request,
                        preimage,
                        claim_tx,
                        claim_txid,
                        payment_dispatch,
                        hashed,
                        record,
                        spent_height,
                        spent_block,
                        *provider_transactions,
                    ) in rows
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("settlement work unavailable") from None
        return items

    def _commit_reverse_proposal_debt(  # noqa: PLR0912, PLR0913 - one atomic financial boundary
        self,
        document: bytes,
        *,
        operation: ReverseOperation,
        core: CooperativeClaimOutpoint,
        invoice: BoundHoldInvoiceObservation,
        observations_started_at: float,
        observations_completed_at: float,
        now: int,
    ) -> None:
        """Commit new proposal-derived debt, never settle or grant signing authority.

        Trusted runtime must bracket the complete Own-Core/Own-LND acquisition
        under this same operation using the original window's clock dependency.
        Typed observations themselves carry no provenance or authority. First
        release admits only an exact live original-owner reservation in
        FUNDING_SENT or FUNDED (a client may claim before the signed depth),
        with no potentially issued refund. Historical knowledge cannot bootstrap
        this path. Existing debt continues through ordinary repayment instead.

        Debt commits before any later settlement dispatch. Expiry or owner loss
        afterward does not erase it or renew cooperation. No RPC, reply, sequence,
        native nonce, or reservation release occurs here.
        """
        self.reverse_operations.check(operation)
        if type(now) is not int or now < 0:
            raise LiveSessionStoreError("reverse proposal debt audit time unsupported")
        attempt: _ReverseProposalAttempt | None = None
        try:
            with self._write() as connection:
                outer, payload, terms = self._authenticated_reverse_preimage(connection, document)
                digest = unsigned_envelope_hash(outer).hex()
                candidate = self._reverse_proposals.get(outer.session_id)
                if (
                    candidate is None
                    or candidate.window is None
                    or candidate.message_id != outer.message_id
                    or candidate.unsigned_digest != digest
                    or candidate.cooperation_id != payload.cooperation_id
                ):
                    raise LiveSessionStoreError("reverse proposal debt has no live reservation")  # noqa: TRY301
                attempt = candidate
                row = connection.execute(
                    "SELECT s.accept_bytes,s.transcript_digest,s.blocked,w.contract_hash,"
                    "w.terms_accept,s.provider_session_key,w.state,w.preimage,"
                    "w.funding_txid,w.funding_vout,w.funding_tx,w.refund_txid,w.refund_tx "
                    "FROM sessions s JOIN swaps w ON w.session_id=s.session_id "
                    "WHERE s.session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("reverse proposal debt lifecycle refused")  # noqa: TRY301
                (
                    accept_bytes,
                    transcript,
                    blocked,
                    contract_digest,
                    accepted_bytes,
                    provider,
                    state,
                    retained,
                    txid,
                    vout,
                    raw,
                    refund_txid,
                    refund_raw,
                ) = row
                if (
                    not self._matches_reverse_negotiation(
                        outer.session_id,
                        contract_digest,
                        (accept_bytes, transcript, blocked, contract_digest, accepted_bytes),
                    )
                    or state not in ("FUNDING_SENT", "FUNDED")
                    or retained is not None
                    or refund_txid is not None
                    or refund_raw is not None
                    or type(txid) is not str
                    or type(vout) is not int
                    or type(raw) is not bytes
                ):
                    raise LiveSessionStoreError("reverse proposal debt lifecycle refused")  # noqa: TRY301
                burned = connection.execute(
                    "SELECT session_id,owner_generation,binding,state,deadline_at,local_nonce,"
                    "peer_nonce,partial_signature,nonce_response_id,partial_response_id "
                    "FROM cooperation_attempts WHERE cooperation_id=?",
                    (bytes.fromhex(payload.cooperation_id),),
                ).fetchone()
                admitted = connection.execute(
                    "SELECT sender_key,seq,unsigned_digest,canonical_bytes FROM inbox "
                    "WHERE session_id=? AND message_id=?",
                    (outer.session_id, outer.message_id),
                ).fetchone()
                if (
                    burned is None
                    or burned[0] != outer.session_id
                    or burned[1] != self._generation
                    or burned[3] != "BURNED"
                    or burned[4] != payload.deadline_at
                    or any(value is not None for value in burned[5:])
                    or admitted is None
                    or admitted[:3] != (outer.sender_session_key, outer.sequence, digest)
                    or unsigned_envelope_hash(_canonical_envelope(admitted[3])).hex() != digest
                ):
                    raise LiveSessionStoreError("reverse proposal debt reservation differs")  # noqa: TRY301
                expected, match, _, _ = self._reverse_reservation_binding(
                    connection,
                    outer,
                    payload,
                    terms,
                    provider=provider,
                    txid=txid,
                    vout=vout,
                    raw=raw,
                )
                if burned[2] != expected:
                    raise LiveSessionStoreError("reverse proposal debt binding differs")  # noqa: TRY301
                binding = parse_json_strict(expected)
                if not isinstance(binding, dict):
                    raise LiveSessionStoreError("reverse proposal debt binding unsupported")  # noqa: TRY301
                if (
                    type(core) is not CooperativeClaimOutpoint
                    or core.network_identity != self._network
                    or type(core.static_match) is not FundingBindingTransactionMatch
                    or core.static_match != match
                    or core.funding_txid != txid
                    or type(core.funding_vout) is not int
                    or core.funding_vout != vout
                    or type(core.funding_value_sat) is not int
                    or core.funding_value_sat != binding["funding_value_sat"]
                    or type(core.funding_script_pubkey) is not bytes
                    or core.funding_script_pubkey.hex() != binding["funding_script_pubkey"]
                    or _reverse_funding_sample_refused(core, terms)
                ):
                    raise LiveSessionStoreError("reverse proposal debt Core evidence refused")  # noqa: TRY301
                minimum_htlc_expiry = (
                    terms.refund_lock_height
                    + 1
                    + int(terms.timing_policy.model_dump()["refund_and_ln_resolution_blocks"])
                )
                if (
                    type(invoice) is not BoundHoldInvoiceObservation
                    or invoice.network != self._network
                    or invoice.payment_hash != terms.invoice_binding.payment_hash
                    or invoice.bolt11_sha256 != terms.invoice_binding.bolt11_sha256
                    or invoice.node_pubkey != terms.invoice_binding.payee_compressed_pubkey
                    or type(invoice.last_lnd_height) is not int
                    or invoice.last_lnd_height != core.tip_height
                    or invoice.last_lnd_block_hash != core.tip_hash
                    or type(invoice.status) is not HoldInvoiceStatus
                    or invoice.status.state != "ACCEPTED"
                    or type(invoice.status.htlcs) is not tuple
                    or not invoice.status.htlcs
                    or any(
                        type(part) is not HeldHtlc
                        or type(part.amount_msat) is not int
                        or part.amount_msat <= 0
                        or type(part.expiry_height) is not int
                        or part.expiry_height <= minimum_htlc_expiry
                        for part in invoice.status.htlcs
                    )
                    or invoice.status.held_msat != int(terms.invoice_binding.amount_msat)
                ):
                    raise LiveSessionStoreError("reverse proposal debt LND evidence refused")  # noqa: TRY301
                candidate.window.check(tip_height=core.tip_height)
                connection.execute(
                    "UPDATE swaps SET preimage=?,updated_at=MAX(updated_at,?) "
                    "WHERE session_id=? AND state IN ('FUNDING_SENT','FUNDED') "
                    "AND preimage IS NULL",
                    (payload.payment_preimage, now, outer.session_id),
                )
                self.reverse_operations.check(operation)
                candidate.window.check_evidence_interval(
                    started_at=observations_started_at, completed_at=observations_completed_at
                )
        except StaleOwnerError:
            if attempt is not None and attempt.window is not None:
                attempt.window.abandon()
            raise
        except Exception:  # noqa: BLE001 - no preimage, backend, or crypto oracle
            if attempt is not None and attempt.window is not None:
                attempt.window.abandon()
        else:
            return
        raise LiveSessionStoreError("reverse proposal debt refused")

    def record_reverse_settlement_preimage(
        self, session_id: str, *, from_state: str, preimage: str, now: int
    ) -> None:
        """Durably owe hold settlement before its RPC, without releasing funds.

        Trusted runtime calls this only after observing the matching claim
        witness through its own Core. Presence proves intent via this controlled
        writer, not prior LND settlement or independent transaction validation.
        Historically this was the only reverse nonterminal preimage writer;
        fresh proposal debt now has its own separately authenticated boundary.
        Missing knowledge never manufactures an obligation or starts recovery work.
        """
        if (
            from_state not in {"FUNDING_SENT", "FUNDED", "REFUNDING"}
            or type(now) is not int
            or now < 0
        ):
            raise LiveSessionStoreError("reverse settlement intent context invalid")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT terms_offer,preimage,funding_txid,funding_vout,funding_tx "
                    "FROM swaps WHERE session_id=? AND state=?",
                    (session_id, from_state),
                ).fetchone()
                if row is None:
                    raise StaleSwapError("swap state changed")  # noqa: TRY301 - atomic obligation
                offer_bytes, retained, txid, vout, raw = row
                terms = _offer_terms(offer_bytes)
                if (
                    terms.profile_id != "ln-to-btc/v1"
                    or terms.network_identity != self._network
                    or type(txid) is not str
                    or len(txid) != 64  # noqa: PLR2004 - canonical txid
                    or any(character not in "0123456789abcdef" for character in txid)
                    or type(vout) is not int
                    or vout < 0
                    or type(raw) is not bytes
                    or not raw
                    or type(preimage) is not str
                    or len(preimage) != 64  # noqa: PLR2004 - canonical preimage
                    or any(character not in "0123456789abcdef" for character in preimage)
                    or hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
                    != terms.invoice_binding.payment_hash
                    or (retained is not None and retained != preimage)
                ):
                    raise LiveSessionStoreError("reverse settlement intent evidence invalid")  # noqa: TRY301
                connection.execute(
                    "UPDATE swaps SET preimage=?,updated_at=MAX(updated_at,?) "
                    "WHERE session_id=? AND state=?",
                    (preimage, now, session_id, from_state),
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - no secret or storage details escape
            raise LiveSessionStoreError("reverse settlement intent refused") from None

    def reverse_spend_checkpoint(
        self, session_id: str, *, operation: ReverseOperation
    ) -> ReverseSpendCheckpoint | None:
        """Read reverse-only progress; malformed state is never treated as absence."""
        self.reverse_operations.check(operation)
        with self._write() as connection:
            row = connection.execute(
                "SELECT floor_height,floor_block,cursor_height,cursor_block "
                "FROM reverse_spend_scans WHERE session_id=?",
                (session_id,),
            ).fetchone()
            return None if row is None else ReverseSpendCheckpoint(*row)

    def update_reverse_spend_checkpoint(
        self,
        session_id: str,
        *,
        expected: ReverseSpendCheckpoint,
        checkpoint: ReverseSpendCheckpoint,
        operation: ReverseOperation,
        rewind: bool = False,
    ) -> None:
        """Compare-and-swap scan progress under the current reverse operation.

        Only an affirmative canonical mismatch permits an explicit rewind to
        the immutable floor. The checkpoint itself is created with FUNDED.
        """
        self.reverse_operations.check(operation)
        if (
            (checkpoint.floor_height, checkpoint.floor_block)
            != (expected.floor_height, expected.floor_block)
            or (rewind and checkpoint.height != checkpoint.floor_height)
            or (not rewind and checkpoint.height < expected.height)
            or (
                not rewind
                and checkpoint.height == expected.height
                and checkpoint.block != expected.block
            )
        ):
            raise LiveSessionStoreError("reverse scan update unsupported")
        with self._write() as connection:
            row = connection.execute(
                "SELECT state,terms_offer FROM swaps WHERE session_id=?", (session_id,)
            ).fetchone()
            if (
                row is None
                or row[0] not in {"FUNDED", "REFUNDING"}
                or _offer_terms(row[1]).profile_id != "ln-to-btc/v1"
            ):
                raise StaleSwapError("reverse scan swap unavailable")
            if (
                connection.execute(
                    "UPDATE reverse_spend_scans SET cursor_height=?,cursor_block=? "
                    "WHERE session_id=? "
                    "AND floor_height=? AND floor_block=? AND cursor_height=? AND cursor_block=?",
                    (
                        checkpoint.height,
                        checkpoint.block,
                        session_id,
                        expected.floor_height,
                        expected.floor_block,
                        expected.height,
                        expected.block,
                    ),
                ).rowcount
                != 1
            ):
                raise StaleSwapError("reverse scan cursor changed")

    def reverse_funding_is_ungranted(self, session_id: str, *, operation: ReverseOperation) -> bool:
        """Certify absent funding authority under the same live settlement owner.

        A failed transition alone is not a rollback certificate. Return only
        after this owner-authenticated checking transaction commits successfully.
        Missing or partial records never authorize wallet input cleanup.
        """
        self.reverse_operations.check(operation)
        ungranted = False
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT state,terms_offer,funding_binding,funding_txid,funding_vout,funding_tx "
                    "FROM swaps WHERE session_id=?",
                    (session_id,),
                ).fetchone()
                reservations = connection.execute(
                    "SELECT payment_hash,state,release_evidence FROM economic_reservations "
                    "WHERE session_id=?",
                    (session_id,),
                ).fetchall()
                outbox = connection.execute(
                    "SELECT canonical_bytes FROM outbox WHERE session_id=?", (session_id,)
                ).fetchall()
                if (
                    row is not None
                    and row[0] == "LN_HELD"
                    and all(value is None for value in row[2:])
                ):
                    terms = _offer_terms(row[1])
                    ungranted = (
                        terms.profile_id == "ln-to-btc/v1"
                        and terms.network_identity == self._network
                        and len(reservations) == 1
                        and reservations[0][0] == terms.invoice_binding.payment_hash
                        and reservations[0][1] == "UNSENT"
                        and reservations[0][2] is None
                        and all(
                            _canonical_envelope(document).message_type != "funding_binding"
                            for (document,) in outbox
                        )
                    )
        except sqlite3.Error:
            raise LiveSessionStoreError("reverse funding refusal evidence unavailable") from None
        return ungranted

    def advance_reverse_swap(  # noqa: PLR0912, PLR0913, PLR0915 - one atomic transition's parts
        self,
        session_id: str,
        *,
        from_state: str,
        to_state: str,
        signer: EnvelopeSigner,
        now: int,
        funding: tuple[FundingBinding, bytes] | None = None,
        refund: tuple[str, bytes] | None = None,
        preimage: str | None = None,
        refund_confirmations: int | None = None,
        observation: dict[str, Any] | None = None,
        scan_checkpoint: ReverseSpendCheckpoint | None = None,
        funding_fee_sat: int | None = None,
        refund_fee_sat: int | None = None,
    ) -> None:
        """Move one LN to BTC swap forward (RS-004) in one transaction.

        ``LN_HELD`` to ``FUNDING_SENT`` is the one funding grant: it records
        the signed funding ``(binding, raw)``, marks the reservation
        ``DISPATCHED`` in the same transaction (refusing when the reservation
        is not open, so a funding can never be signed twice for one swap),
        and queues the RS-003 ``funding_binding`` message signed with the
        session key so the client can record it in its recovery file.
        ``SETTLED`` needs the preimage of the terms' payment hash (checked
        here, whatever reported it) and releases the reservation: the hold
        invoice pays for the contract. ``REFUNDING`` records the refund
        ``(txid, raw)``; ``REFUNDED`` releases on the refund's depth;
        ``ABORTED`` releases an undispatched reservation (nothing was funded).
        The mining fees of our funding and refund, and terminal outcomes, are
        appended to the swap ledger in the same transaction.
        """
        if (to_state == "FUNDED") != (scan_checkpoint is not None):
            raise LiveSessionStoreError("funded transition requires its initial scan checkpoint")
        if scan_checkpoint is not None and scan_checkpoint.height != scan_checkpoint.floor_height:
            raise LiveSessionStoreError("funded transition scan must start at its floor")
        _check_reverse_transition(
            (from_state, to_state),
            funding=funding,
            refund=refund,
            preimage=preimage,
            refund_confirmations=refund_confirmations,
        )
        try:
            with self._write() as connection:
                offer_bytes, retained_preimage = connection.execute(
                    "SELECT terms_offer,preimage FROM swaps WHERE session_id=? AND state=?",
                    (session_id, from_state),
                ).fetchone() or (None, None)
                if offer_bytes is None:
                    raise StaleSwapError("swap state changed")  # noqa: TRY301
                terms = _offer_terms(offer_bytes)
                payment_hash = terms.invoice_binding.payment_hash
                if terms.profile_id != "ln-to-btc/v1":
                    raise LiveSessionStoreError("not an LN to BTC swap")  # noqa: TRY301
                if scan_checkpoint is not None:
                    connection.execute(
                        "INSERT INTO reverse_spend_scans VALUES (?,?,?,?,?)",
                        (
                            session_id,
                            scan_checkpoint.floor_height,
                            scan_checkpoint.floor_block,
                            scan_checkpoint.height,
                            scan_checkpoint.block,
                        ),
                    )
                if retained_preimage is not None and to_state in {"REFUNDING", "REFUNDED"}:
                    raise LiveSessionStoreError(  # noqa: TRY301 - durable debt fences refund transitions
                        "reverse settlement obligation forbids refund progression"
                    )
                if (
                    retained_preimage is not None
                    and to_state == "SETTLED"
                    and preimage != retained_preimage
                ):
                    raise LiveSessionStoreError(  # noqa: TRY301 - retained knowledge is immutable
                        "reverse settlement intent conflicts with completion"
                    )
                if preimage is not None and (
                    type(preimage) is not str
                    or len(preimage) != 64  # noqa: PLR2004 - hex preimage
                    or hashlib.sha256(bytes.fromhex(preimage)).hexdigest() != payment_hash
                ):
                    raise LiveSessionStoreError("preimage does not match the payment hash")  # noqa: TRY301
                columns = "state=?, preimage=COALESCE(?, preimage), updated_at=?"
                values: list[Any] = [to_state, preimage, now]
                if funding is not None:
                    binding, raw = funding
                    if (
                        binding.contract_hash != _canonical_envelope(offer_bytes).contract_hash
                        or binding.funder_role != "provider"
                    ):
                        raise LiveSessionStoreError("funding binding is for another swap")  # noqa: TRY301
                    columns += ", funding_txid=?, funding_vout=?, funding_tx=?"
                    values.extend((binding.funding_txid, binding.contract_vout, raw))
                if refund is not None:
                    columns += ", refund_txid=?, refund_tx=?"
                    values.extend(refund)
                updated = connection.execute(
                    f"UPDATE swaps SET {columns} WHERE session_id=? AND state=?",  # noqa: S608 - static column list
                    (*values, session_id, from_state),
                ).rowcount
                if updated != 1:
                    raise StaleSwapError("swap state changed")  # noqa: TRY301
                if to_state == "FUNDING_SENT":
                    granted = connection.execute(
                        "UPDATE economic_reservations SET state='DISPATCHED' "
                        "WHERE payment_hash=? AND session_id=? AND state='UNSENT'",
                        (payment_hash, session_id),
                    ).rowcount
                    if granted != 1:
                        raise LiveSessionStoreError("funding grant refused")  # noqa: TRY301
                if to_state in ("ABORTED", "SETTLED", "REFUNDED"):
                    _release_reverse_terminal(
                        connection,
                        session_id,
                        to_state,
                        now,
                        terms=terms,
                        refund_confirmations=refund_confirmations,
                    )
                if funding_fee_sat is not None:
                    _record_ledger(connection, session_id, now, FUNDING_FEE, funding_fee_sat)
                if refund_fee_sat is not None:
                    _record_ledger(connection, session_id, now, REFUND_FEE, refund_fee_sat)
                _record_outcome(connection, session_id, to_state, now)
                if funding is not None:
                    self._record_funding_binding(connection, session_id, funding, signer, now)
                if observation is not None:
                    self._record_observation(connection, session_id, observation, signer, now)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("swap transition refused") from None

    def _record_funding_binding(
        self,
        connection: sqlite3.Connection,
        session_id: str,
        funding: tuple[FundingBinding, bytes],
        signer: EnvelopeSigner,
        now: int,
    ) -> None:
        binding, raw = funding
        scalar, _ = self._unseal(connection, session_id)
        try:
            signature = signer.schnorr_sign(
                scalar, funding_binding_hash(binding), secrets.token_bytes(32)
            )
        finally:
            del scalar
        payload = {
            "binding": binding.model_dump(mode="json"),
            "funding_binding_signature": signature.hex(),
            "funding_transaction": raw.hex(),
        }
        self._record_observation(
            connection, session_id, payload, signer, now, message_type="funding_binding"
        )

    def evm_settlement_work(self) -> tuple[EvmSettlementItem, ...]:
        """Return every open EVM-profile swap (RS-010) with its retained evidence."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT w.session_id, w.state, s.blocked, w.terms_offer, i.canonical_bytes, "
                    "w.preimage, COALESCE(p.state, 'UNKNOWN'), p.payment_hash, p.request, "
                    "e.lock_tx_hash, e.lock_log_index, e.lock_block, e.provider_tx_hash, "
                    "e.provider_tx, e.claim_tx_hash, e.claim_tx, e.refund_tx_hash, e.refund_tx "
                    "FROM evm_swaps e "
                    "JOIN swaps w ON w.session_id = e.session_id "
                    "JOIN sessions s ON s.session_id = w.session_id "
                    "LEFT JOIN payment_dispatch p ON p.session_id = w.session_id "
                    "JOIN inbox i ON i.session_id = w.session_id AND i.sender_key = s.client_key "
                    "AND i.seq = ? WHERE w.state IN ('ACCEPTED', 'FUNDING_SEEN', 'PAYING', 'PAID', "
                    "'CLAIMING', 'LN_HELD', 'FUNDING_SENT', 'FUNDED', 'REFUNDING') "
                    "ORDER BY w.updated_at, w.session_id",
                    (FIRST_REQUEST_SEQUENCE,),
                ).fetchall()
                return tuple(
                    EvmSettlementItem(
                        session_id,
                        state,
                        bool(blocked),
                        offer,
                        str(_canonical_envelope(request).payload.get("invoice", "")),
                        preimage,
                        payment_dispatch,
                        bound_payer(record, payment_hash=hashed, network=self._network)
                        if payment_dispatch == "SUBMITTED"
                        else None,
                        *evidence,
                    )
                    for (
                        session_id,
                        state,
                        blocked,
                        offer,
                        request,
                        preimage,
                        payment_dispatch,
                        hashed,
                        record,
                        *evidence,
                    ) in rows
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("EVM settlement work unavailable") from None

    def advance_evm_swap(  # noqa: PLR0912, PLR0913 - one atomic transition's explicit parts
        self,
        session_id: str,
        *,
        from_state: str,
        to_state: str,
        signer: EnvelopeSigner,
        now: int,
        lockup: tuple[str, int, int] | None = None,
        sent: tuple[str, bytes] | None = None,
        observed_claim: str | None = None,
        preimage: str | None = None,
        failed_by_payer: str | None = None,
        observation: dict[str, Any] | None = None,
        routing_fee_msat: int | None = None,
        gas_wei: int | None = None,
    ) -> None:
        """Move one EVM-profile swap (RS-010) forward in one transaction.

        ``FUNDING_SEEN`` records the observed ``lockup`` ``(tx_hash, log_index,
        block)``. ``PAYING`` is the one payment grant (an UNSENT dispatch row).
        ``PAID`` and ``SETTLED`` need the preimage of the terms' payment hash.
        ``CLAIMING``, ``FUNDING_SENT`` and ``REFUNDING`` record our signed
        transaction ``sent`` as ``(tx_hash, raw)`` before it is broadcast;
        ``FUNDING_SENT`` also marks the reservation ``DISPATCHED`` so a lock is
        never signed twice. ``SETTLED`` may name the client's ``observed_claim``
        hash. Terminal states release the reservation with their evidence.
        ``routing_fee_msat``, the ``gas_wei`` our mined transaction cost, and
        terminal outcomes are appended to the swap ledger in the same transaction.
        """
        _check_evm_transition((from_state, to_state), lockup=lockup, sent=sent, preimage=preimage)
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT w.terms_offer, w.preimage FROM swaps w JOIN evm_swaps e "
                    "ON e.session_id = w.session_id WHERE w.session_id=? AND w.state=?",
                    (session_id, from_state),
                ).fetchone()
                if row is None:
                    raise StaleSwapError("swap state changed")  # noqa: TRY301
                offer_bytes, retained_preimage = row
                terms = _evm_offer_terms(offer_bytes)
                payment_hash = terms.invoice_binding.payment_hash
                if preimage is not None and (
                    type(preimage) is not str
                    or len(preimage) != 64  # noqa: PLR2004 - hex preimage
                    or hashlib.sha256(bytes.fromhex(preimage)).hexdigest() != payment_hash
                    or (retained_preimage is not None and retained_preimage != preimage)
                ):
                    raise LiveSessionStoreError("preimage does not match the payment hash")  # noqa: TRY301
                updated = connection.execute(
                    "UPDATE swaps SET state=?, preimage=COALESCE(?, preimage), updated_at=? "
                    "WHERE session_id=? AND state=?",
                    (to_state, preimage, now, session_id, from_state),
                ).rowcount
                if updated != 1:
                    raise StaleSwapError("swap state changed")  # noqa: TRY301
                if to_state == "FUNDING_SEEN" and lockup is not None:
                    connection.execute(
                        "UPDATE evm_swaps SET lock_tx_hash=?, lock_log_index=?, lock_block=? "
                        "WHERE session_id=?",
                        (*lockup, session_id),
                    )
                elif to_state == "PAYING":
                    connection.execute(
                        "INSERT INTO payment_dispatch VALUES (?, ?, 'UNSENT', NULL)",
                        (session_id, payment_hash),
                    )
                elif to_state == "FUNDING_SENT" and sent is not None:
                    connection.execute(
                        "UPDATE evm_swaps SET provider_tx_hash=?, provider_tx=? WHERE session_id=?",
                        (*sent, session_id),
                    )
                    granted = connection.execute(
                        "UPDATE economic_reservations SET state='DISPATCHED' "
                        "WHERE payment_hash=? AND session_id=? AND state='UNSENT'",
                        (payment_hash, session_id),
                    ).rowcount
                    if granted != 1:
                        raise LiveSessionStoreError("funding grant refused")  # noqa: TRY301
                elif to_state == "CLAIMING" and sent is not None:
                    connection.execute(
                        "UPDATE evm_swaps SET claim_tx_hash=?, claim_tx=? WHERE session_id=?",
                        (*sent, session_id),
                    )
                elif to_state == "SETTLED" and observed_claim is not None:
                    connection.execute(
                        "UPDATE evm_swaps SET claim_tx_hash=? WHERE session_id=?",
                        (observed_claim, session_id),
                    )
                elif to_state == "REFUNDING" and sent is not None:
                    connection.execute(
                        "UPDATE evm_swaps SET refund_tx_hash=?, refund_tx=? WHERE session_id=?",
                        (*sent, session_id),
                    )
                if to_state in EVM_TERMINAL_STATES:
                    _release_evm_terminal(
                        connection,
                        session_id,
                        to_state,
                        now,
                        payment_hash=payment_hash,
                        failed_by_payer=failed_by_payer,
                        network=self._network,
                    )
                if routing_fee_msat is not None:
                    _record_ledger(
                        connection, session_id, now, ROUTING_FEE, routing_fee_msat, unit="msat"
                    )
                if gas_wei is not None:
                    _record_ledger(connection, session_id, now, GAS, gas_wei, unit="wei")
                _record_outcome(connection, session_id, to_state, now)
                if observation is not None:
                    self._record_observation(connection, session_id, observation, signer, now)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage or crypto details
            raise LiveSessionStoreError("swap transition refused") from None

    def replace_evm_sent(  # noqa: PLR0913 - one atomic replacement's explicit parts
        self,
        session_id: str,
        *,
        state: str,
        old_hash: str,
        sent: tuple[str, bytes],
        signer: EnvelopeSigner,
        now: int,
    ) -> None:
        """Replace a recorded claim or refund whose nonce another transaction consumed.

        Compare-and-swap on the state and the recorded hash, before any
        broadcast of ``sent``. A claim also re-sends ``claim_broadcast`` naming
        the new hash. Locks are never replaced: ``ERC20Swap`` forgets a swap
        once it is claimed or refunded, so a second lock could fund it again.
        """
        column = {"CLAIMING": "claim", "REFUNDING": "refund"}.get(state)
        if column is None:
            raise LiveSessionStoreError("only a claim or refund may be replaced")
        try:
            with self._write() as connection:
                updated = connection.execute(
                    f"UPDATE evm_swaps SET {column}_tx_hash=?, {column}_tx=? "  # noqa: S608 - fixed names
                    f"WHERE session_id=? AND {column}_tx_hash=? AND session_id IN "
                    "(SELECT session_id FROM swaps WHERE session_id=? AND state=?)",
                    (*sent, session_id, old_hash, session_id, state),
                ).rowcount
                if updated != 1:
                    raise StaleSwapError("swap state changed")  # noqa: TRY301
                connection.execute(
                    "UPDATE swaps SET updated_at=? WHERE session_id=?", (now, session_id)
                )
                if state == "CLAIMING":
                    self._record_observation(
                        connection,
                        session_id,
                        {"kind": "claim_broadcast", "claim_txid": sent[0]},
                        signer,
                        now,
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage or crypto details
            raise LiveSessionStoreError("swap transition refused") from None

    def advance_swap(  # noqa: PLR0912, PLR0913 - one atomic transition's explicit parts
        self,
        session_id: str,
        *,
        from_state: str,
        to_state: str,
        signer: EnvelopeSigner,
        now: int,
        preimage: str | None = None,
        claim_tx: bytes | None = None,
        claim_txid: str | None = None,
        claim_fee_sat: int | None = None,
        claim_height: int | None = None,
        failed_by_payer: str | None = None,
        observation: dict[str, Any] | None = None,
        loss_evidence: FundingConflict | None = None,
        routing_fee_msat: int | None = None,
    ) -> None:
        """Move one swap forward and record its observation in one transaction.

        ``PAID`` to ``CLAIMING`` records the claim as attempt 0 (with its fee
        and the tip it was built at). ``CLAIMING`` to ``CLAIMED`` must name a
        recorded attempt, which becomes the mirrored claim. ``FAILED`` with
        ``failed_by_payer`` (the node public key that attested the terminal
        failure) also releases a dispatched reservation when that key is the
        dispatch record's bound payer; any other failure keeps capacity.
        ``CLAIMING`` to ``LOST`` closes on the anchored refund observation, or
        on ``loss_evidence`` when the deposit itself was double-spent.
        ``routing_fee_msat`` (the LN fee a payment actually paid) and terminal
        outcomes are appended to the swap ledger in the same transaction.

        Raises ``StaleSwapError`` unless the swap is still in ``from_state``,
        so a crash or a concurrent tick can never apply a transition twice.
        The observation is committed to the outbox before anything sends it.
        """
        if (from_state, to_state) not in SWAP_TRANSITIONS:
            raise LiveSessionStoreError("swap transition unsupported")
        if to_state in ("CLAIMING", "CLAIMED") and (claim_tx is None or claim_txid is None):
            raise LiveSessionStoreError("claim transition needs the exact claim")
        if loss_evidence is not None and (from_state, to_state) != ("CLAIMING", "LOST"):
            raise LiveSessionStoreError("loss evidence closes only a claim")
        try:
            with self._write() as connection:
                if (from_state, to_state) == ("PAID", "CLAIMING") and not _immediate_claim_allowed(
                    connection, session_id
                ):
                    raise LiveSessionStoreError(  # noqa: TRY301 - refuse bypass of arbitration
                        "claim arbitration requires transaction selection"
                    )
                if to_state == "CLAIMED" and connection.execute(
                    "SELECT raw FROM claim_attempts WHERE session_id=? AND txid=?",
                    (session_id, claim_txid),
                ).fetchone() != (claim_tx,):
                    raise LiveSessionStoreError("claim is not a recorded attempt")  # noqa: TRY301
                updated = connection.execute(
                    "UPDATE swaps SET state=?, preimage=COALESCE(?, preimage), "
                    "claim_tx=COALESCE(?, claim_tx), claim_txid=COALESCE(?, claim_txid), "
                    "updated_at=? WHERE session_id=? AND state=?",
                    (to_state, preimage, claim_tx, claim_txid, now, session_id, from_state),
                ).rowcount
                if updated != 1:
                    raise StaleSwapError("swap state changed")  # noqa: TRY301
                if to_state == "CLAIMING":
                    connection.execute(
                        "INSERT INTO claim_attempts VALUES (?, 0, ?, ?, ?, ?)",
                        (session_id, claim_txid, claim_tx, claim_fee_sat, claim_height),
                    )
                if (from_state, to_state) == ("FUNDING_SEEN", "PAYING"):
                    (offer_bytes,) = connection.execute(
                        "SELECT terms_offer FROM swaps WHERE session_id=?", (session_id,)
                    ).fetchone()
                    offer = parse_model_json(
                        TermsOfferPayload, canonicalize(_canonical_envelope(offer_bytes).payload)
                    )
                    connection.execute(
                        "INSERT INTO payment_dispatch VALUES (?, ?, 'UNSENT', NULL)",
                        (session_id, offer.terms.contract_terms.invoice_binding.payment_hash),
                    )
                if to_state in ("FAILED", "CLAIMED", "LOST"):
                    _release_terminal(
                        connection,
                        session_id,
                        to_state,
                        now,
                        failed_by_payer=failed_by_payer,
                        network=self._network,
                        conflict=loss_evidence,
                    )
                if routing_fee_msat is not None:
                    _record_ledger(
                        connection, session_id, now, ROUTING_FEE, routing_fee_msat, unit="msat"
                    )
                _record_outcome(
                    connection,
                    session_id,
                    to_state,
                    now,
                    claim_txid=claim_txid if to_state == "CLAIMED" else None,
                )
                if observation is not None:
                    self._record_observation(connection, session_id, observation, signer, now)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage or crypto details
            raise LiveSessionStoreError("swap transition refused") from None

    def immediate_claim_allowed(self, session_id: str) -> bool:
        """Only absent or unprepared admission permits the legacy unilateral path.

        A prepared or closed arbitration must be reconciled and selected first;
        the PAID to CLAIMING transition checks this again in its write transaction.
        """
        try:
            with self._write() as connection:
                return _immediate_claim_allowed(connection, session_id)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("claim arbitration unavailable") from None

    def admitted_featured_claim(self, session_id: str, contract: str) -> bool:
        """Check affirmative agreement, never infer original-session liveness."""
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT a.version,a.state,a.contract_hash,w.contract_hash "
                    "FROM claim_arbitration a JOIN swaps w ON w.session_id=a.session_id "
                    "WHERE a.session_id=?",
                    (session_id,),
                ).fetchone()
                return bool(row == (1, "ADMITTED", contract, contract))
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("claim admission unavailable") from None

    def cooperative_height_cutoff(self, session_id: str, contract: str) -> int | None:
        """Return the signed new-window cutoff only for a PAID admission."""
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT a.version,a.state,a.contract_hash,w.state,w.contract_hash,"
                    "w.terms_offer FROM claim_arbitration a JOIN swaps w "
                    "ON w.session_id=a.session_id WHERE a.session_id=?",
                    (session_id,),
                ).fetchone()
                if row is None or row[:5] != (1, "ADMITTED", contract, "PAID", contract):
                    return None
                terms = _offer_terms(row[5])
                if (
                    COOPERATIVE_CLAIM_FEATURE not in self._policy.features
                    or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                    or contract_hash(terms).hex() != contract
                    or terms.network_identity != self._network
                    or terms.profile_id != "btc-to-ln/v1"
                ):
                    return None
                cutoff = _cooperative_height_cutoff(terms)
                return cutoff if cutoff > 0 else None
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - no unverified height bound
            raise LiveSessionStoreError("cooperative height unavailable") from None

    def issue_cooperative_readiness(  # noqa: PLR0913 - fixed time/height probe budget
        self,
        session_id: str,
        *,
        signer: EnvelopeSigner,
        started_at: int,
        now: int,
        deadline_at: int,
        deadline_height: int,
    ) -> ReadinessChallenge:
        """Sign one process-owned readiness probe for an authenticated PAID swap.

        Issuance alone never delays unilateral claiming. Only a current owner
        holding the returned token in memory may accept a later signed echo.
        An abandoned request must never be reconstructed from the outbox.
        """
        if (
            type(started_at) is not int
            or type(now) is not int
            or type(deadline_at) is not int
            or type(deadline_height) is not int
            or started_at < 0
            or not started_at <= now < deadline_at <= started_at + COOPERATION_BUDGET_SECONDS
            or deadline_height <= 0
        ):
            raise LiveSessionStoreError("readiness deadline unavailable")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT a.state,a.version,a.contract_hash,s.phase,s.blocked,"
                    "w.state,w.contract_hash,w.terms_offer,w.funding_binding,w.preimage,"
                    "w.claim_tx,w.claim_txid FROM claim_arbitration a "
                    "JOIN swaps w ON w.session_id=a.session_id "
                    "JOIN sessions s ON s.session_id=a.session_id WHERE a.session_id=?",
                    (session_id,),
                ).fetchone()
                if row is None or row[:2] != ("ADMITTED", 1):
                    raise LiveSessionStoreError("readiness not admitted")  # noqa: TRY301
                (
                    _,
                    _,
                    admitted_hash,
                    phase,
                    blocked,
                    state,
                    swap_hash,
                    offer,
                    funding,
                    preimage,
                    claim_tx,
                    claim_txid,
                ) = row
                if (
                    phase != "ACCEPTED"
                    or blocked
                    or state != "PAID"
                    or swap_hash != admitted_hash
                    or funding is None
                    or claim_tx is not None
                    or claim_txid is not None
                    or not isinstance(preimage, str)
                    or re.fullmatch(r"[0-9a-f]{64}", preimage) is None
                    or connection.execute(
                        "SELECT 1 FROM claim_attempts WHERE session_id=? LIMIT 1", (session_id,)
                    ).fetchone()
                    or connection.execute(
                        "SELECT 1 FROM cooperation_attempts WHERE session_id=? LIMIT 1",
                        (session_id,),
                    ).fetchone()
                ):
                    raise LiveSessionStoreError("readiness swap unavailable")  # noqa: TRY301
                terms = _offer_terms(offer)
                binding_envelope = _canonical_envelope(funding)
                binding = parse_model_json(
                    FundingBindingPayload, canonicalize(binding_envelope.payload)
                ).binding
                if (
                    COOPERATIVE_CLAIM_FEATURE not in self._policy.features
                    or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                    or terms.profile_id != "btc-to-ln/v1"
                    or terms.network_identity != self._network
                    or contract_hash(terms).hex() != admitted_hash
                    or binding_envelope.contract_hash != admitted_hash
                    or binding.contract_hash != admitted_hash
                    or deadline_height > _cooperative_height_cutoff(terms)
                    or hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
                    != terms.invoice_binding.payment_hash
                ):
                    raise LiveSessionStoreError("readiness authority unavailable")  # noqa: TRY301
                challenge = secrets.token_hex(32)
                request_id = self._record_observation(
                    connection,
                    session_id,
                    {
                        "action": "cooperative_claim_ready",
                        "challenge": challenge,
                        "payment_preimage": preimage,
                        "deadline_at": deadline_at,
                        "deadline_height": deadline_height,
                    },
                    signer,
                    now,
                    message_type="action_request",
                    required_features=(COOPERATIVE_CLAIM_FEATURE,),
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo preimage, session or signer details
            raise LiveSessionStoreError("readiness issue refused") from None
        return ReadinessChallenge(
            session_id,
            request_id,
            challenge,
            admitted_hash,
            self._generation,
            started_at,
            deadline_at,
            deadline_height,
        )

    def retire_cooperative_readiness(self, challenge: ReadinessChallenge) -> None:
        """Stop retrying this owner's expired or abandoned readiness request."""
        if (
            not isinstance(challenge, ReadinessChallenge)
            or challenge.owner_generation != self._generation
        ):
            raise LiveSessionStoreError("readiness owner unavailable")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT canonical_bytes FROM outbox WHERE session_id=? AND message_id=?",
                    (challenge.session_id, challenge.request_id),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("readiness request missing")  # noqa: TRY301
                request = _canonical_envelope(row[0])
                payload = parse_cooperative_payload("action_request", canonicalize(request.payload))
                if (
                    not isinstance(payload, CooperativeClaimReadyRequest)
                    or payload.challenge != challenge.challenge
                    or payload.deadline_at != challenge.deadline_at
                    or payload.deadline_height != challenge.deadline_height
                    or request.contract_hash != challenge.contract_hash
                ):
                    raise LiveSessionStoreError("readiness request changed")  # noqa: TRY301
                connection.execute(
                    "UPDATE outbox SET delivery_state='RECONCILED' "
                    "WHERE session_id=? AND message_id=? AND delivery_state='PENDING'",
                    (challenge.session_id, challenge.request_id),
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo signed request details
            raise LiveSessionStoreError("readiness retirement refused") from None

    def prepare_claim_window(  # noqa: PLR0913 - signed fallback and immutable deadline bundle
        self,
        session_id: str,
        *,
        fallback_raw: bytes,
        fallback_txid: str,
        fallback_fee_sat: int,
        started_at: int,
        now: int,
        deadline_at: int,
        deadline_height: int,
    ) -> None:
        """Commit an authenticated ADMITTED swap's verified fallback before waiting.

        The caller anchors the 30-second budget before any preparation awaits.
        No nonce, response, or claim broadcast can be authorized by this method.
        A failed/uncertain commit must be reconciled from the store, never
        retried with a refreshed deadline.
        """
        if (
            type(started_at) is not int
            or type(now) is not int
            or type(deadline_at) is not int
            or type(deadline_height) is not int
            or started_at < 0
            or not started_at <= now < deadline_at <= started_at + COOPERATION_BUDGET_SECONDS
            or deadline_height <= 0
            or not isinstance(fallback_raw, bytes)
            or not fallback_raw
            or type(fallback_txid) is not str
            or HEX32.fullmatch(fallback_txid) is None
            or type(fallback_fee_sat) is not int
            or fallback_fee_sat < 0
        ):
            raise LiveSessionStoreError("prepared claim parameters refused")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT a.state,a.version,a.contract_hash,s.phase,s.blocked,"
                    "w.state,w.contract_hash,w.terms_offer,w.funding_binding,w.preimage,"
                    "w.claim_tx,w.claim_txid FROM claim_arbitration a "
                    "JOIN swaps w ON w.session_id=a.session_id "
                    "JOIN sessions s ON s.session_id=a.session_id WHERE a.session_id=?",
                    (session_id,),
                ).fetchone()
                if row is None or row[:2] != ("ADMITTED", 1):
                    raise LiveSessionStoreError("claim window not admitted")  # noqa: TRY301
                (
                    _,
                    _,
                    admitted_hash,
                    phase,
                    blocked,
                    state,
                    recorded_hash,
                    offer,
                    funding_bytes,
                    preimage,
                    claim_tx,
                    claim_txid,
                ) = row
                if (
                    phase != "ACCEPTED"
                    or blocked
                    or state != "PAID"
                    or admitted_hash != recorded_hash
                    or funding_bytes is None
                    or not isinstance(preimage, str)
                    or re.fullmatch(r"[0-9a-f]{64}", preimage) is None
                    or claim_tx is not None
                    or claim_txid is not None
                    or connection.execute(
                        "SELECT 1 FROM claim_attempts WHERE session_id=? LIMIT 1", (session_id,)
                    ).fetchone()
                    or connection.execute(
                        "SELECT 1 FROM cooperation_attempts WHERE session_id=? LIMIT 1",
                        (session_id,),
                    ).fetchone()
                ):
                    raise LiveSessionStoreError("claim window unavailable")  # noqa: TRY301
                terms = _offer_terms(offer)
                funding = _canonical_envelope(funding_bytes)
                binding = parse_model_json(
                    FundingBindingPayload, canonicalize(funding.payload)
                ).binding
                if (
                    COOPERATIVE_CLAIM_FEATURE not in self._policy.features
                    or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                    or terms.profile_id != "btc-to-ln/v1"
                    or terms.network_identity != self._network
                    or contract_hash(terms).hex() != recorded_hash
                    or funding.contract_hash != recorded_hash
                    or binding.contract_hash != recorded_hash
                    or hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
                    != terms.invoice_binding.payment_hash
                    or deadline_height > _cooperative_height_cutoff(terms)
                ):
                    raise LiveSessionStoreError("claim window authority unavailable")  # noqa: TRY301
                authorization = UnilateralAuthorization.from_terms(
                    terms,
                    FundingOutput(
                        bytes.fromhex(binding.funding_txid),
                        binding.contract_vout,
                        int(binding.contract_value_sat),
                        bytes.fromhex(binding.contract_script_pubkey),
                    ),
                    "claim",
                    keys=cast("TaprootKeyOperations", self._public_keys),
                )
                verified = validate_unilateral_spend(
                    fallback_raw, authorization, verifier=self._crypto
                )
                if (
                    verified.raw_transaction != fallback_raw
                    or verified.txid != fallback_txid
                    or verified.fee_sat != fallback_fee_sat
                ):
                    raise LiveSessionStoreError("claim window fallback mismatch")  # noqa: TRY301
                if (
                    connection.execute(
                        "UPDATE claim_arbitration SET state='WAITING',owner_generation=?,"
                        "prepared_at=?,deadline_at=?,deadline_height=?,fallback_raw=?,"
                        "fallback_txid=?,fallback_fee_sat=? WHERE session_id=? "
                        "AND state='ADMITTED' AND version=1 AND contract_hash=?",
                        (
                            self._generation,
                            started_at,
                            deadline_at,
                            deadline_height,
                            fallback_raw,
                            fallback_txid,
                            fallback_fee_sat,
                            session_id,
                            recorded_hash,
                        ),
                    ).rowcount
                    != 1
                ):
                    raise StaleSwapError("claim window changed")  # noqa: TRY301
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage or crypto details
            raise LiveSessionStoreError("claim window refused") from None

    def has_current_waiting_claim(self) -> bool:
        """Report whether this owner has any height-supervisable WAITING window."""
        try:
            with self._write() as connection:
                return bool(
                    connection.execute(
                        "SELECT 1 FROM claim_arbitration WHERE state='WAITING' "
                        "AND version=1 AND owner_generation=? LIMIT 1",
                        (self._generation,),
                    ).fetchone()
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - no missing state can justify a Core query
            raise LiveSessionStoreError("waiting claim availability unavailable") from None

    def prepared_fallbacks(self, *, closed_only: bool = False) -> tuple[PreparedFallback, ...]:
        """Return affirmative bundles attached to PAID swaps for validation.

        A newly acquired owner sees the prior owner's WAITING rows as CLOSED.
        Omit rows that are unprepared, already selected, or cooperatively closed;
        absence from this list is never permission to sign a different claim.
        """
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT a.session_id,a.contract_hash,a.state,a.owner_generation,"
                    "a.deadline_at,a.deadline_height,a.fallback_raw,a.fallback_txid,"
                    "a.fallback_fee_sat,w.terms_offer,w.funding_binding,w.preimage "
                    "FROM claim_arbitration a JOIN swaps w ON w.session_id=a.session_id "
                    "WHERE ((a.state='CLOSED' AND a.owner_generation<?) OR "
                    "(a.state='WAITING' AND a.owner_generation=? AND ?=0)) "
                    "AND a.version=1 AND a.cooperative_raw IS NULL "
                    "AND a.fallback_raw IS NOT NULL AND w.state='PAID' "
                    "AND w.contract_hash=a.contract_hash AND w.preimage IS NOT NULL "
                    "AND w.funding_binding IS NOT NULL AND w.claim_tx IS NULL "
                    "AND w.claim_txid IS NULL AND NOT EXISTS "
                    "(SELECT 1 FROM claim_attempts c WHERE c.session_id=w.session_id) "
                    "ORDER BY a.deadline_at,a.session_id",
                    (self._generation, self._generation, int(closed_only)),
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("prepared claims unavailable") from None
        return tuple(PreparedFallback(*row) for row in rows)

    def recorded_fallbacks(self) -> tuple[PreparedFallback, ...]:
        """Discover selected attempt-zero claims even after selection crashed its caller.

        These rows are already CLAIMING; enumeration grants no new signing or
        selection authority. The caller still verifies the persisted exact raw.
        """
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT a.session_id,a.contract_hash,a.state,a.owner_generation,"
                    "a.deadline_at,a.deadline_height,a.fallback_raw,a.fallback_txid,"
                    "a.fallback_fee_sat,w.terms_offer,w.funding_binding,w.preimage "
                    "FROM claim_arbitration a JOIN swaps w ON w.session_id=a.session_id "
                    "JOIN claim_attempts c ON c.session_id=w.session_id AND c.attempt=0 "
                    "WHERE a.state='CLOSED' AND a.version=1 AND a.cooperative_raw IS NULL "
                    "AND a.owner_generation IS NOT NULL AND w.state='CLAIMING' "
                    "AND w.contract_hash=a.contract_hash AND w.preimage IS NOT NULL "
                    "AND w.funding_binding IS NOT NULL AND c.raw=a.fallback_raw "
                    "AND c.txid=a.fallback_txid AND c.fee_sat=a.fallback_fee_sat "
                    "ORDER BY a.session_id"
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("recorded fallbacks unavailable") from None
        return tuple(PreparedFallback(*row) for row in rows)

    def cooperative_winners(self) -> tuple[CooperativeWinner, ...]:
        """Discover affirmative key-path winners, including older PAID rows."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT a.session_id,a.contract_hash,w.state,a.cooperative_raw,"
                    "a.cooperative_txid,w.terms_offer,w.funding_binding,w.preimage "
                    "FROM claim_arbitration a JOIN swaps w ON w.session_id=a.session_id "
                    "JOIN cooperation_attempts c ON c.session_id=a.session_id "
                    "WHERE a.version=1 AND a.state='CLOSED' "
                    "AND a.cooperative_raw IS NOT NULL AND a.cooperative_txid IS NOT NULL "
                    "AND c.state='COMPLETE' AND c.partial_response_id IS NOT NULL "
                    "AND w.contract_hash=a.contract_hash AND w.funding_binding IS NOT NULL "
                    "AND w.preimage IS NOT NULL AND "
                    "((w.state='PAID' AND w.claim_tx IS NULL AND w.claim_txid IS NULL "
                    "AND NOT EXISTS (SELECT 1 FROM claim_attempts q "
                    "WHERE q.session_id=w.session_id)) "
                    "OR (w.state='CLAIMING' AND w.claim_tx=a.cooperative_raw "
                    "AND w.claim_txid=a.cooperative_txid "
                    "AND (SELECT count(*) FROM claim_attempts q WHERE q.session_id=w.session_id)=1 "
                    "AND EXISTS (SELECT 1 FROM claim_attempts q WHERE q.session_id=w.session_id "
                    "AND q.attempt=0 AND q.raw=a.cooperative_raw AND q.txid=a.cooperative_txid))) "
                    "ORDER BY a.session_id"
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("cooperative winners unavailable") from None
        return tuple(CooperativeWinner(*row) for row in rows)

    def promote_cooperative_winner(
        self,
        winner: CooperativeWinner,
        *,
        fee_sat: int,
        signer: EnvelopeSigner,
        now: int,
    ) -> None:
        """Recover older CLOSED+PAID signed winners without recreating a signature."""
        if (
            not isinstance(winner, CooperativeWinner)
            or winner.state != "PAID"
            or type(fee_sat) is not int
            or fee_sat < 0
            or type(now) is not int
            or now < 0
        ):
            raise LiveSessionStoreError("cooperative promotion refused")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT a.state,a.version,a.contract_hash,a.cooperative_raw,"
                    "a.cooperative_txid,w.state,w.contract_hash,w.terms_offer,"
                    "w.funding_binding,w.preimage,w.claim_tx,w.claim_txid "
                    "FROM claim_arbitration a JOIN swaps w ON w.session_id=a.session_id "
                    "WHERE a.session_id=?",
                    (winner.session_id,),
                ).fetchone()
                if (
                    row
                    != (
                        "CLOSED",
                        1,
                        winner.contract_hash,
                        winner.raw,
                        winner.txid,
                        "PAID",
                        winner.contract_hash,
                        winner.terms_offer,
                        winner.funding_binding,
                        winner.preimage,
                        None,
                        None,
                    )
                    or connection.execute(
                        "SELECT 1 FROM claim_attempts WHERE session_id=? LIMIT 1",
                        (winner.session_id,),
                    ).fetchone()
                    or not connection.execute(
                        "SELECT 1 FROM cooperation_attempts WHERE session_id=? "
                        "AND state='COMPLETE' AND partial_response_id IS NOT NULL LIMIT 1",
                        (winner.session_id,),
                    ).fetchone()
                ):
                    raise StaleSwapError("cooperative winner changed")  # noqa: TRY301
                if (
                    connection.execute(
                        "UPDATE swaps SET state='CLAIMING',claim_tx=?,claim_txid=?,updated_at=? "
                        "WHERE session_id=? AND state='PAID' AND claim_tx IS NULL "
                        "AND claim_txid IS NULL",
                        (winner.raw, winner.txid, now, winner.session_id),
                    ).rowcount
                    != 1
                ):
                    raise StaleSwapError("cooperative winner changed")  # noqa: TRY301
                connection.execute(
                    "INSERT INTO claim_attempts VALUES (?,0,?,?,?,NULL)",
                    (winner.session_id, winner.txid, winner.raw, fee_sat),
                )
                self._record_observation(
                    connection,
                    winner.session_id,
                    {"kind": "claim_broadcast", "claim_txid": winner.txid},
                    signer,
                    now,
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage or crypto details
            raise LiveSessionStoreError("cooperative promotion refused") from None

    def select_prepared_fallback(
        self,
        candidate: PreparedFallback,
        *,
        signer: EnvelopeSigner,
        now: int,
        height: int | None,
    ) -> None:
        """Select one validated exact fallback, record attempt 0, then permit broadcast.

        The caller must validate the signed raw against the accepted terms and
        funding, including the computed txid and fee, before this transition.
        A current-owner WAITING window needs an expired time or height.
        Prior-owner CLOSED windows already lost their cooperative opportunity.
        """
        if (
            not isinstance(candidate, PreparedFallback)
            or type(now) is not int
            or now < 0
            or (height is not None and (type(height) is not int or height <= 0))
        ):
            raise LiveSessionStoreError("prepared claim selection refused")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT a.state,a.owner_generation,a.contract_hash,a.deadline_at,"
                    "a.deadline_height,a.fallback_raw,a.fallback_txid,a.fallback_fee_sat,"
                    "a.cooperative_raw,w.state,w.contract_hash,w.terms_offer,"
                    "w.funding_binding,w.preimage,w.claim_tx,w.claim_txid "
                    "FROM claim_arbitration a JOIN swaps w ON w.session_id=a.session_id "
                    "WHERE a.session_id=? AND a.version=1",
                    (candidate.session_id,),
                ).fetchone()
                if (
                    row
                    != (
                        candidate.state,
                        candidate.owner_generation,
                        candidate.contract_hash,
                        candidate.deadline_at,
                        candidate.deadline_height,
                        candidate.raw,
                        candidate.txid,
                        candidate.fee_sat,
                        None,
                        "PAID",
                        candidate.contract_hash,
                        candidate.terms_offer,
                        candidate.funding_binding,
                        candidate.preimage,
                        None,
                        None,
                    )
                    or connection.execute(
                        "SELECT 1 FROM claim_attempts WHERE session_id=? LIMIT 1",
                        (candidate.session_id,),
                    ).fetchone()
                ):
                    raise StaleSwapError("prepared claim changed")  # noqa: TRY301
                old_owner = candidate.state == "CLOSED" and (
                    0 < candidate.owner_generation < self._generation
                )
                expired_window = candidate.state == "WAITING" and (
                    candidate.owner_generation == self._generation
                    and (
                        now >= candidate.deadline_at
                        or (height is not None and height >= candidate.deadline_height)
                    )
                )
                if not (old_owner or expired_window):
                    raise LiveSessionStoreError("prepared claim not selectable")  # noqa: TRY301
                if (
                    connection.execute(
                        "UPDATE swaps SET state='CLAIMING',claim_tx=?,claim_txid=?,updated_at=? "
                        "WHERE session_id=? AND state='PAID' AND claim_tx IS NULL "
                        "AND claim_txid IS NULL",
                        (candidate.raw, candidate.txid, now, candidate.session_id),
                    ).rowcount
                    != 1
                ):
                    raise StaleSwapError("prepared claim changed")  # noqa: TRY301
                connection.execute(
                    "INSERT INTO claim_attempts VALUES (?,0,?,?,?,?)",
                    (
                        candidate.session_id,
                        candidate.txid,
                        candidate.raw,
                        candidate.fee_sat,
                        height,
                    ),
                )
                connection.execute(
                    "UPDATE claim_arbitration SET state='CLOSED' WHERE session_id=?",
                    (candidate.session_id,),
                )
                _reconcile_cooperative_proposal(connection, candidate.session_id)
                self._record_observation(
                    connection,
                    candidate.session_id,
                    {"kind": "claim_broadcast", "claim_txid": candidate.txid},
                    signer,
                    now,
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage or crypto details
            raise LiveSessionStoreError("prepared claim selection refused") from None

    def claim_attempts(self, session_id: str) -> tuple[ClaimAttempt, ...]:
        """Return every recorded claim attempt of one CLAIMING swap, oldest first."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT a.attempt, a.txid, a.raw, a.fee_sat, a.first_seen_height "
                    "FROM claim_attempts a JOIN swaps w ON w.session_id=a.session_id "
                    "WHERE a.session_id=? AND w.state='CLAIMING' ORDER BY a.attempt",
                    (session_id,),
                ).fetchall()
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("claim attempts unavailable") from None
        return tuple(ClaimAttempt(*row) for row in rows)

    def recorded_unilateral_claims(
        self, *, session_id: str | None = None
    ) -> tuple[RecordedUnilateralClaim, ...]:
        """List only exact durable script-path winners, never an unselected PAID row.

        Old and new selected claims are both eligible. An absent arbitration
        row is not claim authority here: the CLAIMING state, matching signed
        attempt, and verified bytes are affirmative evidence of selection.
        """
        if session_id is not None and (
            type(session_id) is not str or HEX32.fullmatch(session_id) is None
        ):
            raise LiveSessionStoreError("recorded claim session unsupported")
        selected = "AND w.session_id=?" if session_id is not None else ""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT DISTINCT w.session_id,w.contract_hash,w.claim_tx,w.claim_txid,"
                    "c.fee_sat,w.terms_offer,w.funding_binding,w.preimage "
                    "FROM swaps w JOIN claim_attempts c ON c.session_id=w.session_id "
                    "AND c.raw=w.claim_tx AND c.txid=w.claim_txid "
                    "LEFT JOIN claim_arbitration a ON a.session_id=w.session_id "
                    "WHERE w.state='CLAIMING' AND w.claim_tx IS NOT NULL "
                    "AND (a.session_id IS NULL OR (a.version=1 AND a.state='ADMITTED' "
                    "AND a.contract_hash=w.contract_hash)) " + selected + " ORDER BY w.session_id",
                    () if session_id is None else (session_id,),
                ).fetchall()
                return tuple(RecordedUnilateralClaim(*row) for row in rows)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - no unverified selected bytes escape
            raise LiveSessionStoreError("recorded unilateral claims unavailable") from None

    def selected_cooperative_claim(self, session_id: str) -> ClaimAttempt | None:
        """Return exact selected key-path attempt zero or quarantine conflicting state."""
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT a.state,a.version,a.contract_hash,a.cooperative_raw,"
                    "a.cooperative_txid,w.state,w.contract_hash,w.claim_tx,w.claim_txid,"
                    "c.raw,c.txid,c.fee_sat,c.first_seen_height "
                    "FROM claim_arbitration a JOIN swaps w ON w.session_id=a.session_id "
                    "LEFT JOIN claim_attempts c ON c.session_id=w.session_id AND c.attempt=0 "
                    "WHERE a.session_id=? AND a.cooperative_raw IS NOT NULL",
                    (session_id,),
                ).fetchone()
                if row is None:
                    return None
                (
                    state,
                    version,
                    contract,
                    raw,
                    txid,
                    swap_state,
                    swap_contract,
                    swap_raw,
                    swap_txid,
                    attempt_raw,
                    attempt_txid,
                    fee,
                    height,
                ) = row
                if (
                    state != "CLOSED"
                    or version != 1
                    or contract != swap_contract
                    or swap_state != "CLAIMING"
                    or raw != swap_raw
                    or txid != swap_txid
                    or raw != attempt_raw
                    or txid != attempt_txid
                    or type(fee) is not int
                    or connection.execute(
                        "SELECT count(*) FROM claim_attempts WHERE session_id=?", (session_id,)
                    ).fetchone()
                    != (1,)
                    or not connection.execute(
                        "SELECT 1 FROM cooperation_attempts WHERE session_id=? "
                        "AND state='COMPLETE' AND partial_response_id IS NOT NULL LIMIT 1",
                        (session_id,),
                    ).fetchone()
                ):
                    raise LiveSessionStoreError("cooperative claim history inconsistent")  # noqa: TRY301
                return ClaimAttempt(0, txid, raw, fee, height)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("cooperative claim history unavailable") from None

    def observe_claim_attempt(
        self, session_id: str, attempt: int, *, fee_sat: int, height: int
    ) -> None:
        """Fill an unobserved attempt's validated fee and first-seen height, once.

        Values already recorded are never overwritten, so a restart cannot move
        the escalation anchor.
        """
        try:
            with self._write() as connection:
                connection.execute(
                    "UPDATE claim_attempts SET fee_sat=COALESCE(fee_sat, ?), "
                    "first_seen_height=COALESCE(first_seen_height, ?) "
                    "WHERE session_id=? AND attempt=? AND session_id IN "
                    "(SELECT session_id FROM swaps WHERE state='CLAIMING')",
                    (fee_sat, height, session_id, attempt),
                )
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("claim attempt update refused") from None

    def record_claim_attempt(  # noqa: PLR0913 - one replacement's explicit parts
        self,
        session_id: str,
        *,
        attempt: int,
        txid: str,
        raw: bytes,
        fee_sat: int,
        height: int,
    ) -> None:
        """Durably add the next fee-bumped claim before it is broadcast.

        Raises ``StaleSwapError`` unless the swap is CLAIMING and ``attempt``
        directly follows the latest recorded one, so a concurrent or repeated
        tick cannot fork the history. Earlier attempts are kept: any may confirm.
        """
        if not 0 < attempt < MAX_CLAIM_ATTEMPTS:
            raise LiveSessionStoreError("claim attempt budget exhausted")
        try:
            with self._write() as connection:
                if connection.execute(
                    "SELECT 1 FROM claim_arbitration WHERE session_id=? "
                    "AND state='CLOSED' AND cooperative_raw IS NOT NULL",
                    (session_id,),
                ).fetchone():
                    raise LiveSessionStoreError(  # noqa: TRY301 - key-path winner is not replaceable
                        "cooperative claim replacement refused"
                    )
                (latest,) = connection.execute(
                    "SELECT MAX(a.attempt) FROM claim_attempts a JOIN swaps w "
                    "ON w.session_id=a.session_id WHERE a.session_id=? AND w.state='CLAIMING'",
                    (session_id,),
                ).fetchone()
                if latest != attempt - 1:
                    raise StaleSwapError("claim attempts changed")  # noqa: TRY301
                connection.execute(
                    "INSERT INTO claim_attempts VALUES (?, ?, ?, ?, ?, ?)",
                    (session_id, attempt, txid, raw, fee_sat, height),
                )
                connection.execute(
                    "UPDATE swaps SET claim_tx=?, claim_txid=? WHERE session_id=?",
                    (raw, txid, session_id),
                )
        except (LiveSessionStoreError, StaleSwapError):
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("claim attempt refused") from None

    def unfunded_swaps(self) -> list[tuple[str, bytes]]:
        """Return (session_id, terms_offer) for accepted swaps still awaiting funding."""
        try:
            with self._write() as connection:
                return [
                    (row[0], row[1])
                    for row in connection.execute(
                        "SELECT session_id, terms_offer FROM swaps WHERE state='ACCEPTED' "
                        "ORDER BY session_id"
                    )
                ]
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("swap listing refused") from None

    def expirable_exposure_pending(self) -> bool:
        """Whether any terminal swap still holds a reservation (worth asking the tip)."""
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT 1 FROM economic_reservations r JOIN swaps w "
                    "ON w.session_id=r.session_id WHERE r.state<>'RELEASED' "
                    "AND w.state IN ('FAILED', 'CLAIMED', 'LOST') LIMIT 1"
                ).fetchone()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("exposure check refused") from None
        return row is not None

    def release_expired_exposure(self, tip_height: int) -> int:
        """Release reservations of terminal swaps whose exposure windows have all closed.

        Once the tip is past both the signed ``max_outgoing_htlc_expiry_height``
        (no Lightning HTLC of this swap can still be pending) and
        ``refund_lock_height`` (the client could refund), plus
        ``refund_resolution_confirmations``, nothing can change what this
        swap cost. This is the only release for ``FAILED`` swaps whose failure
        no payer attested. Non-terminal swaps are never touched. Returns the count.
        """
        if type(tip_height) is not int or tip_height <= 0:
            raise LiveSessionStoreError("tip height must be a positive block height")
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT r.payment_hash, w.state, w.terms_offer FROM economic_reservations r "
                    "JOIN swaps w ON w.session_id=r.session_id "
                    "WHERE r.state<>'RELEASED' AND w.state IN ('FAILED', 'CLAIMED', 'LOST')"
                ).fetchall()
                released = 0
                for payment_hash, state, offer in rows:
                    terms = _offer_terms(offer)
                    policy = terms.timing_policy
                    htlc_expiry = getattr(policy, "max_outgoing_htlc_expiry_height", None)
                    if type(htlc_expiry) is not int:
                        continue  # another profile: no rule here
                    closed = (
                        max(htlc_expiry, terms.refund_lock_height)
                        + terms.refund_resolution_confirmations
                    )
                    if tip_height < closed:
                        continue
                    evidence = _release_evidence(
                        "exposure-expired",
                        swap_state=state,
                        tip_height=tip_height,
                        htlc_expiry_height=htlc_expiry,
                        refund_lock_height=terms.refund_lock_height,
                        required_confirmations=terms.refund_resolution_confirmations,
                    )
                    released += connection.execute(
                        "UPDATE economic_reservations SET state='RELEASED', release_evidence=? "
                        "WHERE payment_hash=? AND state<>'RELEASED'",
                        (evidence, payment_hash),
                    ).rowcount
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("exposure release refused") from None
        return released

    def _economic_capacity(self, connection: sqlite3.Connection, session_id: str) -> bool:
        """Whether one more firm offer in this session fits unreleased capacity."""
        if connection.execute(
            "SELECT 1 FROM economic_reservations WHERE session_id=?", (session_id,)
        ).fetchone():
            return False  # RS-003: at most one firm offer per session
        (active,) = connection.execute(
            "SELECT COUNT(*) FROM economic_reservations WHERE state <> 'RELEASED'"
        ).fetchone()
        return bool(active < self._max_active_reservations)

    def _reserve_offer(
        self, connection: sqlite3.Connection, session_id: str, payment_hash: str
    ) -> None:
        """Reserve capacity for a new firm offer, refusing anything over budget.

        RS-003 allows one firm offer per session, and a session with a swap is
        never offered again. The policy enforces both; this is the backstop.
        """
        if connection.execute(
            "SELECT 1 FROM economic_reservations WHERE session_id=? UNION ALL "
            "SELECT 1 FROM swaps WHERE session_id=?",
            (session_id, session_id),
        ).fetchone():
            raise LiveSessionStoreError("session already has a firm offer")
        if not self._economic_capacity(connection, session_id):
            raise SessionCapacityError("economic capacity reached")
        connection.execute(
            "INSERT INTO economic_reservations VALUES (?, ?, 'UNSENT', NULL)",
            (payment_hash, session_id),
        )

    def commit_payment_dispatch(self, session_id: str, payment_hash: str, request: bytes) -> bool:
        """Durably consume one explicit UNSENT grant before its external effect.

        Missing state is never permission to send. This transaction also orders
        authorization against conflict blocking: a blocked session cannot gain
        a new grant. A later conflict cannot undo an already committed dispatch.
        Lost responses and interrupted callers must reconcile, never recreate
        the grant or resubmit the saved request automatically.
        """
        if type(request) is not bytes or not 0 < len(request) <= MAX_DOCUMENT_BYTES:
            raise LiveSessionStoreError("payment request size unsupported")
        try:
            with self._write() as connection:
                if (
                    connection.execute(
                        "UPDATE payment_dispatch SET state='SUBMITTED', request=? "
                        "WHERE session_id=? AND payment_hash=? AND state='UNSENT' "
                        "AND EXISTS (SELECT 1 FROM swaps w JOIN sessions s "
                        "ON s.session_id=w.session_id "
                        "WHERE w.session_id=payment_dispatch.session_id "
                        "AND w.state='PAYING' AND s.blocked=0)",
                        (request, session_id, payment_hash),
                    ).rowcount
                    != 1
                ):
                    return False
                # Same transaction: a dispatch always marks its unreleased
                # reservation. Missing or released reservations abort the grant.
                if (
                    connection.execute(
                        "UPDATE economic_reservations SET state='DISPATCHED' "
                        "WHERE payment_hash=? AND session_id=? AND state='UNSENT'",
                        (payment_hash, session_id),
                    ).rowcount
                    != 1
                ):
                    raise LiveSessionStoreError("economic reservation unavailable")  # noqa: TRY301
                return True
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo routing or payment details
            raise LiveSessionStoreError("payment dispatch refused") from None

    def _record_observation(  # noqa: PLR0913 - one queued message's parts
        self,
        connection: sqlite3.Connection,
        session_id: str,
        payload: dict[str, Any],
        signer: EnvelopeSigner,
        now: int,
        *,
        message_type: str = "observation",
        required_features: tuple[str, ...] = (),
    ) -> str:
        offer_bytes, contract, key, revision, provider_seq = connection.execute(
            "SELECT w.terms_offer, w.contract_hash, s.provider_session_key, s.revision, "
            "s.next_provider_seq FROM swaps w JOIN sessions s ON s.session_id = w.session_id "
            "WHERE w.session_id=?",
            (session_id,),
        ).fetchone()
        reply = Answer(message_type, payload, contract_hash=contract)
        scalar, _ = self._unseal(connection, session_id)
        try:
            envelope = self._signed_envelope(
                _canonical_envelope(offer_bytes),
                key,
                provider_seq,
                reply,
                scalar,
                signer,
                None,
                required_features=required_features,
            )
        finally:
            del scalar
        connection.execute(
            "INSERT INTO outbox VALUES (?, ?, ?, NULL, ?, ?, 'PENDING')",
            (
                envelope.message_id,
                session_id,
                provider_seq,
                canonicalize(envelope.model_dump(mode="json")),
                revision + 1,
            ),
        )
        connection.execute(
            "UPDATE sessions SET revision=?, next_provider_seq=?, active_at=? WHERE session_id=?",
            (revision + 1, provider_seq + 1, now, session_id),
        )
        return envelope.message_id

    def sign_with_contract_key(
        self, session_id: str, digest: bytes, signer: EnvelopeSigner
    ) -> bytes:
        """BIP340-sign one digest with this swap's sealed provider contract key.

        Only for a swap that reached ``PAID`` or ``CLAIMING`` (the claim leaf),
        or an LN to BTC swap that is ``FUNDED`` or ``REFUNDING`` (the refund
        leaf); the scalar never leaves the store.
        """
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT k.compressed_key, k.secret_age, w.state FROM contract_keys k "
                    "JOIN swaps w ON w.session_id = k.session_id "
                    "WHERE k.session_id=? "
                    "AND w.state IN ('PAID', 'CLAIMING', 'FUNDED', 'REFUNDING')",
                    (session_id,),
                ).fetchone()
                if row is None or type(digest) is not bytes or len(digest) != 32:  # noqa: PLR2004
                    raise LiveSessionStoreError("no claimable swap")  # noqa: TRY301
                compressed, sealed, state = row
                if state == "PAID" and not _immediate_claim_allowed(connection, session_id):
                    raise LiveSessionStoreError(  # noqa: TRY301 - no signing after window opens
                        "claim arbitration requires transaction selection"
                    )
                plaintext = pyrage.decrypt(sealed, [self._custody_identity])
                record = json.loads(plaintext)
                scalar = bytes.fromhex(record["secret_scalar"])
                try:
                    if (
                        record["session_id"] != session_id
                        or record["store_uuid"] != self._store_uuid
                        or bytes(self._public_keys.public_key(scalar)).hex() != compressed
                    ):
                        raise LiveSessionStoreError("contract key custody differs")
                    signature = signer.schnorr_sign(scalar, digest, secrets.token_bytes(32))
                finally:
                    del scalar
                self._crypto.schnorr_verify(bytes.fromhex(compressed)[1:], digest, signature)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo secret material
            raise LiveSessionStoreError("contract key signing refused") from None
        return bytes(signature)

    def session_mailboxes(self) -> tuple[str, ...]:
        """Return our mailbox keys for sessions that may still send to us."""
        return tuple(mailbox.mailbox_key for mailbox in self.mailbox_work())

    def mailbox_work(self) -> tuple[MailboxWork, ...]:
        """Return each mailbox that may still receive from a client, with its work terms.

        ``declared_bits`` is the RS-006 transport proof of work the session's
        init declared (None for sessions admitted without one). ``finished`` is
        True only for a swap in a terminal state (every profile keeps its state
        in ``swaps``); a session without a swap, or in any other state, may
        still need to reach us.
        """
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT s.provider_session_key, s.init_bytes, w.state, s.phase, p.reserved_at "
                    "FROM sessions s "
                    "LEFT JOIN swaps w ON w.session_id = s.session_id "
                    "LEFT JOIN payment_hashes p ON p.session_id = s.session_id WHERE s.blocked=0 "
                    "AND s.phase IN ('ACCEPT_COMMITTED', 'CONFIRMED', 'ACCEPTED') "
                    "ORDER BY s.revision"
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("session mailboxes unavailable") from None
        return tuple(
            MailboxWork(
                key,
                _declared_work(init_bytes),
                state in FINISHED_SWAP_STATES,
                reserved_at if phase == "ACCEPTED" and state in REPLAY_ACTIVE_SWAP_STATES else None,
            )
            for key, init_bytes, state, phase, reserved_at in rows
        )

    def awaiting_confirm_mailboxes(self) -> tuple[str, ...]:
        """Return our session mailbox keys that still expect a client confirm."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT provider_session_key FROM sessions "
                    "WHERE phase='ACCEPT_COMMITTED' AND blocked=0 ORDER BY revision"
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("session mailboxes unavailable") from None
        return tuple(row[0] for row in rows)

    def session_awaiting_confirm(self, session_id: str) -> bool:
        """Return True only while this unblocked session's accept awaits the client's confirm."""
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT 1 FROM sessions WHERE session_id=? "
                    "AND phase='ACCEPT_COMMITTED' AND blocked=0",
                    (session_id,),
                ).fetchone()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("session state unavailable") from None
        return row is not None

    def observe_outpoint_spent(
        self, session_id: str, tip_height: int | None, block_hash: str | None = None
    ) -> None:
        """Record the tip (height and hash) at which a CLAIMING swap's output was seen spent.

        ``None`` clears it (the output is unspent again, a recorded attempt is
        mined, or the anchor block left the active chain). A recorded anchor
        is never replaced: the first observation anchors the resolution wait.
        """
        if tip_height is not None and (
            type(tip_height) is not int
            or tip_height <= 0
            or type(block_hash) is not str
            or not HEX32.fullmatch(block_hash)
        ):
            raise LiveSessionStoreError("spent anchor must be a positive height and block hash")
        try:
            with self._write() as connection:
                if tip_height is None:
                    connection.execute(
                        "UPDATE swaps SET outpoint_spent_height=NULL, outpoint_spent_block=NULL "
                        "WHERE session_id=? AND state='CLAIMING'",
                        (session_id,),
                    )
                else:
                    connection.execute(
                        "UPDATE swaps SET "
                        "outpoint_spent_height=COALESCE(outpoint_spent_height, ?), "
                        "outpoint_spent_block=COALESCE(outpoint_spent_block, ?) "
                        "WHERE session_id=? AND state='CLAIMING'",
                        (tip_height, block_hash, session_id),
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("spent observation refused") from None

    def payment_hash_reserved(self, payment_hash: str) -> bool:
        """Whether ``payment_hash`` is already reserved (pre-check before opening a hold).

        The authoritative check runs inside ``answer_request``; this only
        avoids opening a hold invoice an offer could never bind.
        """
        if type(payment_hash) is not str or len(payment_hash) != 64:  # noqa: PLR2004 - hex digest
            raise LiveSessionStoreError("payment hash must be 32 bytes of hex")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT 1 FROM payment_hashes WHERE payment_hash=?", (payment_hash,)
                ).fetchone()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("reservation check refused") from None
        return row is not None

    def firm_capacity_available(self) -> bool:
        """Whether any session could still receive a firm offer (global count only).

        A cheap pre-check so a full provider skips route preflight; the
        authoritative per-session check runs inside ``answer_request``.
        """
        try:
            with self._write() as connection:
                (active,) = connection.execute(
                    "SELECT COUNT(*) FROM economic_reservations WHERE state <> 'RELEASED'"
                ).fetchone()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("capacity check refused") from None
        return bool(active < self._max_active_reservations)

    def pending_outbox(self, *, session_id: str | None = None) -> tuple[OutboxEntry, ...]:
        """Return committed bytes still owed to peers; current owner only."""
        try:
            with self._write() as connection:
                query = (
                    "SELECT message_id, session_id, canonical_bytes FROM outbox "
                    "WHERE delivery_state='PENDING' ORDER BY committed_revision, message_id"
                    if session_id is None
                    else "SELECT message_id, session_id, canonical_bytes FROM outbox "
                    "WHERE delivery_state='PENDING' AND session_id=? "
                    "ORDER BY committed_revision, message_id"
                )
                rows = connection.execute(
                    query,
                    () if session_id is None else (session_id,),
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("outbox unavailable") from None
        return tuple(OutboxEntry(*row) for row in rows)

    def ledger_head(self) -> int:
        """Return the newest swap ledger entry ID, 0 when the ledger is empty."""
        try:
            with self._write() as connection:
                (head,) = connection.execute(
                    "SELECT COALESCE(MAX(entry_id), 0) FROM swap_ledger"
                ).fetchone()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("swap ledger unavailable") from None
        return int(head)

    def ledger_after(self, entry_id: int, *, limit: int = 256) -> tuple[LedgerEntry, ...]:
        """Return up to ``limit`` ledger entries newer than ``entry_id``, oldest first."""
        if type(entry_id) is not int or type(limit) is not int or not 1 <= limit <= 4096:  # noqa: PLR2004
            raise LiveSessionStoreError("swap ledger bounds unsupported")
        return self._ledger_rows("entry_id > ? ORDER BY entry_id LIMIT ?", (entry_id, limit))

    def pricing_commitments(self, now: int | None = None) -> PricingCommitments:
        """Return this store's open firm-offer volume and committed rebates.

        Advisory input for balance-aware pricing before a quote's transaction;
        ``answer_request`` recomputes the rebates inside it.
        """
        now = int(time.time()) if now is None else now
        try:
            with self._write() as connection:
                return PricingCommitments(
                    _open_offer_volume(connection), _rebates_committed(connection, now)
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("swap ledger unavailable") from None

    def ledger_session(self, session_id: str) -> tuple[LedgerEntry, ...]:
        """Return every ledger entry of one swap, oldest first."""
        return self._ledger_rows("session_id = ? ORDER BY entry_id", (session_id,))

    def ledger_window(self, since: int, until: int) -> tuple[LedgerEntry, ...]:
        """Return the entries recorded in ``[since, until)`` and the swaps closed in it.

        Every entry of a swap whose terminal entry falls in the window is
        included, so its earlier costs count with its outcome.
        """
        terminal = ", ".join("?" for _ in TERMINAL_KINDS)
        return self._ledger_rows(
            "(recorded_at >= ? AND recorded_at < ?) OR session_id IN (SELECT session_id "  # noqa: S608 - placeholders only
            f"FROM swap_ledger WHERE kind IN ({terminal}) AND recorded_at >= ? "
            "AND recorded_at < ?) ORDER BY entry_id",
            (since, until, *sorted(TERMINAL_KINDS), since, until),
        )

    def _ledger_rows(self, predicate: str, values: tuple[object, ...]) -> tuple[LedgerEntry, ...]:
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT entry_id, session_id, recorded_at, kind, amount, unit "
                    "FROM swap_ledger WHERE " + predicate,
                    values,
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("swap ledger unavailable") from None
        return tuple(LedgerEntry(*row) for row in rows)

    def inspect_swaps(
        self, *, session_id: str | None = None, after: str | None = None, limit: int = 100
    ) -> SwapInspectionPage:
        """Return bounded, secret-free retained state under the exclusive owner.

        This neither runs settlement nor interprets absent payment records as
        authority. Index-ordered pagination avoids rescanning past pages. No
        invoice, preimage, key, route, or exact dispatch request is returned.
        """
        if (
            type(limit) is not int
            or not 1 <= limit <= MAX_INSPECTION_PAGE
            or (session_id is not None and after is not None)
            or any(
                value is not None and (type(value) is not str or HEX32.fullmatch(value) is None)
                for value in (session_id, after)
            )
        ):
            raise LiveSessionStoreError("swap inspection bounds unsupported")
        predicate = "w.session_id = ?" if session_id is not None else "w.session_id > ?"
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT w.session_id, w.contract_hash, w.state, s.session_id IS NOT NULL, "
                    "s.blocked, COALESCE(p.state, 'UNKNOWN'), p.request IS NOT NULL, "
                    "w.funding_binding IS NOT NULL, w.preimage IS NOT NULL, "
                    "w.claim_tx IS NOT NULL, w.claim_txid "
                    "FROM swaps w LEFT JOIN sessions s ON s.session_id=w.session_id "
                    "LEFT JOIN payment_dispatch p ON p.session_id=w.session_id WHERE "
                    + predicate
                    + " ORDER BY w.session_id LIMIT ?",
                    (session_id if session_id is not None else after or "", limit + 1),
                ).fetchall()
            result = []
            for row in rows[:limit]:
                (
                    sid,
                    contract,
                    state,
                    present,
                    blocked,
                    dispatch,
                    request,
                    funding,
                    preimage,
                    claim,
                    txid,
                ) = row
                if not (
                    type(sid) is str
                    and HEX32.fullmatch(sid)
                    and type(contract) is str
                    and HEX32.fullmatch(contract)
                    and (txid is None or (type(txid) is str and HEX32.fullmatch(txid)))
                    and state
                    in {
                        "ACCEPTED",
                        "FUNDING_SEEN",
                        "PAYING",
                        "PAID",
                        "FAILED",
                        "CLAIMING",
                        "CLAIMED",
                        "LOST",
                    }
                    and dispatch in {"UNKNOWN", "UNSENT", "SUBMITTED"}
                    and blocked in (None, 0, 1)
                ):
                    raise LiveSessionStoreError("swap inspection state unsupported")  # noqa: TRY301
                result.append(
                    SwapInspection(
                        sid,
                        contract,
                        state,
                        bool(present),
                        None if blocked is None else bool(blocked),
                        dispatch,
                        bool(request),
                        bool(funding),
                        bool(preimage),
                        bool(claim),
                        txid,
                    )
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo retained financial or custody material
            raise LiveSessionStoreError("swap inspection unavailable") from None
        return SwapInspectionPage(
            tuple(result), result[-1].session_id if len(rows) > limit else None
        )


def _immediate_claim_allowed(connection: sqlite3.Connection, session_id: str) -> bool:
    """Allow without an arbitration row (EVM, non-cooperative); never once prepared or closed."""
    row = connection.execute(
        "SELECT state FROM claim_arbitration WHERE session_id=?", (session_id,)
    ).fetchone()
    return row is None or row == ("ADMITTED",)


def _cooperative_now(previous: int, clock: Callable[[], int] | None) -> int:
    """Refresh live time without allowing a correction to reopen eligibility.

    Retained internal test primitives use a fixed timestamp. Selected live
    APIs require a clock anchored to monotonic elapsed time by their owner.
    """
    if clock is None:
        return previous
    try:
        current = clock()
    except Exception:  # noqa: BLE001 - failed owner clocks grant no nonce effect
        raise LiveSessionStoreError("cooperative clock unavailable") from None
    if type(current) is not int or current < 0:
        raise LiveSessionStoreError("cooperative clock unavailable")
    return max(previous, current)


def _cooperative_completion_now(
    previous: int, clock: Callable[[], int] | None, observation: CooperativeClaimObservation
) -> int:
    """Keep the independently validated sample fresh through native/storage work."""
    current = _cooperative_now(previous, clock)
    if not 0 <= current - observation.sampled_at <= COOPERATION_OBSERVATION_MAX_AGE_SECONDS:
        raise LiveSessionStoreError("cooperative signing observation expired")
    return current


def _require_waiting_cooperation(  # noqa: PLR0913 - exact owner, contract, and deadlines
    connection: sqlite3.Connection,
    session_id: str,
    digest: str,
    generation: int,
    *,
    now: int,
    deadline_at: int,
    deadline_height: int,
    tip_height: int,
) -> None:
    """Authorize one live nonce effect against the currently prepared window."""
    if (
        type(now) is not int
        or type(tip_height) is not int
        or tip_height <= 0
        or tip_height >= deadline_height
        or now >= deadline_at
        or connection.execute(
            "SELECT state,owner_generation,contract_hash,deadline_at,deadline_height,"
            "cooperative_raw,cooperative_txid FROM claim_arbitration WHERE session_id=? "
            "AND version=1",
            (session_id,),
        ).fetchone()
        != ("WAITING", generation, digest, deadline_at, deadline_height, None, None)
    ):
        raise LiveSessionStoreError("cooperative window unavailable")


def _reconcile_cooperative_proposal(connection: sqlite3.Connection, session_id: str) -> None:
    """Stop retrying only this swap's committed, now-obsolete proposal."""
    connection.execute(
        "UPDATE outbox SET delivery_state='RECONCILED' "
        "WHERE delivery_state='PENDING' AND session_id=? AND message_id IN "
        "(SELECT nonce_response_id FROM cooperation_attempts WHERE session_id=? "
        "AND nonce_response_id IS NOT NULL)",
        (session_id, session_id),
    )


def _configure(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA busy_timeout=5000")
    if connection.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
        raise LiveSessionStoreError("WAL unavailable")
    connection.execute("PRAGMA synchronous=FULL")
    if connection.execute("PRAGMA synchronous").fetchone() != (2,):
        raise LiveSessionStoreError("FULL sync unavailable")
    connection.execute("PRAGMA secure_delete=ON")  # expired sealed keys leave no old pages


def _check_schema(connection: sqlite3.Connection) -> None:
    """Refuse, before any schema or row change, a store not exactly at this version.

    Older stores have no upgrade path: drain them on their own release, then
    provision a new store. Closing the refusing connection may still
    checkpoint a crashed store's committed WAL frames (no logical change).
    """
    (version,) = connection.execute("PRAGMA user_version").fetchone()
    if connection.execute("PRAGMA application_id").fetchone() != (APPLICATION_ID,):
        raise LiveSessionStoreError("live session store version unsupported")
    if version != SCHEMA_VERSION:
        raise LiveSessionStoreError(
            f"live session store version unsupported (found {int(version)}, "
            f"requires {SCHEMA_VERSION}); recreate it with provision-store"
        )
    objects = {
        (kind, name): definition
        for kind, name, definition in connection.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
        )
    }
    expected = {("table", statement.split()[2]): statement for statement in SCHEMA}
    expected.update(
        {
            (
                "index",
                sql.split()[3] if sql.startswith("CREATE UNIQUE INDEX ") else sql.split()[2],
            ): sql
            for sql in INDEXES
        }
    )
    if objects != expected:
        raise LiveSessionStoreError("live session store schema incompatible")
    if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
        raise LiveSessionStoreError("live session store integrity unavailable")


def _check_evm_transition(
    transition: tuple[str, str],
    *,
    lockup: tuple[str, int, int] | None,
    sent: tuple[str, bytes] | None,
    preimage: str | None,
) -> None:
    """Refuse an EVM transition that lacks, or carries, the wrong evidence."""
    to_state = transition[1]
    if transition not in EVM_SWAP_TRANSITIONS:
        raise LiveSessionStoreError("swap transition unsupported")
    if (to_state == "FUNDING_SEEN") != (lockup is not None):
        raise LiveSessionStoreError("lock observation needs the exact lockup")
    if (to_state in ("CLAIMING", "FUNDING_SENT", "REFUNDING")) != (sent is not None):
        raise LiveSessionStoreError("sent transaction transition needs the signed transaction")
    if (to_state in ("PAID", "SETTLED")) != (preimage is not None):
        raise LiveSessionStoreError("settlement needs the preimage")


def _release_evm_terminal(  # noqa: PLR0913 - explicit terminal evidence
    connection: sqlite3.Connection,
    session_id: str,
    to_state: str,
    now: int,
    *,
    payment_hash: str,
    failed_by_payer: str | None,
    network: NetworkIdentity | None,
) -> bool:
    """Release an EVM swap's reservation with the evidence its terminal state carries.

    The rules mirror the Bitcoin lifecycles: FAILED releases an UNSENT
    reservation, or a DISPATCHED one only when the dispatch record's bound
    payer attested the failure; CLAIMED, LOST, SETTLED and REFUNDED release a
    dispatched reservation on the retained chain evidence; ABORTED releases an
    undispatched one.
    """
    (claim_tx_hash, refund_tx_hash) = connection.execute(
        "SELECT claim_tx_hash, refund_tx_hash FROM evm_swaps WHERE session_id=?", (session_id,)
    ).fetchone()
    if to_state == "FAILED":
        evidence = _release_evidence("failed-before-dispatch", failed_at=int(now))
        allowed: tuple[str, str] = ("UNSENT", "UNSENT")
        row = connection.execute(
            "SELECT request FROM payment_dispatch WHERE session_id=? AND state='SUBMITTED'",
            (session_id,),
        ).fetchone()
        payer = (
            bound_payer(row[0], payment_hash=payment_hash, network=network)
            if row is not None and network is not None
            else None
        )
        if failed_by_payer is not None and payer is not None:
            if payer.node_pubkey != failed_by_payer:
                raise LiveSessionStoreError("failure attributed to another payer")
            evidence = _release_evidence(
                "failed-after-dispatch", failed_at=int(now), payer=payer.node_pubkey
            )
            allowed = ("UNSENT", "DISPATCHED")
    elif to_state == "CLAIMED":
        if claim_tx_hash is None:
            raise LiveSessionStoreError("claim evidence unavailable")
        evidence = _release_evidence("evm-claim-confirmed", claim_tx_hash=claim_tx_hash)
        allowed = ("DISPATCHED", "DISPATCHED")
    elif to_state == "LOST":
        evidence = _release_evidence("evm-claim-lost", lost_at=int(now))
        allowed = ("DISPATCHED", "DISPATCHED")
    elif to_state == "ABORTED":
        evidence = _release_evidence("hold-canceled", aborted_at=int(now))
        allowed = ("UNSENT", "UNSENT")
    elif to_state == "SETTLED":
        evidence = _release_evidence("hold-settled", settled_at=int(now))
        allowed = ("DISPATCHED", "DISPATCHED")
    else:
        if refund_tx_hash is None:
            raise LiveSessionStoreError("refund evidence unavailable")
        evidence = _release_evidence("evm-refund-confirmed", refund_tx_hash=refund_tx_hash)
        allowed = ("DISPATCHED", "DISPATCHED")
    return bool(
        connection.execute(
            "UPDATE economic_reservations SET state='RELEASED', release_evidence=? "
            "WHERE payment_hash=? AND session_id=? AND state IN (?, ?)",
            (evidence, payment_hash, session_id, *allowed),
        ).rowcount
    )


def _reverse_funding_sample_refused(core: CooperativeClaimOutpoint, terms: ContractTerms) -> bool:
    """Whether a reverse cooperative Core sample is malformed, at any funding depth.

    The provider funded this output itself, so a client claiming before the
    signed ``funding_confirmations`` (even from the mempool) risks only its own
    claim. Depth therefore never refuses; a confirmed sample must still name
    its consistent inclusion block, and a mempool sample must name none.
    """
    if (
        type(core.tip_height) is not int
        or type(core.confirmations) is not int
        or type(core.tip_hash) is not str
        or not re.fullmatch("[0-9a-f]{64}", core.tip_hash)
        or not 0 < core.tip_height < terms.refund_lock_height
    ):
        return True
    if core.confirmations == 0:
        return core.inclusion_height is not None or core.inclusion_block_hash is not None
    return (
        type(core.inclusion_height) is not int
        or not 0 < core.inclusion_height <= core.tip_height
        or core.confirmations != core.tip_height - core.inclusion_height + 1
        or type(core.inclusion_block_hash) is not str
        or not re.fullmatch("[0-9a-f]{64}", core.inclusion_block_hash)
        or (core.inclusion_height == core.tip_height and core.inclusion_block_hash != core.tip_hash)
    )


def _check_reverse_transition(
    transition: tuple[str, str],
    *,
    funding: tuple[FundingBinding, bytes] | None,
    refund: tuple[str, bytes] | None,
    preimage: str | None,
    refund_confirmations: int | None,
) -> None:
    """Refuse an LN to BTC transition that lacks, or carries, the wrong evidence."""
    to_state = transition[1]
    if transition not in REVERSE_SWAP_TRANSITIONS:
        raise LiveSessionStoreError("swap transition unsupported")
    if (to_state == "FUNDING_SENT") != (funding is not None):
        raise LiveSessionStoreError("funding transition needs the exact funding")
    if (to_state == "REFUNDING") != (refund is not None):
        raise LiveSessionStoreError("refund transition needs the exact refund")
    if (to_state == "SETTLED") != (preimage is not None):
        raise LiveSessionStoreError("settlement needs the preimage")
    if to_state == "REFUNDED" and refund_confirmations is None:
        raise LiveSessionStoreError("refund release needs observed confirmations")


def _release_reverse_terminal(  # noqa: PLR0913 - explicit terminal evidence
    connection: sqlite3.Connection,
    session_id: str,
    to_state: str,
    now: int,
    *,
    terms: ContractTerms,
    refund_confirmations: int | None,
) -> None:
    """Release an LN to BTC swap's reservation with the evidence its terminal state carries.

    ABORTED releases only an undispatched reservation (no funding was ever
    signed). SETTLED releases a dispatched one: the verified preimage means
    the hold invoice pays for the contract. REFUNDED releases on the retained
    refund txid at its signed depth, like a BTC to LN claim.
    """
    payment_hash = terms.invoice_binding.payment_hash
    if to_state == "ABORTED":
        evidence = _release_evidence("hold-canceled", aborted_at=now)
        allowed = ("UNSENT", "UNSENT")
    elif to_state == "SETTLED":
        evidence = _release_evidence("hold-settled", settled_at=now)
        allowed = ("DISPATCHED", "DISPATCHED")
    else:
        (refund_txid,) = connection.execute(
            "SELECT refund_txid FROM swaps WHERE session_id=?", (session_id,)
        ).fetchone()
        if type(refund_txid) is not str:
            raise LiveSessionStoreError("refund evidence unavailable")
        evidence = _release_evidence(
            "refund-confirmed",
            refund_txid=refund_txid,
            required_confirmations=terms.refund_resolution_confirmations,
            observed_confirmations=int(refund_confirmations or 0),
        )
        allowed = ("DISPATCHED", "DISPATCHED")
    connection.execute(
        "UPDATE economic_reservations SET state='RELEASED', release_evidence=? "
        "WHERE payment_hash=? AND session_id=? AND state IN (?, ?)",
        (evidence, payment_hash, session_id, *allowed),
    )


def _release_terminal(  # noqa: PLR0913 - explicit terminal evidence
    connection: sqlite3.Connection,
    session_id: str,
    to_state: str,
    now: int,
    *,
    failed_by_payer: str | None = None,
    network: NetworkIdentity | None = None,
    conflict: FundingConflict | None = None,
) -> bool:
    """Release a terminal swap's reservation when its history proves closure.

    FAILED releases an UNSENT reservation: every dispatch marks its
    reservation DISPATCHED in the same transaction, and FAILED is terminal,
    so UNSENT proves no payment was or can be sent. A DISPATCHED reservation
    is released only when the failure was attested by the dispatch record's
    own bound payer (``failed_by_payer``): that node reports no HTLC of the
    sole authorized attempt in flight. A failure without attributable payer
    keeps its capacity. CLAIMED (entered only at signed claim depth) releases
    a DISPATCHED reservation: the claim proves the provider recovered its funds. LOST
    releases the same: the exposure was realized as a loss and nothing
    further can happen to it, whether a refund spent the contract output or
    a ``conflict`` double-spent the deposit that would have created it.
    """
    (offer, claim_txid) = connection.execute(
        "SELECT terms_offer, claim_txid FROM swaps WHERE session_id=?", (session_id,)
    ).fetchone()
    terms = _offer_terms(offer)
    if to_state == "FAILED":
        evidence = _release_evidence("failed-before-dispatch", failed_at=int(now))
        allowed = ("UNSENT", "UNSENT")
        row = connection.execute(
            "SELECT request FROM payment_dispatch WHERE session_id=? AND state='SUBMITTED'",
            (session_id,),
        ).fetchone()
        payer = (
            bound_payer(row[0], payment_hash=terms.invoice_binding.payment_hash, network=network)
            if row is not None and network is not None
            else None
        )
        if failed_by_payer is not None and payer is not None:
            if payer.node_pubkey != failed_by_payer:
                raise LiveSessionStoreError("failure attributed to another payer")
            evidence = _release_evidence(
                "failed-after-dispatch", failed_at=int(now), payer=payer.node_pubkey
            )
            allowed = ("UNSENT", "DISPATCHED")
    elif to_state == "LOST" and conflict is not None:
        evidence = _funding_conflict_evidence(conflict)
        allowed = ("DISPATCHED", "DISPATCHED")
    elif to_state == "LOST":
        (spent_height, spent_block) = connection.execute(
            "SELECT outpoint_spent_height, outpoint_spent_block FROM swaps WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if type(spent_height) is not int or type(spent_block) is not str:
            raise LiveSessionStoreError("loss evidence unavailable")
        evidence = _release_evidence(
            "claim-lost",
            outpoint_spent_height=spent_height,
            outpoint_spent_block=spent_block,
            required_confirmations=terms.refund_resolution_confirmations,
        )
        allowed = ("DISPATCHED", "DISPATCHED")
    else:
        if type(claim_txid) is not str:
            raise LiveSessionStoreError("claim evidence unavailable")
        evidence = _release_evidence(
            "claim-confirmed",
            claim_txid=claim_txid,
            required_confirmations=terms.settlement_confirmations,
        )
        allowed = ("DISPATCHED", "DISPATCHED")
    return bool(
        connection.execute(
            "UPDATE economic_reservations SET state='RELEASED', release_evidence=? "
            "WHERE payment_hash=? AND session_id=? AND state IN (?, ?)",
            (evidence, terms.invoice_binding.payment_hash, session_id, *allowed),
        ).rowcount
    )


def _offered_any_terms(offer: bytes) -> AnyContractTerms:
    """Return the contract terms (any profile) of one retained canonical terms offer."""
    return parse_model_json(
        TermsOfferPayload, canonicalize(_canonical_envelope(offer).payload)
    ).terms.contract_terms


def _offer_terms(offer: bytes) -> ContractTerms:
    """Return the Bitcoin contract terms of one retained canonical terms offer."""
    terms = _offered_any_terms(offer)
    if not isinstance(terms, ContractTerms):
        raise TypeError("retained terms offer is not a Bitcoin profile")
    return terms


def _evm_offer_terms(offer: bytes) -> EvmContractTerms:
    """Return the EVM contract terms of one retained canonical terms offer."""
    terms = _offered_any_terms(offer)
    if not isinstance(terms, EvmContractTerms):
        raise LiveSessionStoreError("retained terms offer is not an EVM profile")
    return terms


def _cooperative_height_cutoff(terms: ContractTerms) -> int:
    """Leave signed confirmation blocks before the client's first refund block."""
    return terms.refund_lock_height - terms.timing_policy.claim_confirmation_blocks


def _offered_payment_hash(offer: bytes) -> str:
    """Return the payment hash bound by one retained canonical terms offer."""
    return parse_model_json(
        TermsOfferPayload, canonicalize(_canonical_envelope(offer).payload)
    ).terms.contract_terms.invoice_binding.payment_hash


def _release_evidence(reason: str, **facts: str | int) -> bytes:
    """Versioned, canonical closure evidence for one RELEASED reservation."""
    return canonicalize({"version": 1, "reason": reason, **facts})


def _funding_conflict_evidence(conflict: FundingConflict) -> bytes:
    """Closure evidence of a double-spent deposit, refused unless self-consistent."""
    hashes = (
        conflict.funding_txid,
        conflict.conflict_txid,
        conflict.conflict_input_txid,
        conflict.conflict_block,
    )
    counts = (
        conflict.conflict_input_vout,
        conflict.conflict_height,
        conflict.tip_height,
        conflict.required_confirmations,
    )
    if (
        any(type(value) is not str or HEX32.match(value) is None for value in hashes)
        or any(type(value) is not int for value in counts)
        or conflict.conflict_txid == conflict.funding_txid
        or not 0 <= conflict.conflict_input_vout <= MAX_VOUT
        or conflict.conflict_height < 1
        or conflict.required_confirmations < 1
        or conflict.tip_height - conflict.conflict_height + 1 < conflict.required_confirmations
    ):
        raise LiveSessionStoreError("funding conflict evidence unsupported")
    return _release_evidence(
        "funding-conflict",
        funding_txid=conflict.funding_txid,
        conflict_txid=conflict.conflict_txid,
        conflict_input_txid=conflict.conflict_input_txid,
        conflict_input_vout=conflict.conflict_input_vout,
        conflict_height=conflict.conflict_height,
        conflict_block=conflict.conflict_block,
        tip_height=conflict.tip_height,
        required_confirmations=conflict.required_confirmations,
    )


def _epoch_watermark(connection: sqlite3.Connection) -> int:
    rows = connection.execute("SELECT retired_through FROM epoch_retirement").fetchall()
    if len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] < 0:
        raise LiveSessionStoreError("epoch retirement custody unavailable")
    return int(rows[0][0])


def _retire_epochs(connection: sqlite3.Connection, now: int) -> None:
    """Retire affirmative expired epochs and persist the barrier before pruning.

    Caller owns the transaction. Neither an absent row nor the watermark alone
    permits deleting session history. Session deletion still requires idle,
    pre-economic state; only its epoch-tagged tombstone can later be pruned.
    """
    watermark = _epoch_watermark(connection)
    if type(now) is not int or now < watermark:
        raise LiveSessionStoreError("clock is behind retired epochs")
    (expired_through,) = connection.execute(
        "SELECT MAX(retire_after) FROM epochs WHERE retire_after <= ?", (now,)
    ).fetchone()
    if expired_through is not None and expired_through > watermark:
        watermark = expired_through
        connection.execute("UPDATE epoch_retirement SET retired_through=?", (watermark,))
    connection.execute("DELETE FROM epochs WHERE retire_after <= ?", (watermark,))


def _epoch_policy_bytes(policy: HandshakePolicy) -> bytes:
    """Every session is epoch-bound, so a policy without the feature is refused."""
    _require_policy(policy)
    if EPOCH_SESSION_FEATURE not in policy.features:
        raise LiveSessionStoreError("handshake policy must require epoch-bound sessions")
    return _policy_bytes(policy)


def _session_expired(connection: sqlite3.Connection, session_id: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM epoch_admissions WHERE session_id=? AND expired=1",
            (session_id,),
        ).fetchone()
        is not None
    )


class _TokenBucket:
    """In-memory global admission rate (a restart refills it; capacity still binds)."""

    def __init__(self, per_minute: int) -> None:
        self._capacity = float(per_minute)
        self._tokens = float(per_minute)
        self._rate = per_minute / 60.0
        self._last: int | None = None

    def take(self, now: int) -> bool:
        if self._last is not None and now > self._last:
            self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._rate)
        self._last = now if self._last is None else max(self._last, now)
        if self._tokens < 1:
            return False
        self._tokens -= 1
        return True


def _new_session_scalar() -> bytes:
    return secrets.token_bytes(32)


def _new_epoch_scalar() -> bytes:
    return secrets.token_bytes(32)


def _routing_recipient(outer_event: bytes, transport: Context) -> str:
    """Return the single ``p`` tag of an authenticated gift wrap.

    The outer ID and signature are checked here, before any store lock or
    custody decryption, so a forged or corrupted event costs one signature
    check. The decoder still re-verifies everything it relies on.
    """
    if type(outer_event) is not bytes or len(outer_event) > MAX_OUTER_EVENT_BYTES:
        raise LiveSessionStoreError("frame size unsupported")
    outer = nip01._verify_signed_event(outer_event, verifier=transport)  # noqa: SLF001
    recipients = [tag[1] for tag in outer.tags if len(tag) >= 2 and tag[0] == "p"]  # noqa: PLR2004
    if outer.kind != OUTER_KIND or len(recipients) != 1:
        raise LiveSessionStoreError("frame recipient unsupported")
    return recipients[0]


def _new_challenge() -> str:
    return secrets.token_hex(32)


def _new_message_id() -> str:
    return secrets.token_hex(32)


def _recipient(value: str) -> str:
    try:
        parsed = x25519.Recipient.from_str(value)
    except Exception:  # noqa: BLE001 - never echo caller input
        raise LiveSessionStoreError("custody recipient malformed") from None
    if str(parsed) != value:
        raise LiveSessionStoreError("custody recipient malformed")
    return value


def _xonly(public_keys: CustodyPublicKeys, scalar: bytes) -> str:
    key = public_keys.public_key(scalar)
    if type(key) is not bytes or len(key) != COMPRESSED_KEY_BYTES or key[0] not in (2, 3):
        raise LiveSessionStoreError("session public key derivation failed")
    return key[1:].hex()


def _check_provisioning(store_uuid: object, authority_jcs: object) -> None:
    try:
        parsed = uuid.UUID(str(store_uuid))
        authority: dict[str, object] = json.loads(authority_jcs)  # type: ignore[arg-type]
        declared = AuthorityDeclaration(
            authority["volume_label"],  # type: ignore[arg-type]
            outside_restore_domain=authority["outside_restore_domain"],  # type: ignore[arg-type]
            single_host=authority["single_host"],  # type: ignore[arg-type]
        )
        valid = str(parsed) == store_uuid and declared.jcs() == authority_jcs
    except Exception:  # noqa: BLE001 - malformed metadata is simply not trusted
        valid = False
    if not valid:
        raise LiveSessionStoreError("store provisioning metadata untrusted")


def _discard(connection: sqlite3.Connection | None, lock_fd: int) -> None:
    if connection is not None:
        with suppress(sqlite3.Error):
            connection.close()
    if lock_fd >= 0:
        os.close(lock_fd)  # closing the descriptor releases the flock


def _fresh_challenge(connection: sqlite3.Connection, init: HandshakeInit) -> str:
    for _ in range(MAX_CHALLENGE_TRIES):
        challenge = _new_challenge()
        if (
            HEX32.fullmatch(challenge) is not None
            and challenge not in (init.session_id, init.client_challenge)
            and connection.execute(
                "SELECT 1 FROM sessions WHERE provider_challenge=?", (challenge,)
            ).fetchone()
            is None
        ):
            return challenge
    raise LiveSessionStoreError("independent challenge unavailable")


def _record_conflict(
    connection: sqlite3.Connection, session_id: str, kind: str, evidence: bytes
) -> None:
    # One bounded evidence row per session and kind; later conflicts add nothing.
    connection.execute(
        "INSERT OR IGNORE INTO conflicts VALUES (?, ?, ?)", (session_id, kind, evidence)
    )
    connection.execute(
        "UPDATE sessions SET blocked=1, revision=revision+1 WHERE session_id=? AND blocked=0",
        (session_id,),
    )


def _accept_revision(connection: sqlite3.Connection, message_id: str) -> int:
    row = connection.execute(
        "SELECT committed_revision FROM outbox WHERE message_id=?", (message_id,)
    ).fetchone()
    if row is None:
        raise LiveSessionStoreError("committed accept missing from outbox")
    return int(row[0])


def _swap(connection: sqlite3.Connection, session_id: str) -> SwapRecord | None:
    row = connection.execute(
        f"SELECT {SWAP_COLUMNS} FROM swaps WHERE session_id=?",  # noqa: S608 - fixed columns
        (session_id,),
    ).fetchone()
    return None if row is None else SwapRecord(*row)


def _record_ledger(  # noqa: PLR0913 - one row's explicit parts
    connection: sqlite3.Connection,
    session_id: str,
    now: int,
    kind: str,
    amount: object = None,
    *,
    unit: str = "sat",
) -> None:
    """Append one accounting row inside the caller's transaction.

    The values are sanitized here, so the row can never refuse the swap event
    it describes: an unexpected amount is stored as unmeasured (NULL).
    """
    measured = signed_ledger_amount(amount) if kind == COMPLETED else ledger_amount(amount)
    connection.execute(
        "INSERT INTO swap_ledger (session_id, recorded_at, kind, amount, unit) "
        "VALUES (?, ?, ?, ?, ?)",
        (session_id, int(now), kind, measured, None if measured is None else unit),
    )


# Sessions whose firm offer is still open: reservation unreleased and swap
# absent or unfinished (a CLAIMED swap holds its reservation until expiry).
_OPEN_OFFER_SESSIONS = (
    "SELECT r.session_id FROM economic_reservations r LEFT JOIN swaps w "  # noqa: S608 - placeholders only
    "ON w.session_id=r.session_id WHERE r.state<>'RELEASED' "
    "AND (w.state IS NULL OR w.state NOT IN (" + ", ".join("?" for _ in FINISHED_SWAP_STATES) + "))"
)
_OPEN_OFFER_VALUES = tuple(sorted(FINISHED_SWAP_STATES))


def _rebates_committed(connection: sqlite3.Connection, now: int) -> int:
    """Return the rebates this store's open offers grant plus those paid recently.

    A completed swap counts for ``REBATE_WINDOW_SECONDS``; a finished swap
    that did not complete paid nothing. The responder runs in the same write
    transaction, so concurrent quotes cannot both spend.
    """
    (total,) = connection.execute(
        "SELECT COALESCE(SUM(amount), 0) FROM swap_ledger WHERE kind=? AND session_id IN ("  # noqa: S608 - placeholders only
        + _OPEN_OFFER_SESSIONS
        + " UNION SELECT session_id FROM swap_ledger WHERE kind=? AND recorded_at>?)",
        (REBATE, *_OPEN_OFFER_VALUES, COMPLETED, now - REBATE_WINDOW_SECONDS),
    ).fetchone()
    return int(total)


def _open_offer_volume(connection: sqlite3.Connection) -> int | None:
    """Return the swapped volume of open offers; None if any is unmeasured."""
    total, unmeasured = connection.execute(
        "SELECT COALESCE(SUM(amount), 0), COUNT(*) - COUNT(amount) FROM swap_ledger "  # noqa: S608 - placeholders only
        "WHERE kind=? AND session_id IN (" + _OPEN_OFFER_SESSIONS + ")",
        (OFFERED, *_OPEN_OFFER_VALUES),
    ).fetchone()
    return None if unmeasured else int(total)


def _offer_economics(offer: bytes) -> SwapEconomics | None:
    """Return a retained offer's committed amounts; None if they cannot be read."""
    try:
        return swap_economics(_offered_any_terms(offer))
    except Exception:  # noqa: BLE001 - accounting never refuses a protocol step
        return None


def _record_outcome(
    connection: sqlite3.Connection,
    session_id: str,
    to_state: str,
    now: int,
    *,
    claim_txid: str | None = None,
) -> None:
    """Record a terminal transition with what it realized; other states add nothing.

    ``completed`` carries the revenue and ``lost`` the paid principal, both
    from the signed terms. A confirmed Bitcoin claim also records its fee
    from the attempt that confirmed (NULL when it recorded none).
    """
    kind = TERMINAL_KIND_BY_STATE.get(to_state)
    if kind is None:
        return
    row = connection.execute(
        "SELECT terms_offer FROM swaps WHERE session_id=?", (session_id,)
    ).fetchone()
    economics = None if row is None else _offer_economics(row[0])
    amount: int | None = None
    if economics is not None and kind == COMPLETED:
        amount = economics.revenue_sat
    elif economics is not None and kind == LOST:
        amount = economics.principal_sat
    _record_ledger(connection, session_id, now, kind, amount)
    if kind == COMPLETED and claim_txid is not None:
        fee = connection.execute(
            "SELECT fee_sat FROM claim_attempts WHERE session_id=? AND txid=?",
            (session_id, claim_txid),
        ).fetchone()
        _record_ledger(connection, session_id, now, CLAIM_FEE, None if fee is None else fee[0])


def _apply_effect(
    connection: sqlite3.Connection,
    request: Envelope,
    effect: AcceptSwap | BindFunding,
    replied: tuple[bytes] | None,
    now: int,
) -> None:
    """Apply one responder effect inside the admitting transaction."""
    document = canonicalize(request.model_dump(mode="json"))
    if isinstance(effect, AcceptSwap):
        if replied is None or request.contract_hash != effect.contract_hash:
            raise LiveSessionStoreError("acceptance not bound to an offer")
        offered = _offered_payment_hash(replied[0])
        if not connection.execute(
            "SELECT 1 FROM economic_reservations WHERE payment_hash=? AND session_id=? "
            "AND state='UNSENT'",
            (offered, request.session_id),
        ).fetchone():
            raise LiveSessionStoreError("offer reservation is closed")
        connection.execute(
            "INSERT INTO swaps VALUES (?, ?, ?, ?, 'ACCEPTED', NULL, NULL, NULL, NULL, ?, "
            "NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
            (request.session_id, effect.contract_hash, replied[0], document, now),
        )
        economics = _offer_economics(replied[0])
        _record_ledger(
            connection,
            request.session_id,
            now,
            ACCEPTED,
            None if economics is None else economics.volume_sat,
        )
        if isinstance(_offered_any_terms(replied[0]), EvmContractTerms):
            connection.execute(
                "INSERT INTO evm_swaps VALUES (?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "
                "NULL, NULL)",
                (request.session_id,),
            )
        connection.execute(
            "UPDATE sessions SET phase='ACCEPTED' WHERE session_id=?", (request.session_id,)
        )
        return
    updated = connection.execute(
        "UPDATE swaps SET funding_binding=?, state='FUNDING_SEEN', updated_at=? "
        "WHERE session_id=? AND contract_hash=? AND state='ACCEPTED'",
        (document, now, request.session_id, request.contract_hash),
    ).rowcount
    if updated != 1:
        raise LiveSessionStoreError("funding binding not bound to an accepted swap")
