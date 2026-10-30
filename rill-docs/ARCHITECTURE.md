# RillSwap architecture

**Version:** 0.1.0  
**License:** MIT  
**Status:** current design

This document describes the design that the RillSwap specifications and
components implement: goals, decisions, protocol shape, state machines,
security invariants. The normative wire and contract rules
live in [`specs/`](specs/); where this document and a specification disagree,
the specification wins. Component READMEs describe what each implementation
currently supports. External standards are listed in
[`SOURCES.md`](SOURCES.md).

## 1. Objective and non-goals

RillSwap is an open, provider-neutral Bitcoin–Lightning atomic-swap protocol with a locally verifying client, independent recovery, replaceable discovery, and replaceable encrypted transport. The reference implementation consists of a Python provider, a Python CLI, and a separately implemented TypeScript browser client. No hosted RillSwap service, official provider registry, token, coordinator, or account is required for settlement.

RillSwap supports Bitcoin mainnet, default signet, testnet4 and namespaced regtest, each through a versioned network definition. It supports two explicitly distinct flows: conventional on-chain-first BTC→LN, and held-Lightning-first LN→BTC. Both use the same two-leaf P2TR construction, with roles reversed. Standard BOLT11 invoices, a 32-byte SHA256 preimage, confirmed funding, and unilateral script-path claim/refund are the baseline. A BTC→LN provider may announce zero funding confirmations and pay from an unconfirmed deposit; that double-spend risk is the provider's alone. LN→BTC terms always sign at least one funding confirmation, but the client may explicitly claim earlier, down to an unconfirmed lockup, and then bears that risk alone (RS-004). Cooperative MuSig2 key-path claims provide the normal privacy optimization.

The baseline excludes Electrum-style HTLC-first BTC→LN, AMP/keysend, BOLT12, PTLC/adaptor-signature protocols, automatic swap batching, and early cooperative refunds. These require new profiles or negotiated extensions; they are not hidden implementation choices. Assets other than BTC are added only as separate profiles: [RS-010](specs/RS-010-erc20-swaps.md) defines ERC20 ↔ Lightning swaps over a pinned EVM hash-time-lock contract.

**Security objective:** under stated chain, Lightning, fee, key-security, and monitoring assumptions, a counterparty cannot take the principal without providing the corresponding payment, or leaving the honest party an enforceable recovery path. Fees, liquidity lockup, censorship, and missed deadlines remain possible. A refund becoming eligible is not a refund becoming final.

## 2. Architecture decisions

| Area | Decision |
|---|---|
| Protocol | New wire specification; not implicitly Boltz/Electrum byte compatible |
| Settlement | Exact two-leaf Taproot HTLC; cooperative MuSig2 claim; independent script fallback |
| Bitcoin treasury | Bitcoin Core descriptor wallet; no new general-purpose HD wallet |
| Contract keys | Separate, purpose-limited swap signer; never assume Core wallet RPC covers custom MuSig2 |
| Provider/CLI | Python 3.13 baseline, strict typing, Pydantic 2 at boundaries |
| Browser | Strict TypeScript, local transaction/state verification, bundled WASM cryptography |
| Cryptography | Official libsecp256k1 through narrow bindings; established Nostr and backup libraries |
| Discovery | Abstract interface; Nostr adapter first; manual provider import mandatory |
| Transport | Abstract interface; NIP-44 v2 within NIP-59 gift wrapping first |
| Durability | SQLite WAL, durable action journal and inbox/outbox; idempotent reconciliation |
| Recovery | Versioned, encrypted, independently usable recovery package |
| LN backend | LND first, capability-based interface for other implementations |
| Notifications | Optional; never on the settlement critical path |
| Integration | Real Bitcoin/LND/relay/browser processes in an isolated Docker environment |
| Releases | Immutable spec/vector versions; pinned component versions and container digests |

A Python-only browser runtime is not a goal. Shipping Python through a browser interpreter would not remove the need for browser-specific storage, networking, wallet, and cryptographic interfaces. Keep the native applications Python and implement the browser SDK directly in TypeScript.

## 3. Components

RillSwap is developed in one repository. Each component keeps its own
dependency lock, tests and README.

| Component | Language | Responsibility |
|---|---|---|
| `rill-docs` | Markdown, JSON | Normative specifications (`specs/`), JSON schemas, byte-level vectors, network definitions, BIP/NIP proposal drafts and this document |
| `rill-crypto` | C, Python, WASM | Narrow binding to official libsecp256k1 (Schnorr, extrakeys, MuSig2) for Python (CFFI) and the browser (Emscripten) |
| `rill-core` | Python | Side-effect-free wire types, canonicalization, network identities, Taproot contract construction, settlement and recovery validation |
| `rill-provider` | Python | Liquidity provider (maker): quotes, admission, durable journals, treasury, LND and Bitcoin Core adapters, Nostr transport, ERC20 settlement |
| `rill-cli` | Python | Command-line client and the independent recovery executable |
| `rill-web` | TypeScript | Static browser client: discovery, swaps, local verification and encrypted recovery, independently implemented against the same specs and vectors |
| `rill-payments` | TypeScript | Merchant checkout SDK, merchant ledger and server, shared Lightning/BOLT11 policy |
| `rill-contracts` | Solidity, TypeScript | Pinned EVM contract sources and compiled artifacts (Boltz `ERC20Swap`, account abstraction contracts for gas-sponsored claims) |

The repository root holds the Docker Compose regtest environment (`dev/`,
see `DEVELOPMENT.md`) and CI workflows.

### 3.1 Boundaries

- **Specifications are the source of interoperability.** Human-readable
  normative rules, schemas and vectors are versioned together. JSON Schema does
  not replace contextual protocol validation, and implementations cannot change
  the protocol by regenerating schemas from whichever models happen to be
  current. An unassigned application-layer BIP draft covers the settlement
  construction and a separate NIP draft covers Nostr discovery and transport;
  neither claims a number, assignment date or acceptance status.
- **Cryptography stays upstream.** `rill-crypto` uses official
  `bitcoin-core/secp256k1` with its Schnorr, extrakeys and MuSig2 (BIP327)
  modules, pinned by release and digest. It exposes opaque validated keys
  and one-shot MuSig signing handles, and never creates its own ECC, ECDH,
  nonce generation or signature arithmetic.
- **MuSig secret nonces are never serialized.** No API exports a secret nonce.
  It lives only in an opaque native handle for one exact message; restart
  abandons the cooperative attempt. Public nonces, the public partial signature
  and a burned attempt identifier may be stored. A missing result after a crash
  means a new attempt, not reconstruction of the old nonce.
- **The core has no side effects.** `rill-core` performs no network, disk,
  clock, notification or database access. The provider and CLI reuse it.
- **Operator policy belongs to the provider.** Price calculation, liquidity
  management, admission limits and orchestration live in `rill-provider`, not
  in the normative protocol library.
- **The CLI recovers on its own.** `rill-cli` is both a usable client and the
  independent recovery executable. It works with external Lightning wallets;
  running a user-side LND is optional.
- **The browser is a second implementation.** `rill-web` is maintained in
  TypeScript against the same specifications and fixtures. Generated transport
  validators are useful but not sufficient validation. Other websites and
  wallets should not need to embed the RillSwap interface.

## 4. Dependency and licensing policy

Pin dependencies, native library releases, generated protobuf inputs, container digests, and workflow action commits in release manifests. Do not specify “latest” images or follow upstream main branches in reproducible builds.

| Function | Initial choice | Boundary / qualification |
|---|---|---|
| Native models | Pydantic 2 | Strict boundary validation; domain types remain explicit |
| Type checks | mypy strict, Pydantic plugin | Generated protobuf code isolated; typed conversions mandatory |
| Bitcoin transactions | Purpose-built serialization in `rill-core` and `rill-web` | Only the two-leaf contract, funding and spend shapes RillSwap needs; not a general wallet or consensus oracle; executed against Bitcoin Core in tests |
| Signing / key aggregation | Official libsecp256k1 | Narrow native/WASM binding; no Python/JS fallback for swap-secret signing |
| Browser cryptography | `@noble/curves`, `@noble/hashes`, `@scure/*` | Pinned releases; differential tests against Python and Core |
| Native Nostr | Bounded NIP-44 v2 / NIP-59 codec in `rill-provider` | ChaCha20 from `pycryptodomex`, ECDH and signatures through `rill-crypto`; tested against NIP-44 vectors and the browser implementation |
| Browser Nostr | `nostr-tools` | Use its defined crypto/protocol functions; no copied encryption implementation |
| EVM | Vendored Boltz `ERC20Swap` v6 | Pinned source and artifact in `rill-contracts`; `web3.py` in the provider, in-house ABI encoding in the browser |
| Native LN | Official LND protobuf/gRPC | Pin protos and generate typed stubs; least-privilege macaroon |
| Bitcoin RPC | `httpx` with explicit auth/TLS/proxy policy | No generic RPC credentials in the browser |
| Persistence | Python `sqlite3` | WAL; one provider writer process initially |
| Backup encryption | age v1 via `pyrage` / TypeScript `age-encryption` | Cross-language encrypted backup fixtures |
| Tests | pytest, Hypothesis, Playwright | Dev dependencies separated from runtime |

RillSwap-authored code is MIT licensed. Third-party dependencies, vendored contracts and compiled artifacts keep their own licenses (see `THIRD_PARTY_NOTICES.md` files and `rill-contracts/licenses/`); do not label an entire distribution "MIT-only." Bitcoin Core executes consensus integration tests; no Python or TypeScript script verifier is treated as a consensus validator. Library maturity and audits must be assessed for the exact version used, not inferred from a project name.

## 5. Type system, domain boundaries, and execution model

Use frozen Pydantic models with strict validation and `extra='forbid'` for external messages/configuration. Reject duplicate JSON keys before parsing into models. Use frozen domain dataclasses and opaque validated types for `Sats`, `Millisats`, `BlockHeight`, `UnixSeconds`, `Hash32`, `XOnlyPubkey`, `CompressedPubkey`, `Txid`, `ContractId`, and `PaymentHash`. An invoice expiry time must not be interchangeable with an HTLC expiry block height.

Enable mypy strictness, unused-ignore checks, explicit optional handling, disallowed implicit generic `Any`, and checked untyped code where unavoidable. No blanket `ignore_errors` in business logic. Convert loosely typed third-party/protobuf values exactly once at adapter boundaries. Pydantic strictness is not a substitute for checking monetary ranges, network identities, or transaction semantics.

Core execution is conceptually:

```text
reduce(previous_state, verified_domain_event)
    -> new_state + permitted_effects
```

Transport messages become verified domain events only after authentication, schema checks, transcript checks, and required independent observations. A provider's status message cannot manufacture `FundingConfirmed`.

Useful ports:

```text
DiscoveryBackend: stream_verified_advertisements(query)
SessionTransport: send(frame), receive(), report_transport_failure()
ChainBackend: tip(), observe_outpoint(), transaction(), broadcast(), estimate_fee()
FundingWallet: list_candidates(), reserve(), fund_explicit_inputs(), sign_funding()
LightningBackend: capabilities(), lookup(), hold(), settle(), cancel(), pay_with_deadline()
SwapSigner: script_sign(), musig_begin(), musig_partial_once(), destroy_attempt()
SwapStore: compare_and_append(), durable_intent(), record_observation()
Notifier: enqueue_redacted_notification()
```

`ChainBackend` reports an explicit trust/evidence mode. `LightningBackend` reports exact capabilities, including incoming HTLC expiry visibility and outgoing absolute-deadline enforcement. Unsupported safety capabilities mean unsupported profile; do not emulate them with hopeful assumptions.

Use `asyncio.TaskGroup`, bounded queues, explicit cancellation boundaries, and dependency injection. Avoid adding Redis, Celery, or a message broker before a demonstrated need. A clean shutdown stops admission first and preserves/reconciles ongoing swaps; it does not blindly cancel holds.

## 6. Network identity

Represent a chain by more than a human label:

```text
NetworkIdentity {
  family: "bitcoin",
  name: mainnet | signet | regtest | testnet3 | testnet4 | custom,
  genesis_hash,
  signet_challenge: hex | null,
  consensus_profile,
  deployment_namespace: optional test-only identifier
}
```

All signed terms, invoice interpretation, address parsing, recovery records, provider advertisements, and persistence namespaces bind the network identity. Default and custom signet configurations can share a genesis block while using different challenges; include and verify the challenge rather than treating genesis alone as sufficient.

Regtest deployments additionally bind a test namespace/checkpoint policy to avoid accidental cross-lab discovery. This is application separation, not a new Bitcoin consensus rule. Generate network fixtures from the pinned Core version and verify invoice backend support; do not assume every LND version supports every custom network equally.

Use regtest for deterministic development and public test networks for interoperability trials.

## 7. Wire format and authentication

Use RFC8785 canonical JSON for signing, with RillSwap restrictions: no floating-point protocol values, no duplicate keys, bounded nesting, bounded arrays and strings, and canonical lower-case hex. Represent all satoshi/millisatoshi amounts as canonical nonnegative decimal strings, except success and service fees, which are signed (negative for a provider rebate, never `-0`). Native applications convert to Python integers; browser applications use `bigint`. Heights and timestamps are bounded integer fields within JavaScript's exact range. Contract and invoice values are strictly positive; fees may be negative only down to the provider's configured rebate floor; enforce a maximum of 2,100,000,000,000,000 sats (and its exact millisatoshi equivalent) plus per-provider/client limits.

Every application message carries:

```text
protocol, wire_version, profile_id, network_identity,
session_id, message_id, sender_session_key,
sequence, in_reply_to, contract_hash,
message_type, payload, required_features, extensions
```

Use separate domain-separated BIP340 tagged-hash signatures for provider-authenticated economic terms and any application envelopes that require transferable authentication. Sign canonical bytes excluding the signature field. RS-001 specifies the exact tags and object schemas, with byte vectors. The Nostr rumor itself remains unsigned as required by NIP59; an explicitly signed application object inside it is a different object and forfeits deniability for that object.

Handshakes negotiate profile, protocol version, encryption suite, capabilities, network, fresh client/provider session keys, random challenges, and transport endpoints. A provider-identity signature binds this transcript. Reject downgrade or unknown mandatory features. Unknown fields are invalid except inside a bounded namespaced extension container; optional extensions cannot alter base-profile safety rules.

Economic terms bind the exact invoice/payment hash, both swap keys, amount, fee components, prepayment cap if any, timeout, confirmation requirements, destination scripts, and recovery authorization key. The final contract is mutually accepted before a principal commitment. Funding outpoints arrive afterward in a separately authenticated binding and must be locally checked against the contract.

Indicative quotes can be requested without exposing an invoice or payment hash. Expose the exact invoice only to the selected provider, using a fresh session. Do not create the same hash-bound swap at several providers to race execution.

Message delivery is at least once and may be unordered. Maintain durable inbox/outbox records and idempotency keys. A relay `OK` is not an application acknowledgment, and an application acknowledgment is not evidence that a financial effect succeeded. Retransmissions reuse the logical message identifier but obtain fresh wrappers/encryption randomness.

Expired terms cannot be newly accepted. Expiry does not erase obligations or invalidate recovery for an already funded contract.

## 8. Discovery profile

The discovery interface returns authenticated advertisements, not trusted liquidity guarantees. Advertisements contain provider identity, supported chain/profile/directions, coarse amount bands, indicative fee policy, communication capabilities, epoch mailbox keys, expiry, and a signed monotonically increasing advertisement revision. Avoid exact balance broadcasts and per-swap capacity updates.

The Nostr adapter uses a dedicated addressable announcement kind, not NIP78's generic app-data kind: current NIP78 explicitly directs interoperable public applications toward dedicated kinds and describes owner-authenticated storage behavior.

This design uses **project-local kind 39417** for advertisements and **21417** for unpublished protocol rumors. These are not claimed to be registered or globally unoccupied. Events require a `rillswap` namespace and a binding version. Registering dedicated kinds through the companion NIP draft is a binding-version change, not a silent reinterpretation. The core protocol never embeds these numbers in settlement semantics.

Use a `d` identifier scoped to protocol/network/advertisement slot and minimal public protocol/network tags. Provider names/descriptions are untrusted plain text. Do not put payment hashes, invoices, transaction IDs, swap IDs, individual amounts, or client identities in discovery tags.

Support multiple user-configurable relays, cached signed advertisements, and direct provider import. A starter relay list is bootstrap configuration only. Do not require admission to an official provider list, NIP05 identity, token holding, or a centrally calculated reputation score.

Freshness checks include signed revision, application expiry, maximum clock skew, and a cap on future-dated ads. Treat claimed capacity and proof of work as admission/discovery information, not evidence of solvency or successful routing. Rate-limit advertisement processing and bound per-identity memory. Provider key rotation is explicit and signed where continuity is desired; it cannot replace the identity/key terms of existing swaps.

## 9. Encrypted Nostr transport and relay privacy

The mandatory first transport suite is **NIP-44 v2 inside NIP-59 gift wraps**, with durable outer kind 1059. NIP44 supplies encryption, not a complete messaging protocol. NIP59 separates the application rumor, author-signed encrypted seal, and encrypted one-time outer wrapper. Follow the specifications for empty seal tags, author/recipient validation, randomized outer timestamps, and wrapper signatures.

Use distinct keys for public provider identity, provider epoch inbox, per-swap provider/client session mailboxes, on-chain swap signing, and recovery authorization. Never use the customer's social Nostr key or general wallet master key.

Bootstrap a session against the provider's advertised epoch inbox, then authenticate new per-swap keys through the signed handshake. Protect quote contents and payment information only after identity/network/suite validation. A single shared provider inbox can still identify the service being contacted; per-session migration reduces later linkage but does not erase that initial observation.

Validate outer event shape/signature and payload limits before decryption. Validate the seal author and expected recipient, then validate the application transcript. Apply bounded decryption work and per-peer queues to prevent computational denial of service. Treat malformed ciphertext and plaintext uniformly enough to avoid verbose error oracles.

**Remaining relay visibility:** recipient tags, subscription filters, source IP, arrival time, sizes, retries, and cross-relay correlation. Encryption does not eliminate these observations. NIP44 does not provide forward secrecy or post-compromise security. Fresh keys and deletion limit exposure only to the extent old keys, backups, memory copies, and logs are actually unavailable. Do not market this as an audited ratchet or as anonymity against a global observer.

Proposed mitigations are a small explicitly chosen relay set, per-session recipient mailboxes, no stable client relay-auth identity, fresh wrappers on retry, optional application padding in 4/8/16 KiB buckets within a 16 KiB application-message cap, and a 128 KiB maximum accepted outer event. Validate the final encoded size; do not assume encryption overhead is constant. Padding is authenticated but excluded from business semantics. Do not delay deadline-sensitive recovery for batching or cover traffic.

Tor clients use SOCKS with remote DNS and fail closed: no automatic clearnet reconnect. The browser cannot configure its own arbitrary SOCKS transport; users use Tor Browser or the optional local agent. More relays improve availability but expose metadata to more parties. Deletion/expiration requests are retention hints, never a cryptographic erasure guarantee.

A future direct HTTPS/WebSocket or `.onion` adapter can carry the **same encrypted signed frames** without a relay. This changes transport exposure, not settlement or identity validation. Any future cryptographic suite must use a separately reviewed established construction, authenticate its negotiation, and receive a distinct suite identifier. Cross-transport resume requires authenticated session/recovery authorization and explicit user privacy policy; no silent downgrade or clearnet fallback.

## 10. Taproot contract

This is a RillSwap-specific construction; it is not script-compatible with Boltz swaps. Serialized vectors are in `vectors/`.

Given fresh valid compressed public keys `K_user` and `K_provider`, aggregate in **exact order `[K_user, K_provider]`** using BIP327. Reject duplicate keys. Use the aggregate x-only key as the internal key, applying the BIP341 Taproot tweak for exactly two leaf-version `0xc0` leaves. TapBranch ordering and control-block parity follow BIP341; use library APIs, not custom point arithmetic.

Claim leaf, with a direct SHA256 Lightning hash:

```text
OP_SIZE <32> OP_EQUALVERIFY
OP_SHA256 <payment_hash> OP_EQUALVERIFY
<claimant_xonly_pubkey> OP_CHECKSIG
```

Refund leaf:

```text
<refund_lock_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
<refund_party_xonly_pubkey> OP_CHECKSIG
```

`<32>` is minimally encoded as a script integer; `<refund_lock_height>` is a minimally encoded nonnegative ScriptNum representing a block height, not a timestamp. The claim preimage must be exactly 32 bytes. No extra leaves, OP_SUCCESS opcodes, alternate leaf versions, annex, or arbitrary sighash options are accepted.

The client reconstructs the **entire output commitment**, including the aggregate internal key, both leaves, merkle root, TapTweak, output key, scriptPubKey, and control blocks. A plausible refund leaf does not make a provider-controlled internal key safe.

BTC→LN assigns claimant=provider, refund party=user. LN→BTC assigns claimant=user, refund party=provider. Fresh per-swap keys are not provider identity or mailbox keys.

Initial claim/refund transactions use version 2, one contract input, one approved destination output, and BIP341 `SIGHASH_DEFAULT`. Unilateral claim locktime is 0; refund locktime is the contract's `T`. The contract input sequence is `0xfffffffd`. Required witnesses are `[signature, preimage, claim_script, control_block]` and `[signature, refund_script, control_block]`. Key-path claims use the validated cooperative signature without exposing a leaf.

With refund `nLockTime=T`, model the first eligible block as **R=T+1** and test exact mempool/block boundaries against Core. Claim and refund conditions are independent; the claim does not become invalid at T.

V1 contract outputs are always P2TR. Funding inputs must be native SegWit/Taproot. Destination/change outputs use an explicitly supported standard script allowlist, preferring fresh P2TR; arbitrary scripts are not accepted. Never subtract a funding fee from the contract output.

One contract is funded exactly once. An RBF replacement must preserve the exact intended contract output and remain a replacement, not add a second independent hashlocked deposit. Multiple deposits under one hash are dangerous because one revealed preimage unlocks all matching claim paths. Detect/report extras, but never promise a cryptographic refund for an accidental second deposit already exposed to the same secret.

## 11. BTC→LN state machine

```text
NEGOTIATING -> TERMS_ACCEPTED -> RECOVERY_DURABLE
 -> FUNDING_OBSERVED -> FUNDING_CONFIRMED -> LN_PAYMENT_PENDING
 -> PREIMAGE_KNOWN -> CLAIM_PENDING -> COMPLETED

failure before funding -> ABORTED
funded and unpaid -> REFUND_WAIT -> REFUND_PENDING -> REFUNDED
ambiguous/in-flight effects -> RECONCILIATION_REQUIRED
```

The user obtains a fixed-amount invoice from a receiver wallet they control or whose handling of the secret they explicitly trust. The invoice's secret must not be disclosed prematurely to the provider. Arbitrary third-party invoice issuers can defeat that assumption by sharing the preimage; this is not solved by on-chain scripting.

The provider supplies fresh keys and signed terms. The client verifies the invoice, amount, chain, exact contract, and recovery plan, durably exports recovery material, then funds. The provider independently verifies the funding transaction and required confirmations before attempting payment.

The provider pays only within an **absolute HTLC exposure deadline** that leaves time to learn a successful payment and confirm its on-chain claim before refund competition. It tracks ambiguous payment results after RPC/network failure; a timeout/cancel acknowledgment is not proof that the payment cannot later settle.

After obtaining a valid preimage, the provider can claim unilaterally. Cooperative key-path claiming is optional. A client validates the exact claim transaction and must require the preimage (or independently verified equivalent payment/claim authorization) before releasing a cooperative partial. Seeing a correct preimage demonstrates that the provider already has the contract's unilateral claim authority; it is not necessarily an independently observed Lightning receipt. The UI must distinguish those facts.

A client may always decline cooperation and retain the profile's unilateral behavior. Before the provider has claim authority, no key-path partial may bypass the user's principal protection. Unpaid users refund at the specified deadline, with a valid fee strategy and monitoring until required confirmation depth.

## 12. LN→BTC state machine

```text
NEGOTIATING -> TERMS_ACCEPTED -> RECOVERY_DURABLE
 -> HOLD_INVOICE_OPEN -> LN_HELD -> FUNDING_PENDING
 -> FUNDING_CONFIRMED -> CLAIM_READY -> PREIMAGE_RELEASED
 -> LN_SETTLEMENT_PENDING / CLAIM_PENDING -> COMPLETED

not funded -> HOLD_CANCELED -> ABORTED
funded but unclaimed -> REFUND_WAIT -> REFUND_PENDING
 -> REFUND_CONFIRMED -> HOLD_CANCELED -> REFUNDED
```

The user creates a random 32-byte preimage and saves the secret and swap key in the recovery package before payment. The provider creates a hold invoice for its hash without learning the preimage. The user pays using an ordinary compatible LN wallet. Wallets without hold invoice support may report the held payment as pending or failed until the claim settles it, so clients keep the invoice visible and tell the user not to pay again (RS-004).

The provider waits until the invoice is fully accepted and checks the actual amount and **every relevant accepted HTLC's expiry**, including MPP parts. It must have sufficient time to fund, allow a claim, and recover/refund before its incoming payment exposure expires. It then funds the verified contract and independently watches the chain.

Before revealing the preimage, the user independently verifies the funding outpoint/value/commitment, sufficient confirmations, current height, remaining claim budget, and a viable claim fee. The user constructs and signs a valid unilateral claim first and durably records the claim plan. A pre-signed transaction is useful immediate fallback, but live fee-bump/recovery ability remains necessary.

The user may then request a cooperative claim. The provider must **not issue a usable key-path partial before it has the valid preimage and a safely settleable held payment**. Otherwise the user could obtain on-chain funds without enabling Lightning settlement. Once the preimage is disclosed, the provider can settle the hold. If it withholds cooperation, the user must broadcast/fee-bump the unilateral claim.

This is not fair signature/preimage exchange. Security depends on the already enforceable unilateral claim and sufficient monitoring/fees. After preimage release, closing a tab and missing the deadline can cause principal loss. Service workers are not a reliable always-on watcher; browser execution can be terminated.

If no claim occurs, the provider refunds and verifies the required confirmation evidence before canceling the held invoice. It must not cancel just because the refund height arrived: the claim branch remains valid. The deadline budget must also account for automatic backend cancellation and Lightning force-close resolution; holding indefinitely is not an available strategy.

## 13. Timelock policy and LND adapter

Let R be the first block where the refund may be mined, h the current validated height, E_out the latest actual outgoing HTLC exposure, and E_in the earliest relevant held incoming expiry. Required design inequalities are:

```text
BTC→LN:  E_out + Δlearn_and_claim < R
LN→BTC:  R + Δrefund_and_LN_resolution < E_in
reveal:  h + Δclaim_confirmation < R
```

Funding admission additionally budgets funding confirmations, client response/claim time, backend early-cancel behavior, and the refund margin. These are inequalities, **not universal safe constants**. Define operator/client minimums and maxima in blocks, include negotiated values in terms, and test boundary cases. No finite constants guarantee success under unbounded censorship, fee spikes, reorgs, or offline operation.

The LND adapter uses TLS with certificate verification and a restricted macaroon. Implement lookup/subscribe/create-hold/settle/cancel plus outgoing payment tracking through official pinned RPC definitions. Accepted invoice HTLC entries expose expiry heights and values; aggregate them conservatively rather than using only BOLT11's wall-clock expiry.

Expose `pay_with_deadline(invoice, max_absolute_expiry, max_fee)` as a semantic interface. Initial LND support should construct/obtain explicit routes, validate `route.total_time_lock` against the absolute deadline before each attempt, and submit through `SendToRouteV2`. A simpler single-part outgoing policy is acceptable initially. Supporting `SendPaymentV2` is acceptable only after the pinned-version implementation proves equivalent deadline enforcement across retries, restarts, and unknown outcomes. Its relative CLTV/timeout options must not be casually treated as a durable absolute bound. Official RPC documentation also warns that canceling further attempts does not necessarily abort in-flight HTLCs.

Persist payment hash, attempt identity, route deadline, and maximum fee before initiation. After ambiguous responses, reconcile with LND by hash/attempt rather than sending again. Support incoming MPP by checking all parts; outgoing AMP is out of scope. A backend unable to expose the required information cannot advertise the corresponding profile.

## 14. Cooperative signing lifecycle

Cooperation is a claim optimization, never a prerequisite for unilateral recovery. Freeze exact transaction bytes, all prevout amounts/scripts, contract hash, network, signer keys, role, and a unique cooperation ID before nonce generation.

Exchange and validate public nonces. Each participant signs only after its directional authorization condition is satisfied: provider knowledge of the preimage and safely held LN payment for LN→BTC; provider unilateral claim authority for BTC→LN. Verify received partial signatures before aggregating and verify the final signature against the exact tweaked Taproot output key.

A burned attempt row is persisted before allocating a native nonce. The secret handle stays in memory only and may be consumed once. Persist the resulting public partial signature for retransmission. If a crash loses an unpersisted result, abandon that attempt. Never derive the old nonce from a seed/counter to retry, reuse it for a new fee-bumped transaction, clone a live process, or include it in recovery backups.

A fee-bumped cooperative claim requires a fresh cooperation ID and fresh nonces. A client whose preimage is already exposed does not wait indefinitely for that negotiation; it follows its unilateral fee escalation schedule.

## 15. Treasury and privacy-focused coin selection

Bitcoin Core owns treasury descriptors, ordinary addresses, funding keys, funding transaction signing, and normal wallet backups. The separate swap signer owns temporary contract keys and signs contract spends. Core integration does not remove those keys or their recovery obligations.

Use a dedicated provider treasury wallet separate from LND's channel wallet. Core RPC is local/private. Keep provider identity and LN authentication outside recovery exports. A hardware/external signer can be a later capability; do not assume it can perform MuSig2 or remain available during swap deadlines.

Coin selection is lexicographic rather than simply cheapest:

1. Do not cross locally tracked ownership/provenance clusters by default.
2. Prefer a single adequate UTXO; otherwise use a small explicitly bounded set inside one cluster.
3. Avoid dust/toxic change while respecting exact contract value and fee policy; excess not worth a change output goes to the fee.
4. Compare fee/waste only after the privacy constraints; randomize comparable ties.

Unknown-origin coins start as separate clusters, not one large “unknown” pool. Cluster labels are local heuristics, not proof of anonymity. Change stays labeled with its source cluster and uses a fresh address. A large single input with change may be preferable to consolidating unrelated smaller coins into an exact amount.

Select explicit inputs, reserve them durably, and call Core with `add_inputs=false`. Re-check the resulting PSBT and signed transaction for exact inputs, contract amount/script, change destination, and fee bounds. Explicitly choose supported PSBT version/options, strip unnecessary derivation metadata from any outward-facing artifact, and distinguish `fee_rate` sat/vB from differently named legacy fee units. Do not let Core silently override privacy selection by adding more coins.

Mirror reservations in Core locks where useful, but treat the application's durable reservation ledger as authoritative across restart and reconcile wallet state. Cross-cluster funding, automatic consolidation, and multi-customer batching require separate operator approval and are disabled initially. A maintenance process may deliberately rebalance inventory later, never disguised as ordinary swap funding.

External user wallets retain their own coin selection policy. The browser can verify a supplied PSBT's selected inputs and outputs, but cannot promise to control what a separate wallet does merely by showing a deposit address.

## 16. Fees, abort exposure, and admission

Keep three quantities visible: irrecoverable payment before success, maximum intended lock duration, and mining-fee assumptions necessary for recovery. Avoid describing a swap as costless to abort.

For BTC→LN, let L be the invoice value in sats and S the quoted success fee. The contract amount is `V=L+S`; the user additionally pays funding and any refund mining fee. The provider prices routing and claim costs into S subject to an internal fee cap.

For LN→BTC, let V be the contract amount, D the requested nominal net payout, and C the claim-fee reserve (`V=D+C`). Let S be the success fee, including provider funding cost. An optional explicitly negotiated mining prepayment M must satisfy `0≤M≤S`; the held invoice is `V+S−M`, and total successful LN payment is `V+S`, excluding the user's own routing fee. Use distinct prepayment and principal hashes. Users ask for an exact amount at an address, so C is priced at quote time for the cooperative claim to confirm in the next block, and the claim pays exactly C: the address receives D. Only a claim still unconfirmed late in its window pays more, up to the authorized claim fee cap, to beat the refund. Actual net payout is V minus the claim fee actually paid; do not promise D under arbitrary fee conditions.

Fee rates target first-block inclusion for most transactions without overpaying: the economical two-block estimate of the party's own Core node, or a mempool API's `fastestFee`, never below the node's relay and mempool minimum. Without an estimate, quote or fund later rather than guess.

An upfront fee can be stolen by an uncooperative provider. Make M=0 the client default unless the user explicitly accepts a bounded nonzero exposure. The extension may be essential to some operators' economics, but is not a cryptographic guarantee. Quote signatures establish authenticated terms, not automatic damages.

Provider admission has caps on concurrent swaps, pending quotes, held HTLCs, locked treasury coins, total time-weighted liquidity exposure, miner prepayment exposure, and unpaid request work. Apply per-session and global budgets. Expiring quotes, optional computational challenges, and local reputation can reduce abuse but do not solve Sybil attacks.

Do not introduce slashing without a precise objective proof of misconduct. Routing failure, congestion, disappearing clients, and censored messages are not generally distinguishable on-chain. Fidelity bonds can be a future costly-identity signal; they are not automatically slashable user insurance.

## 17. Persistence, crash safety, and reorgs

Persist immutable terms, domain events, action intents/results, chain observations with block hashes, payment attempts, UTXO reservations, encrypted secret references, and inbox/outbox IDs. One worker serializes each swap through an optimistic revision check. SQLite writes are short transactions; network calls occur outside database transactions.

For every irreversible effect: persist intent, execute at the adapter, record result, reconcile ambiguity. Do not claim exactly-once RPC execution. Payment hashes, transaction IDs, invoice identities, and backend observations make effects reconcilable.

Separate monotonic knowledge (a preimage has been exposed; a signature was issued) from reversible observations (a funding transaction was on the best chain). A reorg can remove confirmation evidence but cannot make a leaked preimage secret again. Restart/reorg replay must preserve that distinction.

Reorg protection is conditional on the chosen depth and assumptions. Tests that remove already revealed funding must expose the limit honestly; do not invent an invariant that all arbitrary reorgs are harmless. Stop new risk when chain observations disagree, while continuing already necessary monitoring and recovery.

Database backups never contain live MuSig secret nonces. Encrypted swap signing secrets are separate from node wallet seeds and session encryption keys. Disaster restore tests start from a consistent snapshot plus chain/LN reconciliation, not from a frozen in-flight signer process.

## 18. Recovery format and watcher

Export a versioned canonical recovery object inside standard age encryption. Support an independent passphrase or user-provided age recipient; decryptability must not depend on a lost browser origin or wallet master key. Cross-test Python `pyrage` and TypeScript `age-encryption` before freezing the format.

Include network, profile, contract terms and signatures, script/tree data, public keys, the user's swap secret key or independently usable derivation information, required preimage where applicable, refund height, destinations, funding transaction/outpoint history, chain scan birthday, fee policy, and recovery authorization key. Include no provider credentials, social identity key, or secret MuSig nonce. Communication-session decrypt keys are not required for unilateral recovery and should not be included by default.

Create/export the initial package before principal commitment, then update it when funding outpoints and replacements are known. Include enough script/key information to find a later funding output even when the first export predates its outpoint. A fixed pre-signed refund alone is not sufficient recovery because outpoints and fees can change.

`rill recover` must inspect offline, verify contract bindings locally, query a user-selected chain source, build/sign the correct unilateral transaction, and broadcast without provider or discovery availability. Backup import must not automatically contact a provider or reveal the preimage.

The provider always runs a durable watcher. CLI users can run `rill recover watch-claim` or `rill recover watch-refund`. Browser users get explicit state-dependent warnings and an optional local watcher handoff. A tab may close safely before a secret commitment with bounded abort costs; after preimage disclosure or issuance of an otherwise dangerous signature, monitoring is a financial requirement. Do not label a backup alone as equivalent to a live watcher.

## 19. Static web UI, local loading, and chain verification

Bundle all JS, WASM, styles, and assets. No CDN dependencies, analytics, remote executable scripts, or third-party fonts. Use a small Vite/TypeScript application, strict compiler options (`strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`), bounded runtime schemas, a signer worker, and safe plain-text rendering.

The static build can be served from GitHub Pages or from loopback:

```sh
python -m http.server 8080 --bind 127.0.0.1 --directory dist
```

Do not promise reliable `file://` execution across browsers: module/WASM loading, storage, origins, and network access vary. Localhost is the supported local operational mode; opening static source files is not the same as a supported wallet environment.

Use encrypted IndexedDB records, a persistent-storage request, an exclusive per-swap/tab lock, and recovery export before funding/payment. Validate that durable storage actually works. Do not silently upgrade executable code in the middle of an active swap; pinned releases and explicit upgrades are the default. Browser-memory zeroization is best effort, not a hardware isolation guarantee.

The UI locally validates contracts, transactions, signatures, invoices, amounts, and state transitions. **That does not automatically validate the entire Bitcoin chain.** Support explicit chain modes:

- `own-node`: data from the user's full node through a restricted authenticated endpoint/local agent; the provider is not the chain authority.
- `remote-chain-source`: clearly disclosed dependence on a selected external data service; multiple sources help availability/cross-checks, not full consensus verification.
- A `verified-light-client` mode is not implemented. It would require header, inclusion and discovery verification with documented security assumptions, not a label attached to explorer queries.

Strict own-node mode rejects provider-only or unverified remote confirmation assertions. A standalone static build has no mandatory RillSwap backend, but still needs chain data, Lightning access through wallets/providers, and transport connectivity. Full validation and zero external infrastructure are different requirements.

The optional local agent serves UI and a narrow same-origin API, binds loopback, checks Host/Origin, uses explicit pairing/capability authorization and CSRF protections, and exposes no generic node RPC forwarding. Do not send Core passwords or LND macaroons to a GitHub Pages origin. Remote-page-to-local-agent CORS is disabled by default; prevent DNS rebinding and avoid `Access-Control-Allow-Origin: *`.

UI flow: select network and privacy/chain mode; discover/import provider; compare indicative terms; create selected quote; verify full terms; export recovery; commit; show evidence-backed status and deadlines; complete or recover. Fee/lockup/preimage-exposure warnings remain visible and precise. A remote provider description never injects HTML.

GitHub Pages deployment runs on pushes to `main` (never on pull requests) through the official Pages artifact/deploy actions. PRs build and test without deploy credentials. The workflow pins action commits, installs locked packages, runs the unit and browser tests, and uploads the tested build. Relative base paths support repository and fork hosting. Do not execute untrusted PR code via privileged `pull_request_target`.

Signed builds and attestations help a user verify a pinned artifact; they do not automatically verify the JavaScript that every website visitor executes. GitHub Pages' header controls also differ from a custom server, so document which CSP protections are actually delivered rather than claiming unavailable headers.

## 20. CLI, notifications, and operations

CLI surface (see `rill-cli/README.md` for options):

```text
rill providers list            # verified provider announcements from Nostr relays
rill swap btc-to-ln            # pay a Lightning invoice with on-chain BTC
rill swap ln-to-btc            # receive on-chain BTC by paying over Lightning
rill recover inspect           # redacted offline inspection of a recovery file
rill recover watch-claim       # claim an LN-to-BTC swap until it confirms
rill recover watch-refund      # refund a failed BTC-to-LN swap until it confirms
```

Passwords/seeds/preimages are read from protected prompts/stdin or configured secret stores, not command-line arguments. Machine-readable output is redacted by default; explicit recovery export is the exception. Distinguish pending/recoverable/unsafe/terminal errors in exit codes. Interrupting the CLI must not delete a live swap.

Notifications are optional. They default to “swap requires attention” plus a local opaque reference. No invoice, preimage, destination, exact amount, transaction ID, or secret-bearing URL by default. Richer notifications require explicit disclosure settings. Treat notification tokens/URLs as secrets and honor the same Tor/egress policy. An unavailable notification service must not block invoice settlement, signing, refunds, or the watcher.

Local provider diagnostics may include per-swap payment/invoice hashes, amounts,
fees and bounded, escaped invoice memos at INFO. Treat these logs as financially
sensitive. Never log full invoices, preimages, keys, credentials, recovery data
or stable customer identifiers. Metrics remain aggregate: do not label them with
payment hashes, addresses, invoices, or stable customer identifiers. Notifications
retain their separate disclosure policy; diagnostic exports omit financial details.
Redaction tests use known synthetic secrets. Expose admin actions locally with
authentication. Run containers as non-root, restrict writable directories, avoid
Docker socket mounts, and use health checks that measure chain/LN/reconciliation
readiness rather than process existence.

## 21. End-to-end testing

The repository ships a Docker Compose regtest environment (`dev/`, see
`DEVELOPMENT.md`) with Bitcoin Core, separate maker, user and merchant LND
nodes, a Nostr relay, an Anvil EVM chain, makers for all four swap profiles,
the CLI, the browser app, a gas sponsor and a demo shop. Playwright suites in
`rill-web/regtest/` drive real browser flows against it, and
`scripts/regtest_e2e.py` runs isolated Core, LND, relay, provider and client
containers for both swap directions.

Use real Bitcoin Core, LND, and relay implementations, pinned by version or digest. Fake adapters are appropriate for unit tests, not as substitutes for money-path end-to-end tests. Default integration tests have no public-network dependencies: no faucets or production relays.

Fixture bootstrap mines enough blocks for coinbase maturity, funds wallets, initializes restricted macaroons, opens channels, and waits on observable state rather than arbitrary sleeps. Tests that depend on block timing control block production explicitly.

Browser tests use a real static HTTP origin and actual browser wallet/backup flows, not only unit tests. Python/TypeScript implementations must agree on canonical messages, contract commitments, signatures, and recoveries. Two provider processes sharing one implementation demonstrate deployment independence, not independent protocol implementation.

Money-path tests must cover both directions, both spend paths, timeout/refund races, restarts at effect boundaries, malformed commitments, short HTLC expiries, ambiguous LN outcomes, nonce lifecycle violations, relay replay/censorship, browser backup loss, unilateral CLI recovery with all RillSwap services removed, coin-selection privacy, and chain-source trust enforcement.

Tor tests should use an isolated private test network where practical, with captured DNS/egress to prove fail-closed behavior. They cannot prove anonymity against a global observer. Public-network smoke tests are separate from deterministic PR tests.

## 22. Security invariants

Threat analysis considers each attack's attacker, prerequisites, principal exposure, fee exposure, privacy loss, liveness assumptions, and mitigation. Mandatory invariants:

- No funding/payment/reveal/signing action based solely on provider status.
- No accepted contract with an unexpected internal key, leaf, network, amount, hash, or timeout.
- No LN→BTC key-path authorization before provider payment authorization conditions hold.
- No user preimage release before an independently validated, viable unilateral claim.
- No invoice cancellation at refund eligibility without the required refund-resolution evidence.
- No reused, copied, serialized, or restored MuSig secret nonce.
- No disappearance of revealed-secret knowledge after restart/reorg.
- No automatic addition of unrelated wallet inputs.
- No provider API, relay, website, or old browser origin required for unilateral recovery.
- No claim that optional prepayments, unlimited congestion, offline operation, or arbitrary reorgs are principal-risk-free.

Model the two directional reducers with stateful property tests and a small bounded state model. Include asynchronous observations, reordered messages, counterparty refusal, crash/restart, fees, and block progression. A model passing is not proof that adapter behavior matches it; test adapters against real nodes and document the correspondence.

## 23. Interoperability with other swap services

Adapters for existing provider APIs are not implemented. A noncustodial adapter translates offers/messages while retaining the actual upstream settlement profile; it cannot make a P2WSH contract become P2TR or turn a custodial exchange deposit into an atomic claim.

A liquidity-bearing router can offer a new RillSwap P2TR contract while sourcing/hedging upstream. That router is an independent swap participant with capital, fee, timing, and counterparty exposure. Hash-linked multi-leg composition requires a separately analyzed profile and nested deadlines. Neither discovery nor the client should conceal the difference between a message translator and a funded intermediary.

The measure of success is not the number of provider listings. It is independently implemented clients and providers agreeing on exact contracts, messages, recovery files, and failure behavior without permission from the original RillSwap maintainers.
