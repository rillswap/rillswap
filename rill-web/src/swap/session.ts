/**
 * One browser client session: keys, signed envelopes, NIP-59 gift wraps,
 * and an authenticated inbox (port of rill-cli live_swap._Session and
 * rill-provider's strict gift-wrap receive rules). Keys live in memory only.
 */
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import canonicalize from "canonicalize";
import { getEventHash, getPublicKey, nip44, type NostrEvent, verifyEvent } from "nostr-tools";

import { wrapWithTransportWork } from "../nip59Transport";
import { validateNetwork } from "../generated/manualAdvertisementValidators.js";
import { jcs, unsignedEnvelopeHash } from "./hashes";
import { requireShape } from "./wire";

export const GIFT_WRAP_KIND = 1059;
const SEAL_KIND = 13;
const RUMOR_KIND = 21417;
const RUMOR_MEMBERS = ["content", "created_at", "id", "kind", "pubkey", "tags"];
const MAX_EVENT_BYTES = 128 * 1024;
const MAX_ENVELOPE_BYTES = 16 * 1024;
const encoder = new TextEncoder();

export interface Envelope {
  readonly protocol: "rillswap";
  readonly wire_version: "1";
  readonly profile_id: string;
  readonly network_identity: unknown;
  readonly session_id: string;
  readonly message_id: string;
  readonly sender_session_key: string;
  readonly sequence: number;
  readonly in_reply_to: string | null;
  readonly contract_hash: string | null;
  readonly message_type: string;
  readonly payload: Record<string, unknown>;
  readonly required_features: readonly string[];
  readonly extensions: Record<string, unknown>;
  readonly signature: string | null;
}

export interface Frame {
  readonly sealAuthor: string;
  readonly envelope: Envelope;
}

const refused = (): never => {
  throw new Error("gift wrap refused");
};

function signedEvent(raw: string, kind: number): NostrEvent {
  if (encoder.encode(raw).length > MAX_EVENT_BYTES) refused();
  const event = JSON.parse(raw) as NostrEvent;
  if (event === null || typeof event !== "object" || event.kind !== kind || !verifyEvent(event)) refused();
  return event;
}

/**
 * Decode one received gift wrap for `recipientSecret`, or throw. Mirrors
 * rill-provider `_nip59_receive._decode`: authenticate before decrypting,
 * exactly one recipient tag, an empty-tag seal, an exact rumor whose ID
 * recomputes, canonical envelope content, and matching authors.
 */
export function unwrapGiftWrap(
  raw: string,
  recipientSecret: Uint8Array,
  network: unknown,
  profile: string,
): Frame {
  const recipient = getPublicKey(recipientSecret);
  const outer = signedEvent(raw, GIFT_WRAP_KIND);
  const recipients = outer.tags.filter((tag) => tag[0] === "p");
  if (recipients.length !== 1 || recipients[0]!.length !== 2 || recipients[0]![1] !== recipient) refused();
  const sealRaw = nip44.decrypt(outer.content, nip44.getConversationKey(recipientSecret, outer.pubkey));
  const seal = signedEvent(sealRaw, SEAL_KIND);
  if (seal.tags.length !== 0) refused();
  const rumorRaw = nip44.decrypt(seal.content, nip44.getConversationKey(recipientSecret, seal.pubkey));
  if (encoder.encode(rumorRaw).length > MAX_EVENT_BYTES) refused();
  const rumor = JSON.parse(rumorRaw) as Record<string, unknown>;
  if (
    rumor === null ||
    typeof rumor !== "object" ||
    Object.keys(rumor).sort().join() !== RUMOR_MEMBERS.join() ||
    rumor.kind !== RUMOR_KIND ||
    !Number.isSafeInteger(rumor.created_at) ||
    (rumor.created_at as number) < 0 ||
    JSON.stringify(rumor.tags) !== JSON.stringify([["rillswap", "nostr-experimental-1"]]) ||
    typeof rumor.content !== "string" ||
    typeof rumor.pubkey !== "string" ||
    rumor.pubkey !== seal.pubkey
  ) {
    refused();
  }
  const content = rumor.content as string;
  const size = encoder.encode(content).length;
  if (size === 0 || size > MAX_ENVELOPE_BYTES) refused();
  if (getEventHash(rumor as unknown as NostrEvent) !== rumor.id) refused();
  const parsed: unknown = JSON.parse(content);
  if (canonicalize(parsed) !== content) refused();
  const envelope = requireShape<Envelope>("validateEnvelope", parsed);
  if (
    envelope.sender_session_key !== rumor.pubkey ||
    canonicalize(envelope.network_identity) !== canonicalize(network) ||
    envelope.profile_id !== profile
  ) {
    refused();
  }
  return { sealAuthor: seal.pubkey, envelope };
}

/** The relay surface a session needs; see relay.ts for the WebSocket one. */
export interface RelayLink {
  readonly failureReason?: string | undefined;
  /** True only when publish runs beforePublish itself, immediately before each socket write. */
  readonly guardedPublication?: boolean;
  publish(event: NostrEvent, options?: PublicationOptions): Promise<boolean>;
  subscribe(filter: Record<string, unknown>): Promise<void>;
  /** The next raw event JSON for our subscription, or null at the deadline. */
  next(deadline: number, signal?: AbortSignal): Promise<string | null>;
}

/** Checked at the actual socket write, including after reconnecting. */
export interface PublicationOptions {
  readonly beforePublish?: () => void;
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

export class SwapError extends Error {
  constructor(message: string, readonly transportReason?: string) {
    super(message);
    this.name = "SwapError";
  }
}

export const NIP59_BACKDATE_SECONDS = 2 * 24 * 3600;

/** Shared transport/session authentication, not application-payload authorization. */
function authenticateSessionEvent(raw: string, secret: Uint8Array, network: unknown, profile: string,
  sessionId: string, providerKey: string | null): Envelope | null {
  try {
    const frame = unwrapGiftWrap(raw, secret, network, profile), envelope = frame.envelope;
    if (envelope.session_id !== sessionId || frame.sealAuthor !== envelope.sender_session_key ||
      (providerKey !== null && envelope.sender_session_key !== providerKey)) return null;
    if (envelope.message_type !== "handshake_accept" &&
      !schnorr.verify(hexToBytes(envelope.signature ?? ""), unsignedEnvelopeHash(envelope as unknown as Record<string, unknown>), hexToBytes(envelope.sender_session_key))) return null;
    return envelope;
  } catch { return null; }
}

export interface ReverseFundingMailboxReader {
  readonly clientKey: string;
  /** Original session only. No restored outbound sequence, send, handshake, payment, or ack API. */
  admit(raw: string): Envelope | null;
  dispose(): void;
}

/**
 * Offline receive-only restoration. Callers independently authenticate the
 * saved transcript first and validate binding signatures/actual funding bytes
 * afterward. Archive queries must have no two-day cutoff or outer-author pin.
 */
export function restoreReverseFundingReader(configuration: {
  readonly secret: Uint8Array; readonly clientKey: string; readonly sessionId: string;
  readonly providerSessionKey: string; readonly network: unknown; readonly contractHash: string;
}): ReverseFundingMailboxReader {
  let secret: Uint8Array | undefined;
  try {
    if (!(configuration.secret instanceof Uint8Array) || configuration.secret.length !== 32) throw new Error();
    secret = Uint8Array.from(configuration.secret);
    const clientKey = getPublicKey(secret), sessionId = configuration.sessionId, providerKey = configuration.providerSessionKey, contractHash = configuration.contractHash;
    if (clientKey !== configuration.clientKey || providerKey === clientKey ||
      ![clientKey, sessionId, providerKey, contractHash].every((value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value))) throw new Error();
    secp256k1.Point.fromBytes(hexToBytes(`02${providerKey}`)).assertValidity();
    const network: unknown = JSON.parse(canonicalize(configuration.network)!); if (!validateNetwork(network)) throw new Error();
    const key = secret, seen = new Set<string>(); let disposed = false;
    return Object.freeze({ clientKey, admit(raw: string): Envelope | null {
      if (disposed || seen.size >= 256) return null;
      const envelope = authenticateSessionEvent(raw, key, network, "ln-to-btc/v1", sessionId, providerKey);
      if (!envelope || envelope.message_type !== "funding_binding" || envelope.in_reply_to !== null ||
        envelope.contract_hash !== contractHash || seen.has(envelope.message_id)) return null;
      seen.add(envelope.message_id); return envelope;
    }, dispose(): void { disposed = true; key.fill(0); seen.clear(); } });
  } catch { secret?.fill(0); throw new SwapError("Original reverse funding mailbox could not be restored"); }
}

export class Session {
  readonly secret = schnorr.utils.randomSecretKey();
  readonly key = getPublicKey(this.secret);
  sessionId = bytesToHex(randomBytes(32)); // replaced by the epoch-bound ID in handshake()
  providerKey: string | null = null;
  /** RS-006 transport work declared at initiation, mined into every send. */
  workBits = 0;
  private sequence = 0;
  private readonly inbox: Envelope[] = [];
  private readonly bySequence = new Map<number, { id: string; digest: string }>();
  private readonly byId = new Map<string, string>();
  private readonly future = new Map<number, Envelope>();
  private providerNext = 0;
  private inboxBytes = 0;

  constructor(
    readonly relay: RelayLink,
    readonly network: unknown,
    readonly profile: string,
    readonly timeoutMs = 60_000,
    readonly clock: () => number = Date.now,
  ) {}

  envelope(
    messageType: string,
    payload: Record<string, unknown>,
    options: { inReplyTo?: string; contract?: string; signed?: boolean; requiredFeatures?: readonly string[] } = {},
  ): Envelope {
    const unsigned: Envelope = {
      protocol: "rillswap",
      wire_version: "1",
      profile_id: this.profile,
      network_identity: this.network,
      session_id: this.sessionId,
      message_id: bytesToHex(randomBytes(32)),
      sender_session_key: this.key,
      sequence: this.sequence,
      in_reply_to: options.inReplyTo ?? null,
      contract_hash: options.contract ?? null,
      message_type: messageType,
      payload,
      required_features: [...(options.requiredFeatures ?? [])],
      extensions: {},
      signature: null,
    };
    requireShape("validateEnvelope", JSON.parse(canonicalize(unsigned)!));
    this.sequence += 1;
    if (options.signed === false) return unsigned;
    const digest = unsignedEnvelopeHash(unsigned as unknown as Record<string, unknown>);
    return { ...unsigned, signature: bytesToHex(schnorr.sign(digest, this.secret, randomBytes(32))) };
  }

  async send(envelope: Envelope, recipient: string, beforePublish?: () => void, options: PublicationOptions = {}): Promise<void> {
    const event = await wrapWithTransportWork(new TextDecoder().decode(jcs(envelope)), this.secret, recipient, this.workBits);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      options.signal?.throwIfAborted();
      if (!this.relay.guardedPublication) beforePublish?.();
      if (await this.relay.publish(event, { ...options, ...(beforePublish ? { beforePublish } : {}) })) return;
    }
    throw new SwapError(`relay did not accept ${envelope.message_type}`, this.relay.failureReason);
  }

  async listen(): Promise<void> {
    const since = Math.floor(this.clock() / 1000) - NIP59_BACKDATE_SECONDS;
    await this.relay.subscribe({ kinds: [GIFT_WRAP_KIND], "#p": [this.key], since });
  }

  /** Admit one raw event as an authenticated envelope for this session, or null. */
  admit(raw: string): Envelope | null {
    const envelope = authenticateSessionEvent(raw, this.secret, this.network, this.profile, this.sessionId, this.providerKey);
    if (envelope === null) return null;
    const digest = bytesToHex(unsignedEnvelopeHash(envelope as unknown as Record<string, unknown>));
    const knownId = this.byId.get(envelope.message_id), knownSequence = this.bySequence.get(envelope.sequence);
    if ((knownId !== undefined && knownId !== digest) || (knownSequence !== undefined &&
      (knownSequence.id !== envelope.message_id || knownSequence.digest !== digest))) throw new SwapError("conflicting provider sequence or message ID");
    if (knownId !== undefined) return null;
    if (envelope.sequence < this.providerNext || envelope.sequence > this.providerNext + 16 || this.byId.size >= 4096)
      throw new SwapError("provider sequence outside the bounded live window");
    this.byId.set(envelope.message_id, digest);
    this.bySequence.set(envelope.sequence, { id: envelope.message_id, digest });
    if (envelope.sequence !== this.providerNext) { this.future.set(envelope.sequence, envelope); return null; }
    this.providerNext++;
    for (;;) {
      const ready = this.future.get(this.providerNext); if (!ready) break;
      this.future.delete(this.providerNext++); this.buffer(ready);
    }
    return envelope;
  }

  private buffer(envelope: Envelope): void {
    const size = jcs(envelope).length;
    if (this.inbox.length >= 64 || this.inboxBytes + size > 256 * 1024) throw new SwapError("provider live inbox exhausted");
    this.inbox.push(envelope); this.inbox.sort((a, b) => a.sequence - b.sequence); this.inboxBytes += size;
  }

  private take(index: number): Envelope {
    const envelope = this.inbox.splice(index, 1)[0]!; this.inboxBytes -= jcs(envelope).length; return envelope;
  }

  async receive(wanted: (envelope: Envelope) => boolean, timeoutMs = this.timeoutMs, signal?: AbortSignal): Promise<Envelope> {
    signal?.throwIfAborted();
    const deadline = this.clock() + timeoutMs;
    for (;;) {
      signal?.throwIfAborted();
      const index = this.inbox.findIndex(wanted);
      if (index >= 0) return this.take(index);
      const raw = await this.relay.next(deadline, signal);
      if (raw === null) throw new SwapError("timed out waiting for the provider");
      const admitted = this.admit(raw);
      if (admitted === null) continue;
      if (wanted(admitted)) return admitted;
      this.buffer(admitted);
    }
  }

  async replyTo(request: Envelope, expected: string, timeoutMs = this.timeoutMs, signal?: AbortSignal): Promise<Envelope> {
    const answer = await this.receive((item) => item.in_reply_to === request.message_id, timeoutMs, signal);
    if (answer.message_type === "error") {
      throw new SwapError(`provider refused ${request.message_type}: ${String(answer.payload.code)}`);
    }
    if (answer.message_type !== expected) throw new SwapError(`unexpected answer ${answer.message_type}`);
    return answer;
  }
}
