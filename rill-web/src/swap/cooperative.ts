/**
 * Browser cosigner for the cooperative MuSig2 key-path claim (port of
 * rill-cli live_swap._CooperativeClaimAttempt and rill-core
 * verify_cooperative_claim_proposal / finalize_cooperative_claim).
 *
 * The client cosigns only after it holds the verified payment preimage, so
 * a signature here can only let the provider take an output it is already
 * owed: BIP341 SIGHASH_DEFAULT commits the exact outpoint, amount, script and
 * output. The browser has no chain backend, so it cannot sample confirmations
 * or fee policy like the CLI; it trusts the provider for confirmation and
 * fee liveness only. Any failure after payment just abandons cooperation:
 * the provider claims with the preimage instead, and the swap is still paid.
 *
 * One attempt per live swap: the stage is consumed before any asynchronous
 * reservation work, the secret nonce lives only inside one WASM handle, and
 * nothing restores signing authority after a reload.
 */
import { schnorr } from "@noble/curves/secp256k1.js";
import { emitActivity } from "./activity";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";

import type { FundingBinding } from "./funding";
import { taggedHash } from "./hashes";
import type { Musig, MusigTranscript } from "./musig";
import { type Envelope, type Session, SwapError } from "./session";
import { reconstructTaprootContract } from "./taproot";
import { serializeTransaction } from "./transaction";
import { type BtcToLnTerms, type LnToBtcTerms, COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_FEATURE, requireShape } from "./wire";

export const COOPERATIVE_RESERVATION_EXTENSION = "rillswap/cooperative-claim-reservation";
const INPUT_SEQUENCE = 0xfffffffd;
const P2WPKH_DUST_SAT = 294n;
const P2TR_DUST_SAT = 330n;
/** The provider's readiness window is nonrenewing and at most 30 seconds. */
const MAX_READY_WINDOW_SECONDS = 30;
/** Relay latency allowed after a provider deadline before giving up. */
const REPLY_GRACE_MS = 5_000;
/** How long a paid client waits for the provider to ask for readiness. */
const READY_WAIT_MS = 60_000;

/** Browser-only capabilities: the WASM signer and the refusal journal. */
export interface Cosigner {
  loadMusig(): Promise<Musig>;
  /**
   * Hold an exclusive cross-tab lock, durably create-only journal `record`
   * under `key`, then run `body` while still holding the lock. Reject on any
   * failure (no locks, no storage, an existing record): that abandons
   * cooperation and nothing is signed. The journal only ever refuses.
   */
  reserve<T>(key: string, record: ReservationRecord, body: () => Promise<T>): Promise<T>;
}

export interface ReservationRecord {
  readonly contract_hash: string;
  readonly cooperation_id: string;
  readonly signature_hash: string;
  readonly created_at: number;
}

export interface ClaimPlan {
  readonly baseTransaction: Uint8Array;
  readonly signatureHash: Uint8Array;
  readonly feeSat: bigint;
  readonly outputValueSat: bigint;
}

export class CooperationRefused extends Error {
  constructor(reason: string) {
    super(`cooperative claim refused: ${reason}`);
    this.name = "CooperationRefused";
  }
}

function u32le(value: number): Uint8Array {
  return Uint8Array.of(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
}

function u64le(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  for (let index = 0; index < 8; index += 1) out[index] = Number((value >> BigInt(8 * index)) & 0xffn);
  return out;
}

const withLength = (bytes: Uint8Array): Uint8Array => {
  if (bytes.length >= 0xfd) throw new CooperationRefused("script too long");
  return concatBytes(Uint8Array.of(bytes.length), bytes);
};

function dustThreshold(script: Uint8Array): bigint {
  if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) return P2WPKH_DUST_SAT;
  if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) return P2TR_DUST_SAT;
  throw new CooperationRefused("unsupported destination script");
}

interface Authorization {
  readonly txid: string;
  readonly vout: number;
  readonly valueSat: bigint;
  readonly fundingScript: Uint8Array;
  readonly destination: Uint8Array;
  readonly feeCapSat: bigint;
  readonly minimumOutputSat: bigint;
}

// Historical reservations may reference any signed revision. These four fields
// are the complete funding input to transaction reconstruction, not a live binding policy.
type ClaimFundingInput = Pick<FundingBinding, "funding_txid" | "contract_vout" | "contract_value_sat" | "contract_script_pubkey">;

/** Bind signed terms to the funded output, like UnilateralAuthorization.from_terms(path="claim"). */
function claimAuthorization(terms: BtcToLnTerms | LnToBtcTerms, binding: ClaimFundingInput): Authorization {
  const contract = reconstructTaprootContract(terms);
  const valueSat = BigInt(binding.contract_value_sat);
  if (valueSat !== BigInt(terms.economics.contract_amount_sat)) {
    throw new CooperationRefused("funding value does not match the signed contract amount");
  }
  if (binding.contract_script_pubkey !== contract.script_pubkey) {
    throw new CooperationRefused("funding script does not match the Taproot contract");
  }
  const reverse = terms.profile_id === "ln-to-btc/v1";
  if (terms.claimant !== (reverse ? "client" : "provider")) throw new CooperationRefused("claimant role differs from the profile");
  const destination = hexToBytes(reverse ? terms.client_destination_script : terms.provider_destination_script);
  dustThreshold(destination);
  const maximum = BigInt(terms.max_claim_fee_sat);
  return {
    txid: binding.funding_txid,
    vout: binding.contract_vout,
    valueSat,
    fundingScript: hexToBytes(binding.contract_script_pubkey),
    destination,
    feeCapSat: reverse && BigInt(terms.economics.claim_fee_reserve_sat) < maximum ? BigInt(terms.economics.claim_fee_reserve_sat) : maximum,
    minimumOutputSat: reverse ? BigInt(terms.economics.nominal_payout_sat) : 0n,
  };
}

/** BIP341 SIGHASH_DEFAULT key-path digest: ext_flag 0, no annex, input 0. */
function keyPathSighash(auth: Authorization, outputValue: bigint): Uint8Array {
  const prevout = concatBytes(hexToBytes(auth.txid).reverse(), u32le(auth.vout));
  const message = concatBytes(
    Uint8Array.of(0x00), // hash_type SIGHASH_DEFAULT
    u32le(2), // version
    u32le(0), // locktime
    sha256(prevout),
    sha256(u64le(auth.valueSat)),
    sha256(withLength(auth.fundingScript)),
    sha256(u32le(INPUT_SEQUENCE)),
    sha256(concatBytes(u64le(outputValue), withLength(auth.destination))),
    Uint8Array.of(0x00), // spend_type
    u32le(0), // input index
  );
  return taggedHash("TapSighash", concatBytes(Uint8Array.of(0x00), message));
}

function claimTransaction(auth: Authorization, outputValue: bigint, witness: Uint8Array[]): Uint8Array {
  return serializeTransaction(
    {
      version: 2,
      inputs: [{ txid: auth.txid, vout: auth.vout, scriptSig: new Uint8Array(), sequence: INPUT_SEQUENCE, witness }],
      outputs: [{ value: outputValue, script: auth.destination }],
      locktime: 0,
    },
    witness.length > 0,
  );
}

function buildCooperativeClaim(auth: Authorization, feeSat: bigint): ClaimPlan {
  if (feeSat < 0n || feeSat > auth.feeCapSat) throw new CooperationRefused("fee exceeds the signed claim cap");
  const outputValueSat = auth.valueSat - feeSat;
  if (outputValueSat <= 0n || outputValueSat < dustThreshold(auth.destination)) {
    throw new CooperationRefused("claim output is dust");
  }
  if (outputValueSat < auth.minimumOutputSat) throw new CooperationRefused("claim output is below the signed payout");
  return {
    baseTransaction: claimTransaction(auth, outputValueSat, []),
    signatureHash: keyPathSighash(auth, outputValueSat),
    feeSat,
    outputValueSat,
  };
}

/** The authorized key-path claim paying `feeSat` (what a provider proposes). */
export function buildCooperativeClaimPlan(terms: BtcToLnTerms | LnToBtcTerms, binding: ClaimFundingInput, feeSat: bigint): ClaimPlan {
  return buildCooperativeClaim(claimAuthorization(terms, binding), feeSat);
}

/** Reconstruct the exact one-input key-path claim the provider proposed, or refuse. */
export function verifyCooperativeClaimProposal(raw: Uint8Array, terms: BtcToLnTerms | LnToBtcTerms, binding: ClaimFundingInput): ClaimPlan {
  const auth = claimAuthorization(terms, binding);
  // version(4) count(1) outpoint(36) scriptSig(1) sequence(4) count(1): the output
  // value is bytes 47..54; exact reconstruction below checks every other byte.
  if (raw.length < 60) throw new CooperationRefused("proposal is truncated");
  let outputValue = 0n;
  for (let index = 7; index >= 0; index -= 1) outputValue = (outputValue << 8n) | BigInt(raw[47 + index]!);
  const plan = buildCooperativeClaim(auth, auth.valueSat - outputValue);
  if (bytesToHex(raw) !== bytesToHex(plan.baseTransaction)) {
    throw new CooperationRefused("proposal differs from the authorized claim");
  }
  return plan;
}

/** Attach the aggregate signature and verify it against the contract output key. */
export function finalizeCooperativeClaim(
  plan: ClaimPlan,
  signature: Uint8Array,
  terms: BtcToLnTerms | LnToBtcTerms,
  binding: ClaimFundingInput,
): { raw: string; txid: string } {
  const auth = claimAuthorization(terms, binding);
  if (signature.length !== 64) throw new CooperationRefused("signature must be 64 bytes");
  if (!schnorr.verify(signature, plan.signatureHash, auth.fundingScript.slice(2))) {
    throw new CooperationRefused("aggregate signature is invalid");
  }
  const base = claimTransaction(auth, plan.outputValueSat, []);
  if (bytesToHex(base) !== bytesToHex(plan.baseTransaction)) throw new CooperationRefused("plan is inconsistent");
  const txid = bytesToHex(sha256(sha256(base)).reverse());
  return { raw: bytesToHex(claimTransaction(auth, plan.outputValueSat, [signature])), txid };
}

// Closed payload shapes (rill-core cooperative_messages.py).
const HEX32 = /^[0-9a-f]{64}$/;
const NONCE = /^[0-9a-f]{132}$/;
const UNSIGNED_TX = /^(?:[0-9a-f]{2}){60,1000}$/;
type Field = RegExp | "integer";

function closed<T>(payload: Record<string, unknown>, fields: Record<string, Field>): T {
  const keys = Object.keys(payload).sort();
  const expected = ["action", ...Object.keys(fields)].sort();
  if (keys.join() !== expected.join()) throw new CooperationRefused("payload shape");
  for (const [name, rule] of Object.entries(fields)) {
    const value = payload[name];
    const ok = rule === "integer" ? Number.isSafeInteger(value) : typeof value === "string" && rule.test(value);
    if (!ok) throw new CooperationRefused(`payload field ${name}`);
  }
  return payload as T;
}

interface ReadyRequest {
  readonly challenge: string;
  readonly payment_preimage: string;
  readonly deadline_at: number;
  readonly deadline_height: number;
}

interface Proposal extends Omit<ReadyRequest, "challenge"> {
  readonly cooperation_id: string;
  readonly unsigned_transaction: string;
  readonly public_nonce: string;
}

interface Completion {
  readonly cooperation_id: string;
  readonly partial_signature: string;
}

type ProviderAction =
  | { kind: "ready"; payload: ReadyRequest }
  | { kind: "propose"; payload: Proposal }
  | { kind: "complete"; payload: Completion };

/** Parse one authenticated provider action_request (check_cooperative_action_context). */
function providerAction(envelope: Envelope, contractHash: string): ProviderAction {
  const features = envelope.required_features;
  if (
    envelope.message_type !== "action_request" ||
    envelope.in_reply_to !== null ||
    envelope.contract_hash !== contractHash ||
    !features.includes(COOPERATIVE_CLAIM_FEATURE) ||
    features.some((item) => item !== COOPERATIVE_CLAIM_FEATURE && item !== EPOCH_SESSION_FEATURE)
  ) {
    throw new CooperationRefused("action is not bound to the signed feature and terms");
  }
  const payload = envelope.payload;
  switch (payload.action) {
    case "cooperative_claim_ready":
      return {
        kind: "ready",
        payload: closed<ReadyRequest>(payload, {
          challenge: HEX32,
          payment_preimage: HEX32,
          deadline_at: "integer",
          deadline_height: "integer",
        }),
      };
    case "cooperative_claim_propose":
      return {
        kind: "propose",
        payload: closed<Proposal>(payload, {
          cooperation_id: HEX32,
          unsigned_transaction: UNSIGNED_TX,
          payment_preimage: HEX32,
          public_nonce: NONCE,
          deadline_at: "integer",
          deadline_height: "integer",
        }),
      };
    case "cooperative_claim_complete":
      return {
        kind: "complete",
        payload: closed<Completion>(payload, { cooperation_id: HEX32, partial_signature: HEX32 }),
      };
    default:
      throw new CooperationRefused("unsupported action");
  }
}

export interface SettlementContext {
  readonly onActivity?: import("./activity").ActivityObserver;
  readonly session: Session;
  readonly providerKey: string;
  readonly terms: BtcToLnTerms;
  readonly contractHash: string;
  readonly binding: FundingBinding;
  readonly contractSecret: Uint8Array;
  /** The lowest height the client knows (the swap's starting tip). */
  readonly tipHeight: number;
  readonly settleMs: number;
  readonly cosigner: Cosigner;
  readonly report: (line: string) => void;
}

export interface SettlementOutcome {
  readonly preimage: string;
  readonly cooperation: "verified" | "abandoned";
  /** The fully signed key-path claim the provider will broadcast, when verified. */
  readonly claimTxid: string | null;
  /** The signed proposal reserved before the nonce, for the paid recovery file. */
  readonly reservation: {
    readonly proposal: Envelope;
    readonly signature_hash: string;
    /** Unix seconds when the reservation was journaled, before the nonce. */
    readonly recordedAt: number;
  } | null;
}

type Stage = "fresh" | "echoed" | "reserved" | "partial issued" | "abandoned";

/**
 * Wait for payment, then run at most one cooperative claim attempt. Throws
 * SwapError only while the payment is unresolved; once the preimage is
 * known every failure returns an abandoned (still paid) outcome.
 */
export async function settle(ctx: SettlementContext, refundHint: string): Promise<SettlementOutcome> {
  const { session, terms, contractHash } = ctx;
  const musigLoad: Promise<Musig | null> = ctx.cosigner.loadMusig().catch(() => null);
  let musig: Musig | null = null;
  let stage: Stage = "fresh";
  let preimage: string | null = null;
  let ready: ReadyRequest | null = null;
  let proposal: { envelope: Envelope; payload: Proposal; plan: ClaimPlan } | null = null;
  let transcript: { musig: MusigTranscript; clientNonce: Uint8Array; clientPartial: Uint8Array } | null = null;
  let reservation: SettlementOutcome["reservation"] = null;
  const settleDeadline = session.clock() + ctx.settleMs;
  let waitUntil = settleDeadline;
  const seconds = (): number => Math.floor(session.clock() / 1000);
  const paid = (cooperation: SettlementOutcome["cooperation"], claimTxid: string | null = null): SettlementOutcome => ({
    preimage: preimage!,
    cooperation,
    claimTxid,
    reservation,
  });
  const learn = (candidate: string): void => {
    if (bytesToHex(sha256(hexToBytes(candidate))) !== terms.invoice_binding.payment_hash) {
      throw new CooperationRefused("wrong preimage");
    }
    if (preimage !== null && preimage !== candidate) throw new CooperationRefused("conflicting preimage");
    const first = preimage === null;
    if (first) waitUntil = Math.min(settleDeadline, session.clock() + READY_WAIT_MS);
    preimage = candidate;
    if (first) emitActivity(ctx.onActivity, "payment.verified");
  };
  const answer = async (request: Envelope, payload: Record<string, unknown>): Promise<void> => {
    const reply = session.envelope("action_result", payload, {
      inReplyTo: request.message_id,
      contract: contractHash,
      requiredFeatures: [COOPERATIVE_CLAIM_FEATURE],
    });
    await session.send(reply, ctx.providerKey);
  };

  try {
    for (;;) {
      if (preimage !== null && stage === "abandoned") return paid("abandoned");
      let envelope: Envelope;
      try {
        envelope = await session.receive(
          (item) =>
            item.in_reply_to === null &&
            item.contract_hash === contractHash &&
            (item.message_type === "observation" || item.message_type === "action_request"),
          Math.max(0, waitUntil - session.clock()),
        );
      } catch {
        if (preimage !== null) return paid("abandoned");
        throw new SwapError(`provider did not pay in time; ${refundHint}`);
      }
      if (envelope.message_type === "observation") {
        let seen: { kind: string; payment_preimage?: string };
        try {
          seen = requireShape("validateObservation", envelope.payload);
        } catch {
          continue;
        }
        if (seen.kind === "payment_failed") {
          if (preimage !== null) return paid("abandoned"); // the preimage already proves payment
          throw new SwapError(`provider reports the payment failed; ${refundHint}`);
        }
        if (seen.kind === "payment_settled") {
          try {
            learn(seen.payment_preimage!);
          } catch {
            if (preimage !== null) {
              stage = "abandoned";
              continue;
            }
            throw new SwapError(`provider sent a wrong preimage; ${refundHint}`);
          }
          ctx.report("the provider paid the invoice");
        }
        continue;
      }
      try {
        const action = providerAction(envelope, contractHash);
        if (action.kind === "ready") {
          if (stage !== "fresh") throw new CooperationRefused("readiness already consumed");
          stage = "abandoned"; // consumed; restored only by a successful echo
          const now = seconds();
          const request = action.payload;
          const cutoff = terms.refund_lock_height - terms.timing_policy.claim_confirmation_blocks;
          if (
            !(now < request.deadline_at && request.deadline_at <= now + MAX_READY_WINDOW_SECONDS) ||
            !(ctx.tipHeight < request.deadline_height && request.deadline_height <= cutoff)
          ) {
            throw new CooperationRefused("readiness deadline");
          }
          learn(request.payment_preimage);
          await answer(envelope, { action: "cooperative_claim_ready", challenge: request.challenge, status: "ready" });
          ready = request;
          stage = "echoed";
          waitUntil = request.deadline_at * 1000 + REPLY_GRACE_MS;
        } else if (action.kind === "propose") {
          if (stage !== "echoed" || ready === null) throw new CooperationRefused("proposal unavailable");
          stage = "reserved"; // consumed before validation, reservation, or nonce effects
          const request = action.payload;
          if (
            request.payment_preimage !== preimage ||
            request.deadline_at !== ready.deadline_at ||
            request.deadline_height !== ready.deadline_height ||
            seconds() >= request.deadline_at
          ) {
            throw new CooperationRefused("proposal context");
          }
          const plan = verifyCooperativeClaimProposal(hexToBytes(request.unsigned_transaction), terms, ctx.binding);
          musig = await musigLoad;
          if (musig === null) throw new CooperationRefused("MuSig2 signer unavailable");
          const signer = musig;
          const providerNonce = hexToBytes(request.public_nonce);
          if (!signer.validateNonce(providerNonce)) throw new CooperationRefused("provider nonce");
          const contract = reconstructTaprootContract(terms);
          const musigTranscript: MusigTranscript = {
            clientKey: hexToBytes(terms.client_contract_compressed_key),
            providerKey: hexToBytes(terms.provider_contract_compressed_key),
            tapTweak: hexToBytes(contract.tap_tweak),
            message: plan.signatureHash,
          };
          const record: ReservationRecord = {
            contract_hash: contractHash,
            cooperation_id: request.cooperation_id,
            signature_hash: bytesToHex(plan.signatureHash),
            created_at: seconds(),
          };
          await ctx.cosigner.reserve(contractHash, record, async () => {
            reservation = { proposal: envelope, signature_hash: record.signature_hash, recordedAt: record.created_at };
            if (seconds() >= request.deadline_at) throw new CooperationRefused("proposal deadline");
            const attempt = signer.begin(musigTranscript, ctx.contractSecret, hexToBytes(request.cooperation_id));
            let clientPartial: Uint8Array;
            try {
              clientPartial = attempt.signOnce(providerNonce);
            } finally {
              attempt.destroy();
            }
            if (!signer.verifyPartial(musigTranscript, attempt.publicNonce, providerNonce, "client", clientPartial)) {
              throw new CooperationRefused("own partial signature does not verify");
            }
            transcript = { musig: musigTranscript, clientNonce: attempt.publicNonce, clientPartial };
            proposal = { envelope, payload: request, plan };
            stage = "partial issued";
            await answer(envelope, {
              action: "cooperative_claim_propose",
              cooperation_id: request.cooperation_id,
              status: "signed",
              public_nonce: bytesToHex(attempt.publicNonce),
              partial_signature: bytesToHex(clientPartial),
            });
          });
          ctx.report("cooperative claim partially signed; waiting for the provider");
          emitActivity(ctx.onActivity, "cooperation.signing");
        } else {
          const current = proposal as { envelope: Envelope; payload: Proposal; plan: ClaimPlan } | null;
          const signed = transcript as { musig: MusigTranscript; clientNonce: Uint8Array; clientPartial: Uint8Array } | null;
          if ((stage as Stage) !== "partial issued" || current === null || signed === null || musig === null) {
            throw new CooperationRefused("completion unavailable");
          }
          stage = "abandoned"; // one completion only
          if (action.payload.cooperation_id !== current.payload.cooperation_id) {
            throw new CooperationRefused("completion refers to another attempt");
          }
          const providerNonce = hexToBytes(current.payload.public_nonce);
          const providerPartial = hexToBytes(action.payload.partial_signature);
          if (!musig.verifyPartial(signed.musig, signed.clientNonce, providerNonce, "provider", providerPartial)) {
            throw new CooperationRefused("provider partial signature does not verify");
          }
          const signature = musig.aggregate(
            signed.musig,
            signed.clientNonce,
            providerNonce,
            signed.clientPartial,
            providerPartial,
          );
          const claim = finalizeCooperativeClaim(current.plan, signature, terms, ctx.binding);
          await answer(envelope, {
            action: "cooperative_claim_complete",
            cooperation_id: action.payload.cooperation_id,
            status: "verified",
          });
          return paid("verified", claim.txid);
        }
      } catch (error) {
        // No failure reopens signing; a known preimage still means paid.
        if (error instanceof SwapError && preimage === null) throw error;
        stage = "abandoned";
      }
    }
  } finally {
    (musig ?? (await musigLoad))?.destroy();
  }
}
