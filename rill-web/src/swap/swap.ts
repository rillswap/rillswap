/**
 * One browser BTC to LN swap (port of rill-cli live_swap.run_swap).
 *
 * Order: decode the invoice, discover the provider, handshake, request firm
 * terms within the user's limits, check and sign them, hand the user the
 * terms recovery file, accept, authorize the user's finalized funding PSBT,
 * hand the user the funded recovery file, bind, let the user broadcast, and
 * wait for the preimage. No key or record leaves memory except through the
 * user's own downloads; refunds use `rill recover watch-refund --chain-only`.
 */
import { schnorr } from "@noble/curves/secp256k1.js";
import { activityFacts, emitActivity } from "./activity";
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";

import { invoiceBinding } from "./bolt11";
import { networkFeeRequest, checkFeeBreakdown, type FeeBreakdown } from "./feePolicy";
import { COOPERATIVE_RESERVATION_EXTENSION, type Cosigner, settle } from "./cooperative";
import { type AnnouncementSource, discoverProvider } from "./discovery";
import { type AuthorizedFunding, authorizeFunding, authorizeFundingPsbt, type FundingBinding, fundingBinding } from "./funding";
import type { FinalizedFunding } from "./transaction";
import { clientAcceptanceHash, fundingBindingHash } from "./hashes";
import { encryptRecovery, type RecoveryParts } from "./recovery";
import { handshake, newKeyPair } from "./handshake";
import { type RelayLink, Session, SwapError } from "./session";
import { verifyNostrProviderAnnouncement } from "../nostrProviderAnnouncement";
import { reconstructTaprootContract } from "./taproot";
import {
  type BtcToLnTerms,
  checkTermsOffer,
  type FirmQuoteRequest,
  requireAnnouncedDepth,
  requireShape,
  type TermsOffer,
} from "./wire";

export const PROFILE = "btc-to-ln/v1";
// The same selection rill-cli requests; the suite name is a label for NIP-59 delivery.
/** Seconds an invoice must stay valid at quote time (the provider needs time to pay). */
const MIN_INVOICE_REMAINING_SECONDS = 600;
/**
 * Extra wait for the provider's payment per deposit block it still needs (five mainnet
 * intervals). It pays only at the signed funding depth, and a confirmed deposit is bound
 * after its first block: a fixed ten minutes gave up, and lost cooperation, whenever the
 * next block took longer, about a third of mainnet swaps.
 */
export const PENDING_BLOCK_WAIT_MS = 3_000_000;

export interface UserLimits {
  readonly maxSuccessFeeSat: bigint;
  readonly maxFundingFeeSat: bigint;
  readonly maxClaimFeeSat: bigint;
  readonly maxRefundFeeSat: bigint;
  readonly maxRefundDelayBlocks: number;
}

export interface SwapRequest {
  readonly identity: string;
  readonly network: { readonly name: string } & Record<string, unknown>;
  readonly invoice: string;
  readonly refundScript: string;
  readonly tipHeight: number;
  readonly ageRecipient: string;
  /** Public wallet derivation hints only, never signing authority. */
  readonly refundAllocation?: import("../browserRecoveryWallet").RefundAllocation;
  readonly limits: UserLimits;
  /** A merchant checkout can expire earlier than the invoice. */
  readonly checkoutExpiresAt?: number;
  /** Fresh independent trusted-chain rate, required for dynamic-priced offers. */
  readonly networkFeeRateSatKvb?: number;
}

export interface FundingRequest {
  readonly contractScript: string;
  readonly amountSat: bigint;
  readonly maxFundingFeeSat: bigint;
  readonly refundLockHeight: number;
  readonly successFeeSat: bigint;
  readonly termsExpiry?: number;
  /** Signed depth the provider pays at; 0 lets a lone unconfirmed deposit fund the swap. Absent: wait for confirmation. */
  readonly fundingConfirmations?: number;
}

/** Every step that needs the user; each promise resolves once the user acted. */
export interface SwapHooks {
  readonly onActivity?: import("./activity").ActivityObserver;
  report(line: string): void;
  /** Offer the age file for download; resolve after the user saved it. */
  saveRecovery(file: Uint8Array, stage: "terms" | "funded"): Promise<void>;
  /**
   * Show the contract output; resolve with the user's funding: a finalized PSBT
   * from the wallet, or a deposit the page found (already broadcast; confirmed unless the terms pay at 0).
   */
  fundingSource(request: FundingRequest): Promise<FundingSource>;
  /** PSBT funding only: show the signed transaction; resolve once the user broadcast it. */
  broadcast(rawTransaction: string, txid: string): Promise<void>;
  /** Persist public references before releasing a signed transaction to the provider. */
  beforeFundingCommit?(txid: string, termsExpiry: number): Promise<void>;
  /** The MuSig2 signer and cross-tab reservation journal for the key-path claim. */
  readonly cosigner: Cosigner;
}

export type FundingSource = { readonly psbt: string } | { readonly deposit: FinalizedFunding };

export interface SwapOutcome {
  readonly sessionId: string;
  readonly contractHash: string;
  readonly fundingTxid: string;
  readonly preimage: string;
  readonly refundLockHeight: number;
  /** "verified": the provider holds a private key-path claim; "abandoned": it claims with the preimage. */
  readonly cooperation: "verified" | "abandoned";
  readonly claimTxid: string | null;
  /** Optional paid recovery file (age-encrypted): preimage and any cooperative reservation. */
  readonly paidRecovery: Uint8Array;
}

export interface SwapTimeouts {
  readonly replyMs: number;
  readonly settleMs: number;
}




const sign = (digest: Uint8Array, secret: Uint8Array): string => bytesToHex(schnorr.sign(digest, secret, randomBytes(32)));

function checkRequest(request: SwapRequest, now: number): ReturnType<typeof invoiceBinding> {
  if (!Number.isSafeInteger(request.tipHeight) || request.tipHeight <= 0) throw new SwapError("tip height invalid");
  if (!Number.isSafeInteger(request.limits.maxRefundDelayBlocks) || request.limits.maxRefundDelayBlocks <= 0) {
    throw new SwapError("maximum refund delay invalid");
  }
  const binding = invoiceBinding(request.invoice, request.network.name);
  if (binding.expires_at < now + MIN_INVOICE_REMAINING_SECONDS) {
    throw new SwapError("invoice expires too soon; ask the recipient for a fresh one");
  }
  return binding;
}

export interface PreparedQuote {
  readonly providerIdentity: string;
  readonly providerSlot: string;
  readonly contractHash: string;
  readonly contractAmountSat: bigint;
  readonly successFeeSat: bigint;
  readonly refundLockHeight: number;
  readonly expiresAt: number;
  /** Signed blocks the provider waits on the funding before paying (0: from the mempool). */
  readonly fundingConfirmations: number;
  readonly feeBreakdown?: FeeBreakdown;
}

/** Holds one exact authenticated offer. Preparation does not accept or fund it. */
export interface PreparedSwap {
  readonly quote: PreparedQuote;
  execute(hooks: SwapHooks): Promise<SwapOutcome>;
  /** Discards an unused offer; never interrupts execution or rolls back funding. */
  dispose(): void;
}

interface PreparationOptions {
  readonly timeouts?: SwapTimeouts;
  readonly clock?: () => number;
  /** Reverified here, preserving the exact directory-selected slot/revision. */
  readonly announcement?: string;
}

export async function prepareSwap(
  relay: RelayLink & AnnouncementSource,
  request: SwapRequest,
  report: SwapHooks["report"],
  options: PreparationOptions = {},
): Promise<PreparedSwap> {
  request = { ...request, network: structuredClone(request.network), limits: { ...request.limits },
    ...(request.refundAllocation === undefined ? {} : { refundAllocation: structuredClone(request.refundAllocation) }) };
  if (request.refundAllocation && (request.refundAllocation.script !== request.refundScript ||
      request.refundAllocation.network !== request.network.name)) throw new SwapError("refund wallet metadata does not match destination");
  const timeouts = { ...(options.timeouts ?? { replyMs: 60_000, settleMs: 600_000 }) };
  const clock = options.clock ?? Date.now;
  const seconds = (): number => Math.floor(clock() / 1000);
  const invoice = checkRequest(request, seconds());
  const checkoutExpiry = request.checkoutExpiresAt ?? invoice.expires_at;
  if (!Number.isSafeInteger(checkoutExpiry) || checkoutExpiry <= seconds()) throw new SwapError("checkout expiry invalid");
  const { identity, network } = request;
  const provider = options.announcement === undefined
    ? await discoverProvider(relay, identity, network, PROFILE)
    : verifyNostrProviderAnnouncement(options.announcement, identity, network, PROFILE);
  report(`provider found (revision ${provider.revision})`);
  const session = new Session(relay, network, PROFILE, timeouts.replyMs, clock);
  let contractSecret: Uint8Array | null = null;
  try {
    const { init, accept, acceptSignature, transcript } = await handshake(session, provider, identity);
    const providerKey = session.providerKey!;
    report(`session ${session.sessionId.slice(0, 16)} confirmed`);

    const contract = newKeyPair();
    contractSecret = contract.secret;
    const recoveryKey = newKeyPair(); // authorization key; its secret is never needed
    recoveryKey.secret.fill(0);
    const limits = request.limits;
    const quote: FirmQuoteRequest = {
      kind: "btc-to-ln",
      mode: "firm",
      lightning_principal_sat: (BigInt(invoice.amount_msat) / 1000n).toString(),
      invoice: request.invoice,
      client_contract_compressed_key: contract.compressed,
      recovery_authorization_xonly_key: recoveryKey.xonly,
      client_destination_script: request.refundScript,
      limits: {
        max_success_fee_sat: limits.maxSuccessFeeSat.toString(),
        max_funding_fee_sat: limits.maxFundingFeeSat.toString(),
        max_claim_fee_sat: limits.maxClaimFeeSat.toString(),
        max_refund_fee_sat: limits.maxRefundFeeSat.toString(),
        max_refund_lock_height: request.tipHeight + limits.maxRefundDelayBlocks,
      },
      extensions: networkFeeRequest(provider, request.networkFeeRateSatKvb),
    };
    requireShape("validateFirmQuoteRequest", quote);
    const quoteEnvelope = session.envelope("quote_request", quote as unknown as Record<string, unknown>);
    await session.send(quoteEnvelope, providerKey);
    const answer = await session.replyTo(quoteEnvelope, "terms_offer");
    const terms: BtcToLnTerms = checkTermsOffer(answer.payload, {
      request: quote,
      invoiceBinding: invoice,
      transcript,
      envelopeContractHash: answer.contract_hash,
      identity,
      network,
      now: seconds(),
    });
    if (terms.refund_lock_height <= request.tipHeight) throw new SwapError("offered refund height is already reached");
    requireAnnouncedDepth(terms.funding_confirmations, provider.fundingConfirmations);
    const offer = answer.payload as unknown as TermsOffer;
    const contractHash = offer.terms.contract_hash;
    const economics = terms.economics;
    const feeBreakdown = provider.feePolicy ? checkFeeBreakdown(terms) : undefined;
    report(`terms: fund ${economics.contract_amount_sat} sat, refund after block ${terms.refund_lock_height}`);

    let state: "ready" | "executing" | "disposed" | "done" = "ready";
    const release = (): void => { session.secret.fill(0); contract.secret.fill(0); };
    return Object.freeze({
      quote: Object.freeze({
        ...(feeBreakdown ? { feeBreakdown } : {}),
        providerIdentity: identity,
        providerSlot: provider.slot,
        contractHash,
        contractAmountSat: BigInt(economics.contract_amount_sat),
        successFeeSat: BigInt(economics.success_fee_sat),
        refundLockHeight: terms.refund_lock_height,
        expiresAt: Math.min(terms.terms_expiry, invoice.expires_at, checkoutExpiry),
        fundingConfirmations: terms.funding_confirmations,
      }),
      dispose: () => {
        if (state === "ready") { state = "disposed"; release(); }
      },
      execute: async (hooks: SwapHooks): Promise<SwapOutcome> => {
        if (state !== "ready") throw new SwapError("quote is already used or discarded; request a fresh quote");
        state = "executing";
        try {
          assertFundingWindow(terms.terms_expiry, invoice.expires_at, seconds(), checkoutExpiry);
          const acceptance = {
            contract_hash: contractHash,
            handshake_hash: transcript,
            session_id: session.sessionId,
            client_session_xonly_key: session.key,
            provider_session_xonly_key: providerKey,
          };
          const acceptanceSignature = sign(clientAcceptanceHash(acceptance), session.secret);
          const createdAt = seconds();
          const record: RecoveryParts = {
            network, profile: PROFILE, init, accept, acceptSignature, offer, acceptanceSignature,
            clientSessionKey: session.key, contractSecret: contract.secret,
            birthday: request.tipHeight, createdAt, updatedAt: createdAt, funding: [], preimage: null,
            extensions: request.refundAllocation ? { "rillswap/browser-refund-wallet": request.refundAllocation } : {},
          };
          await hooks.saveRecovery(await encryptRecovery(record, request.ageRecipient), "terms");
          emitActivity(hooks.onActivity, "terms.verified", { ...activityFacts(terms, request.invoice), session_id: session.sessionId, refund_height: terms.refund_lock_height,
            ...(feeBreakdown ? { service_fee_sat: feeBreakdown.service_fee_sat, network_fee_sat: feeBreakdown.network_fee_sat, fee_rate_sat_kvb: feeBreakdown.feerate_sat_kvb } : {}) });
          emitActivity(hooks.onActivity, "recovery.saved", { stage: "terms" });
          hooks.report("recovery file saved (terms, no funding yet)");
          assertFundingWindow(terms.terms_expiry, invoice.expires_at, seconds(), checkoutExpiry);
          const accepted = session.envelope(
            "terms_accept",
            { acceptance, client_acceptance_signature: acceptanceSignature },
            { inReplyTo: answer.message_id, contract: contractHash },
          );
          await session.send(accepted, providerKey,
            () => assertFundingWindow(terms.terms_expiry, invoice.expires_at, seconds(), checkoutExpiry));
          await session.replyTo(accepted, "ack");

          // RS-003: terms_expiry gates acceptance only. Funding is bounded by the payment the
          // provider still has to make (invoice and checkout expiry); a deposit needs a confirmation.
          const paymentWindow = (): void => assertFundingWindow(invoice.expires_at, invoice.expires_at, seconds(), checkoutExpiry);
          const { funding, broadcastByUser } = await authorizeUserFunding(terms, hooks);
          paymentWindow();
          const binding = fundingBinding(contractHash, funding, bytesToHex(randomBytes(32)), seconds());
          const bindingSignature = sign(fundingBindingHash(binding), session.secret);
          const funded = { ...record, updatedAt: seconds(), funding: [{ binding, signature: bindingSignature }] };
          await hooks.saveRecovery(await encryptRecovery(funded, request.ageRecipient), "funded");
          emitActivity(hooks.onActivity, "recovery.saved", { stage: "funded", txid: funding.txid });
          hooks.report(`funded recovery file saved (funding ${funding.txid}, attempt ${binding.funding_attempt_id} revision 0)`);
          const bound = session.envelope(
            "funding_binding",
            { binding, funding_binding_signature: bindingSignature, funding_transaction: funding.raw },
            { contract: contractHash },
          );
          // Sharing a signed transaction can commit funds before a broadcast acknowledgment.
          await hooks.beforeFundingCommit?.(funding.txid, terms.terms_expiry);
          paymentWindow();
          await session.send(bound, providerKey, paymentWindow);
          await session.replyTo(bound, "ack");
          paymentWindow();
          const depth = terms.funding_confirmations;
          const when = depth === 0 ? "as soon as it sees the transaction" : `at ${depth} confirmation${depth === 1 ? "" : "s"}`;
          if (broadcastByUser) {
            await hooks.broadcast(funding.raw, funding.txid);
            hooks.report(`funding ${funding.txid} broadcast; waiting for the provider to pay (${when})`);
          } else {
            hooks.report(`the provider acknowledged your deposit ${funding.txid}; waiting for it to pay (${when})`);
          }
          const pendingBlocks = Math.max(0, depth - (broadcastByUser ? 0 : 1));
          emitActivity(hooks.onActivity, "funding.acknowledged", { txid: funding.txid, required_confirmations: depth });
          const hint =
            `funds are committed; after block ${terms.refund_lock_height} open Recover a swap with the funded ` +
            `recovery file (funding attempt ${binding.funding_attempt_id}) to check funding and prepare your refund`;
          const settled = await settle(
            { session, providerKey, terms, contractHash, binding, contractSecret: contract.secret,
              tipHeight: request.tipHeight, settleMs: timeouts.settleMs + pendingBlocks * PENDING_BLOCK_WAIT_MS,
              cosigner: hooks.cosigner, report: hooks.report, ...(hooks.onActivity ? { onActivity: hooks.onActivity } : {}) },
            hint,
          );
          hooks.report(settled.cooperation === "verified"
            ? `cooperative key-path claim ${settled.claimTxid} verified; the provider claims privately`
            : "cooperation skipped; the provider claims with the preimage");
          emitActivity(hooks.onActivity, settled.cooperation === "verified" ? "cooperation.verified" : "cooperation.fallback");
          const reserved = settled.reservation;
          const paid: RecoveryParts = {
            ...funded,
            // A reservation is dated when journaled, before its proposal deadline.
            updatedAt: Math.max(funded.updatedAt, reserved?.recordedAt ?? seconds()),
            preimage: settled.preimage,
            extensions: { ...funded.extensions, ...(reserved === null ? {} : {
              [COOPERATIVE_RESERVATION_EXTENSION]: {
                version: 1, proposal: reserved.proposal, signature_hash: reserved.signature_hash,
              },
            }) },
          };
          return {
            sessionId: session.sessionId, contractHash, fundingTxid: funding.txid,
            preimage: settled.preimage, refundLockHeight: terms.refund_lock_height,
            cooperation: settled.cooperation, claimTxid: settled.claimTxid,
            paidRecovery: await encryptRecovery(paid, request.ageRecipient),
          };
        } finally {
          state = "done";
          release();
        }
      },
    });
  } catch (error) {
    session.secret.fill(0);
    contractSecret?.fill(0);
    throw error;
  }
}

/** Compatibility entrypoint: prepares and immediately executes one pinned-provider swap. */
export async function runSwap(
  relay: RelayLink & AnnouncementSource,
  request: SwapRequest,
  hooks: SwapHooks,
  timeouts: SwapTimeouts = { replyMs: 60_000, settleMs: 600_000 },
  clock: () => number = Date.now,
): Promise<SwapOutcome> {
  const prepared = await prepareSwap(relay, request, hooks.report, { timeouts, clock });
  return prepared.execute(hooks);
}

const MAX_FUNDING_ATTEMPTS = 5;

/** Never fund expired terms after a wallet, recovery or provider prompt. */
export function assertFundingWindow(termsExpiry: number, invoiceExpiry: number, now: number, checkoutExpiry = invoiceExpiry): void {
  if (![termsExpiry, invoiceExpiry, checkoutExpiry, now].every(Number.isSafeInteger) || now >= termsExpiry || now >= invoiceExpiry || now >= checkoutExpiry) {
    throw new SwapError("funding deadline exceeded; retain recovery and monitor any transaction already shared with the provider");
  }
}

/** Ask for the user's funding until one passes authorization. A PSBT still needs the user's broadcast. */
async function authorizeUserFunding(terms: BtcToLnTerms, hooks: SwapHooks): Promise<{ funding: AuthorizedFunding; broadcastByUser: boolean }> {
  const request: FundingRequest = {
    contractScript: reconstructTaprootContract(terms).script_pubkey,
    amountSat: BigInt(terms.economics.contract_amount_sat),
    maxFundingFeeSat: BigInt(terms.max_funding_fee_sat),
    refundLockHeight: terms.refund_lock_height,
    successFeeSat: BigInt(terms.economics.success_fee_sat),
    termsExpiry: terms.terms_expiry,
    fundingConfirmations: terms.funding_confirmations,
  };
  for (let attempt = 1; ; attempt += 1) {
    const source = await hooks.fundingSource(request);
    try {
      return "psbt" in source
        ? { funding: authorizeFundingPsbt(source.psbt, terms), broadcastByUser: true }
        : { funding: authorizeFunding(source.deposit, terms), broadcastByUser: false };
    } catch (error) {
      if ("deposit" in source) {
        // The deposit is already on chain: a retry cannot change it, and it was not bound to the swap.
        throw new SwapError(`your deposit ${source.deposit.transaction.txid} cannot fund this swap (${(error as Error).message}). ` +
          `It was not bound to the swap and is refundable after block ${terms.refund_lock_height}; keep the terms recovery file and this transaction id. ` +
          "This page cannot prepare that refund yet.");
      }
      if (attempt >= MAX_FUNDING_ATTEMPTS) throw new SwapError("no acceptable funding transaction; nothing was funded");
      hooks.report(`${(error as Error).message}; nothing was sent, try again`);
    }
  }
}
