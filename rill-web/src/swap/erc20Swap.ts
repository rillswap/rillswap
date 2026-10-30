/**
 * RS-010 ERC20 to Lightning in the browser: the user locks tokens in the
 * Boltz ERC20Swap v6 HTLC through an injected wallet, the provider pays the
 * invoice and claims with the preimage. The wallet owns the refund key, so a
 * recovery record only needs the signed terms and the lock transaction.
 */
import { schnorr } from "@noble/curves/secp256k1.js";
import { activityFacts, emitActivity } from "./activity";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import canonicalize from "canonicalize";

import { type InvoiceBinding, invoiceBinding } from "./bolt11";
import { type AnnouncementSource, discoverProvider } from "./discovery";
import { awaitReceipt, checkEvmAddress, type EvmRpc, type HtlcLock } from "./evmHtlc";
import { stagingAddress } from "./gasSponsor";
import { clientAcceptanceHash } from "./hashes";
import { handshake, newKeyPair } from "./handshake";
import { type RelayLink, Session, SwapError } from "./session";
import { checkSignedOfferBinding, type HandshakeAccept, type HandshakeInit, ProtocolError, requireAnnouncedDepth, requireShape, same, sats } from "./wire";
import { encryptCanonicalRecoveryForRecipient } from "../recoveryAgeContainer";
import type { EvmAssetIdentity } from "../manualProviderAdvertisement";
import { verifyNostrProviderAnnouncement } from "../nostrProviderAnnouncement";

export const ERC20_TO_LN = "erc20-to-ln/v1";
const MIN_INVOICE_REMAINING_SECONDS = 600;
const SATS_PER_BTC = 100_000_000n;
const encoder = new TextEncoder();

export interface Erc20Limits {
  readonly maxSuccessFeeTokenBase: bigint;
  /** The lock must be refundable within this many blocks of the EVM tip at quote time. */
  readonly maxTimelockDelayBlocks: number;
}

export interface Erc20SwapRequest {
  readonly identity: string;
  readonly network: { readonly name: string } & Record<string, unknown>;
  readonly invoice: string;
  readonly asset: EvmAssetIdentity;
  readonly clientEvmAddress: string;
  readonly evmTip: number;
  readonly ageRecipient: string;
  readonly limits: Erc20Limits;
}

export interface Erc20FirmQuoteRequest {
  readonly kind: "erc20-to-ln";
  readonly mode: "firm";
  readonly lightning_principal_sat: string;
  readonly invoice: string;
  readonly evm_asset: { readonly chain_id: number; readonly token_contract: string };
  readonly client_evm_address: string;
  readonly recovery_authorization_xonly_key: string;
  readonly limits: { readonly max_success_fee_token_base: string; readonly max_htlc_timelock_block: number };
  readonly extensions: Record<string, unknown>;
}

export interface Erc20ToLnTerms {
  readonly protocol: "rillswap";
  readonly contract_version: "1";
  readonly profile_id: "erc20-to-ln/v1";
  readonly network_identity: unknown;
  readonly evm_asset: EvmAssetIdentity;
  readonly provider_identity_key: string;
  readonly client_evm_address: string;
  readonly provider_evm_address: string;
  readonly claimant: "provider";
  readonly refund_party: "client";
  readonly invoice_binding: InvoiceBinding;
  readonly economics: {
    readonly kind: "erc20-to-ln";
    readonly lightning_principal_sat: string;
    readonly rate_token_base_per_btc: string;
    readonly success_fee_token_base: string;
    readonly lock_amount_token_base: string;
  };
  readonly htlc_timelock_block: number;
  readonly evm_reference_block: number;
  readonly btc_reference_height: number;
  readonly funding_confirmations: number;
  readonly settlement_confirmations: number;
  readonly recovery_authorization_xonly_key: string;
  readonly terms_expiry: number;
  readonly timing_policy: { readonly kind: "erc20-to-ln"; readonly max_outgoing_htlc_expiry_height: number; readonly learn_and_claim_seconds: number };
  readonly required_features: readonly string[];
  readonly extensions: Record<string, unknown>;
}

export interface Erc20TermsOffer {
  readonly terms: { readonly contract_hash: string; readonly contract_terms: Erc20ToLnTerms; readonly handshake_hash: string };
  readonly provider_terms_signature: string;
}

export interface LnToErc20Terms extends Omit<Erc20ToLnTerms, "profile_id" | "claimant" | "refund_party" | "economics" | "timing_policy"> {
  readonly profile_id: "ln-to-erc20/v1";
  readonly claimant: "client";
  readonly refund_party: "provider";
  readonly economics: {
    readonly kind: "ln-to-erc20";
    readonly payout_token_base: string;
    readonly rate_token_base_per_btc: string;
    readonly payout_sat_equivalent: string;
    readonly success_fee_sat: string;
    readonly hold_invoice_sat: string;
  };
  readonly timing_policy: { readonly kind: "ln-to-erc20"; readonly min_incoming_htlc_expiry_height: number; readonly refund_and_ln_resolution_seconds: number };
}

export interface LnToErc20TermsOffer {
  readonly terms: { readonly contract_hash: string; readonly contract_terms: LnToErc20Terms; readonly handshake_hash: string };
  readonly provider_terms_signature: string;
  readonly hold_invoice: string;
}

export type EvmTerms = Erc20ToLnTerms | LnToErc20Terms;

export interface Erc20OfferContext {
  readonly request: Erc20FirmQuoteRequest;
  readonly invoiceBinding: InvoiceBinding;
  readonly asset: EvmAssetIdentity;
  readonly transcript: string;
  readonly envelopeContractHash: string | null;
  readonly identity: string;
  readonly network: unknown;
  readonly now: number;
}

/** RS-010 forward lock: ceil(L * rate / 1e8) + S_token. */
export function lockAmountTokenBase(principalSat: bigint, rateTokenBasePerBtc: bigint, successFeeTokenBase: bigint): bigint {
  return (principalSat * rateTokenBasePerBtc + SATS_PER_BTC - 1n) / SATS_PER_BTC + successFeeTokenBase;
}

const tokenUnits = (value: string, what: string): bigint => {
  if (!/^(0|[1-9][0-9]{0,38})$/.test(value)) throw new ProtocolError(`${what} is not a decimal token amount`);
  return BigInt(value);
};

/** A canonical signed token fee (never `-0`); negative when the provider pays a rebate. */
const signedTokenUnits = (value: string, what: string): bigint => {
  if (!/^(0|-?[1-9][0-9]{0,38})$/.test(value)) throw new ProtocolError(`${what} is not a signed decimal token amount`);
  return BigInt(value);
};

/** The exact HTLC lock the signed terms describe. */
export function lockOf(terms: EvmTerms): HtlcLock {
  const forward = terms.profile_id === ERC20_TO_LN;
  return Object.freeze({
    preimageHash: terms.invoice_binding.payment_hash,
    amount: BigInt(terms.economics.kind === "erc20-to-ln" ? terms.economics.lock_amount_token_base : terms.economics.payout_token_base),
    token: terms.evm_asset.token_contract,
    claimAddress: forward ? terms.provider_evm_address : terms.client_evm_address,
    refundAddress: forward ? terms.client_evm_address : terms.provider_evm_address,
    timelock: terms.htlc_timelock_block,
  });
}

/** The provider's offer must restate the request exactly and be signed for this identity, network, and time. */
export function checkErc20TermsOffer(payload: unknown, context: Erc20OfferContext): Erc20ToLnTerms {
  const offer = requireShape<Erc20TermsOffer>("validateTermsOffer", payload);
  const terms = offer.terms.contract_terms;
  const { request, invoiceBinding: binding, asset } = context;
  if (terms.profile_id !== ERC20_TO_LN || terms.claimant !== "provider" || terms.refund_party !== "client" ||
      terms.economics.kind !== "erc20-to-ln" || terms.timing_policy.kind !== "erc20-to-ln") {
    throw new ProtocolError("terms offer is not an erc20-to-ln contract");
  }
  const economics = terms.economics;
  const principal = sats(economics.lightning_principal_sat, "principal", true);
  const rate = tokenUnits(economics.rate_token_base_per_btc, "rate");
  const fee = signedTokenUnits(economics.success_fee_token_base, "success fee");
  const lock = tokenUnits(economics.lock_amount_token_base, "lock amount");
  checkEvmAddress(terms.provider_evm_address, "provider EVM address");
  const checks: [boolean, string][] = [
    [offer.terms.handshake_hash === context.transcript, "handshake hash"],
    [same(terms.evm_asset, asset), "EVM asset"],
    [same(terms.invoice_binding, binding), "invoice binding"],
    [terms.client_evm_address === request.client_evm_address, "client EVM address"],
    [terms.provider_evm_address !== terms.client_evm_address, "provider EVM address"],
    [terms.recovery_authorization_xonly_key === request.recovery_authorization_xonly_key, "recovery key"],
    [economics.lightning_principal_sat === request.lightning_principal_sat, "principal"],
    [binding.amount_msat === (principal * 1000n).toString(), "invoice amount"],
    [rate > 0n, "rate"],
    [lock === lockAmountTokenBase(principal, rate, fee), "lock amount"],
    [fee <= BigInt(request.limits.max_success_fee_token_base), "success fee"],
    [terms.htlc_timelock_block <= request.limits.max_htlc_timelock_block, "timelock"],
    [terms.htlc_timelock_block > terms.evm_reference_block + terms.funding_confirmations, "timelock window"],
    [terms.required_features.length === 0, "required features"],
  ];
  for (const [ok, what] of checks) {
    if (!ok) throw new ProtocolError(`terms offer does not honor request: ${what}`);
  }
  checkSignedOfferBinding(offer, context);
  return terms;
}

// Recovery: the signed offer is self-authenticating; the wallet refunds after the timelock.

export interface EvmRecoveryParts {
  readonly network: unknown;
  readonly init: HandshakeInit;
  readonly accept: HandshakeAccept;
  readonly acceptSignature: string;
  readonly offer: Erc20TermsOffer | LnToErc20TermsOffer;
  readonly acceptanceSignature: string;
  readonly clientSessionKey: string;
  readonly lockTxHash: string | null;
  readonly preimage: string | null;
  readonly claimTxHash?: string | null;
  /** Browser-held claim key (hex) for sponsored reverse claims; absent for wallet-held claim accounts. */
  readonly claimKey?: string | null;
  /** Where a sponsored claim forwards the tokens (user-chosen, not part of the signed terms). */
  readonly claimDestination?: string | null;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export function evmRecoveryDocument(parts: EvmRecoveryParts): Uint8Array {
  const document = canonicalize({
    format: "rillswap-evm-recovery",
    format_version: "1",
    profile_id: parts.offer.terms.contract_terms.profile_id,
    network_identity: parts.network,
    handshake: { init: parts.init, accept: parts.accept, accept_signature: parts.acceptSignature },
    offer: parts.offer,
    acceptance_signature: parts.acceptanceSignature,
    client_session_xonly_key: parts.clientSessionKey,
    lock_tx_hash: parts.lockTxHash,
    preimage: parts.preimage,
    ...(parts.offer.terms.contract_terms.profile_id === "ln-to-erc20/v1" ? { claim_tx_hash: parts.claimTxHash ?? null } : {}),
    ...(parts.claimKey ? { claim_key: parts.claimKey, claim_destination: parts.claimDestination ?? null } : {}),
    created_at: parts.createdAt,
    updated_at: parts.updatedAt,
  });
  if (document === undefined) throw new SwapError("recovery record cannot be canonicalized");
  return encoder.encode(document);
}

export const encryptEvmRecovery = (parts: EvmRecoveryParts, ageRecipient: string): Promise<Uint8Array> =>
  encryptCanonicalRecoveryForRecipient(evmRecoveryDocument(parts), ageRecipient);

export interface EvmRecoveryRecord {
  readonly terms: EvmTerms;
  readonly contractHash: string;
  readonly lock: HtlcLock;
  readonly lockTxHash: string | null;
  readonly preimage: string | null;
  readonly updatedAt: number;
  readonly holdInvoice: string | null;
  readonly claimTxHash: string | null;
  /** Present when this browser (not a wallet) holds the key of the claim address. */
  readonly claimKey: string | null;
  readonly claimDestination: string | null;
}

/** Authenticate a decrypted EVM recovery record for `network`: the provider's signature binds the terms. */
export function parseEvmRecovery(plaintext: Uint8Array, network: unknown, now: number): EvmRecoveryRecord {
  const text = new TextDecoder().decode(plaintext);
  const parsed = JSON.parse(text) as Record<string, unknown>;
  if (canonicalize(parsed) !== text || parsed.format !== "rillswap-evm-recovery" || parsed.format_version !== "1" ||
      ![ERC20_TO_LN, "ln-to-erc20/v1"].includes(parsed.profile_id as string) || !same(parsed.network_identity, network)) {
    throw new SwapError("not an RS-010 recovery record for this network");
  }
  const reverse = parsed.profile_id === "ln-to-erc20/v1";
  const offer = requireShape<Erc20TermsOffer | LnToErc20TermsOffer>(reverse ? "validateReverseTermsOffer" : "validateTermsOffer", parsed.offer);
  const terms = offer.terms.contract_terms;
  if (terms.profile_id !== parsed.profile_id || terms.economics.kind !== (reverse ? "ln-to-erc20" : "erc20-to-ln") ||
      terms.claimant !== (reverse ? "client" : "provider") || terms.refund_party !== (reverse ? "provider" : "client")) {
    throw new SwapError("recovery record profile and lock roles disagree");
  }
  // Expiry is irrelevant for a refund: bind identity, network, and hash only.
  checkSignedOfferBinding(offer, { identity: terms.provider_identity_key, envelopeContractHash: offer.terms.contract_hash, network, now: Math.min(now, terms.terms_expiry - 1) });
  const lockTxHash = parsed.lock_tx_hash, preimage = parsed.preimage, updatedAt = parsed.updated_at;
  const claimTxHash = parsed.claim_tx_hash ?? null, claimKey = parsed.claim_key ?? null, claimDestination = parsed.claim_destination ?? null;
  if ((claimKey !== null && (!reverse || typeof claimKey !== "string" || !/^[0-9a-f]{64}$/.test(claimKey) || stagingAddress(hexToBytes(claimKey)) !== terms.client_evm_address)) ||
      (claimDestination !== null && (claimKey === null || typeof claimDestination !== "string" || !/^0x[0-9a-f]{40}$/.test(claimDestination))) ||
      (lockTxHash !== null && (typeof lockTxHash !== "string" || !/^[0-9a-f]{64}$/.test(lockTxHash))) ||
      (preimage !== null && (typeof preimage !== "string" || !/^[0-9a-f]{64}$/.test(preimage))) ||
       (claimTxHash !== null && (typeof claimTxHash !== "string" || !/^[0-9a-f]{64}$/.test(claimTxHash))) ||
       !Number.isSafeInteger(updatedAt)) {
    throw new SwapError("recovery record fields are malformed");
  }
  if (preimage !== null && bytesToHex(sha256(hexToBytes(preimage as string))) !== terms.invoice_binding.payment_hash) throw new SwapError("recovery preimage does not match the invoice");
  let holdInvoice: string | null = null;
  if (reverse) {
    if (preimage === null) throw new SwapError("reverse recovery has no claim preimage");
    holdInvoice = (offer as LnToErc20TermsOffer).hold_invoice;
    if (!same(invoiceBinding(holdInvoice, (network as { name: string }).name), terms.invoice_binding)) throw new SwapError("recovery invoice binding mismatch");
  }
  return Object.freeze({ terms, contractHash: offer.terms.contract_hash, lock: lockOf(terms), lockTxHash: lockTxHash as string | null, preimage: preimage as string | null,
    updatedAt: updatedAt as number, holdInvoice, claimTxHash: claimTxHash as string | null, claimKey: claimKey as string | null,
    claimDestination: claimDestination as string | null });
}

// Preparation and execution.

export interface Erc20SwapHooks {
  readonly onActivity?: import("./activity").ActivityObserver;
  report(line: string): void;
  saveRecovery(ciphertext: Uint8Array, stage: "terms" | "locked" | "paid"): Promise<void>;
  /** Approve the HTLC for `lock.amount` if needed and submit the lock; returns the lock tx hash. */
  lock(lock: HtlcLock, htlc: string): Promise<string>;
  /** Hosts sharing one account must serialize funding by chain/account/token/HTLC through confirmation. */
  withFundingLock?<T>(body: () => Promise<T>): Promise<T>;
  readonly rpc: EvmRpc;
  readonly signal?: AbortSignal;
}

export interface Erc20Quote {
  readonly providerIdentity: string;
  readonly providerSlot: string;
  readonly contractHash: string;
  readonly asset: EvmAssetIdentity;
  readonly lockAmountTokenBase: bigint;
  readonly successFeeTokenBase: bigint;
  readonly rateTokenBasePerBtc: bigint;
  readonly timelockBlock: number;
  readonly providerEvmAddress: string;
  readonly expiresAt: number;
  /** Signed EVM blocks the provider waits on the lock before paying. */
  readonly fundingConfirmations: number;
}

export interface Erc20SwapOutcome {
  readonly sessionId: string;
  readonly contractHash: string;
  readonly lockTxHash: string;
  readonly preimage: string;
  readonly timelockBlock: number;
  readonly paidRecovery: Uint8Array;
}

export interface PreparedErc20Swap {
  readonly quote: Erc20Quote;
  readonly terms: Erc20ToLnTerms;
  execute(hooks: Erc20SwapHooks): Promise<Erc20SwapOutcome>;
  dispose(): void;
}

interface PreparationOptions {
  readonly timeouts?: { readonly replyMs: number; readonly settleMs: number };
  readonly clock?: () => number;
  readonly announcement?: string;
}

const sign = (digest: Uint8Array, secret: Uint8Array): string => bytesToHex(schnorr.sign(digest, secret, randomBytes(32)));

function checkRequest(request: Erc20SwapRequest, now: number): InvoiceBinding {
  const invoice = invoiceBinding(request.invoice, request.network.name);
  if (invoice.expires_at < now + MIN_INVOICE_REMAINING_SECONDS) throw new SwapError("invoice expires too soon; ask the recipient for a fresh one");
  if (BigInt(invoice.amount_msat) % 1000n !== 0n) throw new SwapError("invoice amount must be whole satoshis");
  checkEvmAddress(request.clientEvmAddress, "wallet address");
  if (request.asset.htlc_version !== 6) throw new SwapError("unsupported HTLC version");
  if (request.limits.maxSuccessFeeTokenBase < 0n || !Number.isSafeInteger(request.limits.maxTimelockDelayBlocks) ||
      request.limits.maxTimelockDelayBlocks < 1 || !Number.isSafeInteger(request.evmTip) || request.evmTip < 0) {
    throw new SwapError("limits invalid");
  }
  return invoice;
}

export async function prepareErc20Swap(
  relay: RelayLink & AnnouncementSource,
  request: Erc20SwapRequest,
  report: (line: string) => void,
  options: PreparationOptions = {},
): Promise<PreparedErc20Swap> {
  request = { ...request, network: structuredClone(request.network), asset: { ...request.asset }, limits: { ...request.limits } };
  const timeouts = { ...(options.timeouts ?? { replyMs: 60_000, settleMs: 900_000 }) };
  const clock = options.clock ?? Date.now;
  const seconds = (): number => Math.floor(clock() / 1000);
  const invoice = checkRequest(request, seconds());
  const { identity, network, asset } = request;
  const provider = options.announcement === undefined
    ? await discoverProvider(relay, identity, network, ERC20_TO_LN)
    : verifyNostrProviderAnnouncement(options.announcement, identity, network, ERC20_TO_LN);
  if (!provider.evmAssets.some((served) => same(served, asset))) throw new SwapError("provider does not serve this asset");
  report(`provider found (revision ${provider.revision})`);
  const session = new Session(relay, network, ERC20_TO_LN, timeouts.replyMs, clock);
  try {
    const { init, accept, acceptSignature, transcript } = await handshake(session, provider, identity);
    const providerKey = session.providerKey!;
    report(`session ${session.sessionId.slice(0, 16)} confirmed`);
    const recoveryKey = newKeyPair(); // authorization key; its secret is never needed
    recoveryKey.secret.fill(0);
    const quote: Erc20FirmQuoteRequest = {
      kind: "erc20-to-ln",
      mode: "firm",
      lightning_principal_sat: (BigInt(invoice.amount_msat) / 1000n).toString(),
      invoice: request.invoice,
      evm_asset: { chain_id: asset.chain_id, token_contract: asset.token_contract },
      client_evm_address: request.clientEvmAddress,
      recovery_authorization_xonly_key: recoveryKey.xonly,
      limits: {
        max_success_fee_token_base: request.limits.maxSuccessFeeTokenBase.toString(),
        max_htlc_timelock_block: request.evmTip + request.limits.maxTimelockDelayBlocks,
      },
      extensions: {},
    };
    requireShape("validateErc20FirmQuoteRequest", quote);
    const quoteEnvelope = session.envelope("quote_request", quote as unknown as Record<string, unknown>);
    await session.send(quoteEnvelope, providerKey);
    const answer = await session.replyTo(quoteEnvelope, "terms_offer");
    const terms = checkErc20TermsOffer(answer.payload, {
      request: quote, invoiceBinding: invoice, asset, transcript, envelopeContractHash: answer.contract_hash, identity, network, now: seconds(),
    });
    if (terms.htlc_timelock_block <= request.evmTip + terms.funding_confirmations) throw new SwapError("offered timelock is already reached");
    requireAnnouncedDepth(terms.funding_confirmations, provider.fundingConfirmations);
    const offer = answer.payload as unknown as Erc20TermsOffer;
    const contractHash = offer.terms.contract_hash;
    report(`terms: lock ${terms.economics.lock_amount_token_base} base units, refundable after block ${terms.htlc_timelock_block}`);

    let state: "ready" | "executing" | "disposed" | "done" = "ready";
    const release = (): void => { session.secret.fill(0); };
    const window = (): void => {
      if (seconds() >= Math.min(terms.terms_expiry, invoice.expires_at)) throw new SwapError("terms or invoice expired before the lock");
    };
    return Object.freeze({
      terms,
      quote: Object.freeze({
        providerIdentity: identity, providerSlot: provider.slot, contractHash, asset,
        lockAmountTokenBase: BigInt(terms.economics.lock_amount_token_base),
        successFeeTokenBase: BigInt(terms.economics.success_fee_token_base),
        rateTokenBasePerBtc: BigInt(terms.economics.rate_token_base_per_btc),
        timelockBlock: terms.htlc_timelock_block, providerEvmAddress: terms.provider_evm_address,
        expiresAt: Math.min(terms.terms_expiry, invoice.expires_at),
        fundingConfirmations: terms.funding_confirmations,
      }),
      dispose: () => { if (state === "ready") { state = "disposed"; release(); } },
      execute: async (hooks: Erc20SwapHooks): Promise<Erc20SwapOutcome> => {
        if (state !== "ready") throw new SwapError("quote is already used or discarded; request a fresh quote");
        state = "executing";
        try {
          window();
          const acceptance = {
            contract_hash: contractHash, handshake_hash: transcript, session_id: session.sessionId,
            client_session_xonly_key: session.key, provider_session_xonly_key: providerKey,
          };
          const acceptanceSignature = sign(clientAcceptanceHash(acceptance), session.secret);
          const createdAt = seconds();
          const record: EvmRecoveryParts = {
            network, init, accept, acceptSignature, offer, acceptanceSignature, clientSessionKey: session.key,
            lockTxHash: null, preimage: null, createdAt, updatedAt: createdAt,
          };
          await hooks.saveRecovery(await encryptEvmRecovery(record, request.ageRecipient), "terms");
          emitActivity(hooks.onActivity, "terms.verified", { ...activityFacts(terms, request.invoice), session_id: session.sessionId, timelock_block: terms.htlc_timelock_block });
          emitActivity(hooks.onActivity, "recovery.saved", { stage: "terms" });
          hooks.report("recovery record saved (terms, nothing locked yet)");
          window();
          const accepted = session.envelope("terms_accept",
            { acceptance, client_acceptance_signature: acceptanceSignature },
            { inReplyTo: answer.message_id, contract: contractHash });
          await session.send(accepted, providerKey, window);
          await session.replyTo(accepted, "ack");
          window();
          const lock = lockOf(terms);
          const fund = async () => {
            window(); // A queued wallet lock may outlive the signed funding window.
            if (await hooks.rpc.chainId() !== asset.chain_id) throw new SwapError("wrong EVM RPC chain");
            await hooks.rpc.verifyHtlc(asset.htlc_contract);
            window();
            const lockTxHash = await hooks.lock(lock, asset.htlc_contract);
            const locked = { ...record, updatedAt: seconds(), lockTxHash };
            await hooks.saveRecovery(await encryptEvmRecovery(locked, request.ageRecipient), "locked");
            hooks.report(`lock ${lockTxHash} submitted; recovery record saved`);
            emitActivity(hooks.onActivity, "lock.submitted", { txid: lockTxHash });
            const receipt = await awaitReceipt(hooks.rpc, lockTxHash, terms.funding_confirmations, hooks.signal ? { signal: hooks.signal } : {});
            if (!receipt.status) throw new SwapError(`lock transaction ${lockTxHash} reverted; nothing is locked`);
            return { locked, receipt };
          };
          const { locked, receipt } = await (hooks.withFundingLock ? hooks.withFundingLock(fund) : fund());
          const { lockTxHash } = locked;
          hooks.report(`lock confirmed in block ${receipt.blockNumber}; waiting for the provider to pay`);
          emitActivity(hooks.onActivity, "lock.confirmed", { txid: lockTxHash });
          const preimage = await awaitPayment(session, hooks, { contractHash, paymentHash: invoice.payment_hash, deadline: clock() + timeouts.settleMs, timelock: terms.htlc_timelock_block, lock, htlc: asset.htlc_contract, fromBlock: receipt.blockNumber });
          const paid = { ...locked, updatedAt: seconds(), preimage };
          return { sessionId: session.sessionId, contractHash, lockTxHash, preimage, timelockBlock: terms.htlc_timelock_block,
            paidRecovery: await encryptEvmRecovery(paid, request.ageRecipient) };
        } finally {
          state = "done";
          release();
        }
      },
    });
  } catch (error) {
    session.secret.fill(0);
    throw error;
  }
}

/** The preimage, learned from the provider's settlement observation or from its on-chain Claim. */
async function awaitPayment(
  session: Session, hooks: Erc20SwapHooks,
  ctx: { contractHash: string; paymentHash: string; deadline: number; timelock: number; lock: HtlcLock; htlc: string; fromBlock: number },
): Promise<string> {
  const proves = (preimage: unknown): preimage is string =>
    typeof preimage === "string" && /^[0-9a-f]{64}$/.test(preimage) && bytesToHex(sha256(hexToBytes(preimage))) === ctx.paymentHash;
  const hint = `your tokens stay locked; after block ${ctx.timelock} refund them from the swap page with the same wallet`;
  for (;;) {
    const claim = await hooks.rpc.findClaim(ctx.htlc, ctx.paymentHash, ctx.fromBlock, await hooks.rpc.blockNumber()).catch(() => null);
    if (claim !== null && proves(claim.preimage)) {
      hooks.report(`the provider claimed the lock in ${claim.txHash}; the invoice is paid`);
      emitActivity(hooks.onActivity, "payment.verified", { txid: claim.txHash });
      return claim.preimage;
    }
    const remaining = ctx.deadline - session.clock();
    if (remaining <= 0) throw new SwapError(`provider did not pay in time; ${hint}`);
    let envelope;
    try {
      envelope = await session.receive(
        (item) => item.in_reply_to === null && item.contract_hash === ctx.contractHash && item.message_type === "observation",
        Math.min(remaining, 15_000),
      );
    } catch {
      continue; // poll the chain again
    }
    let seen: { kind: string; payment_preimage?: string };
    try {
      seen = requireShape("validateObservation", envelope.payload);
    } catch {
      continue;
    }
    if (seen.kind === "payment_failed") throw new SwapError(`provider reports the payment failed; ${hint}`);
    if (seen.kind === "payment_settled" && proves(seen.payment_preimage)) {
      hooks.report("the provider paid the invoice");
      emitActivity(hooks.onActivity, "payment.verified");
      return seen.payment_preimage;
    }
    if (seen.kind === "evm_lockup_observed") hooks.report("the provider saw the lock");
  }
}
