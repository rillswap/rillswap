/** RS-010 reverse swaps: indicative shopping, durable secrets, any-wallet LN payment, then an explicit EVM claim. */
import { schnorr } from "@noble/curves/secp256k1.js";
import { activityFacts, emitActivity } from "./activity";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import canonicalize from "canonicalize";
import { verifyNostrProviderAnnouncement } from "../nostrProviderAnnouncement";
import { encryptCanonicalRecoveryForRecipient } from "../recoveryAgeContainer";
import type { EvmAssetIdentity } from "../manualProviderAdvertisement";
import { invoiceBinding } from "./bolt11";
import { encryptEvmRecovery, lockOf, type EvmRecoveryParts, type LnToErc20Terms, type LnToErc20TermsOffer } from "./erc20Swap";
import { awaitReceipt, checkEvmAddress, lockHash, type EvmRpc, type HtlcLock } from "./evmHtlc";
import { stagingAddress } from "./gasSponsor";
import { clientAcceptanceHash } from "./hashes";
import { handshake, newKeyPair } from "./handshake";
import { Session, SwapError, type RelayLink } from "./session";
import { checkSignedOfferBinding, MAX_SATS, ProtocolError, requireAnnouncedDepth, requireShape, same, sats, signedSats } from "./wire";

export const LN_TO_ERC20 = "ln-to-erc20/v1";
export interface LnErc20Request {
  readonly identity: string;
  readonly network: { readonly name: string } & Record<string, unknown>;
  readonly payoutTokenBase: bigint;
  readonly asset: EvmAssetIdentity;
  readonly limits: {
    readonly maxSuccessFeeSat: bigint;
    readonly minTimelockDelayBlocks: number;
    readonly maxIncomingHtlcDelayBlocks: number;
  };
}
export interface LnErc20QuoteOffer {
  readonly kind: "ln-to-erc20";
  readonly economics: LnToErc20Terms["economics"];
  readonly evm_asset: EvmAssetIdentity;
  readonly funding_confirmations: number;
  readonly settlement_confirmations: number;
  readonly evm_reference_block: number;
  readonly timelock_delay_blocks: number;
  readonly incoming_htlc_expiry_delta_blocks: number;
  readonly expires_at: number;
}
export interface LnErc20FirmRequest {
  readonly kind: "ln-to-erc20";
  readonly mode: "firm";
  readonly payout_token_base: string;
  readonly payment_hash: string;
  readonly evm_asset: { readonly chain_id: number; readonly token_contract: string };
  readonly client_evm_address: string;
  readonly recovery_authorization_xonly_key: string;
  readonly limits: { readonly max_success_fee_sat: string; readonly min_htlc_timelock_block: number; readonly max_incoming_htlc_expiry_height: number };
  readonly extensions: Record<string, unknown>;
}

export function payoutSatEquivalent(payout: bigint, rate: bigint): bigint {
  if (payout <= 0n || rate <= 0n) throw new ProtocolError("payout and exchange rate must be positive");
  return (payout * 100_000_000n + rate - 1n) / rate;
}

function checkEconomics(economics: LnToErc20Terms["economics"], payout: bigint, maxFee: bigint): void {
  const equivalent = payoutSatEquivalent(BigInt(economics.payout_token_base), BigInt(economics.rate_token_base_per_btc));
  const fee = signedSats(economics.success_fee_sat, "provider fee"), hold = sats(economics.hold_invoice_sat, "hold invoice", true);
  if (BigInt(economics.payout_token_base) !== payout || equivalent > MAX_SATS ||
      equivalent !== sats(economics.payout_sat_equivalent, "payout equivalent", true) || fee > maxFee || equivalent + fee !== hold) {
    throw new ProtocolError("reverse stablecoin economics do not honor the requested payout and fee");
  }
}

export function checkLnErc20QuoteOffer(payload: unknown, request: Omit<LnErc20Request, "identity">, now: number): LnErc20QuoteOffer {
  const offer = requireShape<LnErc20QuoteOffer>("validateLnToErc20QuoteOffer", payload);
  checkEconomics(offer.economics, request.payoutTokenBase, request.limits.maxSuccessFeeSat);
  if (!same(offer.evm_asset, request.asset) || offer.expires_at <= now ||
      offer.timelock_delay_blocks < request.limits.minTimelockDelayBlocks ||
      offer.incoming_htlc_expiry_delta_blocks > request.limits.maxIncomingHtlcDelayBlocks ||
      offer.timelock_delay_blocks * request.asset.block_seconds >= offer.incoming_htlc_expiry_delta_blocks * 600) {
    throw new ProtocolError("reverse stablecoin estimate has unacceptable asset, expiry, or timing");
  }
  return offer;
}

export function checkLnErc20TermsOffer(payload: unknown, context: {
  readonly request: LnErc20FirmRequest; readonly asset: EvmAssetIdentity; readonly network: unknown;
  readonly identity: string; readonly transcript: string; readonly envelopeContractHash: string | null; readonly now: number;
  /** The EVM tip this client sampled before the firm request. */
  readonly evmTip: number;
}): LnToErc20TermsOffer {
  const offer = requireShape<LnToErc20TermsOffer>("validateReverseTermsOffer", payload);
  const terms = offer.terms.contract_terms, { request } = context;
  if (terms.profile_id !== LN_TO_ERC20 || terms.claimant !== "client" || terms.refund_party !== "provider" ||
      terms.economics.kind !== "ln-to-erc20" || terms.timing_policy.kind !== "ln-to-erc20") throw new ProtocolError("not reverse stablecoin terms");
  checkEconomics(terms.economics, BigInt(request.payout_token_base), BigInt(request.limits.max_success_fee_sat));
  const binding = invoiceBinding(offer.hold_invoice, (context.network as { name: string }).name);
  checkEvmAddress(terms.provider_evm_address, "provider address");
  if (offer.terms.handshake_hash !== context.transcript || !same(terms.evm_asset, context.asset) || !same(binding, terms.invoice_binding) ||
      binding.payment_hash !== request.payment_hash || binding.amount_msat !== (BigInt(terms.economics.hold_invoice_sat) * 1000n).toString() ||
      binding.expires_at < context.now + 600 || terms.client_evm_address !== request.client_evm_address ||
      terms.provider_evm_address === terms.client_evm_address || terms.recovery_authorization_xonly_key !== request.recovery_authorization_xonly_key ||
      terms.required_features.length !== 0 || terms.htlc_timelock_block < request.limits.min_htlc_timelock_block ||
      terms.htlc_timelock_block <= terms.evm_reference_block + terms.funding_confirmations ||
      terms.timing_policy.min_incoming_htlc_expiry_height > request.limits.max_incoming_htlc_expiry_height ||
      (terms.htlc_timelock_block - terms.evm_reference_block) * context.asset.block_seconds + terms.timing_policy.refund_and_ln_resolution_seconds >=
        (terms.timing_policy.min_incoming_htlc_expiry_height - terms.btc_reference_height) * 600) {
    throw new ProtocolError("reverse stablecoin terms do not honor invoice, address, asset, features, or timing limits");
  }
  // The signed reference starts every lock scan and the timing math: keep it within ten minutes of blocks of our tip.
  if (Math.abs(terms.evm_reference_block - context.evmTip) > Math.ceil(600 / context.asset.block_seconds)) {
    throw new ProtocolError("reverse stablecoin terms reference an EVM block far from the current tip");
  }
  checkSignedOfferBinding(offer, context);
  return offer;
}

export interface LnErc20Configuration {
  /** The HTLC claim address: the user's wallet account, or the staging account of `claimKey`. */
  readonly clientEvmAddress: string;
  /** Browser-held secp256k1 key behind `clientEvmAddress` for gas-sponsored claims; stored with the preimage. */
  readonly claimKey?: Uint8Array;
  /** Where the sponsored claim forwards the tokens; required with `claimKey`. */
  readonly claimDestination?: string;
  readonly evmTip: number;
  readonly btcTip: number;
  readonly ageRecipient: string;
  /** Commit the encrypted preimage before the firm request (RS-010). Not a download callback. */
  saveSecrets(file: Uint8Array, sessionId: string): Promise<void>;
}
export interface LnErc20Hooks {
  readonly onActivity?: import("./activity").ActivityObserver;
  readonly rpc: EvmRpc;
  readonly signal?: AbortSignal;
  report(line: string): void;
  saveRecovery(file: Uint8Array, stage: "terms" | "locked" | "claim-submitted" | "claimed", contractHash: string): Promise<void>;
  showInvoice(invoice: string): void;
  checkWallet(): Promise<void>;
  /** Atomic durable exposure grant, before any preimage-bearing wallet/RPC request. */
  markExposure(contractHash: string): Promise<void>;
  /** Submit the claim and return its transaction hash once known (sponsored claims: after inclusion). */
  claim(lock: HtlcLock, preimage: string, htlc: string): Promise<string>;
  /** Sponsored execution must bind the final-depth receipt to the locally verified operation. */
  verifyClaim?(txHash: string): Promise<void>;
  /** Who pays claim gas: the claim account itself (`wallet`) or a gas sponsor (`sponsored`). */
  readonly claimGas: "wallet" | "sponsored";
}
export interface PreparedLnErc20Execution {
  readonly terms: LnToErc20Terms;
  readonly contractHash: string;
  execute(hooks: LnErc20Hooks): Promise<{ readonly claimTxHash: string; readonly recovery: Uint8Array }>;
  dispose(): void;
}
export interface PreparedLnErc20Quote {
  readonly quote: { readonly providerIdentity: string; readonly providerSlot: string; readonly offer: LnErc20QuoteOffer };
  prepareExecution(config: LnErc20Configuration): Promise<PreparedLnErc20Execution>;
  dispose(): void;
}

function checkRequest(request: LnErc20Request): void {
  if (request.payoutTokenBase <= 0n || request.payoutTokenBase >= 10n ** 39n || request.asset.htlc_version !== 6 ||
      request.limits.maxSuccessFeeSat < 0n || request.limits.maxSuccessFeeSat > MAX_SATS ||
      !Number.isSafeInteger(request.limits.minTimelockDelayBlocks) || request.limits.minTimelockDelayBlocks < 1 ||
      !Number.isSafeInteger(request.limits.maxIncomingHtlcDelayBlocks) || request.limits.maxIncomingHtlcDelayBlocks < 1) throw new SwapError("invalid stablecoin payout or limits");
}

export async function prepareLnErc20Quote(relay: RelayLink, request: LnErc20Request, options: { readonly announcement: string; readonly replyMs?: number; readonly clock?: () => number }): Promise<PreparedLnErc20Quote> {
  request = structuredClone(request);
  checkRequest(request);
  const clock = options.clock ?? Date.now;
  const provider = verifyNostrProviderAnnouncement(options.announcement, request.identity, request.network, LN_TO_ERC20);
  if (!provider.evmAssets.some((asset) => same(asset, request.asset))) throw new SwapError("provider does not serve this asset");
  const session = new Session(relay, request.network, LN_TO_ERC20, options.replyMs ?? 15_000, clock);
  try {
    await handshake(session, provider, request.identity);
    const indicative = requireShape<Record<string, unknown>>("validateLnToErc20IndicativeQuoteRequest", {
      kind: "ln-to-erc20", mode: "indicative", payout_token_base: request.payoutTokenBase.toString(),
      evm_asset: { chain_id: request.asset.chain_id, token_contract: request.asset.token_contract }, extensions: {},
    });
    const envelope = session.envelope("quote_request", indicative);
    await session.send(envelope, session.providerKey!);
    const answer = await session.replyTo(envelope, "quote_offer");
    const offer = checkLnErc20QuoteOffer(answer.payload, request, Math.floor(clock() / 1000));
    requireAnnouncedDepth(offer.funding_confirmations, provider.fundingConfirmations);
    let used = false;
    return {
      quote: Object.freeze({ providerIdentity: request.identity, providerSlot: provider.slot, offer }),
      dispose() { used = true; session.secret.fill(0); },
      async prepareExecution(config) {
        if (used || clock() / 1000 >= offer.expires_at) throw new SwapError("estimate used or expired; request another");
        used = true; session.secret.fill(0);
        const execution = await prepareFirm(relay, request, options, config);
        if (BigInt(execution.terms.economics.hold_invoice_sat) > BigInt(offer.economics.hold_invoice_sat)) {
          execution.dispose();
          throw new SwapError("Firm price increased. Nothing was accepted or paid; request another quote");
        }
        // Ranked and shown on the estimate's depth: the signed terms must keep it.
        if (execution.terms.funding_confirmations !== offer.funding_confirmations) {
          execution.dispose();
          throw new ProtocolError("signed funding confirmations differ from the estimate");
        }
        return execution;
      },
    };
  } catch (error) { session.secret.fill(0); throw error; }
}

async function prepareFirm(relay: RelayLink, request: LnErc20Request, options: { readonly announcement: string; readonly replyMs?: number; readonly clock?: () => number }, config: LnErc20Configuration): Promise<PreparedLnErc20Execution> {
  checkEvmAddress(config.clientEvmAddress, "claim address");
  const claimKey = config.claimKey === undefined ? null : bytesToHex(config.claimKey);
  if (claimKey !== null && (config.claimKey!.length !== 32 || stagingAddress(config.claimKey!) !== config.clientEvmAddress)) throw new SwapError("claim key does not control the claim address");
  if (claimKey !== null) checkEvmAddress(config.claimDestination, "token destination");
  if (![config.evmTip, config.btcTip].every((tip) => Number.isSafeInteger(tip) && tip >= 0)) throw new SwapError("invalid chain tips");
  const clock = options.clock ?? Date.now, seconds = (): number => Math.floor(clock() / 1000);
  const provider = verifyNostrProviderAnnouncement(options.announcement, request.identity, request.network, LN_TO_ERC20);
  const session = new Session(relay, request.network, LN_TO_ERC20, options.replyMs ?? 15_000, clock);
  const secret = randomBytes(32), preimage = bytesToHex(secret), paymentHash = bytesToHex(sha256(secret));
  secret.fill(0);
  try {
    const { init, accept, acceptSignature, transcript } = await handshake(session, provider, request.identity);
    const recoveryKey = newKeyPair(); recoveryKey.secret.fill(0);
    const createdAt = seconds();
    const secrets = canonicalize({ format: "rillswap-evm-recovery", format_version: "1", profile_id: LN_TO_ERC20,
      stage: "pre-firm", network_identity: request.network, session_id: session.sessionId, preimage, payment_hash: paymentHash,
      ...(claimKey === null ? {} : { claim_key: claimKey }), created_at: createdAt });
    await config.saveSecrets(await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(secrets!), config.ageRecipient), session.sessionId);
    const firm: LnErc20FirmRequest = {
      kind: "ln-to-erc20", mode: "firm", payout_token_base: request.payoutTokenBase.toString(), payment_hash: paymentHash,
      evm_asset: { chain_id: request.asset.chain_id, token_contract: request.asset.token_contract }, client_evm_address: config.clientEvmAddress,
      recovery_authorization_xonly_key: recoveryKey.xonly, limits: {
        max_success_fee_sat: request.limits.maxSuccessFeeSat.toString(), min_htlc_timelock_block: config.evmTip + request.limits.minTimelockDelayBlocks,
        max_incoming_htlc_expiry_height: config.btcTip + request.limits.maxIncomingHtlcDelayBlocks,
      }, extensions: {},
    };
    requireShape("validateLnToErc20FirmQuoteRequest", firm);
    const envelope = session.envelope("quote_request", firm as unknown as Record<string, unknown>);
    await session.send(envelope, session.providerKey!);
    const answer = await session.replyTo(envelope, "terms_offer");
    const offer = checkLnErc20TermsOffer(answer.payload, { request: firm, asset: request.asset, network: request.network,
      identity: request.identity, transcript, envelopeContractHash: answer.contract_hash, now: seconds(), evmTip: config.evmTip });
    const terms = offer.terms.contract_terms, contractHash = offer.terms.contract_hash;
    let used = false;
    return {
      terms, contractHash,
      dispose() { used = true; session.secret.fill(0); },
      async execute(hooks) {
        if (used) throw new SwapError("firm offer already used"); used = true;
        const window = (): void => { if (seconds() >= Math.min(terms.terms_expiry, terms.invoice_binding.expires_at)) throw new SwapError("firm offer expired before invoice exposure"); };
        try {
          if (hooks.claimGas === "sponsored" && typeof hooks.verifyClaim !== "function") {
            throw new SwapError("Sponsored claims require operation-bound completion verification");
          }
          window();
          const acceptance = { contract_hash: contractHash, handshake_hash: transcript, session_id: session.sessionId,
            client_session_xonly_key: session.key, provider_session_xonly_key: session.providerKey! };
          const acceptanceSignature = bytesToHex(schnorr.sign(clientAcceptanceHash(acceptance), session.secret));
          let record: EvmRecoveryParts = { network: request.network, init, accept, acceptSignature, offer, acceptanceSignature,
            clientSessionKey: session.key, lockTxHash: null, preimage, claimKey, claimDestination: config.claimDestination ?? null, createdAt, updatedAt: seconds() };
          const save = async (stage: "terms" | "locked" | "claim-submitted" | "claimed"): Promise<Uint8Array> => {
            const file = await encryptEvmRecovery(record, config.ageRecipient); await hooks.saveRecovery(file, stage, contractHash); return file;
          };
          await save("terms"); window();
          emitActivity(hooks.onActivity, "terms.verified", { ...activityFacts(terms, offer.hold_invoice), session_id: session.sessionId, timelock_block: terms.htlc_timelock_block });
          const accepted = session.envelope("terms_accept", { acceptance, client_acceptance_signature: acceptanceSignature }, { inReplyTo: answer.message_id, contract: contractHash });
          await session.send(accepted, session.providerKey!, window); await session.replyTo(accepted, "ack"); window();
          hooks.showInvoice(offer.hold_invoice);
          emitActivity(hooks.onActivity, "invoice.exposed");
          hooks.report("Pay the hold invoice from any Lightning wallet; waiting for the provider's token lock");
          const lock = lockOf(terms), deadline = clock() + 900_000;
          let funded: { txHash: string } | undefined;
          while (!funded) {
            hooks.signal?.throwIfAborted();
            const tip = await hooks.rpc.blockNumber();
            if (tip >= lock.timelock || clock() >= deadline) throw new SwapError("No confirmed token lock in time. Keep your recovery file; your Lightning payment may remain held until canceled");
            const logs = await hooks.rpc.findLockups(request.asset.htlc_contract, paymentHash, Math.max(0, terms.evm_reference_block - 12), tip);
            funded = logs.find((log) => lockHash(log.lock) === lockHash(lock) && tip - log.blockNumber + 1 >= terms.funding_confirmations);
            if (!funded) await new Promise((resolve) => setTimeout(resolve, 2_000));
          }
          record = { ...record, lockTxHash: funded.txHash, updatedAt: seconds() }; await save("locked");
          emitActivity(hooks.onActivity, "lock.confirmed", { txid: funded.txHash });
          hooks.report(hooks.claimGas === "sponsored" ? "Token lock confirmed. Claiming through the gas sponsor" : "Token lock confirmed. Check and approve the claim in your EVM wallet");
          const safety = await assertSafeEvmClaim(hooks.rpc, terms, preimage, hooks.claimGas);
          await hooks.checkWallet();
          await hooks.markExposure(contractHash);
          assertFreshEvmClaim(safety);
          const claimTxHash = await hooks.claim(lock, preimage, request.asset.htlc_contract);
          record = { ...record, claimTxHash, updatedAt: seconds() }; await save("claim-submitted");
          emitActivity(hooks.onActivity, "claim.submitted", { txid: claimTxHash });
          const receipt = await awaitReceipt(hooks.rpc, claimTxHash, terms.settlement_confirmations, hooks.signal ? { signal: hooks.signal } : {});
          if (!receipt.status) throw new SwapError("Claim reverted after preimage exposure. Do not assume Lightning was refunded; inspect the chain before any retry");
          if (hooks.claimGas === "sponsored") await hooks.verifyClaim!(claimTxHash);
          // A bundled claim can be included without taking effect; the lock itself is the proof.
          if (await hooks.rpc.lockActive(request.asset.htlc_contract, lock)) throw new SwapError("Claim transaction confirmed but the token lock is still active. Inspect the chain before any retry");
          record = { ...record, updatedAt: seconds() };
          emitActivity(hooks.onActivity, "claim.confirmed", { txid: claimTxHash });
          return { claimTxHash, recovery: await save("claimed") };
        } finally { session.secret.fill(0); }
      },
    };
  } catch (error) { session.secret.fill(0); throw error; }
}

/** No claim calldata is sent during these checks: even eth_estimateGas would leak the preimage. */
export async function assertSafeEvmClaim(rpc: EvmRpc, terms: LnToErc20Terms, preimage: string, claimGas: "wallet" | "sponsored" = "wallet"): Promise<{ readonly checkedAt: number }> {
  if (!/^[0-9a-f]{64}$/.test(preimage) || bytesToHex(sha256(hexToBytes(preimage))) !== terms.invoice_binding.payment_hash) throw new SwapError("claim preimage mismatch");
  if (await rpc.chainId() !== terms.evm_asset.chain_id) throw new SwapError("wrong EVM RPC chain");
  await rpc.verifyHtlc(terms.evm_asset.htlc_contract);
  const tip = await rpc.blockNumber(), lock = lockOf(terms);
  const margin = Math.max(terms.settlement_confirmations + 12, Math.ceil(600 / terms.evm_asset.block_seconds));
  if (tip + margin >= lock.timelock) throw new SwapError("Too close to the provider's refund block to reveal the preimage safely");
  const logs = await rpc.findLockups(terms.evm_asset.htlc_contract, lock.preimageHash, Math.max(0, terms.evm_reference_block - 12), tip);
  if (!logs.some((log) => lockHash(log.lock) === lockHash(lock) && tip - log.blockNumber + 1 >= terms.funding_confirmations) ||
      !await rpc.lockActive(terms.evm_asset.htlc_contract, lock)) throw new SwapError("Exact confirmed token lock is not active");
  if (claimGas === "wallet") {
    // A conservative gas budget, not a simulation or guarantee. Wallet estimation happens only after the exposure marker.
    const balance = await rpc.nativeBalance(terms.client_evm_address), price = await rpc.gasPrice();
    if (balance <= 0n || balance < price * 500_000n) throw new SwapError("Fund your EVM wallet with gas before claiming; the preimage has not been exposed");
  }
  // Historical scans and gas reads can stall. The disclosure grant uses a new live check,
  // and its age includes those final RPC requests, wallet checks, and the durable commit.
  const checkedAt = performance.now();
  if (await rpc.chainId() !== terms.evm_asset.chain_id || !await rpc.lockActive(terms.evm_asset.htlc_contract, lock) ||
      await rpc.blockNumber() + margin >= lock.timelock) throw new SwapError("Claim window or active lock changed during verification");
  const safety = { checkedAt }; assertFreshEvmClaim(safety); return safety;
}

/** A suspended tab or delayed journal commit must not disclose a previously safe preimage. */
export function assertFreshEvmClaim(safety: { readonly checkedAt: number }, now = performance.now()): void {
  if (now < safety.checkedAt || now - safety.checkedAt > 5_000) throw new SwapError("Claim safety check became stale. Exposure remains unknown; no transaction was requested");
}
