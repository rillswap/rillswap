/**
 * RS-010 browser UI pieces: token amount formatting, the wallet-driven lock
 * (approve, then lock), and the recovery view with a wallet refund after the
 * timelock. The injected wallet signs; this page only reads the chain.
 */
import { type Erc20SwapOutcome, type EvmRecoveryRecord, parseEvmRecovery, type PreparedErc20Swap } from "./swap/erc20Swap";
import { activityStatus, type ActivityObserver } from "./swap/activity";
import {
  awaitReceipt, encodeApprove, encodeClaim, encodeLock, encodeRefund, encodeTransfer, EvmError, EvmRpc, EvmWallet, type HtlcLock, injectedProvider, type SponsoredClaimProof,
} from "./swap/evmHtlc";
import { GasSponsor, type SponsorConfig, stagingAddress } from "./swap/gasSponsor";
import type { EvmSponsorDefaults } from "./swap/config";
import type { EvmAssetIdentity } from "./manualProviderAdvertisement";
import { assertFreshEvmClaim, assertSafeEvmClaim, type PreparedLnErc20Execution } from "./swap/lnErc20Swap";
import { EvmClaimJournal } from "./evmClaimJournal";
import { qrSvg } from "./qr";
import canonicalize from "canonicalize";
import { hexToBytes } from "@noble/hashes/utils.js";
import { encryptCanonicalRecoveryForRecipient } from "./recoveryAgeContainer";

function node<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", id = ""): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag); e.textContent = text; if (id) e.id = id; return e;
}

/** `1005000` with 6 decimals is `1.005`; trailing zeros are dropped. */
export function formatTokenAmount(base: bigint, decimals: number): string {
  if (base < 0n) return `-${formatTokenAmount(-base, decimals)}`;
  const unit = 10n ** BigInt(decimals);
  const whole = base / unit, fraction = (base % unit).toString().padStart(decimals, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

/** Decimal token text to base units; more fraction digits than the token has are refused. */
export function parseTokenAmount(text: string, decimals: number, what: string): bigint {
  const match = /^(0|[1-9][0-9]{0,17})(?:\.([0-9]{1,18}))?$/.exec(text.trim());
  if (!match || (match[2] ?? "").length > decimals) throw new Error(`${what} must be a decimal amount with at most ${decimals} fraction digits`);
  return BigInt(match[1]!) * 10n ** BigInt(decimals) + BigInt((match[2] ?? "").padEnd(decimals, "0") || "0");
}

export const tokenLabel = (base: bigint, asset: EvmAssetIdentity): string =>
  `${formatTokenAmount(base, asset.token_decimals)} ${asset.token_symbol}`;

export class WalletRefusedError extends Error {
  constructor(message: string) { super(message); this.name = "WalletRefusedError"; }
}

/** Connect the injected wallet on the asset's chain; the RPC must agree on the chain id. */
export async function connectEvmWallet(rpc: EvmRpc, asset: EvmAssetIdentity): Promise<{ wallet: EvmWallet; account: string }> {
  const provider = injectedProvider();
  if (provider === null) throw new WalletRefusedError("No EVM wallet found in this browser. Install a wallet extension (MetaMask or similar) and reload.");
  const rpcChain = await rpc.chainId();
  if (rpcChain !== asset.chain_id) {
    throw new WalletRefusedError(`The configured EVM RPC serves chain ${rpcChain}, but ${asset.token_symbol} is on ${asset.name} (chain ${asset.chain_id}). Change it in Settings.`);
  }
  const wallet = new EvmWallet(provider);
  try {
    return { wallet, account: await wallet.connect(asset.chain_id) };
  } catch (error) {
    throw new WalletRefusedError(`Wallet connection refused: ${error instanceof Error ? error.message : "unknown error"}`);
  }
}

export interface Erc20ExecutionOptions {
  readonly onActivity?: ActivityObserver;
  readonly prepared: PreparedErc20Swap;
  readonly asset: EvmAssetIdentity;
  readonly rpc: EvmRpc;
  readonly wallet: EvmWallet;
  readonly account: string;
  readonly ageRecipient: string;
  readonly status: (message: string, step: number, state?: string) => void;
  readonly report: (line: string) => void;
  readonly download: (root: HTMLElement, file: Uint8Array, name: string) => void;
  readonly signal?: AbortSignal;
}

/** Only the allowance-consuming funding step is exclusive, never Lightning settlement. */
export function erc20FundingLock(asset: EvmAssetIdentity, account: string, signal?: AbortSignal): <T>(body: () => Promise<T>) => Promise<T> {
  const locks = globalThis.navigator?.locks;
  if (!locks) throw new WalletRefusedError("This browser cannot coordinate token funding across tabs. Use a browser with Web Locks support.");
  const key = `rillswap-erc20-funding:${asset.chain_id}:${account.toLowerCase()}:${asset.token_contract.toLowerCase()}:${asset.htlc_contract.toLowerCase()}`;
  return (body) => locks.request(key, { mode: "exclusive", ...(signal ? { signal } : {}) }, body);
}

/** Approve (if needed) and lock through the wallet, then wait for the provider's payment. */
export async function mountErc20Execution(panel: HTMLElement, options: Erc20ExecutionOptions): Promise<Erc20SwapOutcome> {
  const { prepared, asset, rpc, wallet, account, report, status } = options;
  const withFundingLock = erc20FundingLock(asset, account, options.signal);
  const files = node("section", "", "swap-erc20-files");
  const message = node("p", "", "swap-erc20-message");
  panel.replaceChildren(message, files);
  const say = (text: string, step: number, state?: string): void => { message.textContent = text; status(text, step, state); };
  const lock = async (terms: HtlcLock, htlc: string): Promise<string> => {
    const balance = await rpc.balanceOf(terms.token, account);
    if (balance < terms.amount) {
      throw new WalletRefusedError(`Your wallet holds ${tokenLabel(balance, asset)}; the lock needs ${tokenLabel(terms.amount, asset)}. Nothing was locked.`);
    }
    if (await rpc.allowance(terms.token, account, htlc) < terms.amount) {
      await wallet.assertAccount(asset.chain_id, account);
      options.signal?.throwIfAborted();
      say(`Approve ${tokenLabel(terms.amount, asset)} for the swap contract in your wallet`, 2);
      const approval = await wallet.send(account, terms.token, encodeApprove(htlc, terms.amount));
      report(`approval ${approval} submitted`);
      const receipt = await awaitReceipt(rpc, approval, 1, options.signal ? { signal: options.signal } : {});
      if (!receipt.status) throw new EvmError("the approval transaction reverted; nothing was locked");
    }
    await wallet.assertAccount(asset.chain_id, account);
    options.signal?.throwIfAborted();
    if (Math.floor(Date.now() / 1000) >= prepared.quote.expiresAt) throw new EvmError("The funding window expired; tokens were not locked");
    say(`Confirm the lock of ${tokenLabel(terms.amount, asset)} in your wallet`, 2);
    return wallet.send(account, htlc, encodeLock(terms));
  };
  const outcome = await prepared.execute({
    rpc,
    withFundingLock: (body) => {
      say("Waiting for this wallet's other swap to finish locking, if any", 2);
      return withFundingLock(body);
    },
    ...(options.signal ? { signal: options.signal } : {}),
    report,
    onActivity: (event) => { options.onActivity?.(event); const progress = activityStatus(event); say(progress.text, progress.step); },
    saveRecovery: async (file, stage) => {
      options.download(files, file, `rillswap-${asset.token_symbol.toLowerCase()}-to-ln-${stage}.age`);
      report(`recovery record saved (${stage})`);
    },
    lock,
  });
  options.download(files, outcome.paidRecovery, `rillswap-${asset.token_symbol.toLowerCase()}-to-ln-paid.age`);
  say("Lightning invoice paid", 4, "success");
  panel.append(node("p", `Preimage ${outcome.preimage}. Lock ${outcome.lockTxHash}.`, "swap-erc20-paid"));
  return outcome;
}

export interface EvmRecoveryOptions {
  readonly plaintext: Uint8Array;
  readonly network: unknown;
  readonly evmRpc: () => string;
  readonly assertCurrent: () => void;
  readonly rpcFactory?: (url: string) => EvmRpc;
  readonly ageRecipient?: () => Promise<string>;
  /** Gas sponsor for records whose claim key this browser holds; null when none is configured. */
  readonly sponsor?: () => EvmSponsorDefaults | null;
  readonly sponsorFactory?: (config: SponsorConfig) => GasSponsor;
}

/** Who submits the reverse claim: the user's wallet account, or a gas sponsor for a browser-held claim key. */
export type LnErc20Claimer =
  | { readonly kind: "wallet"; readonly wallet: EvmWallet; readonly account: string }
  | { readonly kind: "sponsored"; readonly sponsor: GasSponsor; readonly secret: Uint8Array; readonly destination: string };

/**
 * Claim and forward in one atomic batch from the staging account, then confirm the destination
 * received the payout from that very transaction. The sponsor's own status is not trusted for that.
 */
async function sponsoredClaim(rpc: EvmRpc, claimer: Extract<LnErc20Claimer, { kind: "sponsored" }>, lock: HtlcLock, preimage: string, htlc: string,
  report: (line: string) => void, signal?: AbortSignal): Promise<{ txHash: string; proof: SponsoredClaimProof }> {
  const { callId, userOpHash } = await claimer.sponsor.submit(rpc, claimer.secret, [
    { to: htlc, data: encodeClaim(lock, preimage) }, { to: lock.token, data: encodeTransfer(claimer.destination, lock.amount) },
  ]);
  report(`Claim submitted to the gas sponsor (call ${callId}); waiting for inclusion`);
  const txHash = await claimer.sponsor.awaitInclusion(callId, signal ? { signal } : {});
  const proof = { userOpHash, entryPoint: claimer.sponsor.config.entryPoint, sender: stagingAddress(claimer.secret),
    lock, preimage, htlc, destination: claimer.destination };
  await rpc.verifySponsoredClaim(txHash, proof, 1);
  return { txHash, proof };
}

/** Reopen an RS-010 record: show the signed lock, check it on request, and refund through the wallet after the timelock. */
export function evmRecoveryControls(root: HTMLElement, options: EvmRecoveryOptions): () => void {
  let disposed = false, busy = false;
  const current = (): void => { if (disposed) throw new Error("Selection changed"); options.assertCurrent(); };
  let record: EvmRecoveryRecord;
  try {
    record = parseEvmRecovery(Uint8Array.from(options.plaintext), options.network, Math.floor(Date.now() / 1000));
  } catch {
    root.replaceChildren(node("p", "Could not verify this recovery file for the selected network. Keep your backups; nothing was changed or uploaded."));
    return () => { disposed = true; };
  }
  if (record.terms.profile_id === "ln-to-erc20/v1") return reverseEvmRecoveryControls(root, record, options);
  const { terms, lock } = record;
  const asset = terms.evm_asset;
  const message = node("p", "", "swap-evm-recovery-message");
  const check = node("button", "Check lock status", "swap-evm-recovery-check"); check.type = "button";
  const refund = node("button", `Refund ${tokenLabel(lock.amount, asset)} with your wallet`, "swap-evm-recovery-refund"); refund.type = "button";
  refund.className = "primary";
  refund.disabled = true;
  root.replaceChildren(
    node("h3", `${asset.token_symbol} to Lightning recovery verified`),
    node("p", `${asset.name} (chain ${asset.chain_id}) · ${tokenLabel(lock.amount, asset)} locked for ${terms.economics.kind === "erc20-to-ln" ? terms.economics.lightning_principal_sat : ""} sat. ` +
      `Refund address ${lock.refundAddress}. Refundable from block ${lock.timelock}.` +
      (record.lockTxHash ? ` Lock transaction ${record.lockTxHash}.` : " No lock transaction recorded.") +
      (record.preimage ? " The provider paid; the preimage is known." : "")),
    node("p", "Verified locally against the provider's signature. Checking the chain and refunding connect to the configured EVM RPC and your wallet only when you ask."),
    message, check, refund,
  );
  const openRpc = (): EvmRpc => (options.rpcFactory ?? ((url) => new EvmRpc(url)))(options.evmRpc());
  const inspect = async (): Promise<{ active: boolean; tip: number }> => {
    const rpc = openRpc();
    if (await rpc.chainId() !== asset.chain_id) throw new Error(`The configured EVM RPC is not chain ${asset.chain_id}`);
    const tip = await rpc.blockNumber();
    const active = await rpc.lockActive(asset.htlc_contract, lock);
    current();
    if (active) {
      message.textContent = tip >= lock.timelock
        ? `Still locked at block ${tip}. The timelock (${lock.timelock}) has passed: you can refund.`
        : `Still locked at block ${tip}. Refund possible from block ${lock.timelock} (${lock.timelock - tip} blocks, about ${Math.ceil((lock.timelock - tip) * asset.block_seconds / 60)} min).`;
    } else {
      const claim = await rpc.findClaim(asset.htlc_contract, lock.preimageHash, Math.max(0, tip - 10_000), tip).catch(() => null);
      message.textContent = claim ? `Claimed by the provider in ${claim.txHash}; the invoice was paid. Nothing to refund.`
        : "Not locked: either refunded already or never locked. Nothing to refund.";
    }
    refund.disabled = !(active && tip >= lock.timelock);
    return { active, tip };
  };
  check.onclick = () => {
    if (busy) return;
    busy = true; check.disabled = true;
    message.textContent = "Checking the lock on the configured EVM RPC...";
    void inspect().catch((error: unknown) => { message.textContent = `Could not check: ${error instanceof Error ? error.message : "unknown error"}`; })
      .finally(() => { busy = false; check.disabled = false; });
  };
  refund.onclick = () => {
    if (busy) return;
    busy = true; check.disabled = refund.disabled = true;
    void (async () => {
      const rpc = openRpc();
      const { wallet, account } = await connectEvmWallet(rpc, asset);
      if (account !== lock.refundAddress) throw new Error(`Connect the wallet account ${lock.refundAddress}; the refund pays only that address`);
      current();
      message.textContent = "Confirm the refund in your wallet...";
      const txHash = await wallet.send(account, asset.htlc_contract, encodeRefund(lock));
      message.textContent = `Refund ${txHash} submitted; waiting for confirmation...`;
      const receipt = await awaitReceipt(rpc, txHash, 1);
      message.textContent = receipt.status ? `Refunded in ${txHash}. ${tokenLabel(lock.amount, asset)} returned to ${account}.`
        : `Refund ${txHash} reverted. Check the lock status again; the timelock or the lock state may have changed.`;
    })().catch((error: unknown) => { message.textContent = `Refund stopped: ${error instanceof Error ? error.message : "unknown error"}`; refund.disabled = false; })
      .finally(() => { busy = false; check.disabled = false; });
  };
  return () => { disposed = true; };
}

/** Persisted terms and exposure state are independent: stale URL files cannot reset the journal. */
function reverseEvmRecoveryControls(root: HTMLElement, record: EvmRecoveryRecord, options: EvmRecoveryOptions): () => void {
  const terms = record.terms;
  if (terms.profile_id !== "ln-to-erc20/v1") throw new Error("not reverse EVM recovery");
  const plaintext = Uint8Array.from(options.plaintext), journal = new EvmClaimJournal();
  let disposed = false, busy = false;
  const current = (): void => { if (disposed) throw new Error("Recovery view closed"); options.assertCurrent(); };
  const message = node("p", "Payment and claim status are unknown until you explicitly check the chain.", "swap-evm-recovery-message");
  const check = node("button", "Check lock status", "swap-evm-recovery-check"); check.type = "button";
  const sponsorConfig = record.claimKey !== null ? options.sponsor?.() ?? null : null;
  const claim = node("button", sponsorConfig ? "Claim through the gas sponsor" : "Claim with your EVM wallet", "swap-evm-recovery-claim"); claim.type = "button"; claim.disabled = true;
  claim.className = "primary";
  root.replaceChildren(node("h3", `Lightning to ${terms.evm_asset.token_symbol} recovery verified`),
    node("p", `${tokenLabel(record.lock.amount, terms.evm_asset)} to ${record.lock.claimAddress}` +
      (record.claimDestination ? `, forwarded to ${record.claimDestination}` : "") + `. Provider refund block ${record.lock.timelock}. ` +
      "Keep the preimage private until a confirmed token lock has enough time left. A failed claim request may still disclose it."), message, check, claim);
  if (record.claimKey !== null && !sponsorConfig) root.append(node("p", "This record's claim key lives in this browser; configure the gas sponsor in Settings to claim without a wallet.", "swap-evm-recovery-note"));
  // Do not redisplay an old hold invoice on reload: it may have been paid already.
  const rpc = (): EvmRpc => (options.rpcFactory ?? ((url) => new EvmRpc(url)))(options.evmRpc());
  check.onclick = () => {
    if (busy) return; busy = true; check.disabled = claim.disabled = true;
    void (async () => {
      current(); const chain = rpc();
      if (await chain.chainId() !== terms.evm_asset.chain_id) throw new Error("Wrong EVM chain");
      await chain.verifyHtlc(terms.evm_asset.htlc_contract);
      const tip = await chain.blockNumber();
      const found = await chain.findClaim(terms.evm_asset.htlc_contract, record.lock.preimageHash, Math.max(0, terms.evm_reference_block - 12), tip);
      current();
      if (found) {
        message.textContent = record.claimKey !== null
          ? `Claim observed in ${found.txHash}; sponsored completion is unverified. This record does not retain the submitted operation proof. Inspect the exact payout; do not retry automatically.`
          : `Tokens claimed in ${found.txHash}. The provider can settle the Lightning hold.`;
        return;
      }
      const entry = await journal.read(record.contractHash); current();
      if (!entry || entry.exposure !== "unexposed") {
        message.textContent = "Claim exposure is unknown (or this browser has no exposure journal). No automatic retry is allowed. Keep the recovery file and inspect any pending wallet transaction.";
        return;
      }
      await assertSafeEvmClaim(chain, terms, record.preimage!, sponsorConfig ? "sponsored" : "wallet"); current();
      message.textContent = sponsorConfig ? "Exact confirmed token lock is active with a safe claim window. Claim through the gas sponsor."
        : "Exact confirmed token lock is active with a safe claim window. Connect the wallet that receives the tokens to claim.";
      claim.disabled = !(sponsorConfig || record.claimKey === null);
    })().catch((error: unknown) => { if (!disposed) message.textContent = `Check stopped: ${error instanceof Error ? error.message : "unknown error"}`; })
      .finally(() => { busy = false; if (!disposed) check.disabled = false; });
  };
  claim.onclick = () => {
    if (busy) return; busy = true; check.disabled = claim.disabled = true;
    void (async () => {
      current(); const chain = rpc();
      let claimer: LnErc20Claimer;
      if (sponsorConfig) {
        if (!record.claimDestination) throw new Error("Recovery record has no token destination");
        claimer = { kind: "sponsored", sponsor: (options.sponsorFactory ?? ((config) => new GasSponsor(config)))({ ...sponsorConfig, chainId: terms.evm_asset.chain_id }), secret: hexToBytes(record.claimKey!), destination: record.claimDestination };
      } else {
        const { wallet, account } = await connectEvmWallet(chain, terms.evm_asset);
        if (account !== terms.client_evm_address) throw new Error("Connect the signed token destination's wallet account");
        claimer = { kind: "wallet", wallet, account };
      }
      if (!options.ageRecipient) throw new Error("Recovery encryption key unavailable");
      const recipient = await options.ageRecipient(); current();
      const safety = await assertSafeEvmClaim(chain, terms, record.preimage!, claimer.kind);
      if (claimer.kind === "wallet") await claimer.wallet.assertAccount(terms.evm_asset.chain_id, claimer.account); current();
      await journal.expose(record.contractHash); current();
      assertFreshEvmClaim(safety);
      message.textContent = claimer.kind === "wallet" ? "Confirm the claim in your wallet. The preimage may be disclosed even if the request fails."
        : "Claiming through the gas sponsor. The preimage is disclosed to it even if the request fails.";
      let hash: string, sponsored: { txHash: string; proof: SponsoredClaimProof } | null = null;
      if (claimer.kind === "wallet") {
        hash = await claimer.wallet.send(claimer.account, terms.evm_asset.htlc_contract, encodeClaim(record.lock, record.preimage!));
      } else {
        sponsored = await sponsoredClaim(chain, claimer, record.lock, record.preimage!, terms.evm_asset.htlc_contract, (line) => { message.textContent = line; });
        hash = sponsored.txHash;
      }
      const document = JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
      document.claim_tx_hash = hash; document.updated_at = Math.floor(Date.now() / 1000);
      await journal.save(record.contractHash, await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(document)!), recipient));
      const receipt = await awaitReceipt(chain, hash, terms.settlement_confirmations);
      if (receipt.status && sponsored) await chain.verifySponsoredClaim(hash, sponsored.proof, terms.settlement_confirmations);
      current(); message.textContent = receipt.status ? `Tokens claimed in ${hash}. The provider can settle the Lightning hold.`
        : "Claim reverted after preimage exposure. Inspect the chain and Lightning payment; do not assume a refund.";
    })().catch((error: unknown) => { if (!disposed) message.textContent = `Claim stopped: ${error instanceof Error ? error.message : "unknown error"}`; })
      .finally(() => { busy = false; if (!disposed) check.disabled = false; });
  };
  return () => { disposed = true; plaintext.fill(0); };
}

export async function mountLnErc20Execution(panel: HTMLElement, options: {
  readonly prepared: PreparedLnErc20Execution; readonly rpc: EvmRpc; readonly claimer: LnErc20Claimer;
  readonly journal: EvmClaimJournal; readonly status: (message: string, step: number, state?: string) => void;
  readonly report: (line: string) => void; readonly download: (root: HTMLElement, file: Uint8Array, name: string) => void;
  readonly signal?: AbortSignal;
  readonly onActivity?: ActivityObserver;
}): Promise<void> {
  const { prepared, rpc, claimer, journal } = options, asset = prepared.terms.evm_asset;
  const files = node("section", "", "swap-erc20-files"), invoice = node("section"), message = node("p", "Preparing durable recovery before exposing the invoice");
  panel.replaceChildren(message, invoice, files);
  let sponsored: { txHash: string; proof: SponsoredClaimProof } | null = null;
  const outcome = await prepared.execute({
    rpc, report: options.report,
    onActivity: (event) => { options.onActivity?.(event); const progress = activityStatus(event); message.textContent = progress.text; options.status(progress.text, progress.step); },
    saveRecovery: async (file, stage, contract) => {
      if (stage === "terms") await journal.create(contract, file); else await journal.save(contract, file);
      options.download(files, file, `rillswap-ln-to-${asset.token_symbol.toLowerCase()}-${stage}.age`);
    },
    showInvoice: (bolt11) => {
      invoice.replaceChildren(node("h3", `Pay ${prepared.terms.economics.hold_invoice_sat} sat from any Lightning wallet`),
        node("p", "No Lightning node connection is needed. Your payment stays held until the token claim reveals the preimage."),
        qrSvg(`lightning:${bolt11}`, "QR code of the Lightning invoice", "swap-reverse-invoice-qr"),
        node("code", bolt11, "swap-reverse-invoice"));
      const open = node("a", "Open in Lightning wallet"); open.href = `lightning:${bolt11}`; invoice.append(open);
    },
    checkWallet: async () => { if (claimer.kind === "wallet") await claimer.wallet.assertAccount(asset.chain_id, claimer.account); },
    markExposure: (contract) => journal.expose(contract),
    claimGas: claimer.kind,
    claim: async (lock, preimage, htlc) => {
      if (claimer.kind === "wallet") return claimer.wallet.send(claimer.account, htlc, encodeClaim(lock, preimage));
      sponsored = await sponsoredClaim(rpc, claimer, lock, preimage, htlc, (line) => { options.report(line); message.textContent = line; }, options.signal);
      return sponsored.txHash;
    },
    ...(claimer.kind === "sponsored" ? { verifyClaim: async (txHash: string) => {
      if (!sponsored || sponsored.txHash !== txHash) throw new EvmError("Submitted sponsored operation proof is unavailable");
      await rpc.verifySponsoredClaim(txHash, sponsored.proof, prepared.terms.settlement_confirmations);
    } } : {}),
  });
  invoice.replaceChildren();
  message.textContent = `${tokenLabel(BigInt(prepared.terms.economics.payout_token_base), asset)} received in ${outcome.claimTxHash}.`;
  options.status("Stablecoins received", 4, "success");
}
