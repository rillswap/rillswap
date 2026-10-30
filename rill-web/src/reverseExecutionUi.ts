/** One reverse swap step at a time, with a shared live/Resume claim driver. */
import canonicalize from "canonicalize";
import { BrowserReverseJournal } from "./browserReverseJournal";
import { BrowserHoldPayer } from "./swap/browserHoldPayer";
import { browserCosigner } from "./swap/browserCosigner";
import { explorerTxUrl, validateMempoolApi, type NetworkName } from "./swap/config";
import { readBoundedChainText, readChainTip, readNextBlockFeeRate } from "./swap/chainTip";
import { quoteTiming, type TimingMarket } from "./swap/quoteTiming";
import { notifyActivity } from "./swap/notifications";
import { activityFacts, emitActivity, type ActivityObserver, type ActivityName, type ActivityFacts } from "./swap/activity";
import { parseStrictEventJson } from "./strictEventJson";
import { qrSvg } from "./qr";
import { RecoveryFundingUnavailableError } from "./recoveryFunding";
import type { PreparedReverseQuote } from "./swap/reverseSwap";
import type { PreparedReverseExecution } from "./swap/reverseExecution";
import { makerCostText, miningAllowanceDetails } from "./swapUiStatus";

function node<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", id = ""): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag); element.textContent = text; if (id) element.id = id; return element;
}
function input(root: HTMLElement, label: string, id: string, value = ""): HTMLInputElement {
  const caption = node("label", label), field = node("input", "", id); field.value = value; field.autocomplete = "off"; field.spellcheck = false;
  caption.htmlFor = id; root.append(caption, field); return field;
}
function button(root: HTMLElement, text: string, id: string): HTMLButtonElement {
  const control = node("button", text, id); control.type = "button"; root.append(control); return control;
}
function txLink(api: string, txid: string, label: string): HTMLAnchorElement {
  const link = node("a", label); link.href = explorerTxUrl(api, txid); link.target = "_blank"; link.rel = "noopener noreferrer"; return link;
}

interface ReverseProgressOptions {
  readonly onActivity?: ActivityObserver;
  readonly network: { readonly name: NetworkName; readonly genesis_hash: string };
  readonly chainApi: string;
  readonly broadcastApi: string;
  readonly assertCurrent: () => void;
  readonly status: (message: string, step: number) => void;
  readonly download: (root: HTMLElement, file: Uint8Array, name: string) => void;
  readonly saved?: (file: Uint8Array) => void;
  /** The swap log: fixed, secret-free lines such as why the claim was not cooperative. */
  readonly report?: (line: string) => void;
}
export interface ReverseExecutionUiOptions extends ReverseProgressOptions {
  readonly prepared: PreparedReverseQuote;
  readonly destinationScript: string;
  readonly ageRecipient: string;
  readonly nodeApi: string;
  /** Claim below the signed funding depth (0: from the mempool); absent waits for the signed depth. */
  readonly claimConfirmations?: number;
  readonly timingMarket?: TimingMarket | null;
}
type ClaimExecution = Pick<PreparedReverseExecution, "terms" | "record" | "recoveryFile" | "claimFeeSat" | "claimDepth" | "lowerClaimDepth" | "funding" | "fundingDepth" | "receiveFunding" | "prepareClaim" | "exposeClaim" | "dispose">;

/** Wallets without hold invoice support may give up on a payment that is still held (as the CLI says). */
const DO_NOT_PAY_AGAIN = "Until the claim settles it, your wallet may show the payment as pending, or as failed after a timeout; this is normal. Do not pay again.";

/** The double-spend risk of claiming below the signed depth, or null at the signed depth. */
export function earlyClaimWarning(depth: number, signed: number): string | null {
  if (depth >= signed) return null;
  const funding = depth === 0 ? "unconfirmed funding" : `funding at ${depth} confirmation${depth === 1 ? "" : "s"}`;
  return `Claiming on ${funding}, below the provider's signed ${signed}. Claiming reveals the payment secret, which lets the provider ` +
    "settle your Lightning payment; until its funding is buried it can still double-spend it and keep both. " +
    "Only lower this for providers and amounts you are willing to lose.";
}

function view(root: HTMLElement, e: ClaimExecution, options: ReverseProgressOptions) {
  const screen = node("section", "", "swap-reverse-steps"), advanced = node("details", "", "swap-reverse-advanced");
  const message = node("p", "", "swap-reverse-message"), backups = node("div", "", "swap-reverse-backups");
  // The shown invoice stays reachable after funding, while the wallet may still report it as pending or failed.
  const payment = node("section", "", "swap-reverse-payment"); payment.hidden = true;
  advanced.append(node("summary", "Advanced"));
  const maximum = BigInt(e.terms.economics.claim_fee_reserve_sat) < BigInt(e.terms.max_claim_fee_sat)
    ? e.terms.economics.claim_fee_reserve_sat : e.terms.max_claim_fee_sat;
  const fee = input(advanced, "Claim network fee (sat)", "swap-reverse-claim-fee", e.claimFeeSat ?? maximum);
  // Spend the signed reserve by default. An arbitrary low manual fee can strand a one-shot claim.
  fee.readOnly = true;
  advanced.append(backups);
  const backup = (file: Uint8Array): void => {
    for (const old of backups.querySelectorAll<HTMLAnchorElement>("a")) if (old.href.startsWith("blob:")) URL.revokeObjectURL(old.href);
    backups.replaceChildren(); options.download(backups, file, "rillswap-ln-to-btc-backup.age");
    const link = backups.querySelector("a"); if (link) link.textContent = "Download swap backup";
    options.saved?.(file);
  };
  root.replaceChildren(screen, payment, advanced, message);
  return { screen, payment, advanced, message, fee, backup };
}

/** The invoice shown for an external wallet, with its payment hash. */
function paymentDetails(e: ClaimExecution, open: boolean): { notes: HTMLParagraphElement; details: HTMLDetailsElement } | null {
  const intent = e.record.payment;
  if (intent?.state !== "external-wallet") return null;
  const details = node("details", "", "swap-reverse-payment-details");
  details.append(node("summary", "Your Lightning invoice"), node("p", `${BigInt(e.terms.economics.hold_invoice_sat).toLocaleString()} sat, payment hash:`),
    node("pre", intent.paymentHash, "swap-reverse-payment-hash"));
  const bolt11 = intent.bolt11, link = node("a", "Open in your wallet", "swap-reverse-payment-uri"); link.href = `lightning:${bolt11}`;
  details.append(qrSvg(`lightning:${bolt11}`, "QR code of the Lightning invoice", "swap-reverse-payment-qr"), node("pre", bolt11, "swap-reverse-payment-invoice"), link);
  const copy = button(details, "Copy invoice", "swap-reverse-payment-copy");
  copy.onclick = () => { void navigator.clipboard?.writeText(bolt11).then(() => { copy.textContent = "Copied"; }, () => {}); };
  details.open = open;
  return { notes: node("p", "", "swap-reverse-payment-notes"), details };
}

/** `claimNowOffered`: Advanced offers the explicit mempool claim. */
function paymentNotes(e: ClaimExecution, claimNowOffered: boolean): string {
  const stage = e.record.stage;
  if (stage === "payment-unknown") {
    const expires = new Date(e.terms.invoice_binding.expires_at * 1000).toLocaleString();
    return `If your wallet has not sent this payment, pay it once before ${expires}. If it did, do not pay again: the provider locks the Bitcoin once it holds your payment.`;
  }
  if (stage === "claim-unknown" || stage === "accepted") return "Your claim lets the provider settle this payment. Do not pay again.";
  return `The provider locked the Bitcoin, so it holds your payment. ${DO_NOT_PAY_AGAIN}` +
    (claimNowOffered ? " If your wallet gives up waiting, Advanced can claim now from the mempool, at a double-spend risk." : "");
}

async function claimConfirmed(api: string, txid: string, network: ReverseProgressOptions["network"], signal: AbortSignal): Promise<boolean> {
  const timeout = AbortSignal.any([signal, AbortSignal.timeout(15000)]), tip = await readChainTip(api, network, { signal: timeout });
  const get = async (path: string, limit: number) => readBoundedChainText(await fetch(`${api}/${path}`, { signal: timeout,
    credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" }), timeout, limit);
  const inclusion = parseStrictEventJson(await get(`tx/${txid}/status`, 4096), 4096) as Record<string, unknown>;
  if (inclusion.confirmed !== true || typeof inclusion.block_height !== "number" || !Number.isSafeInteger(inclusion.block_height) ||
    inclusion.block_height < 1 || inclusion.block_height > tip.height || typeof inclusion.block_hash !== "string" || !/^[0-9a-f]{64}$/.test(inclusion.block_hash)) return false;
  return await get(`block-height/${inclusion.block_height}`, 64) === inclusion.block_hash;
}

/**
 * Only this driver advances a paid live or explicitly resumed swap. UNKNOWN stages are read-only.
 * `resumed`: no live payment screen shows the invoice, so it is shown before funding too.
 */
function drive(v: ReturnType<typeof view>, e: ClaimExecution, options: ReverseProgressOptions, signal: AbortSignal,
  flow: { readonly settlement?: () => Promise<string | null>; readonly resumed?: boolean } = {}): void {
  const { settlement, resumed = false } = flow;
  let reference: string | undefined;
  try { reference = e.record.context?.sessionId ?? e.record.id; } catch { /* Diagnostic identity is optional. */ }
  const observe = (name: ActivityName, facts: ActivityFacts = {}): void => {
    try {
      const details = { ...activityFacts(e.terms), profile: "ln-to-btc/v1", ...(reference ? { session_id: reference } : {}), ...facts };
      emitActivity(options.onActivity, name, details);
      notifyActivity({ name, facts: details }, reference);
    } catch { /* Optional diagnostic metadata cannot stop a live claim watcher. */ }
  };
  observe("terms.verified");
  const api = validateMempoolApi(options.chainApi, options.network.name), broadcastApi = validateMempoolApi(options.broadcastApi, options.network.name);
  const current = (): void => { signal.throwIfAborted(); options.assertCurrent(); };
  let busy = false, terminal = false, notifiedConfirmation = false;
  const check = button(v.advanced, "Check now", "swap-reverse-funding");
  const exported = button(v.advanced, "Download exact signed fallback", "swap-reverse-export"); exported.hidden = true;
  // After funding, an explicit, risk-accepted earlier claim for wallets that give up on a held payment.
  const signed = e.terms.funding_confirmations, claimNowWarning = earlyClaimWarning(0, signed) ?? "";
  const claimNow = node("section", "", "swap-reverse-claim-now-controls"), consent = node("input", "", "swap-reverse-claim-now-consent");
  const consentLabel = node("label", " I accept this risk for this swap"), claimNowButton = node("button", "Claim now from the mempool (risky)", "swap-reverse-claim-now");
  consent.type = "checkbox"; consentLabel.prepend(consent); claimNowButton.type = "button"; claimNowButton.disabled = true; claimNow.hidden = true;
  claimNow.append(node("p", claimNowWarning, "swap-reverse-claim-now-warning"), consentLabel, claimNowButton); v.advanced.append(claimNow);
  consent.onchange = () => { claimNowButton.disabled = !consent.checked; };
  let payment: ReturnType<typeof paymentDetails> = null;
  const refresh = (): void => {
    const stage = e.record.stage, offered = !terminal && (stage === "funded" || stage === "claim-ready") && e.claimDepth > 0;
    claimNow.hidden = !offered;
    if (!resumed && stage === "payment-unknown") return; // the live payment screen still shows the invoice
    payment ??= paymentDetails(e, resumed && stage === "payment-unknown");
    if (payment === null) return;
    if (v.payment.hidden) { v.payment.replaceChildren(payment.notes, payment.details); v.payment.hidden = false; }
    payment.notes.textContent = paymentNotes(e, offered);
  };
  claimNowButton.onclick = () => {
    if (!consent.checked || signal.aborted) return;
    try { current(); e.lowerClaimDepth(0); } catch { if (!signal.aborted) v.message.textContent = "The claim can no longer be moved earlier."; return; }
    options.report?.(`warning: ${claimNowWarning}`); options.report?.("claim now: claiming from the mempool by your choice");
    consent.checked = false; claimNowButton.disabled = true; refresh(); void advance();
  };
  const showClaim = (txid: string): void => {
    v.screen.replaceChildren(node("h2", "Confirming your claim"), node("p", e.record.stage === "claim-unknown"
      ? "Not confirmed yet. You can download the signed fallback below and broadcast it manually." : "Your Bitcoin is on its way."),
      txLink(api, txid, "View claim transaction"));
    exported.hidden = false;
  };
  const advance = async (): Promise<void> => {
    if (busy || terminal || signal.aborted) return;
    busy = true; check.disabled = true;
    try {
      current(); refresh();
      if (e.record.stage === "payment-unknown") {
        try { const file = await e.receiveFunding(10000); current(); v.backup(file); v.message.textContent = ""; observe("funding.received"); }
        catch { current(); v.message.textContent = "Waiting for the provider to lock the Bitcoin. Do not pay again."; return; }
        refresh();
      }
      if (e.record.stage === "funded") {
        v.screen.replaceChildren(node("h2", "Locking Bitcoin"), node("p", "Checking confirmations...", "swap-reverse-funding-status"));
        if (e.funding) v.screen.append(txLink(api, e.funding.txid, "View deposit transaction"));
        options.status("Waiting for Bitcoin confirmations", 2);
        let depth: number;
        try { depth = await e.fundingDepth(api); current(); }
        catch { current(); v.message.textContent = "Waiting for confirmation data from your mempool API."; return; }
        v.screen.querySelector("p")!.textContent = `${depth} of ${e.claimDepth} confirmations`;
        observe("funding.depth", { confirmations: depth, required_confirmations: e.claimDepth });
        if (depth < e.claimDepth) return;
        const fee = v.fee.value.trim();
        if (!/^(0|[1-9][0-9]{0,15})$/.test(fee)) throw new Error("Invalid fee");
        v.fee.disabled = true;
        v.screen.replaceChildren(node("h2", "Claiming your Bitcoin")); options.status("Claiming your Bitcoin", 3);
        const prepared = await e.prepareClaim(api, BigInt(fee), current); current(); v.backup(prepared.recoveryFile);
      }
      if (e.record.stage === "claim-ready") {
        v.fee.disabled = true;
        v.screen.replaceChildren(node("h2", "Claiming your Bitcoin")); options.status("Claiming your Bitcoin", 3);
        const result = await e.exposeClaim(api, broadcastApi, "broadcast", current); current();
        showClaim(result.txid);
        options.status(`Claim ${result.outcome}: ${result.txid}`, 3);
        observe(result.outcome === "accepted" ? "claim.submitted" : "claim.unknown", { txid: result.txid });
        if (result.outcome === "unknown") v.message.textContent = "Submission is uncertain. Checking the chain without sending again.";
      }
      if (e.record.stage === "claim-unknown" || e.record.stage === "accepted") {
        const txid = e.record.claim!.txid; showClaim(txid);
        let confirmed = false;
        try { confirmed = await claimConfirmed(api, txid, options.network, signal); current(); } catch { current(); }
        if (!confirmed) return;
        let payment: string | null = null;
        try { if (settlement) payment = await settlement(); current(); } catch { current(); }
        v.screen.replaceChildren(node("h2", "Bitcoin received"), txLink(api, txid, "View claim transaction"));
        const awaitingNode = settlement !== undefined && payment !== "SUCCEEDED";
        options.status(payment === "SUCCEEDED" ? "Swap complete. Bitcoin received and Lightning payment settled" :
          awaitingNode ? "Bitcoin received. Waiting for Lightning settlement" : "Bitcoin claim confirmed", awaitingNode ? 3 : 4);
        v.message.textContent = payment === "SUCCEEDED" ? "Swap complete." : awaitingNode
          ? "Checking your node's original payment. It will not be paid again." : "Your wallet reports the Lightning payment's settlement.";
        if (!notifiedConfirmation) { observe("claim.confirmed", { txid }); notifiedConfirmation = true; }
        terminal = !awaitingNode;
      } else if (e.record.stage === "terms-ready" || e.record.stage === "secrets-ready") {
        v.screen.replaceChildren(node("h2", "No payment was started here"), node("p", "This saved record cannot start or repeat a payment.")); terminal = true;
      }
    } catch (error) {
      if (!signal.aborted && error instanceof RecoveryFundingUnavailableError && (e.record.stage === "funded" || e.record.stage === "claim-ready")) {
        v.message.textContent = "Waiting for fresh Bitcoin funding data. Your saved fallback is kept.";
      } else if (!signal.aborted) { v.message.textContent = "Swap paused. Open it from Your swaps to inspect the saved state; uncertain payments and claims are never retried.";
        observe("swap.attention"); terminal = true; }
    } finally { busy = false; check.disabled = signal.aborted; if (!signal.aborted) refresh(); }
  };
  check.onclick = () => { void advance(); };
  exported.onclick = () => {
    if (busy || signal.aborted) return;
    busy = true; exported.disabled = true;
    void e.exposeClaim(api, broadcastApi, "download", current).then((result) => {
      current(); if (result.transactionHex) options.download(v.advanced, new TextEncoder().encode(result.transactionHex), "rillswap-signed-claim.hex");
    }).catch(() => { if (!signal.aborted) v.message.textContent = "Could not export the saved claim. Keep the swap backup."; })
      .finally(() => { busy = false; exported.disabled = false; });
  };
  void (async () => {
    while (!signal.aborted && !terminal) {
      await advance();
      if (signal.aborted || terminal) break;
      await new Promise<void>((resolve) => {
        const finish = (): void => { clearTimeout(timer); signal.removeEventListener("abort", finish); resolve(); };
        const timer = setTimeout(finish, 5000); signal.addEventListener("abort", finish, { once: true });
      });
    }
  })();
}

/** Resume must be explicitly chosen; merely listing or opening saved records has no claim side effects. */
export function mountResumedReverseExecution(root: HTMLElement, execution: ClaimExecution, options: ReverseProgressOptions): () => void {
  const cancellation = new AbortController(), v = view(root, execution, options); v.backup(execution.recoveryFile);
  const stopped = (): void => { cancellation.abort(); execution.dispose(); window.removeEventListener("pagehide", stopped); };
  window.addEventListener("pagehide", stopped, { once: true });
  drive(v, execution, options, cancellation.signal, { resumed: true }); return stopped;
}

/** The signed price review authorizes the bounded automatic claim, not any new Lightning payment. */
export async function mountReverseExecution(root: HTMLElement, options: ReverseExecutionUiOptions): Promise<() => void> {
  options = { ...options, network: structuredClone(options.network) };
  const cancellation = new AbortController(); let execution: PreparedReverseExecution | undefined;
  const current = (): void => { cancellation.signal.throwIfAborted(); options.assertCurrent(); };
  const journal = await BrowserReverseJournal.open();
  const stopped = (): void => { cancellation.abort(); execution?.dispose(); journal.close(); window.removeEventListener("pagehide", stopped); };
  window.addEventListener("pagehide", stopped, { once: true });
  try {
    current(); options.status("Checking signed final terms", 0);
    const api = validateMempoolApi(options.chainApi, options.network.name), tip = await readChainTip(api, options.network); current();
    // No estimate, no swap: the claim reserve must pay at least the next-block rate.
    const claimFeeRateSatKvb = await readNextBlockFeeRate(api, options.network.name, { signal: cancellation.signal }); current();
    execution = await options.prepared.prepareExecution({ destinationScript: options.destinationScript, tipHeight: tip.height, claimFeeRateSatKvb,
      ageRecipient: options.ageRecipient, journal, cooperation: browserCosigner, assertCurrent: current,
      ...(options.claimConfirmations !== undefined ? { claimConfirmations: options.claimConfirmations } : {}),
      ...(options.report ? { report: options.report } : {}) }); current();
    const e = execution, terms = e.terms, v = view(root, e, options); v.backup(e.recoveryFile);
    v.screen.append(node("h2", `Pay ${BigInt(terms.economics.hold_invoice_sat).toLocaleString()} sat`),
      node("p", `Receive at least ${BigInt(terms.economics.nominal_payout_sat).toLocaleString()} sat in Bitcoin. Your wallet's routing fee is extra.`),
      node("p", "After payment, this page checks confirmations and claims your Bitcoin automatically."));
    const fees = e.feeBreakdown;
    const timing = quoteTiming({ profile: "ln-to-btc/v1", fundingConfirmations: e.claimDepth,
      ...(fees ? { fundingRate: Number(fees.feerate_sat_kvb) / 1000 } : {}),
      claimFeeSat: BigInt(terms.economics.claim_fee_reserve_sat), destinationScriptBytes: options.destinationScript.length / 2 }, options.timingMarket ?? null);
    const time = node("p", timing.text, "swap-reverse-time"); time.className = "swap-time-estimate"; time.title = timing.tooltip;
    v.screen.append(node("p", `${makerCostText(BigInt(terms.economics.success_fee_sat), fees)} Claim mining fee: ${BigInt(terms.economics.claim_fee_reserve_sat).toLocaleString()} sat (included in the Lightning total).`),
      time);
    v.advanced.append(node("small", timing.detail));
    if (fees) v.advanced.append(node("small", `${miningAllowanceDetails(fees)} Accept before ${new Date(terms.terms_expiry * 1000).toLocaleTimeString()}.`));
    // Before any payment: the client's own lower claim depth risks a provider double-spend.
    const warning = earlyClaimWarning(e.claimDepth, terms.funding_confirmations);
    if (warning !== null) { v.screen.append(node("p", warning, "swap-reverse-early-claim")); options.report?.(`warning: ${warning}`); }
    const accept = button(v.screen, "Accept and show the invoice", "swap-reverse-accept");
    accept.className = "primary";
    const nodeControls = node("section"); v.advanced.append(nodeControls);
    const afterPayment = (settlement?: () => Promise<string | null>): void => {
      nodeControls.remove(); v.message.textContent = "Waiting for the provider to lock the Bitcoin.";
      drive(v, e, options, cancellation.signal, settlement ? { settlement } : {});
    };
    accept.onclick = () => {
      accept.disabled = true;
      void (async () => {
        await e.accept(current); current(); const invoice = await e.exposeInvoice(current); current(); nodeControls.remove();
        options.status("Pay the invoice from your Lightning wallet", 1);
        const open = node("a", "Open in your wallet", "swap-reverse-invoice-uri"); open.href = `lightning:${invoice.bolt11}`;
        v.screen.replaceChildren(node("h2", `Pay ${terms.economics.hold_invoice_sat} sat`),
          qrSvg(`lightning:${invoice.bolt11}`, "QR code of the Lightning invoice", "swap-reverse-invoice-qr"),
          node("pre", invoice.bolt11, "swap-reverse-invoice"), open,
          node("p", "Pay it once; your wallet shows it as pending until Bitcoin is locked and claimed, because only your browser holds the secret needed to settle it.", "swap-reverse-invoice-notes"));
        const copy = button(v.screen, "Copy invoice", "swap-reverse-invoice-copy");
        copy.onclick = () => { void navigator.clipboard?.writeText(invoice.bolt11).then(() => { copy.textContent = "Copied"; }, () => {}); };
        afterPayment();
      })().catch(() => { if (!cancellation.signal.aborted) v.message.textContent = "Could not continue. Keep the saved swap; no payment will be retried."; });
    };
    const endpoint = input(nodeControls, "LND REST endpoint (optional)", "swap-reverse-node-api", options.nodeApi);
    const identity = input(nodeControls, "Pinned node compressed public key", "swap-reverse-node-identity");
    const credential = input(nodeControls, "Scoped macaroon (this tab only)", "swap-reverse-macaroon"); credential.type = "password";
    const routingFee = input(nodeControls, "Maximum routing fee (sat)", "swap-reverse-routing-fee", "1000");
    const connect = button(nodeControls, "Accept and connect configured Lightning node", "swap-reverse-connect");
    connect.onclick = () => {
      accept.disabled = connect.disabled = true;
      void (async () => {
        current(); const nodeApi = validateMempoolApi(endpoint.value.trim(), options.network.name), feeValue = routingFee.value.trim();
        if (!/^(0|[1-9][0-9]{0,15})$/.test(feeValue)) throw new Error("Invalid routing fee");
        let macaroon = credential.value.trim(), key = identity.value.trim();
        if (options.network.name === "regtest" && !macaroon && !key) {
          const signal = AbortSignal.timeout(10000), response = await fetch(nodeApi + "/configuration", { signal, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" });
          const data = parseStrictEventJson(await readBoundedChainText(response, signal, 16384), 16384) as Record<string, unknown>;
          current(); if (Object.keys(data).sort().join() !== "macaroon,network_identity,node_identity" || canonicalize(data.network_identity) !== canonicalize(options.network) ||
            typeof data.macaroon !== "string" || typeof data.node_identity !== "string") throw new Error("Node configuration mismatch");
          macaroon = data.macaroon; key = data.node_identity;
        }
        current(); const payer = new BrowserHoldPayer({ endpoint: nodeApi, macaroon, nodeIdentity: key, network: options.network }); credential.value = "";
        endpoint.disabled = identity.disabled = credential.disabled = routingFee.disabled = true;
        await e.accept(current); current();
        const approval = (): void => { current(); if (endpoint.value.trim() !== nodeApi || routingFee.value.trim() !== feeValue) throw new Error("Node selection changed"); };
        const plan = await e.planPayment(payer, nodeApi, BigInt(feeValue), approval); approval();
        v.screen.replaceChildren(node("h2", "Approve your Lightning payment"), node("p", `${terms.economics.hold_invoice_sat} sat plus ${plan.feeMsat} msat routing fee.`));
        const pay = button(v.screen, "Pay this exact Lightning route once", "swap-reverse-pay");
        pay.className = "primary";
        pay.onclick = () => { pay.disabled = true; void (async () => {
          await e.pay(payer, plan, nodeApi, approval); current(); v.screen.replaceChildren(node("h2", "Locking Bitcoin"));
          afterPayment(() => payer.status(plan.paymentHash, plan.invoiceBinding.amount_msat));
        })().catch(() => { v.message.textContent = "Payment outcome is uncertain. Resume the saved swap without paying again."; }); };
      })().catch(() => { if (!cancellation.signal.aborted) v.message.textContent = "Could not connect or prepare the payment. No payment will be retried."; });
    };
    return stopped;
  } catch (error) {
    stopped();
    root.replaceChildren(node("p", "Could not prepare this swap. No payment was started."), node("small", (error as Error).message, "swap-reverse-prepare-error"));
    return stopped;
  }
}
