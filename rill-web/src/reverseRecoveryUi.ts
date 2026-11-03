/** Imported reverse controls remain disconnected until an explicit action. */
import { inspectReverseRecoveryPlaintext } from "./recoveryInspection";
import { observeReverseRecoveryFunding, RecoveryFundingSpentError } from "./recoveryFunding";
import { loadBrowserReverseRecovery, recoverBrowserReverseFunding, prepareRecoveredReverseClaim, exposeRecoveredReverseClaim } from "./browserReverseRecovery";
import { scriptAddress } from "./swap/address";
import type { NetworkName } from "./swap/config";
import { recoveryTiming } from "./recoveryTiming";

function node<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", id = ""): HTMLElementTagNameMap[K] { const e = document.createElement(tag); e.textContent = text; if (id) e.id = id; return e; }
function button(root: HTMLElement, text: string, id: string): HTMLButtonElement { const e = node("button", text, id); e.type = "button"; root.append(e); return e; }
function download(root: HTMLElement, file: Uint8Array, name: string): void { const e = node("a", "Download " + name); e.href = URL.createObjectURL(new Blob([Uint8Array.from(file)])); e.download = name; root.append(e); }

export function reverseRecoveryControls(root: HTMLElement, options: {
  readonly plaintext: Uint8Array; readonly identity: string; readonly network: { readonly name: NetworkName; readonly genesis_hash: string };
  readonly chainApi: () => string; readonly broadcastApi: () => string; readonly relays: () => readonly string[]; readonly assertCurrent: () => void;
}): () => void {
  const document = Uint8Array.from(options.plaintext), network = structuredClone(options.network); let disposed = false, busy = false;
  const current = (): void => { if (disposed) throw new Error("Selection changed"); options.assertCurrent(); };
  const report = inspectReverseRecoveryPlaintext(document, network), message = node("p", "", "swap-reverse-recovery-message"), controls = node("section"), files = node("section");
  const lookupActions = node("div"); lookupActions.className = "recovery-actions"; controls.append(lookupActions);
  files.className = "recovery-backups";
  const timing = node("p", recoveryTiming({ profile: "ln-to-btc/v1", network: report.networkName,
    refundLockHeight: report.refundLockHeight, claimMarginBlocks: report.claimConfirmationBlocks }), "swap-reverse-recovery-time");
  let confirmSaved: (saved: { claimTxid: string | null; claimFeeSat: string | null; stage: string }) => void = () => {};
  root.replaceChildren(node("h3", "Lightning to Bitcoin recovery verified"), node("p", `${report.networkName} · ${report.fundingHistory.length} signed funding revision(s). Payout: ${scriptAddress(report.destinationScript, report.networkName)}.`),
    node("p", "This proves internal consistency under embedded signers, not provenance, ownership or current funding. Nothing connected or was paid. Recovery never accepts or pays another invoice."), timing, controls, files, message);
  const act = (control: HTMLButtonElement, run: () => Promise<void>): void => { control.onclick = () => {
    if (busy || disposed) return; busy = true; control.disabled = true;
    void run().catch((error: unknown) => {
      message.textContent = error instanceof RecoveryFundingSpentError
        ? "Your API reports this swap's Bitcoin lockup already spent, so there is nothing left to claim here. Usually your claim already went through " +
          "(check your wallet for the payout), or the provider refunded it after its refund height. Keep the originals. Nothing was broadcast."
        : "Recovery remains blocked for this selection. Keep the originals. No uncertain payment or claim will be retried.";
    })
      .finally(() => { busy = false; if (!disposed) control.disabled = control.dataset.locked === "true"; });
  }; };
  const local = button(lookupActions, "Inspect local execution state", "swap-reverse-recovery-local");
  act(local, async () => { current(); const saved = await loadBrowserReverseRecovery(document, options.identity, network); current();
    message.textContent = `Local state: ${saved.stage}. This is not a new payment authorization.`; download(files, saved.ciphertext, "rillswap-reverse-latest.age"); confirmSaved(saved); });
  const archive = button(lookupActions, "Recover signed funding from selected relays", "swap-reverse-recovery-archive");
  controls.append(node("small", "Archive lookup uses the original recipient key. It publishes nothing. Missing signed evidence cannot be inferred from a UTXO."));
  act(archive, async () => { current(); const relays = [...options.relays()], captured = relays.join("\n");
    const approve = (): void => { current(); if (options.relays().join("\n") !== captured) throw new Error("Relays changed"); };
    const file = await recoverBrowserReverseFunding(document, options.identity, network, relays, approve); approve();
    download(files, file, "rillswap-reverse-funded.age"); message.textContent = "Save and inspect this funded backup before continuing."; });
  if (report.fundingHistory.length) {
    const binding = report.fundingHistory.at(-1)!, selection = { fundingAttemptId: binding.funding_attempt_id, bindingRevision: binding.binding_revision };
    const check = button(lookupActions, "Check reverse funding with selected API", "swap-reverse-recovery-check");
    act(check, async () => { current(); const api = options.chainApi(), observedAt = Date.now(), observation = await observeReverseRecoveryFunding(document, network, selection, api); current();
      if (options.chainApi() !== api) throw new Error("API changed");
      timing.textContent = recoveryTiming({ profile: "ln-to-btc/v1", network: report.networkName, refundLockHeight: report.refundLockHeight,
        claimMarginBlocks: report.claimConfirmationBlocks, observation: { height: observation.tipHeight, observedAt } });
      message.textContent = `Trusted API: ${observation.confirmations} confirmations at block ${observation.tipHeight}. Required claim margin: ${report.claimConfirmationBlocks} blocks before first provider refund block ${report.refundLockHeight + 1}. This is not independent chain proof.`; });
    const feeLabel = node("label", "Claim network fee (sat)"), fee = node("input", "", "swap-reverse-recovery-fee"); fee.type = "number"; fee.min = "0";
    fee.value = report.fallbackFeeSat ?? String(BigInt(report.maxClaimFeeSat) < BigInt(report.claimFeeReserveSat) ? BigInt(report.maxClaimFeeSat) : BigInt(report.claimFeeReserveSat)); feeLabel.htmlFor = fee.id;
    // Each button is its own approval; the consent notes state what it approves. No checkbox gates them.
    const consent = node("p", "By preparing the claim you confirm you recognize this file, control the fixed payout address, approve this fee, and keep the funded backup. Prior exposure may be UNKNOWN; exporting or broadcasting reveals your preimage.", "swap-reverse-recovery-consent");
    consent.className = "swap-consent";
    controls.append(feeLabel, fee, consent);
    const prepareActions = node("div"); prepareActions.className = "recovery-actions"; controls.append(prepareActions);
    const prepare = button(prepareActions, "Approve and prepare recovery claim", "swap-reverse-recovery-prepare");
    prepare.className = "primary";
    const claimStatus = node("p", "First prepare a claim or inspect local execution state to obtain its exact encrypted backup.", "swap-reverse-recovery-claim-status");
    claimStatus.className = "swap-consent";
    controls.append(claimStatus); let savedClaimTxid = "";
    confirmSaved = (saved) => {
      savedClaimTxid = saved.claimTxid ?? "";
      if (saved.claimFeeSat !== null) fee.value = saved.claimFeeSat;
      claimStatus.textContent = savedClaimTxid ? `The exact encrypted backup for claim ${savedClaimTxid} is in your backups above. Exporting or broadcasting reveals its preimage; keep that backup.` : "No exact claim backup is prepared yet.";
      if (saved.stage === "claim-unknown" || saved.stage === "accepted") { broadcast.dataset.locked = "true"; broadcast.disabled = true; }
    };
    const capturedApproval = (): { feeSat: bigint; api: string; broadcastApi: string; check: () => void } => {
      const value = fee.value, api = options.chainApi(), broadcastApi = options.broadcastApi();
      if (!/^(0|[1-9][0-9]{0,15})$/.test(value)) throw new Error("Invalid fee");
      const check = (): void => { current(); if (fee.value !== value || options.chainApi() !== api || options.broadcastApi() !== broadcastApi) throw new Error("Approval changed"); };
      check(); return { feeSat: BigInt(value), api, broadcastApi, check };
    };
    act(prepare, async () => { const approval = capturedApproval();
      const file = await prepareRecoveredReverseClaim(document, options.identity, network, approval.api, approval.feeSat, approval.check); approval.check();
      download(files, file, "rillswap-reverse-claim.age");
      const saved = await loadBrowserReverseRecovery(document, options.identity, network); approval.check(); confirmSaved(saved);
      message.textContent = saved.stage === "claim-unknown" || saved.stage === "accepted"
        ? "Exact claim bytes are saved; prior exposure is unknown. Only identical manual export is available."
        : "Exact claim bytes are saved, not yet exposed. Keep the claim backup; export or broadcast it when ready."; });
    const exposureActions = node("div"); exposureActions.className = "recovery-actions"; controls.append(exposureActions);
    const exportClaim = button(exposureActions, "Approve and download exact saved claim", "swap-reverse-recovery-export"), broadcast = button(exposureActions, "Approve and broadcast saved claim once", "swap-reverse-recovery-broadcast");
    broadcast.className = "primary";
    const expose = async (action: "download" | "broadcast"): Promise<void> => { const approval = capturedApproval(), claimTxid = savedClaimTxid;
      const exposureApproved = (): void => { approval.check(); if (!claimTxid || savedClaimTxid !== claimTxid) throw new Error("No exact claim backup is prepared"); };
      exposureApproved(); broadcast.dataset.locked = "true"; broadcast.disabled = true;
      const result = await exposeRecoveredReverseClaim(document, options.identity, network, approval.api, approval.broadcastApi, approval.feeSat, claimTxid, action, exposureApproved); exposureApproved();
      if (result.transactionHex) download(files, new TextEncoder().encode(result.transactionHex), "rillswap-recovered-claim.hex");
      broadcast.disabled = true; message.textContent = `Claim ${result.outcome}: ${result.txid}. Exposure remains UNKNOWN; only identical manual export is available afterward.`;
    };
    act(exportClaim, () => expose("download")); act(broadcast, () => expose("broadcast"));
  }
  return () => { disposed = true; document.fill(0); };
}
