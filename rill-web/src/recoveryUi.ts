/** Explicit local recovery import and separately approved refund actions. Never uploads keys or imports. */
import { MAX_RECOVERY_CIPHERTEXT_BYTES } from "./recoveryAgeContainer";
import { decryptRecoveryContainer } from "./recoveryKeys";
import { inspectRecoveryPlaintext, type RecoveryInspection, type RecoveryRefundSelection } from "./recoveryInspection";
import { observeRecoveryFunding, observeRecoveryOutpoint, RecoveryFundingSpentError } from "./recoveryFunding";
import { discoverRecoveryDeposits, type RecoveryDepositCandidate } from "./recoveryDiscovery";
import { reverseRecoveryControls } from "./reverseRecoveryUi";
import { evmRecoveryControls } from "./erc20Ui";
import { identityToRecipient } from "age-encryption";
import { parseRecoveryPlaintext } from "./recoveryDocument";
import type { EvmSponsorDefaults, NetworkName } from "./swap/config";
import { scriptAddress } from "./swap/address";
import { prepareBrowserRefund, exportBrowserRefund, broadcastBrowserRefund } from "./browserRefund";
import type { RefundJournalRecord } from "./browserRefundJournal";
import { parseWalletBackup, recoveryKeyFromWords, walletRecoveryKey } from "./browserRecoveryWallet";
import { recoveryTiming } from "./recoveryTiming";

interface RecoveryUiOptions {
  /** Chosen by the user outside the file, including the complete chain identity. */
  readonly selectedNetwork: () => { readonly name: string; readonly identity: unknown };
  readonly browserIdentity: () => Promise<string>;
  readonly selectedChainApi: () => string;
  readonly selectedBroadcastApi: () => string;
  readonly selectedRelays?: () => readonly string[];
  /** RS-010 records check and refund through this endpoint and the injected wallet. */
  readonly selectedEvmRpc?: () => string;
  readonly selectedEvmSponsor?: () => EvmSponsorDefaults | null;
}

function element<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", id?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.textContent = text;
  if (id) node.id = id;
  return node;
}

/** Format sniff only; `evmRecoveryControls` authenticates the record. */
function isEvmRecovery(plaintext: Uint8Array): boolean {
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
    return typeof parsed === "object" && parsed !== null && (parsed as { format?: unknown }).format === "rillswap-evm-recovery";
  } catch { return false; }
}

/** Public controls needed by the owning Settings UI, without exposing imported state. */
export interface RecoveryPanel {
  readonly element: HTMLElement;
  clearFundingObservation(): void;
  /** Open the panel on an in-memory recovery container (for example from a swap link) and inspect it locally. */
  load(file: Uint8Array, name: string, source?: "link" | "saved"): void;
}

/** A collapsed panel with local imports and explicitly requested, report-only chain reads. */
export function recoveryPanel(options: RecoveryUiOptions): RecoveryPanel {
  const details = element("details", "", "swap-recovery");
  const intro = element("section");
  intro.append(element("p",
    "Open an encrypted swap recovery file using your saved browser key. " +
    "Choose the original swap's network in Settings. Files and keys stay on this device."), element("p",
    "Recovering on another site or browser also requires the original recovery words or key backup. " +
    "The encrypted .age file cannot be opened with the network alone. There is no domain restriction, but each site has separate browser key storage."));
  details.append(element("summary", "Recover a swap"), intro);
  const loaded = element("section", "", "swap-recovery-loaded"); loaded.hidden = true;
  const loadedTitle = element("h3"), loadedHelp = element("p");
  loaded.append(loadedTitle, loadedHelp);
  const fileChoice = element("details", "", "swap-recovery-file-choice"); fileChoice.open = true;
  const fileSummary = element("summary", "Choose a recovery file");
  const fileLabel = element("label", "Encrypted swap recovery file (.age)");
  const file = element("input", "", "swap-recovery-file");
  file.type = "file";
  file.accept = ".age";
  fileLabel.htmlFor = file.id;
  fileChoice.append(fileSummary, fileLabel, file);
  details.append(loaded, fileChoice);
  const olderKey = element("details", "", "swap-recovery-key");
  const keySummary = element("summary", "Use a saved recovery key (optional)");
  olderKey.append(keySummary, element("p",
    "Enter the original site's 12 words or choose its key backup. This is required if the file uses a different key from this browser's saved key. " +
    "One mnemonic can unlock many swap files; your browser's saved key is not replaced."));
  const wordsLabel = element("label", "12-word recovery key"), words = element("input", "", "swap-recovery-words");
  words.type = "password"; words.autocomplete = "off"; words.spellcheck = false; words.maxLength = 4096; wordsLabel.htmlFor = words.id;
  olderKey.append(wordsLabel, words);
  const keyLabel = element("label", "Recovery key backup (.json, .key or .age-key)");
  const keyFile = element("input", "", "swap-recovery-key-file");
  keyFile.type = "file";
  keyFile.accept = ".json,.key,.age-key,.txt";
  keyLabel.htmlFor = keyFile.id;
  olderKey.append(keyLabel, keyFile);
  const readIdentity = async (selectedKey: File | undefined, selectedWords: string): Promise<string> => {
    if (selectedKey && selectedWords.trim()) throw new Error("Choose words or a key file, not both");
    if (selectedWords.trim()) {
      const key = await recoveryKeyFromWords(selectedWords); key.file.fill(0); return key.identity;
    }
    if (!selectedKey) return options.browserIdentity();
    const text = await selectedKey.text();
    if (!text.trimStart().startsWith("{")) return text;
    const key = await walletRecoveryKey(parseWalletBackup(text)); key.file.fill(0); return key.identity;
  };
  const inspect = element("button", "Inspect recovery file", "swap-recovery-inspect");
  inspect.type = "button";
  inspect.className = "primary";
  const result = element("section", "", "swap-recovery-result");
  result.setAttribute("aria-live", "polite");
  const fundingControls = element("section", "", "swap-recovery-funding-controls");
  fundingControls.hidden = true;
  const txidLabel = element("label", "Deposit transaction ID (optional)");
  const txid = element("input", "", "swap-recovery-deposit-txid"); txid.type = "text"; txid.maxLength = 64; txid.spellcheck = false; txid.autocomplete = "off";
  txidLabel.htmlFor = txid.id;
  const discover = element("button", "Find deposits", "swap-recovery-find-deposits"); discover.type = "button";
  const discoveryActions = element("div"); discoveryActions.className = "recovery-actions"; discoveryActions.append(discover);
  const discoveryResult = element("section", "", "swap-recovery-discovery-result"); discoveryResult.setAttribute("aria-live", "polite");
  fundingControls.append(element("h3", "Find your escrow deposit"), element("p",
    "Your original terms backup can recover deposits without the provider or a recorded funding revision. Find deposits queries your selected chain API with the public escrow address, or only the transaction ID entered below. Your file and keys stay here."),
    txidLabel, txid, discoveryActions, discoveryResult);
  const revisionLabel = element("label", "Recorded funding revision");
  const revision = element("select", "", "swap-recovery-revision");
  revisionLabel.htmlFor = revision.id;
  const check = element("button", "Check funding", "swap-recovery-check-funding");
  check.type = "button";
  const checkActions = element("div"); checkActions.className = "recovery-actions"; checkActions.append(check);
  const fundingResult = element("section", "", "swap-recovery-funding-result");
  fundingResult.setAttribute("aria-live", "polite");
  fundingControls.append(revisionLabel, revision, element("p",
    "Check funding connects to the API selected in Settings for this attempt. It sends the selected public transaction ID, never your recovery file or key."), checkActions, fundingResult);
  const refundControls = element("section", "", "swap-refund-controls");
  const destination = element("p", "", "swap-refund-destination");
  const feeLabel = element("label", "Total refund transaction fee (sat)");
  const fee = element("input", "", "swap-refund-fee"); fee.type = "number"; fee.min = "0"; fee.step = "1";
  feeLabel.htmlFor = fee.id;
  const amount = element("p", "", "swap-refund-amount");
  // Preparing is the approval; no checkbox gates it. The consent note states what the button approves.
  const consent = element("p", "By preparing the refund you confirm you recognize this recovery file and control the refund address above, and approve the displayed destination and fee.", "swap-refund-consent");
  consent.className = "swap-consent";
  const prepare = element("button", "Approve and prepare refund", "swap-refund-prepare"); prepare.type = "button";
  prepare.className = "primary";
  const download = element("button", "Download signed transaction", "swap-refund-download"); download.type = "button"; download.hidden = true;
  const broadcast = element("button", "Broadcast refund", "swap-refund-broadcast"); broadcast.type = "button"; broadcast.hidden = true;
  broadcast.className = "primary";
  const refundResult = element("section", "", "swap-refund-result"); refundResult.setAttribute("aria-live", "polite");
  const prepareActions = element("div"), exposureActions = element("div");
  prepareActions.className = exposureActions.className = "recovery-actions";
  prepareActions.append(prepare); exposureActions.append(download, broadcast);
  refundControls.append(element("h3", "Refund to the signed destination"), destination, feeLabel, fee, amount,
    element("p", "An imported file cannot prove ownership of this address. Verify it in your wallet before approving. The signed destination cannot be changed."),
    element("p", "After the timeout, a refund can still race a provider claim if the provider learned the payment preimage. Check your Lightning wallet; an API observation cannot eliminate that race."),
    consent, prepareActions, exposureActions, refundResult);
  fundingControls.append(refundControls);
  details.append(olderKey, inspect, result, fundingControls);
  let busy = false;
  let disposeReverse: (() => void) | undefined;
  let inspected: RecoveryInspection | undefined;
  let pendingInvalidated = false;
  let prepared: RefundJournalRecord | undefined;
  let candidates: readonly RecoveryDepositCandidate[] = [];
  const invalidateRefund = (): void => { prepared = undefined; download.hidden = broadcast.hidden = true; refundResult.replaceChildren(); };
  const candidateKey = (candidate: RecoveryDepositCandidate): string => `outpoint:${candidate.fundingTxid}:${candidate.fundingVout}`;
  const selectedFunding = (): { selection: RecoveryRefundSelection; valueSat: string } | undefined => {
    const candidate = candidates.find((item) => candidateKey(item) === revision.value);
    if (candidate) return { selection: { kind: "outpoint", fundingTxid: candidate.fundingTxid, fundingVout: candidate.fundingVout }, valueSat: candidate.valueSat };
    const binding = inspected?.fundingHistory.find((item) => String(item.binding_revision) === revision.value);
    return binding ? { selection: { fundingAttemptId: binding.funding_attempt_id, bindingRevision: binding.binding_revision }, valueSat: binding.contract_value_sat } : undefined;
  };
  const recordedOptions = () => inspected!.fundingHistory.map((binding) => Object.assign(element("option",
    `Revision ${binding.binding_revision} · ${binding.funding_txid.slice(0, 12)}...`), { value: String(binding.binding_revision) }));

  const clear = (): void => {
    disposeReverse?.(); disposeReverse = undefined;
    pendingInvalidated = true; invalidateRefund();
    if (!busy) { result.replaceChildren(); fundingResult.replaceChildren(); discoveryResult.replaceChildren(); candidates = []; fundingControls.hidden = true; inspected = undefined; }
  };
  file.onchange = () => {
    intro.hidden = false; loaded.hidden = true; fileChoice.open = true; fileSummary.textContent = "Choose a recovery file";
    keySummary.textContent = "Use a saved recovery key (optional)"; inspect.textContent = "Inspect recovery file";
    clear();
  };
  keyFile.onchange = clear;
  words.oninput = clear;
  const show = (report: RecoveryInspection): void => {
    inspected = report;
    candidates = []; txid.value = ""; discoveryResult.replaceChildren();
    invalidateRefund();
    destination.textContent = `Refund address: ${scriptAddress(report.destinationScript, report.networkName)}`;
    fee.max = report.maxRefundFeeSat;
    fee.value = (BigInt(report.maxRefundFeeSat) < 300n ? BigInt(report.maxRefundFeeSat) : 300n).toString();
    revision.replaceChildren(...recordedOptions());
    revision.value = String(report.fundingHistory.at(-1)?.binding_revision ?? "");
    revisionLabel.textContent = "Recorded funding revision";
    revisionLabel.hidden = revision.hidden = report.fundingHistory.length <= 1;
    fundingControls.hidden = false;
    fundingResult.replaceChildren();
    result.replaceChildren(element("h3", "Recovery record verified"),
      element("p", `${report.networkName} · BTC to Lightning · ${report.recordedBindingCount} recorded funding revision${report.recordedBindingCount === 1 ? "" : "s"}.`),
      element("p", `The signed refund lock is block ${report.refundLockHeight}. The first eligible block is ${report.firstRefundEligibleHeight}.`),
      element("p", recoveryTiming({ profile: "btc-to-ln/v1", network: report.networkName, refundLockHeight: report.refundLockHeight }), "swap-recovery-time"),
      element("p", "This verifies consistency with the file's embedded signers, not its provenance or your ownership of the refund address. " +
        "Funding, unspent state, and refund maturity have not been checked."),
      element("p", "Local inspection did not connect, sign, or broadcast. Refund signing requires separate approval below."));
    updateAmount();
  };
  inspect.onclick = () => {
    if (busy) return;
    // Snapshot file objects and the independent network before the first await.
    const selectedFile = file.files?.[0], selectedKey = keyFile.files?.[0], selectedWords = words.value;
    const selected = options.selectedNetwork();
    const expectedNetwork = structuredClone(selected.identity);
    if (!selectedFile || selectedFile.size === 0 || selectedFile.size > MAX_RECOVERY_CIPHERTEXT_BYTES ||
      (selectedKey && (selectedKey.size === 0 || selectedKey.size > 4096))) {
      result.replaceChildren(element("p", "Choose a nonempty encrypted recovery file (at most 256 KiB) and, if needed, an age key file (at most 4 KiB)."));
      return;
    }
    busy = true;
    disposeReverse?.(); disposeReverse = undefined;
    inspected = undefined; fundingControls.hidden = true; fundingResult.replaceChildren();
    file.disabled = keyFile.disabled = words.disabled = inspect.disabled = true;
    result.replaceChildren(element("p", "Opening and verifying locally..."));
    void (async () => {
      let plaintext: Uint8Array | undefined;
      try {
        const identity = await readIdentity(selectedKey, selectedWords);
        plaintext = await decryptRecoveryContainer(new Uint8Array(await selectedFile.arrayBuffer()), identity);
        if (isEvmRecovery(plaintext)) {
          pendingInvalidated = false;
          const assertCurrent = (): void => { if (pendingInvalidated || options.selectedNetwork().name !== selected.name || file.files?.[0] !== selectedFile || keyFile.files?.[0] !== selectedKey || words.value !== selectedWords) throw new Error("Recovery selection changed"); };
          assertCurrent();
          disposeReverse = evmRecoveryControls(result, { plaintext, network: expectedNetwork, evmRpc: options.selectedEvmRpc ?? (() => ""),
            ...(options.selectedEvmSponsor ? { sponsor: options.selectedEvmSponsor } : {}), ageRecipient: () => identityToRecipient(identity), assertCurrent });
          return;
        }
        if (parseRecoveryPlaintext(plaintext).document.profile_id === "ln-to-btc/v1") {
          pendingInvalidated = false;
          const assertCurrent = (): void => { if (pendingInvalidated || options.selectedNetwork().name !== selected.name || file.files?.[0] !== selectedFile || keyFile.files?.[0] !== selectedKey || words.value !== selectedWords) throw new Error("Recovery selection changed"); };
          assertCurrent();
          disposeReverse = reverseRecoveryControls(result, { plaintext, identity, network: expectedNetwork as { name: NetworkName; genesis_hash: string },
            chainApi: options.selectedChainApi, broadcastApi: options.selectedBroadcastApi, relays: options.selectedRelays ?? (() => []), assertCurrent });
          return;
        }
        const report = inspectRecoveryPlaintext(plaintext, expectedNetwork);
        if (options.selectedNetwork().name !== selected.name || file.files?.[0] !== selectedFile || keyFile.files?.[0] !== selectedKey || words.value !== selectedWords) throw new Error("Selection changed");
        show(report);
      } catch {
        // No parser/crypto/wallet error, raw input, path, filename, or secret becomes a UI diagnostic.
        if (!plaintext) {
          olderKey.open = true;
          result.replaceChildren(element("p", "Could not verify this recovery file. The encrypted file could not be opened with this key. " +
            "If it came from another site or browser, enter the original recovery words or key backup in the recovery key section above. " +
            "This site cannot read another site's browser-stored key. Keep your original backups; nothing was changed or uploaded."));
        } else {
          result.replaceChildren(element("p", "Could not verify this recovery file. The file decrypted, but its record could not be verified for the current selection. " +
            "Check the original network and keep your original backups; nothing was changed or uploaded."));
        }
      } finally {
        // Best-effort byte clearing, not a guarantee for immutable strings or decrypter copies.
        plaintext?.fill(0);
        busy = false;
        file.disabled = keyFile.disabled = words.disabled = inspect.disabled = false;
        if (inspected) updateAmount();
      }
    })();
  };
  const updateAmount = (): void => {
    const funding = selectedFunding();
    check.disabled = prepare.disabled = busy || !funding;
    amount.textContent = funding && /^(0|[1-9][0-9]{0,15})$/.test(fee.value) ?
      `Refund amount: ${(BigInt(funding.valueSat) - BigInt(fee.value)).toString()} sat, minus no further provider fee. Signed fee cap: ${inspected!.maxRefundFeeSat} sat. Selected output value: ${funding.valueSat} sat.` :
      funding ? "Choose a valid total fee." : "Find and explicitly select a deposit output before approving a refund.";
  };
  revision.onchange = () => { pendingInvalidated = true; fundingResult.replaceChildren(); invalidateRefund(); updateAmount(); };
  fee.oninput = () => { pendingInvalidated = true; invalidateRefund(); updateAmount(); };
  txid.oninput = () => { pendingInvalidated = true; invalidateRefund(); };
  discover.onclick = () => {
    if (busy || !inspected) return;
    const selectedFile = file.files?.[0], selectedKey = keyFile.files?.[0], selectedWords = words.value, transactionId = txid.value.trim().toLowerCase();
    if (!selectedFile || (transactionId && !/^[0-9a-f]{64}$/.test(transactionId))) {
      discoveryResult.replaceChildren(element("p", "Enter a 64-character transaction ID, or leave it empty to search the escrow address.")); return;
    }
    const selected = options.selectedNetwork(), network = structuredClone(selected.identity) as { name: NetworkName; genesis_hash: string };
    let api: string;
    try { api = options.selectedChainApi(); } catch { discoveryResult.replaceChildren(element("p", "Check the chain API in Settings. No connection was made.")); return; }
    busy = true; pendingInvalidated = false; invalidateRefund();
    file.disabled = keyFile.disabled = words.disabled = inspect.disabled = discover.disabled = txid.disabled = revision.disabled = check.disabled = fee.disabled = prepare.disabled = true;
    discoveryResult.replaceChildren(element("p", "Looking for deposits with your selected API..."));
    void (async () => {
      let plaintext: Uint8Array | undefined;
      try {
        const identity = await readIdentity(selectedKey, selectedWords);
        plaintext = await decryptRecoveryContainer(new Uint8Array(await selectedFile.arrayBuffer()), identity);
        const discovery = await discoverRecoveryDeposits(plaintext, network, api, transactionId ? { transactionId } : {});
        if (pendingInvalidated || options.selectedNetwork().name !== selected.name || options.selectedChainApi() !== api ||
          file.files?.[0] !== selectedFile || keyFile.files?.[0] !== selectedKey || words.value !== selectedWords || txid.value.trim().toLowerCase() !== transactionId) throw new Error("Selection changed");
        candidates = discovery.candidates;
        revision.replaceChildren(Object.assign(element("option", "Choose an output to check and recover"), { value: "" }), ...recordedOptions(),
          ...candidates.map((candidate) => Object.assign(element("option",
            `${candidate.fundingTxid}:${candidate.fundingVout} · ${candidate.valueSat} sat${candidate.matchesQuotedAmount ? "" : " (differs from quoted amount)"}`), { value: candidateKey(candidate) })));
        revision.value = ""; revisionLabel.textContent = "Select funding output"; revisionLabel.hidden = revision.hidden = false;
        fundingResult.replaceChildren();
        discoveryResult.replaceChildren(element("p", `Found ${candidates.length} matching output${candidates.length === 1 ? "" : "s"}. Select each output separately; nothing is selected automatically.`),
          element("p", candidates.length ? "Candidates are not proof of confirmed or unspent funds. Check the selected output before approving its refund." :
            "No matching deposit was found by this lookup. This is not proof that no deposit exists. Enter its transaction ID or try another chain API."),
          element("p", transactionId ? "Only the supplied transaction was checked, not the address history." : discovery.historyComplete ?
            "The API reported the end of its address history. This is not an independent or birthday-based full-chain scan." :
            "The bounded address search is incomplete or pagination is unavailable. Use a transaction ID for deposits not listed."),
          element("p", "Nothing was signed or broadcast."));
      } catch {
        discoveryResult.replaceChildren(element("p", "Deposit discovery unavailable. Check the file, key, network and chain API, or enter the deposit transaction ID. Keep your original backup. Nothing was signed or broadcast."));
      } finally {
        plaintext?.fill(0); busy = false;
        file.disabled = keyFile.disabled = words.disabled = inspect.disabled = discover.disabled = txid.disabled = revision.disabled = fee.disabled = false;
        updateAmount();
      }
    })();
  };
  check.onclick = () => {
    if (busy || !inspected) return;
    const selectedFile = file.files?.[0], selectedKey = keyFile.files?.[0], selectedWords = words.value;
    const selected = options.selectedNetwork(), expectedNetwork = structuredClone(selected.identity);
    const selectedRevision = revision.value;
    const funding = selectedFunding();
    if (!selectedFile || !funding || selectedFile.size === 0 || selectedFile.size > MAX_RECOVERY_CIPHERTEXT_BYTES ||
      (selectedKey && (selectedKey.size === 0 || selectedKey.size > 4096))) return;
    let api: string;
    try { api = options.selectedChainApi(); }
    catch { fundingResult.replaceChildren(element("p", "Check the chain API in Settings. No connection was made.")); return; }
    busy = true;
    pendingInvalidated = false;
    file.disabled = keyFile.disabled = words.disabled = inspect.disabled = check.disabled = revision.disabled = discover.disabled = txid.disabled = true;
    fundingResult.replaceChildren(element("p", "Checking funding with your selected API..."));
    void (async () => {
      let plaintext: Uint8Array | undefined;
      try {
        const identity = await readIdentity(selectedKey, selectedWords);
        plaintext = await decryptRecoveryContainer(new Uint8Array(await selectedFile.arrayBuffer()), identity);
        const observedAt = Date.now();
        const network = expectedNetwork as { name: NetworkName; genesis_hash: string };
        const observation = "kind" in funding.selection ? await observeRecoveryOutpoint(plaintext, network, funding.selection, api) :
          await observeRecoveryFunding(plaintext, network, funding.selection, api);
        if (pendingInvalidated || options.selectedNetwork().name !== selected.name || options.selectedChainApi() !== api || revision.value !== selectedRevision ||
          file.files?.[0] !== selectedFile || keyFile.files?.[0] !== selectedKey || words.value !== selectedWords) throw new Error("Selection changed");
        fundingResult.replaceChildren(element("h3", "Funding observed by your API"),
          element("p", `${observation.confirmations} confirmation${observation.confirmations === 1 ? "" : "s"} · observed tip ${observation.tipHeight}.`),
          element("p", observation.refundMatureAtObservedTip ? "The refund lock has passed at this observed tip." :
            `Waiting for a tip above block ${observation.refundLockHeight}. The refund lock has not passed yet.`),
          element("p", recoveryTiming({ profile: "btc-to-ln/v1", network: observation.networkName, refundLockHeight: observation.refundLockHeight,
            observation: { height: observation.tipHeight, observedAt } }), "swap-recovery-observed-time"),
          element("p", "Repeated API responses agree on confirmed, unspent funding. These are trusted observations, not independent chain proof or permission to sign."),
          element("p", "Nothing was signed or broadcast by this funding check. Refund signing requires separate approval."));
      } catch (error) {
        fundingResult.replaceChildren(element("p", error instanceof RecoveryFundingSpentError
          ? "Funding could not be verified as unspent: your API reports the selected revision's swap output already spent, so it cannot be refunded. " +
            "Usually the provider claimed it after paying your Lightning invoice (check your wallet), or a refund was already broadcast. Nothing was signed or broadcast."
          : "Funding could not be verified for the current selection. Check the file, key, network, API, and revision, then try again. Nothing was signed or broadcast."));
      } finally {
        plaintext?.fill(0); busy = false;
        file.disabled = keyFile.disabled = words.disabled = inspect.disabled = revision.disabled = discover.disabled = txid.disabled = false; updateAmount();
      }
    })();
  };
  const refundAction = (action: "prepare" | "export" | "broadcast"): void => {
    if (busy || !inspected || (action !== "prepare" && !prepared)) return;
    const selectedFile = file.files?.[0], selectedKey = keyFile.files?.[0], selectedWords = words.value, selectedRevision = revision.value, feeText = fee.value;
    const selected = options.selectedNetwork(), network = structuredClone(selected.identity) as { name: NetworkName; genesis_hash: string };
    const funding = selectedFunding();
    if (!selectedFile || !funding || selectedFile.size === 0 || selectedFile.size > MAX_RECOVERY_CIPHERTEXT_BYTES ||
      (selectedKey && (selectedKey.size === 0 || selectedKey.size > 4096)) || !/^(0|[1-9][0-9]{0,15})$/.test(feeText)) return;
    let api: string, broadcastApi: string;
    try { api = options.selectedChainApi(); broadcastApi = options.selectedBroadcastApi(); }
    catch { refundResult.replaceChildren(element("p", "Check your API settings before approving a refund.")); return; }
    const saved = prepared;
    pendingInvalidated = false; busy = true;
    file.disabled = keyFile.disabled = words.disabled = inspect.disabled = check.disabled = revision.disabled = fee.disabled = prepare.disabled = download.disabled = broadcast.disabled = discover.disabled = txid.disabled = true;
    refundResult.replaceChildren(element("p", action === "prepare" ? "Checking funding and preparing your approved refund..." : "Rechecking the approved refund..."));
    const assertCurrent = (): void => {
      if (pendingInvalidated || file.files?.[0] !== selectedFile || keyFile.files?.[0] !== selectedKey || words.value !== selectedWords || revision.value !== selectedRevision || fee.value !== feeText ||
        options.selectedNetwork().name !== selected.name || options.selectedChainApi() !== api || options.selectedBroadcastApi() !== broadcastApi) throw new Error("Approval changed");
    };
    void (async () => {
      let plaintext: Uint8Array | undefined;
      try {
        const identity = await readIdentity(selectedKey, selectedWords);
        plaintext = await decryptRecoveryContainer(new Uint8Array(await selectedFile.arrayBuffer()), identity);
        assertCurrent();
        const selection = funding.selection;
        const approved = { assertCurrent, broadcastApi };
        if (action === "prepare") {
          const record = await prepareBrowserRefund(plaintext, network, selection, api, BigInt(feeText), approved);
          assertCurrent(); prepared = record;
          refundResult.replaceChildren(element("h3", record.state === "prepared" ? "Refund prepared and saved" : "Previously exposed refund loaded"),
            element("p", `Transaction ID: ${record.refund.txid}`),
            element("p", record.state === "prepared" ? "Nothing has been exported or broadcast. Downloading exposes these spending bytes and disables application broadcast." :
              "This intent may already have been submitted. No automatic resend or replacement is permitted. You can download its identical signed bytes."));
        } else if (action === "export") {
          const record = await exportBrowserRefund(plaintext, network, selection, api, saved!, approved);
          assertCurrent(); prepared = record;
          const url = URL.createObjectURL(new Blob([record.refund.transactionHex + "\n"], { type: "text/plain" }));
          const link = element("a"); link.href = url; link.download = `rillswap-refund-${record.refund.txid}.hex`; link.click();
          setTimeout(() => URL.revokeObjectURL(url), 10000);
          refundResult.replaceChildren(element("h3", "Signed transaction exported"), element("p", "It may be broadcast outside this page. Application resend is disabled; keep the identical transaction and original recovery backup."));
        } else {
          const outcome = await broadcastBrowserRefund(plaintext, network, selection, api, saved!, approved);
          prepared = undefined;
          refundResult.replaceChildren(element("h3", outcome.outcome === "accepted" ? "Refund accepted by the API" : "Refund submission outcome unknown"),
            element("p", `Submitted selection: ${selected.name}, API ${broadcastApi}.`),
            element("p", `Transaction ID: ${outcome.txid}`), element("p", outcome.outcome === "accepted" ? "Acceptance is not confirmation. Do not submit another refund for this output." :
              "The transaction may have reached the network. It will not be retried. Load the saved intent to export identical bytes, never a replacement."));
        }
        download.hidden = !prepared; broadcast.hidden = prepared?.state !== "prepared";
      } catch {
        prepared = undefined; download.hidden = broadcast.hidden = true;
        refundResult.replaceChildren(element("p", "Refund action could not be completed. No automatic retry or replacement will occur. A saved intent may be prepared, unknown, or accepted; approve and load it again to inspect its state."));
      } finally {
        plaintext?.fill(0); busy = false;
        file.disabled = keyFile.disabled = words.disabled = inspect.disabled = revision.disabled = fee.disabled = download.disabled = broadcast.disabled = discover.disabled = txid.disabled = false; updateAmount();
      }
    })();
  };
  prepare.onclick = () => refundAction("prepare"); download.onclick = () => refundAction("export"); broadcast.onclick = () => refundAction("broadcast");
  return {
    element: details,
    clearFundingObservation() { pendingInvalidated = true; fundingResult.replaceChildren(); invalidateRefund(); },
    load(bytes, name, source = "saved") {
      // The same path as a chosen file: the input holds it, so every later action rechecks the same selection.
      const transfer = new DataTransfer();
      transfer.items.add(new File([Uint8Array.from(bytes)], name, { type: "application/octet-stream" }));
      file.files = transfer.files;
      clear();
      intro.hidden = true;
      loaded.hidden = false;
      loadedTitle.textContent = source === "link" ? "Encrypted swap loaded from your saved link" : "Encrypted swap loaded from this browser";
      loadedHelp.textContent = "Your encrypted recovery data is already loaded. You do not need to choose a separate .age file. " +
        "We will try this browser's saved key. If it does not unlock the swap, enter the original 12 words below or choose the original key backup, then unlock and inspect. " +
        "The link alone cannot decrypt your swap. Your words and keys stay on this device.";
      fileChoice.open = false; fileSummary.textContent = "Open a different recovery file";
      olderKey.open = true; keySummary.textContent = "Unlock with your original recovery key";
      inspect.textContent = "Unlock and inspect swap";
      details.open = true;
      inspect.click();
    },
  };
}
