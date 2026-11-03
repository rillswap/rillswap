/** Explicitly approved recovery actions. Durable intent precedes any export or POST. */
import canonicalize from "canonicalize";
import { hexToBytes } from "@noble/hashes/utils.js";
import { BrowserRefundJournal, type RefundJournalRecord } from "./browserRefundJournal";
import { constructRecoveryOutpointRefund, constructSelectedRecoveryRefund, inspectRecoveryPlaintext, verifyRecoveryOutpointRefund, verifySelectedRecoveryRefund, type RecoveryRefundSelection } from "./recoveryInspection";
import { observeRecoveryFunding, observeRecoveryOutpoint } from "./recoveryFunding";
import { readBoundedChainText, type ChainFetch } from "./swap/chainTip";
import { validateMempoolApi, type NetworkName } from "./swap/config";
import { MAX_RECOVERY_PLAINTEXT_BYTES } from "./recoveryAgeContainer";

type Network = { readonly name: NetworkName; readonly genesis_hash: string };
interface ApprovedAction {
  readonly broadcastApi: string;
  /** Check the immutable user-approved file, network, destination, fee, API, and revision selection. */
  readonly assertCurrent: () => void;
  readonly signal?: AbortSignal;
  readonly fetch?: ChainFetch;
}
export class BrowserRefundRefusedError extends Error {
  constructor() { super("Refund action refused. Keep your backups and inspect the saved intent before trying again."); this.name = "BrowserRefundRefusedError"; }
}
const require = (condition: boolean): void => { if (!condition) throw new BrowserRefundRefusedError(); };
function documentSnapshot(value: Uint8Array): Uint8Array {
  require(value instanceof Uint8Array && value.length > 0 && value.length <= MAX_RECOVERY_PLAINTEXT_BYTES);
  return Uint8Array.from(value);
}
function reauthorize(document: Uint8Array, network: Network, selection: RecoveryRefundSelection, api: string, record: RefundJournalRecord): void {
  require(canonicalize(record.networkIdentity) === canonicalize(network) && record.api === api);
  if (!("kind" in selection) && !("selection" in record)) {
    require(record.fundingAttemptId === selection.fundingAttemptId && record.bindingRevision === selection.bindingRevision);
  }
  // Cross-mode loading preserves the exact stored variant, bytes and exposure state.
  // Each mode still authenticates its own selected actual output against the original document.
  // History-mode admission remains strict, so non-policy deposits stay outpoint-mode only.
  const verified = "kind" in selection ?
    verifyRecoveryOutpointRefund(document, network, selection, hexToBytes(record.rawFundingTransactionHex), hexToBytes(record.refund.transactionHex)) :
    verifySelectedRecoveryRefund(document, network, selection, hexToBytes(record.rawFundingTransactionHex), hexToBytes(record.refund.transactionHex));
  require(canonicalize(verified) === canonicalize(record.refund));
}

/** Called only after explicit destination/fee approval, never on import, page load, or polling. */
export async function prepareBrowserRefund(
  plaintext: Uint8Array, independentNetwork: Network, selection: RecoveryRefundSelection, base: string, feeSat: bigint, options: ApprovedAction,
): Promise<RefundJournalRecord> {
  let document: Uint8Array | undefined, journal: BrowserRefundJournal | undefined;
  try {
    options = { ...options };
    document = documentSnapshot(plaintext);
    const network = structuredClone(independentNetwork), chosen = { ...selection }, api = validateMempoolApi(base, network.name);
    require(typeof options.broadcastApi === "string");
    const broadcastApi = validateMempoolApi(options.broadcastApi!, network.name);
    const report = inspectRecoveryPlaintext(document, network);
    require(typeof feeSat === "bigint" && feeSat >= 0n && feeSat <= BigInt(report.maxRefundFeeSat));
    let fundingTxid: string, fundingVout: number;
    if ("kind" in chosen) {
      require(chosen.kind === "outpoint" && /^[0-9a-f]{64}$/.test(chosen.fundingTxid) && Number.isSafeInteger(chosen.fundingVout) && chosen.fundingVout >= 0 && chosen.fundingVout <= 0xffffffff);
      fundingTxid = chosen.fundingTxid; fundingVout = chosen.fundingVout;
    } else {
      const matches = report.fundingHistory.filter((b) => b.funding_attempt_id === chosen.fundingAttemptId && b.binding_revision === chosen.bindingRevision);
      require(matches.length === 1);
      fundingTxid = matches[0]!.funding_txid; fundingVout = matches[0]!.contract_vout;
    }
    options.assertCurrent(); options.signal?.throwIfAborted();
    journal = await BrowserRefundJournal.open();
    const stored = await journal.get(network, fundingTxid, fundingVout);
    options.assertCurrent(); options.signal?.throwIfAborted();
    if (stored) {
      reauthorize(document, network, chosen, api, stored);
      require(stored.refund.feeSat === feeSat.toString());
      require(stored.broadcastApi === broadcastApi);
      return stored; // Never re-sign a saved plan, including an ambiguous exposed plan.
    }
    const observation = await observeSelected(document, network, chosen, api, options);
    require(observation.refundMatureAtObservedTip);
    options.assertCurrent(); options.signal?.throwIfAborted();
    const input = { rawFundingTransaction: hexToBytes(observation.rawFundingTransactionHex), sampledTipHeight: observation.tipHeight, feeSat };
    const refund = "kind" in chosen ? constructRecoveryOutpointRefund(document, network, { ...chosen, ...input }) :
      constructSelectedRecoveryRefund(document, network, { ...chosen, ...input });
    options.assertCurrent(); options.signal?.throwIfAborted();
    return await journal.prepare({ networkIdentity: network, api, broadcastApi,
      ...("kind" in chosen ? { selection: "outpoint" as const } : chosen), rawFundingTransactionHex: observation.rawFundingTransactionHex, refund });
  } catch { /* Redact all crypto, imported-document, storage, and endpoint errors. */ }
  finally { journal?.close(); document?.fill(0); }
  throw new BrowserRefundRefusedError();
}

function observeSelected(document: Uint8Array, network: Network, selection: RecoveryRefundSelection, api: string, options: ApprovedAction) {
  return "kind" in selection ? observeRecoveryOutpoint(document, network, selection, api, options) :
    observeRecoveryFunding(document, network, selection, api, options);
}

/** Manual identical-byte export remains available after UNKNOWN/accepted, without authorizing a POST. */
export async function exportBrowserRefund(
  plaintext: Uint8Array, independentNetwork: Network, selection: RecoveryRefundSelection, base: string, expected: RefundJournalRecord, options: ApprovedAction,
): Promise<RefundJournalRecord> {
  let document: Uint8Array | undefined, journal: BrowserRefundJournal | undefined;
  try {
    options = { ...options };
    document = documentSnapshot(plaintext);
    const network = structuredClone(independentNetwork), chosen = { ...selection }, api = validateMempoolApi(base, network.name);
    const record = structuredClone(expected);
    reauthorize(document, network, chosen, api, record);
    require(validateMempoolApi(options.broadcastApi, network.name) === record.broadcastApi);
    options.assertCurrent(); options.signal?.throwIfAborted();
    journal = await BrowserRefundJournal.open();
    if (record.state !== "prepared") return await journal.reexportIdentical(record);
    const observation = await observeSelected(document, network, chosen, api, options);
    require(observation.refundMatureAtObservedTip && observation.rawFundingTransactionHex === record.rawFundingTransactionHex);
    options.assertCurrent(); options.signal?.throwIfAborted();
    return await journal.beginExposure(record);
  } catch { /* Failure never resets a durable exposure marker. */ }
  finally { journal?.close(); document?.fill(0); }
  throw new BrowserRefundRefusedError();
}

export interface RefundBroadcastOutcome { readonly outcome: "accepted" | "unknown"; readonly txid: string }

/** One POST, only following this invocation's successful atomic exposure transition. */
export async function broadcastBrowserRefund(
  plaintext: Uint8Array, independentNetwork: Network, selection: RecoveryRefundSelection, base: string, expected: RefundJournalRecord, options: ApprovedAction,
): Promise<RefundBroadcastOutcome> {
  let document: Uint8Array | undefined, journal: BrowserRefundJournal | undefined;
  try {
    options = { ...options };
    document = documentSnapshot(plaintext);
    const network = structuredClone(independentNetwork), chosen = { ...selection }, api = validateMempoolApi(base, network.name);
    const record = structuredClone(expected);
    require(record.state === "prepared");
    reauthorize(document, network, chosen, api, record);
    require(validateMempoolApi(options.broadcastApi, network.name) === record.broadcastApi);
    options.assertCurrent(); options.signal?.throwIfAborted();
    const observation = await observeSelected(document, network, chosen, api, options);
    require(observation.refundMatureAtObservedTip && observation.rawFundingTransactionHex === record.rawFundingTransactionHex);
    options.assertCurrent(); options.signal?.throwIfAborted();
    journal = await BrowserRefundJournal.open();
    options.assertCurrent(); options.signal?.throwIfAborted();
    const exposed = await journal.beginExposure(record);
    // From here every failure is potentially exposed. No rollback or retry.
    try {
      options.assertCurrent(); options.signal?.throwIfAborted();
      const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000);
      const response = await (options.fetch ?? fetch)(`${exposed.broadcastApi}/tx`, { method: "POST", body: exposed.refund.transactionHex,
        headers: { "Content-Type": "text/plain" }, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer", signal });
      const txid = await readBoundedChainText(response, signal);
      require(txid === exposed.refund.txid);
      await journal.markAccepted(exposed, txid);
      return Object.freeze({ outcome: "accepted", txid });
    } catch { return Object.freeze({ outcome: "unknown", txid: exposed.refund.txid }); }
  } catch { /* Admission or exposure-commit failure grants no submission permission. */ }
  finally { journal?.close(); document?.fill(0); }
  throw new BrowserRefundRefusedError();
}
