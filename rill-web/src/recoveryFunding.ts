/** Explicit, trusted-API funding observations. No signing, storage, retries, or broadcast. */
import { hexToBytes } from "@noble/hashes/utils.js";
import { MAX_RECOVERY_PLAINTEXT_BYTES } from "./recoveryAgeContainer";
import { checkRecoveryOutpointTransaction, checkSelectedRecoveryFundingTransaction, checkSelectedReverseFundingTransaction, inspectRecoveryPlaintext, inspectReverseRecoveryPlaintext, isSupportedRecoveryNetwork, type RecoveryFundingSelection, type RecoveryOutpointSelection, type RecoveryRefundSelection } from "./recoveryInspection";
import { parseStrictEventJson } from "./strictEventJson";
import { readBoundedChainText, readChainTip, type ChainFetch } from "./swap/chainTip";
import { validateMempoolApi, type NetworkName } from "./swap/config";
import { MAX_TRANSACTION_BYTES } from "./swap/transaction";

export interface RecoveryFundingObservation {
  /** Validated public bytes for a later, separately approved signing operation. Not UTXO proof. */
  readonly rawFundingTransactionHex: string;
  readonly observation: "trusted-api";
  readonly networkName: string;
  readonly fundingTxid: string;
  readonly fundingVout: number;
  /** Null only for reverse funding still in the mempool, observed on explicit request (0 confirmations). */
  readonly fundingBlockHeight: number | null;
  readonly fundingBlockHash: string | null;
  readonly confirmations: number;
  readonly tipHeight: number;
  readonly tipHash: string;
  readonly refundLockHeight: number;
  /** Height comparison only, NOT permission to sign or independent chain proof. */
  readonly refundMatureAtObservedTip: boolean;
}

export class RecoveryFundingUnavailableError extends Error {
  constructor() {
    super("Funding observation unavailable. Check the network, API, and selected revision, then try again.");
    this.name = "RecoveryFundingUnavailableError";
  }
}

/**
 * The API reported the authenticated, confirmed contract output as spent. Still
 * unavailable to every caller (no refund, the same retries); only the message is
 * specific, so a user whose provider claimed after paying is not sent to debug a file.
 */
export class RecoveryFundingSpentError extends RecoveryFundingUnavailableError {
  constructor() {
    super();
    this.message = "Your API reports the funding output already spent.";
    this.name = "RecoveryFundingSpentError";
  }
}

const HEX32 = /^[0-9a-f]{64}$/;
function require(condition: boolean): void { if (!condition) throw new RecoveryFundingUnavailableError(); }

function jsonObject(text: string): Record<string, unknown> {
  const object = parseStrictEventJson(text, 2048);
  require(object !== null && typeof object === "object" && !Array.isArray(object));
  return object as Record<string, unknown>;
}

/**
 * One output's spend status. Esplora serves `outspend/:vout`; a self-hosted
 * mempool backend serves only the per-transaction `outspends` list. The list
 * is read only when the single lookup is unavailable, never to override an
 * answer the single lookup gave.
 */
async function readOutspend(get: (path: string, limit?: number) => Promise<string>, txid: string, vout: number): Promise<Record<string, unknown>> {
  let single: string;
  try { single = await get(`tx/${txid}/outspend/${vout}`); } catch {
    const list = parseStrictEventJson(await get(`tx/${txid}/outspends`, MAX_TRANSACTION_BYTES * 2), MAX_TRANSACTION_BYTES * 2);
    require(Array.isArray(list) && vout < list.length);
    const entry = (list as unknown[])[vout];
    require(entry !== null && typeof entry === "object" && !Array.isArray(entry));
    return entry as Record<string, unknown>;
  }
  return jsonObject(single);
}

/**
 * Matching/repeated responses are consistency checks on ONE explicitly trusted
 * API, not cryptographic inclusion or a global mempool view. This report grants
 * no signing or broadcast authority. Authenticate before revealing any outpoint.
 */
export async function observeRecoveryFunding(
  plaintext: Uint8Array,
  independentlySelectedNetwork: { readonly name: NetworkName; readonly genesis_hash: string },
  selection: RecoveryFundingSelection,
  base: string,
  options: { readonly signal?: AbortSignal; readonly fetch?: ChainFetch } = {},
): Promise<RecoveryFundingObservation> {
  return observeFunding(plaintext, independentlySelectedNetwork,
    { fundingAttemptId: selection.fundingAttemptId, bindingRevision: selection.bindingRevision }, base, options, "btc-to-ln/v1");
}

/** Explicit actual-output observation, without a recorded or synthesized binding. */
export async function observeRecoveryOutpoint(
  plaintext: Uint8Array,
  independentlySelectedNetwork: { readonly name: NetworkName; readonly genesis_hash: string },
  selection: RecoveryOutpointSelection, base: string,
  options: { readonly signal?: AbortSignal; readonly fetch?: ChainFetch } = {},
): Promise<RecoveryFundingObservation> {
  return observeFunding(plaintext, independentlySelectedNetwork,
    { kind: selection.kind, fundingTxid: selection.fundingTxid, fundingVout: selection.fundingVout }, base, options, "btc-to-ln/v1");
}

/**
 * Same explicit trusted-API consistency boundary, independently authenticated reverse evidence.
 * `allowUnconfirmed` reports the provider's funding while it is only in the mempool as 0
 * confirmations, for a client that chose to claim that early (the provider can still double-spend it).
 */
export async function observeReverseRecoveryFunding(
  plaintext: Uint8Array,
  independentlySelectedNetwork: { readonly name: NetworkName; readonly genesis_hash: string },
  selection: RecoveryFundingSelection, base: string,
  options: { readonly signal?: AbortSignal; readonly fetch?: ChainFetch; readonly allowUnconfirmed?: boolean } = {},
): Promise<RecoveryFundingObservation> {
  return observeFunding(plaintext, independentlySelectedNetwork,
    { fundingAttemptId: selection.fundingAttemptId, bindingRevision: selection.bindingRevision }, base, options, "ln-to-btc/v1", options.allowUnconfirmed === true);
}

async function observeFunding(plaintext: Uint8Array,
  independentlySelectedNetwork: { readonly name: NetworkName; readonly genesis_hash: string }, selection: RecoveryRefundSelection, base: string,
  options: { readonly signal?: AbortSignal; readonly fetch?: ChainFetch }, profile: "btc-to-ln/v1" | "ln-to-btc/v1",
  allowUnconfirmed = false,
): Promise<RecoveryFundingObservation> {
  let snapshot: Uint8Array | undefined, spent = false;
  try {
    require(plaintext instanceof Uint8Array && plaintext.length > 0 && plaintext.length <= MAX_RECOVERY_PLAINTEXT_BYTES);
    snapshot = Uint8Array.from(plaintext);
    const network = structuredClone(independentlySelectedNetwork);
    require(isSupportedRecoveryNetwork(network));
    const chosen = { ...selection };
    const api = validateMempoolApi(base, network.name);
    const report = profile === "ln-to-btc/v1" ? inspectReverseRecoveryPlaintext(snapshot, network) : inspectRecoveryPlaintext(snapshot, network);
    let fundingTxid: string, fundingVout: number;
    let checkRaw: (raw: Uint8Array) => void;
    if ("kind" in chosen) {
      require(profile === "btc-to-ln/v1" && chosen.kind === "outpoint");
      require(typeof chosen.fundingTxid === "string" && HEX32.test(chosen.fundingTxid));
      require(Number.isSafeInteger(chosen.fundingVout) && chosen.fundingVout >= 0 && chosen.fundingVout <= 0xffffffff);
      fundingTxid = chosen.fundingTxid; fundingVout = chosen.fundingVout;
      checkRaw = (raw) => checkRecoveryOutpointTransaction(snapshot!, network, chosen, raw);
    } else {
      require(typeof chosen.fundingAttemptId === "string" && HEX32.test(chosen.fundingAttemptId));
      require(Number.isSafeInteger(chosen.bindingRevision) && chosen.bindingRevision >= 0 && chosen.bindingRevision < 64);
      const matches = report.fundingHistory.filter((binding) => binding.funding_attempt_id === chosen.fundingAttemptId && binding.binding_revision === chosen.bindingRevision);
      require(matches.length === 1);
      fundingTxid = matches[0]!.funding_txid; fundingVout = matches[0]!.contract_vout;
      checkRaw = (raw) => (profile === "ln-to-btc/v1" ? checkSelectedReverseFundingTransaction : checkSelectedRecoveryFundingTransaction)(snapshot!, network, chosen, raw);
    }
    const transport = options.fetch ?? fetch;
    const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000);
    signal.throwIfAborted();
    const get = async (path: string, limit = 2048): Promise<string> => readBoundedChainText(await transport(`${api}/${path}`, {
      signal, method: "GET", credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
    }), signal, limit);
    const tip = await readChainTip(api, network, { signal, fetch: transport });
    // Null: still in the mempool (only with allowUnconfirmed). Both passes must agree.
    let inclusion: { height: number; hash: string } | null | undefined;
    let rawHex: string | undefined;
    for (let pass = 0; pass < 2; pass++) {
      const text = await get(`tx/${fundingTxid}/hex`, MAX_TRANSACTION_BYTES * 2);
      require(/^(?:[0-9a-f]{2})+$/.test(text));
      if (rawHex !== undefined) require(text === rawHex);
      // Establish actual output existence BEFORE interpreting any outspend flag.
      checkRaw(hexToBytes(text));
      rawHex = text;
      const status = jsonObject(await get(`tx/${fundingTxid}/status`));
      if (allowUnconfirmed && status.confirmed === false) {
        require(inclusion === undefined || inclusion === null);
        inclusion = null;
      } else {
        require(status.confirmed === true && typeof status.block_height === "number" && Number.isSafeInteger(status.block_height) && status.block_height >= 0 && status.block_height <= tip.height);
        require(typeof status.block_hash === "string" && HEX32.test(status.block_hash));
        const height = status.block_height as number, hash = status.block_hash as string;
        if (height === tip.height) require(hash === tip.hash);
        if (height === 0) require(hash === network.genesis_hash);
        require(await get(`block-height/${height}`, 128) === hash);
        if (inclusion !== undefined) require(inclusion !== null && inclusion.height === height && inclusion.hash === hash);
        inclusion = { height, hash };
      }
      const outspend = await readOutspend(get, fundingTxid, fundingVout);
      spent = outspend.spent === true;
      require(outspend.spent === false);
    }
    const after = await readChainTip(api, network, { signal, fetch: transport });
    require(after.height === tip.height && after.hash === tip.hash);
    signal.throwIfAborted();
    return Object.freeze({ observation: "trusted-api", networkName: network.name,
      rawFundingTransactionHex: rawHex!,
      fundingTxid, fundingVout,
      fundingBlockHeight: inclusion?.height ?? null, fundingBlockHash: inclusion?.hash ?? null,
      confirmations: inclusion ? tip.height - inclusion.height + 1 : 0, tipHeight: tip.height, tipHash: tip.hash,
      refundLockHeight: report.refundLockHeight, refundMatureAtObservedTip: tip.height > report.refundLockHeight });
  } catch { /* Never expose document, parser, endpoint response, or nested error details. */ }
  finally { snapshot?.fill(0); }
  throw spent ? new RecoveryFundingSpentError() : new RecoveryFundingUnavailableError();
}
