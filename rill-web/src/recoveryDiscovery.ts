/** Explicit public deposit lookup. Never creates signed funding history or refund authority. */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { MAX_RECOVERY_PLAINTEXT_BYTES } from "./recoveryAgeContainer";
import { inspectRecoveryDepositTarget, isSupportedRecoveryNetwork } from "./recoveryInspection";
import { parseStrictEventJson } from "./strictEventJson";
import { scriptAddress } from "./swap/address";
import { readBoundedChainText, readChainTip, type ChainFetch } from "./swap/chainTip";
import { validateMempoolApi, type NetworkName } from "./swap/config";
import { MAX_TRANSACTION_BYTES, parseRecoveryFundingTransaction } from "./swap/transaction";

const HEX32 = /^[0-9a-f]{64}$/;
const MAX_HISTORY_BYTES = 1024 * 1024;
const CHAIN_PAGE_SIZE = 25;
const MAX_HISTORY_PAGES = 8;
const MAX_TRANSACTIONS = 200;
const MAX_OUTPUTS = 32;

export interface RecoveryDepositCandidate {
  readonly fundingTxid: string;
  readonly fundingVout: number;
  readonly valueSat: string;
  readonly matchesQuotedAmount: boolean;
}

export interface RecoveryDepositDiscovery {
  readonly address: string;
  /** False means the bounded search stopped before the API's history ended. */
  readonly historyComplete: boolean;
  readonly candidates: readonly RecoveryDepositCandidate[];
}

export class RecoveryDiscoveryUnavailableError extends Error {
  constructor() {
    super("Deposit discovery unavailable. Keep your backup and try the deposit transaction ID with your selected chain API.");
    this.name = "RecoveryDiscoveryUnavailableError";
  }
}

function require(condition: boolean): void { if (!condition) throw new RecoveryDiscoveryUnavailableError(); }

/** Authenticate before disclosing an address or transaction ID. No background scans or writes. */
export async function discoverRecoveryDeposits(
  plaintext: Uint8Array,
  independentlySelectedNetwork: { readonly name: NetworkName; readonly genesis_hash: string },
  base: string,
  options: { readonly transactionId?: string; readonly signal?: AbortSignal; readonly fetch?: ChainFetch } = {},
): Promise<RecoveryDepositDiscovery> {
  let snapshot: Uint8Array | undefined;
  try {
    require(plaintext instanceof Uint8Array && plaintext.length > 0 && plaintext.length <= MAX_RECOVERY_PLAINTEXT_BYTES);
    snapshot = Uint8Array.from(plaintext);
    const network = structuredClone(independentlySelectedNetwork), chosen = { ...options };
    require(isSupportedRecoveryNetwork(network));
    const target = inspectRecoveryDepositTarget(snapshot, network), api = validateMempoolApi(base, network.name);
    const address = scriptAddress(target.scriptPubkey, network.name);
    if (chosen.transactionId !== undefined) require(HEX32.test(chosen.transactionId));
    const transport = chosen.fetch ?? fetch;
    const signal = chosen.signal ? AbortSignal.any([chosen.signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000);
    signal.throwIfAborted();
    const get = async (path: string, limit: number): Promise<string> => readBoundedChainText(await transport(`${api}/${path}`, {
      signal, method: "GET", credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
    }), signal, limit);
    const tip = await readChainTip(api, network, { signal, fetch: transport });
    const ids = new Set<string>();
    let historyComplete = false;
    if (chosen.transactionId !== undefined) ids.add(chosen.transactionId);
    else {
      let cursor: string | undefined;
      pages: for (let page = 0; page < MAX_HISTORY_PAGES; page++) {
        const path = `address/${address}/txs${cursor ? `/chain/${cursor}` : ""}`;
        let text: string;
        try { text = await get(path, MAX_HISTORY_BYTES); } catch (error) {
          // Some user-selected APIs return a bounded first page but lack pagination.
          // Keep already found candidates, never claim that their history ended.
          if (page > 0) break;
          throw error;
        }
        const history = parseStrictEventJson(text, MAX_HISTORY_BYTES);
        require(Array.isArray(history) && history.length <= MAX_TRANSACTIONS);
        const confirmed: string[] = [];
        const pageIds = new Set<string>();
        let repeated = false;
        for (const entry of history as unknown[]) {
          require(entry !== null && typeof entry === "object" && !Array.isArray(entry));
          const row = entry as { txid?: unknown; status?: { confirmed?: unknown } };
          require(typeof row.txid === "string" && HEX32.test(row.txid));
          require(row.status !== null && typeof row.status === "object" && !Array.isArray(row.status) && typeof row.status.confirmed === "boolean");
          if (pageIds.has(row.txid as string) || ids.has(row.txid as string)) repeated = true;
          pageIds.add(row.txid as string);
          if (!ids.has(row.txid as string) && ids.size === MAX_TRANSACTIONS) break pages;
          ids.add(row.txid as string);
          if (row.status?.confirmed === true) confirmed.push(row.txid as string);
        }
        if (repeated) break;
        if (confirmed.length < CHAIN_PAGE_SIZE) { historyComplete = true; break; }
        const next = confirmed.at(-1)!;
        if (next === cursor) break;
        cursor = next;
      }
    }
    const candidates: RecoveryDepositCandidate[] = [];
    transactions: for (const txid of ids) {
      const text = await get(`tx/${txid}/hex`, MAX_TRANSACTION_BYTES * 2);
      require(/^(?:[0-9a-f]{2})+$/.test(text));
      const transaction = parseRecoveryFundingTransaction(hexToBytes(text));
      require(transaction.txid === txid);
      for (const [fundingVout, output] of transaction.outputs.entries()) {
        if (bytesToHex(output.script) !== target.scriptPubkey) continue;
        // A broad search stays small; the explicit TXID fallback can list every
        // output within the transaction parser's existing item/byte bounds.
        if (chosen.transactionId === undefined && candidates.length === MAX_OUTPUTS) { historyComplete = false; break transactions; }
        candidates.push(Object.freeze({ fundingTxid: txid, fundingVout, valueSat: output.value.toString(),
          matchesQuotedAmount: output.value === BigInt(target.nominalValueSat) }));
      }
    }
    const after = await readChainTip(api, network, { signal, fetch: transport });
    require(after.height === tip.height && after.hash === tip.hash);
    signal.throwIfAborted();
    return Object.freeze({ address, historyComplete, candidates: Object.freeze(candidates) });
  } catch { /* Never reveal imported data, keys, backend content, or nested error causes. */ }
  finally { snapshot?.fill(0); }
  throw new RecoveryDiscoveryUnavailableError();
}
