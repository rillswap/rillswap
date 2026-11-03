import { expect, spyOn, test } from "bun:test";
import canonicalize from "canonicalize";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { schnorr } from "@noble/curves/secp256k1.js";
import { discoverRecoveryDeposits, RecoveryDiscoveryUnavailableError } from "../src/recoveryDiscovery";
import { scriptAddress } from "../src/swap/address";
import { parseRecoveryFundingTransaction, serializeTransaction } from "../src/swap/transaction";
import type { ChainFetch } from "../src/swap/chainTip";
import type { NetworkName } from "../src/swap/config";
import { refundCase } from "./fixtures/recoveryRefundCases";

const BASE = "http://127.0.0.1:8091/api";
function mock(count = 1) {
  const item = refundCase(); item.record.funding_history = [];
  const document = new TextEncoder().encode(canonicalize(item.record)!);
  const network = item.expectedNetwork as { name: NetworkName; genesis_hash: string };
  const address = scriptAddress(item.record.taproot_contract.script_pubkey, network.name);
  const responses = new Map<string, string>([["block-height/0", network.genesis_hash], ["blocks/tip/height", "1101"], ["blocks/tip/hash", "a".repeat(64)]]);
  const original = parseRecoveryFundingTransaction(hexToBytes(item.fundingTxHex));
  const rows = Array.from({ length: count }, (_, i) => {
    const raw = serializeTransaction({ ...original, locktime: i, version: 1,
      outputs: i === 0 ? original.outputs : [original.outputs[1]!] }, true);
    const txid = parseRecoveryFundingTransaction(raw).txid;
    responses.set(`tx/${txid}/hex`, bytesToHex(raw));
    return { txid, status: { confirmed: true } };
  });
  responses.set(`address/${address}/txs`, JSON.stringify(rows));
  const calls: string[] = [];
  const transport: ChainFetch = async (url, init) => {
    expect(init!.method ?? "GET").toBe("GET"); expect(init!.body).toBeUndefined(); expect(init!.credentials).toBe("omit");
    const path = String(url).slice(BASE.length + 1); calls.push(path);
    return new Response(responses.get(path) ?? "unavailable", { status: responses.has(path) ? 200 : 404 });
  };
  const run = (transactionId?: string) => discoverRecoveryDeposits(document, network, BASE, { fetch: transport, ...(transactionId ? { transactionId } : {}) });
  return { document, network, address, responses, calls, rows, transport, run };
}

test("terms-only discovery verifies transaction identity and scripts without signing or granting spend authority", async () => {
  const api = mock(2), sign = spyOn(schnorr, "sign");
  try {
    const result = await api.run(); expect(result.historyComplete).toBe(true);
    expect(result.candidates).toEqual([{ fundingTxid: api.rows[0]!.txid, fundingVout: 0, valueSat: "101000", matchesQuotedAmount: true }]);
    expect(Object.isFrozen(result.candidates)).toBe(true); expect(sign).not.toHaveBeenCalled();
    expect(api.calls.some((p) => p.includes("outspend"))).toBe(false);
  } finally { sign.mockRestore(); }
});

test("transaction-ID fallback bypasses address history and does not claim complete history", async () => {
  const api = mock(); api.responses.delete(`address/${api.address}/txs`);
  const result = await api.run(api.rows[0]!.txid);
  expect(result.candidates).toHaveLength(1); expect(result.historyComplete).toBe(false);
  expect(api.calls.some((p) => p.startsWith("address/"))).toBe(false);
});

test("empty history is not evidence of a missing deposit", async () => {
  const api = mock(0), result = await api.run();
  expect(result.historyComplete).toBe(true); expect(result.candidates).toHaveLength(0);
  expect(api.calls.some((p) => p.startsWith("tx/"))).toBe(false);
});

test("standard 25-entry pages and mempool entries are paginated, with explicit incomplete fallback for unsupported pagination", async () => {
  for (const count of [24, 25, 26]) {
    const api = mock(count);
    const result = await api.run(); expect(result.candidates).toHaveLength(1);
    expect(result.historyComplete).toBe(count < 25);
  }
  const api = mock(27);
  api.responses.set(`address/${api.address}/txs`, JSON.stringify([{ ...api.rows[26], status: { confirmed: false } }, ...api.rows.slice(0, 25)]));
  api.responses.set(`address/${api.address}/txs/chain/${api.rows[24]!.txid}`, JSON.stringify([api.rows[25]]));
  expect((await api.run()).historyComplete).toBe(true);
  expect(api.calls.filter((p) => p.startsWith("tx/")).length).toBe(27);
});

test("transaction and page limits preserve verified candidates without claiming complete history", async () => {
  const api = mock(201);
  api.responses.set(`address/${api.address}/txs`, JSON.stringify([{ ...api.rows[200], status: { confirmed: false } }, ...api.rows.slice(0, 25)]));
  for (let page = 1; page <= 7; page++) api.responses.set(`address/${api.address}/txs/chain/${api.rows[page * 25 - 1]!.txid}`, JSON.stringify(api.rows.slice(page * 25, (page + 1) * 25)));
  const result = await api.run(); expect(result.historyComplete).toBe(false); expect(result.candidates).toHaveLength(1);
  expect(api.calls.filter((p) => p.startsWith("tx/"))).toHaveLength(200);
  expect(api.calls.filter((p) => p.startsWith("address/"))).toHaveLength(8);
});

test("replayed pages stop conservatively, and malformed status or raw identity refuses", async () => {
  const api = mock(25), first = `address/${api.address}/txs`;
  api.responses.set(`${first}/chain/${api.rows[24]!.txid}`, JSON.stringify(api.rows.slice(0, 1)));
  expect((await api.run()).historyComplete).toBe(false);
  for (const status of [null, {}, { confirmed: "true" }]) {
    api.responses.set(first, JSON.stringify([{ txid: api.rows[0]!.txid, status }]));
    await expect(api.run()).rejects.toBeInstanceOf(RecoveryDiscoveryUnavailableError);
  }
  api.responses.set(`tx/${api.rows[0]!.txid}/hex`, api.responses.get(`tx/${api.rows[1]!.txid}/hex`)!);
  await expect(api.run(api.rows[0]!.txid)).rejects.toBeInstanceOf(RecoveryDiscoveryUnavailableError);
});

test("invalid documents, networks, TXIDs and canceled requests refuse before disclosing anything", async () => {
  const api = mock(), options = { fetch: api.transport };
  await expect(discoverRecoveryDeposits(new Uint8Array(), api.network, BASE, options)).rejects.toBeInstanceOf(RecoveryDiscoveryUnavailableError);
  await expect(discoverRecoveryDeposits(api.document, { ...api.network, genesis_hash: "f".repeat(64) }, BASE, options)).rejects.toBeInstanceOf(RecoveryDiscoveryUnavailableError);
  await expect(discoverRecoveryDeposits(api.document, api.network, BASE, { ...options, transactionId: "bad" })).rejects.toBeInstanceOf(RecoveryDiscoveryUnavailableError);
  await expect(discoverRecoveryDeposits(api.document, api.network, BASE, { ...options, signal: AbortSignal.abort() })).rejects.toBeInstanceOf(RecoveryDiscoveryUnavailableError);
  expect(api.calls).toHaveLength(0);
});

test("output budget keeps partial search results and TXID fallback lists all outputs within parser bounds", async () => {
  const api = mock();
  const funding = parseRecoveryFundingTransaction(hexToBytes(api.responses.get(`tx/${api.rows[0]!.txid}/hex`)!));
  const raw = serializeTransaction({ ...funding, outputs: Array.from({ length: 40 }, () => funding.outputs[0]!) }, true);
  const txid = parseRecoveryFundingTransaction(raw).txid;
  api.responses.set(`tx/${txid}/hex`, bytesToHex(raw));
  api.responses.set(`address/${api.address}/txs`, JSON.stringify([{ txid, status: { confirmed: true } }]));
  const partial = await api.run(); expect(partial.candidates).toHaveLength(32); expect(partial.historyComplete).toBe(false);
  const explicit = await api.run(txid); expect(explicit.candidates).toHaveLength(40);
  expect(explicit.candidates.map((candidate) => candidate.fundingVout)).toEqual(Array.from({ length: 40 }, (_, i) => i));
});
