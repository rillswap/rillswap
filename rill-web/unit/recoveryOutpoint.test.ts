import { expect, spyOn, test } from "bun:test";
import canonicalize from "canonicalize";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { schnorr } from "@noble/curves/secp256k1.js";
import { constructRecoveryOutpointRefund, constructSelectedRecoveryRefund, inspectRecoveryPlaintext,
  verifyRecoveryOutpointRefund, RecoveryRefundRefusedError, type RecoveryOutpointRefundInput } from "../src/recoveryInspection";
import { observeRecoveryOutpoint, RecoveryFundingSpentError, RecoveryFundingUnavailableError } from "../src/recoveryFunding";
import { parseTransaction, parseRecoveryFundingTransaction, serializeTransaction } from "../src/swap/transaction";
import { refundCase, recoveryRefundCases } from "./fixtures/recoveryRefundCases";
import type { NetworkName } from "../src/swap/config";
import type { ChainFetch } from "../src/swap/chainTip";

const encode = (record: unknown) => new TextEncoder().encode(canonicalize(record)!);
const BASE = "http://127.0.0.1:8091/api";

test("original terms-only backup signs and reauthorizes an actual output without fabricating history", () => {
  const item = refundCase(); item.record.funding_history = [];
  const document = encode(item.record), before = Uint8Array.from(document);
  const args: RecoveryOutpointRefundInput = { kind: "outpoint", fundingTxid: parseTransaction(hexToBytes(item.fundingTxHex)).txid,
    fundingVout: 0, rawFundingTransaction: hexToBytes(item.fundingTxHex), sampledTipHeight: item.tipHeight, feeSat: 100n };
  expect(inspectRecoveryPlaintext(document, item.expectedNetwork).recordedBindingCount).toBe(0);
  expect(() => constructSelectedRecoveryRefund(document, item.expectedNetwork, { ...args,
    fundingAttemptId: item.fundingAttemptId, bindingRevision: 0 })).toThrow(RecoveryRefundRefusedError);
  const result = constructRecoveryOutpointRefund(document, item.expectedNetwork, args);
  const sign = spyOn(schnorr, "sign");
  try {
    expect(verifyRecoveryOutpointRefund(document, item.expectedNetwork, args, args.rawFundingTransaction, hexToBytes(result.transactionHex))).toEqual(result);
    expect(sign).not.toHaveBeenCalled(); expect(document).toEqual(before);
    const tx = parseTransaction(hexToBytes(result.transactionHex));
    expect(tx.inputs[0]!.txid).toBe(args.fundingTxid);
    expect(tx.outputs[0]!.value).toBe(100900n);
    expect(bytesToHex(tx.outputs[0]!.script)).toBe(item.record.contract_terms.client_destination_script);
    expect(() => verifyRecoveryOutpointRefund(document, item.expectedNetwork, args, args.rawFundingTransaction,
      serializeTransaction({ ...tx, outputs: [{ ...tx.outputs[0]!, value: 100899n }] }, true))).toThrow(RecoveryRefundRefusedError);
    const witness = [...tx.inputs[0]!.witness]; witness[0] = Uint8Array.from(witness[0]!); witness[0]![0] = witness[0]![0]! ^ 1;
    expect(() => verifyRecoveryOutpointRefund(document, item.expectedNetwork, args, args.rawFundingTransaction,
      serializeTransaction({ ...tx, inputs: [{ ...tx.inputs[0]!, witness }] }, true))).toThrow(RecoveryRefundRefusedError);
  } finally { sign.mockRestore(); }
});

for (const name of ["funding anchor absent", "funding nonempty scriptSig", "funding wrong contract value", "funding duplicate contract outputs", "funding unsupported change script"]) {
  test(`outpoint recovery does not apply live admission: ${name}`, () => {
    const item = recoveryRefundCases().find((c) => c.name === name)!; item.record.funding_history = [];
    const raw = hexToBytes(item.fundingTxHex), funding = parseRecoveryFundingTransaction(raw);
    for (const [fundingVout, output] of funding.outputs.entries()) {
      if (bytesToHex(output.script) !== item.record.taproot_contract.script_pubkey) continue;
      const result = constructRecoveryOutpointRefund(encode(item.record), item.expectedNetwork, { kind: "outpoint",
        fundingTxid: funding.txid, fundingVout, rawFundingTransaction: raw, sampledTipHeight: item.tipHeight, feeSat: 100n });
      expect(result.outputValueSat).toBe((output.value - 100n).toString()); expect(result.fundingVout).toBe(fundingVout);
    }
  });
}

for (const version of [1, 3, 0xffffffff]) {
  test(`recovery reads funding version ${version}, without relaxing live parser`, () => {
    const item = refundCase(); item.record.funding_history = [];
    const raw = serializeTransaction({ ...parseTransaction(hexToBytes(item.fundingTxHex)), version }, true);
    expect(() => parseTransaction(raw)).toThrow();
    const result = constructRecoveryOutpointRefund(encode(item.record), item.expectedNetwork, { kind: "outpoint",
      fundingTxid: parseRecoveryFundingTransaction(raw).txid, fundingVout: 0, rawFundingTransaction: raw,
      sampledTipHeight: item.tipHeight, feeSat: 100n });
    expect(parseTransaction(hexToBytes(result.transactionHex)).version).toBe(2);
  });
}

test("outpoint refunds preserve authentication, outpoint, fee, dust, maturity and byte constraints before signing", () => {
  const item = refundCase(); item.record.funding_history = [];
  const raw = hexToBytes(item.fundingTxHex), args: RecoveryOutpointRefundInput = { kind: "outpoint",
    fundingTxid: parseTransaction(raw).txid, fundingVout: 0, rawFundingTransaction: raw, sampledTipHeight: item.tipHeight, feeSat: 100n };
  const badCases = recoveryRefundCases().filter((c) => ["funding duplicate inputs", "funding aggregate exceeds money range", "P2WPKH below dust"].includes(c.name));
  const sign = spyOn(schnorr, "sign");
  try {
    for (const change of [{ kind: "binding" }, { fundingTxid: "f".repeat(64) }, { fundingVout: 1 }, { fundingVout: 2 },
      { fundingVout: -1 }, { fundingVout: true }, { sampledTipHeight: item.tipHeight - 1 }, { feeSat: 601n }, { feeSat: -1n },
      { rawFundingTransaction: [] }, { rawFundingTransaction: new Uint8Array() }]) {
      expect(() => constructRecoveryOutpointRefund(encode(item.record), item.expectedNetwork, { ...args, ...change } as RecoveryOutpointRefundInput)).toThrow(RecoveryRefundRefusedError);
    }
    const bad = structuredClone(item.record); bad.verification_context.client_acceptance_signature = "0".repeat(128);
    expect(() => constructRecoveryOutpointRefund(encode(bad), item.expectedNetwork, args)).toThrow(RecoveryRefundRefusedError);
    expect(() => constructRecoveryOutpointRefund(encode(item.record), { name: "signet" }, args)).toThrow(RecoveryRefundRefusedError);
    for (const c of badCases) {
      c.record.funding_history = [];
      const funding = hexToBytes(c.fundingTxHex);
      expect(() => constructRecoveryOutpointRefund(encode(c.record), c.expectedNetwork, { ...args,
        fundingTxid: parseRecoveryFundingTransaction(funding).txid, rawFundingTransaction: funding, feeSat: BigInt(c.feeSat) })).toThrow(RecoveryRefundRefusedError);
    }
    expect(sign).not.toHaveBeenCalled();
  } finally { sign.mockRestore(); }
});

test("terms-only observation checks actual bytes, confirmed inclusion, mempool unspent and stable tips without signing", async () => {
  const item = refundCase(); item.record.funding_history = [];
  const chosen = { kind: "outpoint" as const, fundingTxid: parseTransaction(hexToBytes(item.fundingTxHex)).txid, fundingVout: 0 };
  const network = item.expectedNetwork as { name: NetworkName; genesis_hash: string };
  const responses = new Map<string, string>([["block-height/0", network.genesis_hash], ["blocks/tip/height", "1101"],
    ["blocks/tip/hash", "a".repeat(64)], ["block-height/1000", "d".repeat(64)],
    [`tx/${chosen.fundingTxid}/hex`, item.fundingTxHex], [`tx/${chosen.fundingTxid}/status`, JSON.stringify({ confirmed: true, block_height: 1000, block_hash: "d".repeat(64) })],
    [`tx/${chosen.fundingTxid}/outspend/0`, '{"spent":false}']]);
  const calls: string[] = [];
  const transport: ChainFetch = async (url) => { const path = String(url).slice(BASE.length + 1); calls.push(path);
    if (!responses.has(path)) throw new Error("unavailable"); return new Response(responses.get(path)!); };
  const run = () => observeRecoveryOutpoint(encode(item.record), network, chosen, BASE, { fetch: transport });
  const sign = spyOn(schnorr, "sign");
  try {
    const report = await run(); expect(report.refundMatureAtObservedTip).toBe(true); expect(report.confirmations).toBe(102);
    expect(calls.filter((p) => p.endsWith("/hex"))).toHaveLength(2); expect(sign).not.toHaveBeenCalled();
    for (const [path, value] of [[`tx/${chosen.fundingTxid}/status`, '{"confirmed":false}'],
      ["block-height/1000", "e".repeat(64)], [`tx/${chosen.fundingTxid}/hex`, "00"],
      [`tx/${chosen.fundingTxid}/outspend/0`, '{}']] as const) {
      const old = responses.get(path)!; responses.set(path, value);
      await expect(run()).rejects.toBeInstanceOf(RecoveryFundingUnavailableError); responses.set(path, old);
    }
    responses.set(`tx/${chosen.fundingTxid}/outspend/0`, '{"spent":true}');
    await expect(run()).rejects.toBeInstanceOf(RecoveryFundingSpentError);
    calls.length = 0; chosen.fundingVout = -1;
    await expect(run()).rejects.toBeInstanceOf(RecoveryFundingUnavailableError); expect(calls).toHaveLength(0);
  } finally { sign.mockRestore(); }
});
