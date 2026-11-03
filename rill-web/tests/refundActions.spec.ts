import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import canonicalize from "canonicalize";
import type * as RefundActions from "../src/browserRefund";
import type { RecoveryRefundCase } from "../unit/fixtures/recoveryRefundCases";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { parseTransaction, serializeTransaction } from "../src/swap/transaction";
import type { RefundJournalDraft } from "../src/browserRefundJournal";

declare global { interface Window { refundActions: typeof RefundActions } }
const vector = (): RecoveryRefundCase => JSON.parse(readFileSync(new URL("../tmp/preview/test-only/recovery-refund-cases.json", import.meta.url), "utf8"))[0];
async function ready(page: Page) { await page.goto("http://127.0.0.1:18765/test-only/refund-journal.html"); await page.waitForFunction(() => window.refundJournalReady); }

test("approved preparation stores before exposure, reuses exact bytes, and writes UNKNOWN before its single POST", async ({ page }) => {
  await ready(page);
  const item = vector();
  const result = await page.evaluate(async ({ item, plaintext }) => {
    const network = item.expectedNetwork as { name: "regtest"; genesis_hash: string };
    const document = new TextEncoder().encode(plaintext), selection = { fundingAttemptId: item.fundingAttemptId, bindingRevision: item.bindingRevision };
    const base = "http://127.0.0.1:8091/api";
    let gets = 0, posts = 0, unknownBeforePost = false, signedBody = "";
    const transport = async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = String(url).slice(base.length + 1);
      if (init?.method === "POST") {
        posts++; signedBody = String(init.body);
        const journal = await window.BrowserRefundJournal.open();
        const stored = await journal.get(network, item.record.funding_history[0]!.binding.funding_txid, 0); journal.close();
        unknownBeforePost = stored?.state === "submission-unknown" && signedBody === stored.refund.transactionHex;
        return new Response(stored!.refund.txid);
      }
      gets++;
      if (path === "block-height/0") return new Response(network.genesis_hash);
      if (path === "blocks/tip/height") return new Response("1101");
      if (path === "blocks/tip/hash") return new Response("a".repeat(64));
      if (path === "block-height/1000") return new Response("d".repeat(64));
      if (path.endsWith("/hex")) return new Response(item.fundingTxHex);
      if (path.endsWith("/status")) return new Response(JSON.stringify({ confirmed: true, block_height: 1000, block_hash: "d".repeat(64) }));
      if (path.endsWith("/outspend/0")) return new Response('{"spent":false}');
      throw new Error("unexpected endpoint");
    };
    const options = { fetch: transport, broadcastApi: base, assertCurrent() {} };
    const saved = await window.refundActions.prepareBrowserRefund(document, network, selection, base, 100n, options);
    const initialGets = gets;
    const reused = await window.refundActions.prepareBrowserRefund(document, network, selection, base, 100n, options);
    const reusedWithoutRequests = initialGets === gets;
    const outcome = await window.refundActions.broadcastBrowserRefund(document, network, selection, base, reused, options);
    let replayRefused = false;
    try { await window.refundActions.broadcastBrowserRefund(document, network, selection, base, saved, options); } catch { replayRefused = true; }
    const journal = await window.BrowserRefundJournal.open(); const stored = (await journal.get(network, saved.refund.fundingTxid, 0))!; journal.close();
    return { saved, reused, stored, outcome, reusedWithoutRequests, replayRefused, posts, unknownBeforePost, signedBody };
  }, { item, plaintext: canonicalize(item.record)! });
  expect(result.saved.state).toBe("prepared"); expect(result.reused).toEqual(result.saved); expect(result.reusedWithoutRequests).toBe(true);
  expect(result.outcome.outcome).toBe("accepted"); expect(result.stored.state).toBe("accepted");
  expect(result.posts).toBe(1); expect(result.replayRefused).toBe(true); expect(result.unknownBeforePost).toBe(true);
  expect(result.signedBody).toBe(result.saved.refund.transactionHex);
});

for (const failure of ["lost response", "wrong txid", "HTTP failure", "acceptance persistence"]) {
  test(`ambiguous ${failure} keeps immutable intent and allows identical export without another POST`, async ({ page }) => {
    await ready(page); const item = vector();
    const outcome = await page.evaluate(async ({ item, plaintext, failure }) => {
      const network = item.expectedNetwork as { name: "regtest"; genesis_hash: string }, base = "http://127.0.0.1:8091/api";
      const document = new TextEncoder().encode(plaintext), selection = { fundingAttemptId: item.fundingAttemptId, bindingRevision: item.bindingRevision };
      let posts = 0, reads = 0;
      const transport = async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const path = String(url).slice(base.length + 1);
        if (init?.method === "POST") {
          posts++; if (failure === "lost response") throw new Error("lost response");
          if (failure === "wrong txid") return new Response("0".repeat(64));
          if (failure === "HTTP failure") return new Response("upstream failed", { status: 503 });
          const journal = await window.BrowserRefundJournal.open(); const stored = await journal.get(network, item.record.funding_history[0]!.binding.funding_txid, 0); journal.close();
          return new Response(stored!.refund.txid);
        }
        reads++;
        if (path === "block-height/0") return new Response(network.genesis_hash);
        if (path === "blocks/tip/height") return new Response("1101");
        if (path === "blocks/tip/hash") return new Response("a".repeat(64));
        if (path === "block-height/1000") return new Response("d".repeat(64));
        if (path.endsWith("/hex")) return new Response(item.fundingTxHex);
        if (path.endsWith("/status")) return new Response(JSON.stringify({ confirmed: true, block_height: 1000, block_hash: "d".repeat(64) }));
        if (path.endsWith("/outspend/0")) return new Response('{"spent":false}');
        throw new Error("unexpected endpoint");
      };
      const options = { fetch: transport, broadcastApi: base, assertCurrent() {} };
      const saved = await window.refundActions.prepareBrowserRefund(document, network, selection, base, 100n, options);
      const original = window.BrowserRefundJournal.prototype.markAccepted;
      if (failure === "acceptance persistence") window.BrowserRefundJournal.prototype.markAccepted = async () => { throw new Error("quota failure"); };
      let result;
      try { result = await window.refundActions.broadcastBrowserRefund(document, network, selection, base, saved, options); }
      finally { window.BrowserRefundJournal.prototype.markAccepted = original; }
      const loaded = await window.refundActions.prepareBrowserRefund(document, network, selection, base, 100n, options);
      const before = reads;
      const exported = await window.refundActions.exportBrowserRefund(document, network, selection, base, loaded, options);
      let replay = false; try { await window.refundActions.broadcastBrowserRefund(document, network, selection, base, loaded, options); replay = true; } catch {}
      return { result, loaded, identical: saved.refund.transactionHex === exported.refund.transactionHex, noReadsOnReexport: reads === before, replay, posts };
    }, { item, plaintext: canonicalize(item.record)!, failure });
    expect(outcome.result!.outcome).toBe("unknown"); expect(outcome.loaded.state).toBe("submission-unknown");
    expect(outcome.identical).toBe(true); expect(outcome.noReadsOnReexport).toBe(true); expect(outcome.replay).toBe(false); expect(outcome.posts).toBe(1);
  });
}

test("approval withdrawn before signing prevents randomness, storage writes, and spending-byte exposure", async ({ page }) => {
  await ready(page); const item = vector();
  const outcome = await page.evaluate(async ({ item, plaintext }) => {
    const network = item.expectedNetwork as { name: "regtest"; genesis_hash: string }, document = new TextEncoder().encode(plaintext);
    const original = crypto.getRandomValues.bind(crypto); let randomCalls = 0, refused = false;
    crypto.getRandomValues = ((array: Uint8Array) => { randomCalls++; return original(array); }) as typeof crypto.getRandomValues;
    try { await window.refundActions.prepareBrowserRefund(document, network, { fundingAttemptId: item.fundingAttemptId, bindingRevision: 0 }, "http://127.0.0.1:8091/api", 100n,
      { broadcastApi: "http://127.0.0.1:8092/api", assertCurrent() { throw new Error("approval withdrawn"); } }); } catch { refused = true; } finally { crypto.getRandomValues = original; }
    const journal = await window.BrowserRefundJournal.open(); const stored = await journal.get(network, item.record.funding_history[0]!.binding.funding_txid, 0); journal.close();
    return { refused, randomCalls, stored };
  }, { item, plaintext: canonicalize(item.record)! });
  expect(outcome.refused).toBe(true); expect(outcome.randomCalls).toBe(0); expect(outcome.stored).toBeUndefined();
});

for (const race of ["withdraw during observation", "withdraw after UNKNOWN commit", "two broadcasts", "export versus broadcast"]) {
  test(`asynchronous refund boundary: ${race}`, async ({ page }) => {
    await ready(page); const item = vector();
    const result = await page.evaluate(async ({ item, plaintext, race }) => {
      const document = new TextEncoder().encode(plaintext), network = item.expectedNetwork as { name: "regtest"; genesis_hash: string };
      const selection = { fundingAttemptId: item.fundingAttemptId, bindingRevision: 0 }, base = "http://127.0.0.1:8091/api";
      let approved = true, posts = 0, randomCalls = 0;
      let release!: () => void, started!: () => void;
      const pending = new Promise<void>((resolve) => { started = resolve; });
      const gate = new Promise<void>((resolve) => { release = resolve; });
      const transport = async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const path = String(url).slice(base.length + 1);
        if (init?.method === "POST") {
          posts++; const journal = await window.BrowserRefundJournal.open(); const stored = await journal.get(network, item.record.funding_history[0]!.binding.funding_txid, 0); journal.close();
          return new Response(stored!.refund.txid);
        }
        if (path === "block-height/0") return new Response(network.genesis_hash);
        if (path === "blocks/tip/height") return new Response("1101");
        if (path === "blocks/tip/hash") return new Response("a".repeat(64));
        if (path === "block-height/1000") return new Response("d".repeat(64));
        if (path.endsWith("/hex")) {
          if (race === "withdraw during observation") { started(); await gate; }
          return new Response(item.fundingTxHex);
        }
        if (path.endsWith("/status")) return new Response(JSON.stringify({ confirmed: true, block_height: 1000, block_hash: "d".repeat(64) }));
        if (path.endsWith("/outspend/0")) return new Response('{"spent":false}');
        throw new Error("unexpected endpoint");
      };
      const options = { broadcastApi: base, fetch: transport, assertCurrent() { if (!approved) throw new Error("approval changed"); } };
      const originalRng = crypto.getRandomValues.bind(crypto);
      crypto.getRandomValues = ((array: Uint8Array) => { randomCalls++; return originalRng(array); }) as typeof crypto.getRandomValues;
      let stored, rejected = false, exportWon = false, outcomes: unknown[] = [];
      const originalExposure = window.BrowserRefundJournal.prototype.beginExposure;
      try {
        if (race === "withdraw during observation") {
          const action = window.refundActions.prepareBrowserRefund(document, network, selection, base, 100n, options).catch(() => { rejected = true; });
          await pending; approved = false; release(); await action;
        } else {
          const saved = await window.refundActions.prepareBrowserRefund(document, network, selection, base, 100n, options);
          const send = () => window.refundActions.broadcastBrowserRefund(document, network, selection, base, saved, options);
          if (race === "withdraw after UNKNOWN commit") {
            window.BrowserRefundJournal.prototype.beginExposure = async function (record) {
              const exposed = await originalExposure.call(this, record); started(); await gate; return exposed;
            };
            const action = send(); await pending; approved = false; release(); outcomes = [await action];
          } else if (race === "two broadcasts") {
            outcomes = await Promise.allSettled([send(), send()]);
          } else {
            const attempts = await Promise.allSettled([window.refundActions.exportBrowserRefund(document, network, selection, base, saved, options), send()]);
            exportWon = attempts[0]!.status === "fulfilled"; outcomes = attempts;
          }
        }
        const journal = await window.BrowserRefundJournal.open();
        stored = await journal.get(network, item.record.funding_history[0]!.binding.funding_txid, 0);
        const exported = stored?.state === "submission-unknown" ? await journal.reexportIdentical(stored) : undefined;
        journal.close(); return { posts, randomCalls, stored, rejected, outcomes, exportWon, identicalExport: exported?.refund.transactionHex === stored?.refund.transactionHex };
      } finally { crypto.getRandomValues = originalRng; window.BrowserRefundJournal.prototype.beginExposure = originalExposure; }
    }, { item, plaintext: canonicalize(item.record)!, race });
    if (race === "withdraw during observation") { expect(result.rejected).toBe(true); expect(result.randomCalls).toBe(0); expect(result.stored).toBeUndefined(); }
    else if (race === "two broadcasts") { expect(result.posts).toBe(1); expect(result.stored!.state).toBe("accepted"); }
    else if (race === "export versus broadcast") { expect(result.posts).toBe(result.exportWon ? 0 : 1); expect(result.stored!.state).toBe(result.exportWon ? "submission-unknown" : "accepted"); }
    else { expect(result.stored!.state).toBe("submission-unknown"); expect(result.identicalExport).toBe(true); }
    if (race !== "two broadcasts" && race !== "export versus broadcast") expect(result.posts).toBe(0);
    if (race === "two broadcasts" || race === "export versus broadcast") {
      expect(result.outcomes.filter((item) => (item as { status: string }).status === "fulfilled")).toHaveLength(1);
      expect(result.outcomes.filter((item) => (item as { status: string }).status === "rejected")).toHaveLength(1);
    }
  });
}

for (const initialMode of ["legacy", "outpoint"]) {
  for (const state of ["prepared", "submission-unknown", "accepted"]) {
    test(`cross-mode ${initialMode} ${state} reauthorizes exact bytes, never re-signs or resubmits exposed intent`, async ({ page }) => {
      await ready(page); const item = vector();
      const termsOnly = structuredClone(item.record); termsOnly.funding_history = [];
      const result = await page.evaluate(async ({ item, initialMode, state, plaintext, termsPlaintext }) => {
        const network = item.expectedNetwork as { name: "regtest"; genesis_hash: string }, base = "http://127.0.0.1:8091/api";
        const binding = item.record.funding_history[0]!.binding;
        const legacy = { fundingAttemptId: item.fundingAttemptId, bindingRevision: 0 };
        const outpoint = { kind: "outpoint" as const, fundingTxid: binding.funding_txid, fundingVout: binding.contract_vout };
        const document = new TextEncoder().encode(plaintext);
        const termsOnly = new TextEncoder().encode(termsPlaintext);
        let posts = 0, reads = 0;
        const transport = async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
          if (init?.method === "POST") { posts++; throw new Error("lost response"); }
          reads++; const path = String(url).slice(base.length + 1);
          if (path === "block-height/0") return new Response(network.genesis_hash);
          if (path === "blocks/tip/height") return new Response("1101");
          if (path === "blocks/tip/hash") return new Response("a".repeat(64));
          if (path === "block-height/1000") return new Response("d".repeat(64));
          if (path.endsWith("/hex")) return new Response(item.fundingTxHex);
          if (path.endsWith("/status")) return new Response(JSON.stringify({ confirmed: true, block_height: 1000, block_hash: "d".repeat(64) }));
          if (path.endsWith("/outspend/0")) return new Response('{"spent":false}');
          throw new Error("unexpected endpoint");
        };
        const options = { broadcastApi: base, fetch: transport, assertCurrent() {} };
        const saved = await window.refundActions.prepareBrowserRefund(initialMode === "legacy" ? document : termsOnly, network,
          initialMode === "legacy" ? legacy : outpoint, base, 100n, options);
        const journal = await window.BrowserRefundJournal.open(); let stored = saved;
        try {
          if (state !== "prepared") stored = await journal.beginExposure(saved);
          if (state === "accepted") stored = await journal.markAccepted(stored, stored.refund.txid);
        } finally { journal.close(); }
        const otherDocument = initialMode === "legacy" ? termsOnly : document;
        const otherSelection = initialMode === "legacy" ? outpoint : legacy;
        const original = crypto.getRandomValues.bind(crypto); let randomCalls = 0;
        crypto.getRandomValues = ((array: Uint8Array) => { randomCalls++; return original(array); }) as typeof crypto.getRandomValues;
        try {
          const before = reads;
          const loaded = await window.refundActions.prepareBrowserRefund(otherDocument, network, otherSelection, base, 100n, options);
          const noReadOnLoad = before === reads;
          let wrongFeeRefused = false;
          try { await window.refundActions.prepareBrowserRefund(otherDocument, network, otherSelection, base, 101n, options); } catch { wrongFeeRefused = true; }
          let refused = false;
          if (state !== "prepared") {
            try { await window.refundActions.broadcastBrowserRefund(otherDocument, network, otherSelection, base, loaded, options); } catch { refused = true; }
            const exported = await window.refundActions.exportBrowserRefund(otherDocument, network, otherSelection, base, loaded, options);
            if (exported.refund.transactionHex !== stored.refund.transactionHex) throw new Error("changed bytes");
          }
          let wrongOutputRefused = false;
          try { await window.refundActions.exportBrowserRefund(termsOnly, network, { ...outpoint, fundingVout: 1 }, base, loaded, options); } catch { wrongOutputRefused = true; }
          return { loaded, stored, randomCalls, posts, noReadOnLoad, refused, wrongOutputRefused, wrongFeeRefused };
        } finally { crypto.getRandomValues = original; }
      }, { item, initialMode, state, plaintext: canonicalize(item.record)!, termsPlaintext: canonicalize(termsOnly)! });
      expect(result.loaded).toEqual(result.stored); expect(result.randomCalls).toBe(0); expect(result.posts).toBe(0);
      expect(result.noReadOnLoad).toBe(true); expect(result.wrongOutputRefused).toBe(true);
      expect(result.wrongFeeRefused).toBe(true);
      if (state !== "prepared") expect(result.refused).toBe(true);
    });
  }
}

test("outpoint reauthorization rejects structurally intact tampered signed plans without clearing their exposure marker", async ({ page }) => {
  await ready(page); const item = vector(); item.record.funding_history = [];
  const input = JSON.parse(readFileSync(new URL("../tmp/preview/test-only/refund-journal-draft.json", import.meta.url), "utf8")) as RefundJournalDraft;
  const saved = await page.evaluate(async (input) => {
    const journal = await window.BrowserRefundJournal.open(); try { return await journal.prepare(input); } finally { journal.close(); }
  }, input);
  const transaction = parseTransaction(hexToBytes(saved.refund.transactionHex));
  const witness = [...transaction.inputs[0]!.witness]; witness[0] = Uint8Array.from(witness[0]!); witness[0]![0] = witness[0]![0]! ^ 1;
  const alternatives = [
    { ...transaction, inputs: [{ ...transaction.inputs[0]!, witness }] },
    { ...transaction, outputs: [{ ...transaction.outputs[0]!, value: transaction.outputs[0]!.value - 1n }] },
  ];
  for (const [index, tx] of alternatives.entries()) {
    const raw = serializeTransaction(tx, true), parsed = parseTransaction(raw);
    const corrupt = { ...saved, state: "submission-unknown" as const, signedDigest: bytesToHex(sha256(raw)),
      refund: { ...saved.refund, transactionHex: bytesToHex(raw), txid: parsed.txid, outputValueSat: parsed.outputs[0]!.value.toString(), feeSat: index === 0 ? saved.refund.feeSat : (BigInt(saved.refund.feeSat) + 1n).toString() } };
    const result = await page.evaluate(async ({ corrupt, plaintext, network }) => {
      const db = await new Promise<IDBDatabase>((resolve) => { const r = indexedDB.open("rillswap-refund-submissions"); r.onsuccess = () => resolve(r.result); });
      await new Promise<void>((resolve) => { const tx = db.transaction("intents", "readwrite"); tx.objectStore("intents").put(corrupt); tx.oncomplete = () => resolve(); });
      const journal = await window.BrowserRefundJournal.open(); let calls = 0, refused = 0;
      try {
        const stored = (await journal.get(network, corrupt.refund.fundingTxid, corrupt.refund.fundingVout))!;
        const document = new TextEncoder().encode(plaintext), selection = { kind: "outpoint" as const, fundingTxid: stored.refund.fundingTxid, fundingVout: stored.refund.fundingVout };
        const options = { broadcastApi: stored.broadcastApi, assertCurrent() {}, fetch: async () => { calls++; throw new Error("no network allowed"); } };
        for (const run of [
          () => window.refundActions.prepareBrowserRefund(document, network, selection, stored.api, BigInt(stored.refund.feeSat), options),
          () => window.refundActions.exportBrowserRefund(document, network, selection, stored.api, stored, options),
          () => window.refundActions.broadcastBrowserRefund(document, network, selection, stored.api, stored, options),
        ]) { try { await run(); } catch { refused++; } }
        const after = await new Promise<unknown>((resolve) => { const r = db.transaction("intents").objectStore("intents").get(stored.id); r.onsuccess = () => resolve(r.result); });
        return { calls, refused, stored, after };
      } finally { journal.close(); db.close(); }
    }, { corrupt, plaintext: canonicalize(item.record)!, network: item.expectedNetwork as { name: "regtest"; genesis_hash: string } });
    expect(result.stored).toEqual(corrupt); expect(result.after).toEqual(corrupt); expect(result.refused).toBe(3); expect(result.calls).toBe(0);
  }
});
