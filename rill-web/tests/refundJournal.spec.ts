import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { BrowserRefundJournal, RefundJournalDraft, RefundJournalRecord } from "../src/browserRefundJournal";

declare global { interface Window { BrowserRefundJournal: typeof BrowserRefundJournal; refundJournalReady: boolean } }
const URL = "http://127.0.0.1:18765/test-only/refund-journal.html";
const draft = (): RefundJournalDraft => JSON.parse(readFileSync(new globalThis.URL("../tmp/preview/test-only/refund-journal-draft.json", import.meta.url), "utf8"));
async function ready(page: Page) { await page.goto(URL); await page.waitForFunction(() => window.refundJournalReady); }
async function prepare(page: Page, input = draft()): Promise<RefundJournalRecord> {
  return page.evaluate(async (input) => { const journal = await window.BrowserRefundJournal.open(); try { return await journal.prepare(input); } finally { journal.close(); } }, input);
}

function outpointDraft(): RefundJournalDraft {
  const input = draft();
  return { networkIdentity: input.networkIdentity, api: input.api, broadcastApi: input.broadcastApi,
    rawFundingTransactionHex: input.rawFundingTransactionHex, refund: input.refund, selection: "outpoint" };
}

test("explicit preparation survives reopening, snapshots caller inputs, and keeps only public immutable intent fields", async ({ page }) => {
  await ready(page);
  const saved = await prepare(page);
  expect(saved.state).toBe("prepared");
  await page.reload(); await page.waitForFunction(() => window.refundJournalReady);
  const loaded = await page.evaluate(async (saved) => {
    const journal = await window.BrowserRefundJournal.open();
    try {
      const record = await journal.get(saved.networkIdentity, saved.refund.fundingTxid, saved.refund.fundingVout);
      return { record, frozen: Object.isFrozen(record) && Object.isFrozen(record!.refund) && Object.isFrozen(record!.networkIdentity) };
    } finally { journal.close(); }
  }, saved);
  expect(loaded.record).toEqual(saved); expect(loaded.frozen).toBe(true);
  expect(Object.keys(saved).sort()).toEqual(["api", "bindingRevision", "broadcastApi", "createdAt", "fundingAttemptId", "id", "networkIdentity", "rawFundingTransactionHex", "refund", "signedDigest", "state", "updatedAt"]);
});

test("two tabs create one immutable intent and only one atomic exposure winner", async ({ page, context }) => {
  await ready(page); const second = await context.newPage(); await ready(second);
  const [one, two] = await Promise.all([prepare(page), prepare(second)]);
  expect(one).toEqual(two);
  const expose = (tab: Page) => tab.evaluate(async (record) => {
    const journal = await window.BrowserRefundJournal.open();
    try { return { ok: true, record: await journal.beginExposure(record) }; } catch { return { ok: false }; } finally { journal.close(); }
  }, one);
  const outcomes = await Promise.all([expose(page), expose(second)]);
  expect(outcomes.filter((result) => result.ok)).toHaveLength(1);
  const winner = outcomes.find((result) => result.ok)!.record!;
  expect(winner.state).toBe("submission-unknown");
  // Simulate losing the response or crashing before exposing bytes. No restart or reset.
  await page.reload(); await page.waitForFunction(() => window.refundJournalReady);
  const recovery = await page.evaluate(async (record) => {
    const journal = await window.BrowserRefundJournal.open();
    try {
      const existing = (await journal.get(record.networkIdentity, record.refund.fundingTxid, record.refund.fundingVout))!;
      let resend = false; try { await journal.beginExposure(existing); resend = true; } catch {}
      return { existing, exported: await journal.reexportIdentical(existing), resend };
    } finally { journal.close(); }
  }, winner);
  expect(recovery.resend).toBe(false); expect(recovery.exported.refund.transactionHex).toBe(one.refund.transactionHex);
  expect(recovery.existing.state).toBe("submission-unknown");
});

test("conflicting plans cannot replace an intent, and exact acceptance never permits another POST", async ({ page }) => {
  await ready(page); const saved = await prepare(page);
  const result = await page.evaluate(async ({ saved, input }) => {
    const journal = await window.BrowserRefundJournal.open();
    try {
      let replaced = false; try { await journal.prepare({ ...input, api: "http://localhost:8091/api" }); replaced = true; } catch {}
      const unknown = await journal.beginExposure(saved);
      let acceptedWrong = false; try { await journal.markAccepted(unknown, "0".repeat(64)); acceptedWrong = true; } catch {}
      const accepted = await journal.markAccepted(unknown, unknown.refund.txid);
      let resent = false; try { await journal.beginExposure(accepted); resent = true; } catch {}
      return { replaced, acceptedWrong, resent, accepted, exported: await journal.reexportIdentical(accepted) };
    } finally { journal.close(); }
  }, { saved, input: draft() });
  expect(result.replaced).toBe(false); expect(result.acceptedWrong).toBe(false); expect(result.resent).toBe(false);
  expect(result.accepted.state).toBe("accepted"); expect(result.exported.refund).toEqual(saved.refund);
});

test("partial or corrupted entries remain preserved and block reads, preparations, and exposure", async ({ page }) => {
  await ready(page); const saved = await prepare(page);
  for (const corrupt of [{ ...saved, signedDigest: "0".repeat(64) }, { id: saved.id, state: "prepared" }, { ...saved, state: "unknown-old-format" }]) {
    const result = await page.evaluate(async ({ corrupt, saved, input }) => {
      const raw = await new Promise<IDBDatabase>((resolve) => { const request = indexedDB.open("rillswap-refund-submissions"); request.onsuccess = () => resolve(request.result); });
      await new Promise<void>((resolve) => { const tx = raw.transaction("intents", "readwrite"); tx.objectStore("intents").put(corrupt); tx.oncomplete = () => resolve(); }); raw.close();
      const journal = await window.BrowserRefundJournal.open(); let failures = 0;
      try {
        for (const operation of [() => journal.get(saved.networkIdentity, saved.refund.fundingTxid, saved.refund.fundingVout), () => journal.prepare(input), () => journal.beginExposure(saved)]) {
          try { await operation(); } catch { failures++; }
        }
      } finally { journal.close(); }
      return failures;
    }, { corrupt, saved, input: draft() });
    expect(result).toBe(3);
  }
});

test("unsupported stores, unavailable strict durability, and quota failures refuse rather than silently degrade", async ({ page }) => {
  await ready(page);
  const result = await page.evaluate(async (input) => {
    const journal = await window.BrowserRefundJournal.open();
    const original = IDBDatabase.prototype.transaction;
    let strictRefused = false, quotaRefused = false;
    try {
      IDBDatabase.prototype.transaction = function (...args: Parameters<IDBDatabase["transaction"]>) {
        const tx = original.apply(this, args); if (args[1] === "readwrite") Object.defineProperty(tx, "durability", { value: "relaxed" }); return tx;
      };
      try { await journal.prepare(input); } catch { strictRefused = true; }
      IDBDatabase.prototype.transaction = original;
      const add = IDBObjectStore.prototype.add;
      IDBObjectStore.prototype.add = () => { throw new DOMException("synthetic quota", "QuotaExceededError"); };
      try { await journal.prepare(input); } catch { quotaRefused = true; } finally { IDBObjectStore.prototype.add = add; }
      return { strictRefused, quotaRefused, record: await journal.get(input.networkIdentity, input.refund.fundingTxid, input.refund.fundingVout) };
    } finally { IDBDatabase.prototype.transaction = original; journal.close(); }
  }, draft());
  expect(result.strictRefused).toBe(true); expect(result.quotaRefused).toBe(true); expect(result.record).toBeUndefined();
});

test("a crash after durable exposure commit but before validated readback leaves UNKNOWN and permits identical manual export", async ({ page }) => {
  await ready(page); const saved = await prepare(page);
  const result = await page.evaluate(async (saved) => {
    const journal = await window.BrowserRefundJournal.open(); const original = journal.get.bind(journal);
    let blocked = false;
    journal.get = async () => { throw new Error("synthetic interrupted readback"); };
    try { await journal.beginExposure(saved); } catch { blocked = true; }
    journal.get = original;
    try { const stored = (await journal.get(saved.networkIdentity, saved.refund.fundingTxid, saved.refund.fundingVout))!;
      return { blocked, stored, exported: await journal.reexportIdentical(stored) };
    } finally { journal.close(); }
  }, saved);
  expect(result.blocked).toBe(true); expect(result.stored.state).toBe("submission-unknown");
  expect(result.exported.refund.transactionHex).toBe(saved.refund.transactionHex);
});

test("incompatible existing database shapes are refused and preserved without repair", async ({ page }) => {
  await ready(page);
  for (const shape of ["missing", "keypath", "index", "extra"]) {
    const result = await page.evaluate(async (shape) => {
      await new Promise<void>((resolve) => { const request = indexedDB.deleteDatabase("rillswap-refund-submissions"); request.onsuccess = () => resolve(); });
      const db = await new Promise<IDBDatabase>((resolve) => {
        const request = indexedDB.open("rillswap-refund-submissions");
        request.onupgradeneeded = () => {
          if (shape !== "missing") {
            const store = request.result.createObjectStore("intents", { keyPath: shape === "keypath" ? "wrong" : "id" });
            if (shape === "index") store.createIndex("unexpected", "state");
          }
          if (shape === "extra" || shape === "missing") request.result.createObjectStore("unexpected");
        };
        request.onsuccess = () => resolve(request.result);
      });
      const original = Array.from(db.objectStoreNames); db.close();
      let refused = false; try { (await window.BrowserRefundJournal.open()).close(); } catch { refused = true; }
      const check = await new Promise<IDBDatabase>((resolve) => { const request = indexedDB.open("rillswap-refund-submissions"); request.onsuccess = () => resolve(request.result); });
      const after = Array.from(check.objectStoreNames); check.close(); return { refused, original, after };
    }, shape);
    expect(result.refused, shape).toBe(true); expect(result.after, shape).toEqual(result.original);
  }
});

test("conflicting concurrent witnesses or fees cannot replace the winning exact bytes", async ({ page, context }) => {
  await ready(page); const second = await context.newPage(); await ready(second);
  const alternatives = JSON.parse(readFileSync(new globalThis.URL("../tmp/preview/test-only/refund-journal-alternatives.json", import.meta.url), "utf8")) as RefundJournalDraft[];
  expect(alternatives[0]!.refund.txid).toBe(draft().refund.txid);
  expect(alternatives[0]!.refund.transactionHex).not.toBe(draft().refund.transactionHex);
  const attempt = (tab: Page, input: RefundJournalDraft) => tab.evaluate(async (input) => {
    const journal = await window.BrowserRefundJournal.open();
    try { return await journal.prepare(input); } catch { return null; } finally { journal.close(); }
  }, input);
  const outcomes = await Promise.all([attempt(page, draft()), attempt(second, alternatives[0]!)]);
  expect(outcomes.filter(Boolean)).toHaveLength(1);
  const winner = outcomes.find(Boolean)!;
  expect(await attempt(second, alternatives[1]!)).toBeNull();
  const stored = await page.evaluate(async (winner) => {
    const journal = await window.BrowserRefundJournal.open(); try { return await journal.get(winner.networkIdentity, winner.refund.fundingTxid, winner.refund.fundingVout); } finally { journal.close(); }
  }, winner);
  expect(stored).toEqual(winner);
});

test("failed transition commits preserve prepared or UNKNOWN without exposure permission", async ({ page }) => {
  await ready(page); const saved = await prepare(page);
  const result = await page.evaluate(async (saved) => {
    const journal = await window.BrowserRefundJournal.open(), original = IDBObjectStore.prototype.put;
    let exposeFailed = false, acceptFailed = false;
    try {
      IDBObjectStore.prototype.put = function (...args: Parameters<IDBObjectStore["put"]>) { this.transaction.abort(); return original.apply(this, args); };
      try { await journal.beginExposure(saved); } catch { exposeFailed = true; }
      IDBObjectStore.prototype.put = original;
      const before = (await journal.get(saved.networkIdentity, saved.refund.fundingTxid, saved.refund.fundingVout))!;
      const unknown = await journal.beginExposure(before);
      IDBObjectStore.prototype.put = () => { throw new DOMException("synthetic quota", "QuotaExceededError"); };
      try { await journal.markAccepted(unknown, unknown.refund.txid); } catch { acceptFailed = true; }
      IDBObjectStore.prototype.put = original;
      return { exposeFailed, acceptFailed, before, after: await journal.get(saved.networkIdentity, saved.refund.fundingTxid, saved.refund.fundingVout) };
    } finally { IDBObjectStore.prototype.put = original; journal.close(); }
  }, saved);
  expect(result.exposeFailed).toBe(true); expect(result.before.state).toBe("prepared");
  expect(result.acceptFailed).toBe(true); expect(result.after!.state).toBe("submission-unknown");
});

test("acceptance readback interruption retains accepted state and never authorizes replay", async ({ page }) => {
  await ready(page); const saved = await prepare(page);
  const result = await page.evaluate(async (saved) => {
    const journal = await window.BrowserRefundJournal.open(), original = journal.get.bind(journal);
    const unknown = await journal.beginExposure(saved);
    journal.get = async () => { throw new Error("readback interrupted"); };
    let failed = false; try { await journal.markAccepted(unknown, unknown.refund.txid); } catch { failed = true; }
    journal.get = original;
    try { const stored = (await journal.get(saved.networkIdentity, saved.refund.fundingTxid, saved.refund.fundingVout))!;
      let replay = false; try { await journal.beginExposure(stored); replay = true; } catch {}
      return { failed, stored, replay };
    } finally { journal.close(); }
  }, saved);
  expect(result.failed).toBe(true); expect(result.stored.state).toBe("accepted"); expect(result.replay).toBe(false);
});

test("drafts are snapshotted immediately and refused corrupted entries remain byte-identical", async ({ page }) => {
  await ready(page);
  const result = await page.evaluate(async (input) => {
    const journal = await window.BrowserRefundJournal.open();
    const pending = journal.prepare(input);
    (input as { api: string }).api = "https://example.invalid/api";
    (input.refund as { transactionHex: string }).transactionHex = "00";
    const saved = await pending;
    journal.close();
    const corrupt = { ...saved, signedDigest: "0".repeat(64) };
    const db = await new Promise<IDBDatabase>((resolve) => { const request = indexedDB.open("rillswap-refund-submissions"); request.onsuccess = () => resolve(request.result); });
    await new Promise<void>((resolve) => { const tx = db.transaction("intents", "readwrite"); tx.objectStore("intents").put(corrupt); tx.oncomplete = () => resolve(); });
    const reader = await window.BrowserRefundJournal.open();
    try { await reader.get(saved.networkIdentity, saved.refund.fundingTxid, saved.refund.fundingVout); } catch {} finally { reader.close(); }
    const after = await new Promise<unknown>((resolve) => { const tx = db.transaction("intents"); const request = tx.objectStore("intents").get(saved.id); request.onsuccess = () => resolve(request.result); });
    db.close(); return { saved, corrupt, after };
  }, draft());
  expect(result.saved.api).toBe(draft().api); expect(result.saved.refund).toEqual(draft().refund);
  expect(result.after).toEqual(result.corrupt);
});

for (const mode of ["legacy", "outpoint"]) {
  test(`${mode} records keep their exact stored shape through exposure and acceptance without migration`, async ({ page }) => {
    await ready(page); const saved = await prepare(page, mode === "legacy" ? draft() : outpointDraft());
    const expectedKeys = mode === "legacy" ? Object.keys(saved).sort() :
      ["api", "broadcastApi", "createdAt", "id", "networkIdentity", "rawFundingTransactionHex", "refund", "selection", "signedDigest", "state", "updatedAt"];
    expect(Object.keys(saved).sort()).toEqual(expectedKeys);
    const records = await page.evaluate(async (saved) => {
      const journal = await window.BrowserRefundJournal.open();
      const db = await new Promise<IDBDatabase>((resolve) => { const r = indexedDB.open("rillswap-refund-submissions"); r.onsuccess = () => resolve(r.result); });
      const raw = () => new Promise<RefundJournalRecord>((resolve) => { const r = db.transaction("intents").objectStore("intents").get(saved.id); r.onsuccess = () => resolve(r.result); });
      try {
        const before = await raw(), exposed = await journal.beginExposure(saved), unknown = await raw();
        await journal.markAccepted(exposed, exposed.refund.txid);
        return [before, unknown, await raw()];
      } finally { journal.close(); db.close(); }
    }, saved);
    expect(records.map((r) => r.state)).toEqual(["prepared", "submission-unknown", "accepted"]);
    for (const record of records) {
      expect(Object.keys(record).sort()).toEqual(expectedKeys);
      expect(record.refund).toEqual(saved.refund); expect(record.signedDigest).toBe(saved.signedDigest);
    }
  });
}

test("mixed selector shapes and unknown tags are refused without rewriting raw records", async ({ page }) => {
  await ready(page); const saved = await prepare(page), alternative = outpointDraft();
  const independent = { ...alternative, id: saved.id, signedDigest: saved.signedDigest, createdAt: saved.createdAt, updatedAt: saved.updatedAt, state: saved.state };
  for (const corrupt of [{ ...saved, selection: "outpoint" }, { ...saved, ...alternative, selection: "outpoint" },
    { ...independent, selection: "unknown" }]) {
    const result = await page.evaluate(async ({ corrupt, saved, input }) => {
      const db = await new Promise<IDBDatabase>((resolve) => { const r = indexedDB.open("rillswap-refund-submissions"); r.onsuccess = () => resolve(r.result); });
      await new Promise<void>((resolve) => { const tx = db.transaction("intents", "readwrite"); tx.objectStore("intents").put(corrupt); tx.oncomplete = () => resolve(); });
      const journal = await window.BrowserRefundJournal.open(); let refused = 0;
      try {
        for (const run of [() => journal.get(saved.networkIdentity, saved.refund.fundingTxid, saved.refund.fundingVout), () => journal.prepare(input), () => journal.beginExposure(saved)]) {
          try { await run(); } catch { refused++; }
        }
        const after = await new Promise<unknown>((resolve) => { const r = db.transaction("intents").objectStore("intents").get(saved.id); r.onsuccess = () => resolve(r.result); });
        return { refused, after };
      } finally { journal.close(); db.close(); }
    }, { corrupt, saved, input: alternative });
    expect(result.refused).toBe(3); expect(result.after).toEqual(corrupt);
  }
  // Rollback refusal follows from the old build's closed legacy key set, not an executed old-build test.
});

test("cross-mode preparations race for one outpoint and neither mode can re-expose UNKNOWN", async ({ page, context }) => {
  await ready(page); const second = await context.newPage(); await ready(second);
  const attempt = (tab: Page, input: RefundJournalDraft) => prepare(tab, input).catch(() => null);
  const outcomes = await Promise.all([attempt(page, draft()), attempt(second, outpointDraft())]);
  expect(outcomes.filter(Boolean)).toHaveLength(1);
  const saved = outcomes.find(Boolean)!;
  const exposed = await page.evaluate(async (saved) => {
    const journal = await window.BrowserRefundJournal.open(); try { return await journal.beginExposure(saved); } finally { journal.close(); }
  }, saved);
  const result = await second.evaluate(async (saved) => {
    const journal = await window.BrowserRefundJournal.open();
    try {
      const loaded = (await journal.get(saved.networkIdentity, saved.refund.fundingTxid, saved.refund.fundingVout))!;
      let replay = false; try { await journal.beginExposure(loaded); replay = true; } catch {}
      return { loaded, replay, exported: await journal.reexportIdentical(loaded) };
    } finally { journal.close(); }
  }, saved);
  expect(result.loaded).toEqual(exposed); expect(result.replay).toBe(false); expect(result.exported.refund).toEqual(saved.refund);
});
