import { expect, openRecovery, openSettings, openTool, test } from "./fixtures/swapPage";
import type { Page } from "@playwright/test";
import canonicalize from "canonicalize";
import { readFileSync } from "node:fs";
import { encryptCanonicalRecoveryForRecipient } from "../src/recoveryAgeContainer";
import { createRecoveryKey } from "../src/recoveryKeys";
import { swapLinkFragment } from "../src/swapLink";
import type { RecoveryRefundCase } from "../unit/fixtures/recoveryRefundCases";
import type { BrowserRefundJournal } from "../src/browserRefundJournal";
import { testInvoice } from "../../rill-payments/tests/helpers";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { parseRecoveryFundingTransaction, parseTransaction } from "../src/swap/transaction";

declare global { interface Window { uiRefundJournal: typeof BrowserRefundJournal; refundExposurePending: boolean; releaseRefundExposure: () => void; restoreTermsStorage: () => void } }

const BASE = "http://127.0.0.1:8091/api";
const corpus = (): RecoveryRefundCase[] => JSON.parse(readFileSync(new URL("../tmp/preview/test-only/recovery-refund-cases.json", import.meta.url), "utf8"));
const payload = (buffer: Uint8Array, name: string) => ({ name, mimeType: "application/octet-stream", buffer: Buffer.from(buffer) });

async function importRecord(page: Page, item: RecoveryRefundCase): Promise<void> {
  const recipient = await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { return (await wallet.recoveryKey()).recipient; } finally { wallet.close(); }
  });
  const encrypted = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(item.record)!), recipient);
  await openRecovery(page);
  await page.locator("#swap-recovery-file").setInputFiles(payload(encrypted, "public-test-swap.age"));
  await page.locator("#swap-recovery-inspect").click();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
}

async function chainApi(page: Page, item: RecoveryRefundCase, tip = 1101, pause?: () => Promise<void>) {
  const calls: string[] = [];
  const fundingTxid = item.record.funding_history[item.bindingRevision]?.binding.funding_txid ?? parseRecoveryFundingTransaction(hexToBytes(item.fundingTxHex)).txid;
  await page.route(`${BASE}/**`, async (route) => {
    const request = route.request(), path = new URL(request.url()).pathname.slice(5);
    calls.push(path);
    expect(request.method()).toBe("GET"); expect(request.postData()).toBeNull();
    expect(request.headers()["authorization"]).toBeUndefined(); expect(request.headers()["referer"]).toBeUndefined();
    if (path.endsWith("/hex") && pause) await pause();
    let body: string | undefined;
    if (path === "block-height/0") body = item.record.network_identity.genesis_hash;
    else if (path === "blocks/tip/height") body = String(tip);
    else if (path === "blocks/tip/hash") body = "a".repeat(64);
    else if (path === "block-height/1000") body = "d".repeat(64);
    else if (path === `tx/${fundingTxid}/hex`) body = item.fundingTxHex;
    else if (path.endsWith("/status")) body = JSON.stringify({ confirmed: true, block_height: 1000, block_hash: "d".repeat(64) });
    else if (path.endsWith("/outspend/0")) body = '{"spent":false}';
    await route.fulfill({ status: body ? 200 : 404, body: body ?? "Unknown fixture transaction", headers: {
      "Access-Control-Allow-Origin": "http://127.0.0.1:18765", "Content-Type": path.endsWith("/status") || path.includes("outspend") ? "application/json" : "text/plain",
    } });
  });
  return calls;
}

test("a swap link reopens its encrypted record locally in the tracking view without connecting", async ({ page }) => {
  const item = corpus()[0]!, calls = await chainApi(page, item);
  const sockets: string[] = []; page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto("http://127.0.0.1:18765/test-only/swap.html");
  const recipient = await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { return (await wallet.recoveryKey()).recipient; } finally { wallet.close(); }
  });
  const encrypted = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(item.record)!), recipient);
  const fragment = swapLinkFragment({ file: encrypted, network: "regtest" });
  await page.evaluate((fragment) => { location.hash = fragment; }, fragment); // a bookmark followed from the open page reloads it
  await page.waitForLoadState();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
  await expect(page.locator("#swap-form")).toBeHidden();
  await expect(page.locator("#swap-tracking h2")).toHaveText("Swap record");
  await expect(page.locator("#swap-status")).toHaveText("Swap record opened from its link");
  await expect(page.locator("#swap-network")).toHaveValue("regtest");
  expect(new URL(page.url()).hash).toBe(fragment); // the address stays bookmarkable
  await expect(page.locator("#swap-link-anchor")).toHaveAttribute("href", page.url());
  expect(calls).toEqual([]); expect(sockets).toEqual([]);
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result h3")).toHaveText("Funding observed by your API");
  await page.goto("about:blank");
  await page.goto("http://127.0.0.1:18765/test-only/swap.html#swap=not*base64&network=regtest");
  await expect(page.locator("#swap-form")).toBeVisible(); // malformed links are ignored, not partially used
  await expect(page.locator("#swap-tracking")).toBeHidden();
});

for (const failStorage of [false, true]) test(`funded callback ${failStorage ? "refuses publication but keeps downloadable bytes" : "survives a URL-less reload with explicit local opening"}`, async ({ page }, testInfo) => {
  const item = corpus()[0]!, calls = await chainApi(page, item);
  const sockets: string[] = []; page.on("websocket", (socket) => sockets.push(socket.url()));
  const url = "http://127.0.0.1:18765/test-only/swap.html";
  await page.goto(url);
  const recipient = await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { return (await wallet.recoveryKey()).recipient; } finally { wallet.close(); }
  });
  const encrypted = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(item.record)!), recipient);
  const checkpointId = `funded:regtest:${bytesToHex(sha256(encrypted))}`;
  await page.evaluate(({ bytes, failStorage, checkpointId }) => {
    window.uiFixture.fundedRecovery = bytes;
    if (failStorage) {
      const original = IDBObjectStore.prototype.add;
      IDBObjectStore.prototype.add = function(this: IDBObjectStore, ...args: Parameters<typeof original>) {
        // Refuse this funded checkpoint, not the earlier independent terms checkpoint.
        if (args[1] === checkpointId) throw new DOMException("quota", "QuotaExceededError");
        return original.apply(this, args);
      };
    }
  }, { bytes: Array.from(encrypted), failStorage, checkpointId });
  const now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("funded_storage", "1000000", now, now + 7200));
  await page.locator("#swap-start").click();
  await page.locator("#swap-quote-accept").click();
  await expect(page.locator("#swap-error")).toContainText(failStorage ? "Browser recovery storage" : "Fixture stopped after funded checkpoint");
  expect(await page.evaluate(() => !!window.uiFixture.fundingPublished)).toBe(!failStorage);
  const downloading = page.waitForEvent("download");
  await page.locator("#swap-backups summary").click();
  await page.locator('#swap-backups a[download*="funded-recovery"]').click();
  const path = testInfo.outputPath("funded.age"); await (await downloading).saveAs(path);
  expect(readFileSync(path)).toEqual(Buffer.from(encrypted));
  expect(new URL(page.url()).hash).toBe(swapLinkFragment({ file: encrypted, network: "regtest" }));
  if (failStorage) return;
  const before = calls.length;
  await page.goto("about:blank"); await page.goto(url); // No URL fragment or download is used.
  await openTool(page, "history");
  await page.locator(".saved-swap").filter({ hasText: checkpointId.slice(-16) }).getByRole("button", { name: "Open saved swap", exact: true }).click();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
  await expect(page.locator("#swap-status")).toHaveText("Saved recovery opened locally");
  expect(calls).toHaveLength(before); expect(sockets).toEqual([]);
});

test("terms checkpoints survive URL-less reload, open without uploads, and reuse one wallet for multiple swaps", async ({ page }) => {
  const url = "http://127.0.0.1:18765/test-only/swap.html", item = corpus()[0]!, calls = await chainApi(page, item);
  const sockets: string[] = []; page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto(url);
  const identity = await page.evaluate(async () => { const wallet = await window.uiFixture.wallet.open(); try { return wallet.info(); } finally { wallet.close(); } });
  const checkpointIds: string[] = [];
  for (const [index, name] of ["P2WPKH refund", "P2TR refund"].entries()) {
    const record = corpus().find((c) => c.name === name)!; record.record.funding_history = [];
    const encrypted = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(record.record)!), identity.recipient);
    const id = `funded:regtest:${bytesToHex(sha256(encrypted))}`; checkpointIds.push(id);
    await page.evaluate(({ bytes, script }) => { window.uiFixture.termsRecovery = bytes; window.uiFixture.fundingScript = script; },
      { bytes: Array.from(encrypted), script: record.record.taproot_contract.script_pubkey });
    const now = Math.floor(Date.now() / 1000);
    await page.locator("#swap-invoice").fill(testInvoice(`terms_storage_${index}`, "1000000", now, now + 7200));
    await page.locator("#swap-start").click(); await page.locator("#swap-quote-accept").click();
    await expect(page.locator("#swap-funding-uri")).toBeVisible();
    expect(await page.evaluate(async (id) => { const wallet = await window.uiFixture.wallet.open(); try { return (await wallet.listFundedRecoveries()).some((entry) => entry.id === id); } finally { wallet.close(); } }, id)).toBe(true);
    await page.goto("about:blank"); await page.goto(url); // No bookmarked link, key import or recovery-file input.
  }
  const state = await page.evaluate(async () => { const wallet = await window.uiFixture.wallet.open(); try { return { info: await wallet.info(), nextIndex: (await wallet.allocateRefund("regtest")).index }; } finally { wallet.close(); } });
  expect(state.info.fingerprint).toBe(identity.fingerprint); expect(state.info.recipient).toBe(identity.recipient); expect(state.nextIndex).toBe(2);
  const before = calls.length;
  await openRecovery(page); await page.locator("#swap-open-saved-recoveries").click();
  await expect(page.locator("#swap-saved-recoveries")).toBeVisible(); await expect(page.locator(".saved-swap")).toHaveCount(2);
  for (const id of checkpointIds) {
    await page.locator(".saved-swap").filter({ hasText: id.slice(-16) }).getByRole("button", { name: "Open saved swap", exact: true }).click();
    await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
    await expect(page.locator("#swap-recovery-result")).toContainText("0 recorded funding revisions");
    await expect(page.locator("#swap-status")).toHaveText("Saved recovery opened locally");
    expect(new URL(page.url()).hash).toBe("");
    await page.locator("#swap-open-saved-recoveries").click();
  }
  expect(calls).toHaveLength(before); expect(sockets).toEqual([]);
});

for (const failure of ["quota", "readback"]) {
  test(`terms ${failure} failure refuses the deposit address, retains backup, and never resets the wallet`, async ({ page }) => {
    const item = corpus()[0]!; item.record.funding_history = []; await chainApi(page, item);
    await page.goto("http://127.0.0.1:18765/test-only/swap.html");
    const identity = await page.evaluate(async () => { const wallet = await window.uiFixture.wallet.open(); try { return wallet.info(); } finally { wallet.close(); } });
    const encrypted = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(item.record)!), identity.recipient);
    const id = `funded:regtest:${bytesToHex(sha256(encrypted))}`;
    await page.evaluate(({ bytes, script, id, failure }) => {
      window.uiFixture.termsRecovery = bytes; window.uiFixture.fundingScript = script;
      const add = IDBObjectStore.prototype.add, get = IDBObjectStore.prototype.get;
      window.restoreTermsStorage = () => { IDBObjectStore.prototype.add = add; IDBObjectStore.prototype.get = get; };
      IDBObjectStore.prototype.add = function (...args: Parameters<IDBObjectStore["add"]>) {
        if (failure === "quota" && args[1] === id) throw new DOMException("quota", "QuotaExceededError");
        return add.apply(this, args);
      };
      IDBObjectStore.prototype.get = function (...args: Parameters<IDBObjectStore["get"]>) {
        if (failure === "readback" && args[0] === id && this.transaction.mode === "readonly") throw new Error("synthetic interrupted readback");
        return get.apply(this, args);
      };
    }, { bytes: Array.from(encrypted), script: item.record.taproot_contract.script_pubkey, id, failure });
    try {
      const now = Math.floor(Date.now() / 1000);
      await page.locator("#swap-invoice").fill(testInvoice(`terms_${failure}`, "1000000", now, now + 7200));
      await page.locator("#swap-start").click(); await page.locator("#swap-quote-accept").click();
      await expect(page.locator("#swap-error")).toContainText("Browser recovery storage");
      await expect(page.locator("#swap-funding-uri")).toHaveCount(0);
      expect(await page.evaluate(() => !!window.uiFixture.fundingPublished || !!window.uiFixture.fundingSource)).toBe(false);
      await page.locator("#swap-backups summary").click(); await expect(page.locator('#swap-backups a[download*="terms-recovery"]')).toBeVisible();
      expect(new URL(page.url()).hash).toBe(swapLinkFragment({ file: encrypted, network: "regtest" }));
    } finally { await page.evaluate(() => window.restoreTermsStorage()); }
    const state = await page.evaluate(async () => { const wallet = await window.uiFixture.wallet.open(); try { return { info: await wallet.info(), nextIndex: (await wallet.allocateRefund("regtest")).index, saved: (await wallet.listFundedRecoveries()).length }; } finally { wallet.close(); } });
    expect(state.info.fingerprint).toBe(identity.fingerprint); expect(state.nextIndex).toBe(1);
    expect(state.saved).toBe(failure === "quota" ? 0 : 1);
  });
}

test("opening a saved checkpoint clears a different linked record's URL authority", async ({ page }) => {
  const item = corpus()[0]!, calls = await chainApi(page, item);
  const url = "http://127.0.0.1:18765/test-only/swap.html";
  await page.goto(url);
  const recipient = await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { return (await wallet.recoveryKey()).recipient; } finally { wallet.close(); }
  });
  const plaintext = new TextEncoder().encode(canonicalize(item.record)!);
  const linked = await encryptCanonicalRecoveryForRecipient(plaintext, recipient);
  const saved = await encryptCanonicalRecoveryForRecipient(plaintext, recipient);
  await page.evaluate(async (bytes) => {
    const wallet = await window.uiFixture.wallet.open();
    try { await wallet.saveFundedRecovery("regtest", Uint8Array.from(bytes)); } finally { wallet.close(); }
  }, Array.from(saved));
  await page.goto(url + swapLinkFragment({ file: linked, network: "regtest" }));
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
  await expect(page.locator("#swap-link")).toBeVisible();
  await openTool(page, "history");
  await page.getByRole("button", { name: "Open saved swap", exact: true }).click();
  await expect(page.locator("#swap-status")).toHaveText("Saved recovery opened locally");
  await expect(page.locator("#swap-link")).toBeHidden();
  expect(new URL(page.url()).hash).toBe("");
  const bytes = await page.locator("#swap-recovery-file").evaluate(async (input) =>
    Array.from(new Uint8Array(await (input as HTMLInputElement).files![0]!.arrayBuffer())));
  expect(bytes).toEqual(Array.from(saved));
  await page.reload(); await expect(page.locator("#swap-form")).toBeVisible();
  await expect(page.locator("#swap-recovery-result h3")).toHaveCount(0);
  expect(calls).toEqual([]);
});

test("a delayed local Open cannot replace an active quote's network or recovery view", async ({ page }) => {
  const item = corpus()[0]!; await chainApi(page, item);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html");
  await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { await wallet.saveFundedRecovery("signet", Uint8Array.of(1)); } finally { wallet.close(); }
  });
  await page.reload();
  await openTool(page, "history");
  await page.evaluate(() => {
    const prototype = window.uiFixture.wallet.prototype, original = prototype.readFundedRecovery;
    prototype.readFundedRecovery = async function(id) {
      const result = await original.call(this, id);
      await new Promise<void>((resolve) => { window.uiFixture.releaseInfo = resolve; window.uiFixture.infoPending = true; });
      return result;
    };
  });
  await page.getByRole("button", { name: "Open saved swap", exact: true }).click();
  await page.waitForFunction(() => window.uiFixture.infoPending);
  const now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("busy_saved_open", "1000000", now, now + 7200));
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeEnabled();
  await page.evaluate(() => window.uiFixture.releaseInfo!());
  await openTool(page, "history");
  await expect(page.getByRole("button", { name: "Open saved swap", exact: true })).toBeEnabled();
  await expect(page.locator("#swap-network")).toHaveValue("regtest");
  await expect(page.locator("#swap-recovery-result h3")).toHaveCount(0);
  await expect(page.locator("#swap-quote-accept")).toBeEnabled();
});

test("local inspection connects to nothing; an explicit funding check reports trusted mature observations", async ({ page }) => {
  const item = corpus()[0]!, calls = await chainApi(page, item);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html");
  await importRecord(page, item);
  expect(calls).toEqual([]);
  await expect(page.locator("#swap-recovery-revision")).not.toBeVisible();
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result h3")).toHaveText("Funding observed by your API");
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("102 confirmations");
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("refund lock has passed");
  await expect(page.locator("#swap-recovery-observed-time")).toContainText("Observed tip 1101 has reached this height");
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("not independent chain proof or permission to sign");
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("Nothing was signed or broadcast");
  expect(calls.filter((path) => path.endsWith("/hex"))).toHaveLength(2);
  expect(calls.filter((path) => path.includes("outspend"))).toHaveLength(2);
  await page.locator("#swap-recovery-file").setInputFiles([]);
  await expect(page.locator("#swap-recovery-funding-controls")).not.toBeVisible();
  await expect(page.locator("#swap-recovery-result h3")).toHaveCount(0);
  await expect(page.locator("#swap-recovery-funding-result h3")).toHaveCount(0);
});

test("a coherent immature observation is a waiting state, not a refund authorization", async ({ page }) => {
  const item = corpus()[0]!; await chainApi(page, item, 1100);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result h3")).toHaveText("Funding observed by your API");
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("Waiting for a tip above block 1100");
  await expect(page.locator("#swap-recovery-funding-result")).not.toContainText("refund lock has passed");
  await expect(page.locator("#swap-recovery-observed-time")).toContainText("1 block remaining at observed tip 1100");
  await expect(page.locator("#swap-recovery-observed-time")).toContainText("mining is on demand");
  await expect(page.locator("#swap-recovery-observed-time")).not.toContainText("estimated ");
});

test("preparing is the destination approval, export records exposure, and identical saved bytes remain recoverable", async ({ page }, testInfo) => {
  const item = corpus()[0]!, calls = await chainApi(page, item);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await expect(page.locator("#swap-refund-destination")).toContainText("bcrt1");
  await expect(page.locator("#swap-refund-approve")).toHaveCount(0);
  await expect(page.locator("#swap-refund-consent")).toContainText("By preparing the refund you confirm");
  await expect(page.locator("#swap-refund-download")).not.toBeVisible();
  expect(calls).toEqual([]);
  await page.locator("#swap-refund-prepare").click();
  await expect(page.locator("#swap-refund-result h3")).toHaveText("Refund prepared and saved");
  await expect(page.locator("#swap-refund-broadcast")).toBeVisible();
  const download = page.waitForEvent("download"); await page.locator("#swap-refund-download").click();
  const signed = await download; const path = testInfo.outputPath("refund.hex"); await signed.saveAs(path);
  const first = readFileSync(path, "utf8"); expect(first).toMatch(/^[0-9a-f]+\n$/);
  await expect(page.locator("#swap-refund-result h3")).toHaveText("Signed transaction exported");
  await expect(page.locator("#swap-refund-broadcast")).not.toBeVisible();
  const before = calls.length;
  await page.locator("#swap-refund-prepare").click();
  await expect(page.locator("#swap-refund-result h3")).toHaveText("Previously exposed refund loaded");
  const again = page.waitForEvent("download"); await page.locator("#swap-refund-download").click();
  const same = await again; const samePath = testInfo.outputPath("refund-identical.hex"); await same.saveAs(samePath);
  expect(readFileSync(samePath, "utf8")).toBe(first); expect(calls).toHaveLength(before);
});

test("a broadcast sends only the saved signed transaction after durable UNKNOWN and never automatically retries", async ({ page }) => {
  const item = corpus()[0]!; await chainApi(page, item);
  let posts = 0, txid = "", unknownBeforePost = false;
  await page.route("http://127.0.0.1:8092/api/tx", async (route) => {
    posts++;
    const saved = await page.evaluate(async () => {
      const db = await new Promise<IDBDatabase>((resolve) => { const request = indexedDB.open("rillswap-refund-submissions"); request.onsuccess = () => resolve(request.result); });
      try { return await new Promise<{ state: string; refund: { txid: string; transactionHex: string } }>((resolve) => {
        const request = db.transaction("intents").objectStore("intents").getAll(); request.onsuccess = () => resolve(request.result[0]);
      }); } finally { db.close(); }
    });
    unknownBeforePost = saved.state === "submission-unknown";
    expect(route.request().postData()).toBe(saved.refund.transactionHex); txid = saved.refund.txid;
    await route.fulfill({ status: 200, body: txid, headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await page.locator("#swap-refund-prepare").click();
  await expect(page.locator("#swap-refund-result h3")).toHaveText("Refund prepared and saved");
  await page.locator("#swap-refund-broadcast").click();
  await expect(page.locator("#swap-refund-result h3")).toHaveText("Refund accepted by the API");
  await expect(page.locator("#swap-refund-result")).toContainText(txid); expect(posts).toBe(1); expect(unknownBeforePost).toBe(true);
  await page.locator("#swap-refund-prepare").click();
  await expect(page.locator("#swap-refund-result h3")).toHaveText("Previously exposed refund loaded");
  await expect(page.locator("#swap-refund-broadcast")).not.toBeVisible(); expect(posts).toBe(1);
});

test("changing settings after approval invalidates prepared exposure controls without broadcasting", async ({ page }) => {
  const item = corpus()[0]!; await chainApi(page, item);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await page.locator("#swap-refund-prepare").click();
  await expect(page.locator("#swap-refund-result h3")).toHaveText("Refund prepared and saved");
  await openSettings(page, "connection"); await page.locator("#swap-broadcast-api").fill("https://mempool.space/api");
  await page.locator("#swap-settings-close").click();
  await openRecovery(page);
  await expect(page.locator("#swap-refund-broadcast")).not.toBeVisible();
  await expect(page.locator("#swap-refund-download")).not.toBeVisible();
});

test("resetting connection settings clears funding observations and prepared exposure without broadcasting", async ({ page }) => {
  const item = corpus()[0]!, calls = await chainApi(page, item);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result h3")).toHaveText("Funding observed by your API");
  await page.locator("#swap-refund-prepare").click();
  await expect(page.locator("#swap-refund-result h3")).toHaveText("Refund prepared and saved");
  const before = calls.length;
  await openSettings(page, "connection");
  await page.locator("#swap-reset-connections").click();
  await expect(page.locator("#swap-recovery-funding-result")).toBeEmpty();
  await openRecovery(page);
  await expect(page.locator("#swap-refund-broadcast")).not.toBeVisible();
  await expect(page.locator("#swap-refund-download")).not.toBeVisible();
  expect(calls).toHaveLength(before);
});

test("approval invalidated after export commitment but before its return prevents the browser download", async ({ page }) => {
  const item = corpus()[0]!; await chainApi(page, item); let downloads = 0;
  page.on("download", () => downloads++);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await page.locator("#swap-refund-prepare").click();
  await expect(page.locator("#swap-refund-result h3")).toHaveText("Refund prepared and saved");
  await page.evaluate(() => {
    const original = window.uiRefundJournal.prototype.beginExposure;
    window.uiRefundJournal.prototype.beginExposure = async function (record) {
      const stored = await original.call(this, record); window.refundExposurePending = true;
      await new Promise<void>((resolve) => { window.releaseRefundExposure = resolve; }); return stored;
    };
  });
  await page.locator("#swap-refund-download").click(); await page.waitForFunction(() => window.refundExposurePending);
  await openSettings(page, "connection"); await page.locator("#swap-broadcast-api").fill("https://mempool.space/api");
  await page.locator("#swap-settings-close").click(); await openRecovery(page); await page.evaluate(() => window.releaseRefundExposure());
  await expect(page.locator("#swap-refund-result")).toContainText("Refund action could not be completed");
  expect(downloads).toBe(0);
  const stored = await page.evaluate(async () => {
    const db = await new Promise<IDBDatabase>((resolve) => { const request = indexedDB.open("rillswap-refund-submissions"); request.onsuccess = () => resolve(request.result); });
    try { return await new Promise<{ state: string }>((resolve) => { const request = db.transaction("intents").objectStore("intents").getAll(); request.onsuccess = () => resolve(request.result[0]); }); }
    finally { db.close(); }
  });
  expect(stored.state).toBe("submission-unknown");
});

for (const changed of ["network", "API"]) {
  test(`completed observations are cleared on ${changed} changes without any new connection`, async ({ page }) => {
    const item = corpus()[0]!, calls = await chainApi(page, item);
    const outside: string[] = [], sockets: string[] = [];
    page.on("request", (request) => { if (new URL(request.url()).host !== "127.0.0.1:18765") outside.push(request.url()); });
    page.on("websocket", (socket) => sockets.push(socket.url()));
    await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
    await page.locator("#swap-recovery-check-funding").click();
    await expect(page.locator("#swap-recovery-funding-result h3")).toHaveText("Funding observed by your API");
    const before = calls.length;
    const outsideBefore = outside.length;
    await openSettings(page, "connection");
    if (changed === "network") await page.locator("#swap-network").selectOption("signet");
    else await page.locator("#swap-chain-api").fill("https://mempool.space/api");
    await page.locator("#swap-settings-close").click();
    await expect(page.locator("#swap-recovery-funding-result")).toBeEmpty();
    expect(calls).toHaveLength(before);
    expect(outside).toHaveLength(outsideBefore); expect(sockets).toEqual([]);
  });
}

for (const spent of [true, false]) {
  test(`a spent swap output is named instead of blaming the file: spent ${spent}`, async ({ page }) => {
    const item = corpus()[0]!; await chainApi(page, item);
    await page.route(`${BASE}/tx/*/outspend/0`, (route) => route.fulfill({ status: 200, body: spent ? '{"spent":true}' : "{}", headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } }));
    await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
    await page.locator("#swap-recovery-check-funding").click();
    const result = page.locator("#swap-recovery-funding-result");
    await expect(result).toContainText("Nothing was signed or broadcast");
    if (spent) {
      await expect(result).toContainText("already spent"); await expect(result).toContainText("provider claimed it after paying");
      await expect(result).not.toContainText("Check the file, key");
    } else {
      await expect(result).toContainText("Check the file, key, network, API, and revision"); await expect(result).not.toContainText("already spent");
    }
  });
}

test("a failed observation acknowledges no signing/broadcast without denying the API disclosure", async ({ page }) => {
  const item = corpus()[0]!, calls = await chainApi(page, item);
  await page.route(`${BASE}/tx/*/outspend/0`, (route) => route.fulfill({ status: 200, body: '{"spent":true}', headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } }));
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("Funding could not be verified");
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("Nothing was signed or broadcast");
  await expect(page.locator("#swap-recovery-funding-result")).not.toContainText("Nothing was signed or sent");
  expect(calls.some((path) => path.endsWith("/hex"))).toBe(true);
});

test("terms-only recovery offers discovery without connecting or selecting an output on import", async ({ page }) => {
  const item = structuredClone(corpus()[0]!); item.record.funding_history = [];
  const calls = await chainApi(page, item);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await expect(page.locator("#swap-recovery-result")).toContainText("0 recorded funding revisions");
  await expect(page.locator("#swap-recovery-funding-controls")).toBeVisible();
  await expect(page.locator("#swap-recovery-find-deposits")).toBeEnabled();
  await expect(page.locator("#swap-recovery-deposit-txid")).toBeVisible();
  await expect(page.locator("#swap-recovery-check-funding")).toBeDisabled();
  await expect(page.locator("#swap-refund-prepare")).toBeDisabled();
  expect(calls).toEqual([]);
});

for (const name of ["P2WPKH refund", "funding wrong contract value", "funding duplicate contract outputs"]) {
  test(`original terms backup discovers and refunds explicitly selected actual outputs: ${name}`, async ({ page }, testInfo) => {
    const item = corpus().find((c) => c.name === name)!; item.record.funding_history = [];
    const funding = parseRecoveryFundingTransaction(hexToBytes(item.fundingTxHex));
    await chainApi(page, item);
    await page.route(`${BASE}/address/**`, (route) => route.fulfill({ status: 200, json: [{ txid: funding.txid, status: { confirmed: true } }], headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } }));
    await page.route(`${BASE}/tx/*/outspend/*`, (route) => route.fulfill({ status: 200, json: { spent: false }, headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } }));
    await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
    await page.locator("#swap-recovery-find-deposits").click();
    await expect(page.locator("#swap-recovery-discovery-result")).toContainText("matching output");
    await expect(page.locator("#swap-recovery-revision")).toHaveValue("");
    await expect(page.locator("#swap-refund-prepare")).toBeDisabled();
    for (const fundingVout of name === "funding duplicate contract outputs" ? [0, 2] : [0]) {
      await page.locator("#swap-recovery-revision").selectOption(`outpoint:${funding.txid}:${fundingVout}`);
      await expect(page.locator("#swap-refund-amount")).toContainText(`Selected output value: ${funding.outputs[fundingVout]!.value} sat`);
      await page.locator("#swap-recovery-check-funding").click();
      await expect(page.locator("#swap-recovery-funding-result h3")).toHaveText("Funding observed by your API");
      await page.locator("#swap-refund-prepare").click();
      await expect(page.locator("#swap-refund-result h3")).toHaveText("Refund prepared and saved");
      const downloading = page.waitForEvent("download"); await page.locator("#swap-refund-download").click();
      const path = testInfo.outputPath(`outpoint-${fundingVout}.hex`); await (await downloading).saveAs(path);
      const refund = parseTransaction(hexToBytes(readFileSync(path, "utf8").trim()));
      expect(refund.inputs[0]!.txid).toBe(funding.txid); expect(refund.inputs[0]!.vout).toBe(fundingVout);
      expect(refund.outputs[0]!.value).toBe(funding.outputs[fundingVout]!.value - 300n);
      await expect(page.locator("#swap-refund-broadcast")).toBeHidden();
    }
    await expect(page.locator("#swap-recovery-result")).toContainText("0 recorded funding revisions");
  });
}

test("terms-only TXID fallback works without address history and empty lookup never claims funds are absent", async ({ page }) => {
  const item = corpus()[0]!; item.record.funding_history = [];
  const fundingTxid = parseRecoveryFundingTransaction(hexToBytes(item.fundingTxHex)).txid;
  const calls = await chainApi(page, item);
  await page.route(`${BASE}/address/**`, (route) => route.fulfill({ status: 200, json: [], headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } }));
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await page.locator("#swap-recovery-find-deposits").click();
  await expect(page.locator("#swap-recovery-discovery-result")).toContainText("not proof that no deposit exists");
  await expect(page.locator("#swap-refund-prepare")).toBeDisabled();
  calls.length = 0;
  await page.locator("#swap-recovery-deposit-txid").fill(fundingTxid);
  await page.locator("#swap-recovery-find-deposits").click();
  await expect(page.locator("#swap-recovery-discovery-result")).toContainText("Only the supplied transaction was checked");
  expect(calls.some((p) => p.startsWith("address/"))).toBe(false);
  await page.locator("#swap-recovery-revision").selectOption(`outpoint:${fundingTxid}:0`);
  await page.locator("#swap-refund-prepare").click();
  await expect(page.locator("#swap-refund-result h3")).toHaveText("Refund prepared and saved");
});

test("production CSP lets mainnet recovery checks use the user's own https mempool instance", async ({ page }) => {
  const item = corpus().find((c) => c.name === "existing mainnet refund")!, key = await createRecoveryKey();
  const encrypted = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(item.record)!), key.recipient);
  let reached = false;
  await page.route("https://mempool.example.invalid/**", async (route) => { reached = true; await route.abort(); });
  await page.goto("http://127.0.0.1:18765/swap.html");
  await openSettings(page, "connection"); await page.locator("#swap-chain-api").fill("https://mempool.example.invalid/api");
  await page.locator("#swap-settings-close").click();
  await openRecovery(page);
  await page.locator("#swap-recovery-file").setInputFiles(payload(encrypted, "mainnet-test.age"));
  await page.locator("#swap-recovery-key-file").setInputFiles(payload(key.file, "original.key"));
  await page.locator("#swap-recovery-inspect").click();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("Funding could not be verified");
  expect(reached).toBe(true); await expect(page.locator("#swap-start")).toBeEnabled();
});

test("multiple revisions require an explicit choice and a failed newest revision never falls back automatically", async ({ page }) => {
  const item = corpus().find((c) => c.name === "explicit older revision selection")!, calls = await chainApi(page, item);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await expect(page.locator("#swap-recovery-revision")).toHaveValue("1");
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("Funding could not be verified");
  expect(calls.some((path) => path.includes(item.record.funding_history[0]!.binding.funding_txid))).toBe(false);
  await page.locator("#swap-recovery-revision").selectOption("0");
  await expect(page.locator("#swap-recovery-funding-result")).toBeEmpty();
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result h3")).toHaveText("Funding observed by your API");
});

for (const changed of ["network", "API", "file", "key", "revision"]) {
  test(`changed ${changed} while observing discards the stale result`, async ({ page }) => {
    const item = corpus().find((c) => c.name === "explicit newest revision selection")!;
    let release!: () => void, started!: () => void;
    const pending = new Promise<void>((resolve) => { started = resolve; });
    const gate = new Promise<void>((resolve) => { release = resolve; });
    await chainApi(page, item, 1101, async () => { started(); await gate; });
    await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
    await page.locator("#swap-recovery-check-funding").click(); await pending;
    if (changed === "network" || changed === "API") {
      await openSettings(page, "connection");
      if (changed === "network") await page.locator("#swap-network").selectOption("signet");
      else await page.locator("#swap-chain-api").fill("https://mempool.space/api");
      await page.locator("#swap-settings-close").click();
      await openRecovery(page);
    } else if (changed === "file") await page.locator("#swap-recovery-file").setInputFiles([]);
    else if (changed === "key") {
      const key = await createRecoveryKey(); await page.locator("#swap-recovery-key-file").setInputFiles(payload(key.file, "different.key"));
    } else await page.evaluate(() => {
      const select = document.querySelector<HTMLSelectElement>("#swap-recovery-revision")!;
      select.value = "0"; select.dispatchEvent(new Event("change"));
    });
    release();
    await expect(page.locator("#swap-recovery-funding-result")).toContainText("Funding could not be verified");
    await expect(page.locator("#swap-recovery-funding-result h3")).toHaveCount(0);
    await expect(page.locator("#swap-recovery-check-funding")).toBeEnabled();
  });
}
