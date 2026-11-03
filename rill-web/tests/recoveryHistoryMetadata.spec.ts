import { expect, openTool, test } from "./fixtures/swapPage";
import canonicalize from "canonicalize";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { encryptCanonicalRecoveryForRecipient } from "../src/recoveryAgeContainer";
import { createRecoveryKey } from "../src/recoveryKeys";
import type { InspectionCase } from "../unit/fixtures/recoveryInspectionCases";
import type { ReverseIntentContext } from "../src/browserReverseJournal";
import type { BoundedHoldPlan } from "../src/swap/browserHoldPayer";

const PAGE = "http://127.0.0.1:18765/test-only/swap.html";
declare global { interface Window { historyReads: number; historyListingPending: boolean; releaseHistoryListing: () => void } }

test("History verifies forward amounts and invoice dates on demand, with per-entry fallbacks and network anchors", async ({ page }) => {
  await page.goto(PAGE);
  const recipient = await page.evaluate(async () => { const wallet = await window.uiFixture.wallet.open(); try { return (await wallet.recoveryKey()).recipient; } finally { wallet.close(); } });
  const cases = JSON.parse(readFileSync(new URL("../tmp/preview/test-only/recovery-inspection-cases.json", import.meta.url), "utf8")) as InspectionCase[];
  const valid = cases.find((item) => item.name === "signed funding revision zero")!.record;
  const terms = structuredClone(valid); terms.funding_history = []; terms.created_at = 1;
  const mainnet = cases.find((item) => item.name === "expired mainnet session")!.record;
  const damaged = cases.find((item) => item.name === "invalid provider_terms_signature")!.record;
  const otherKey = await createRecoveryKey(); otherKey.file.fill(0);
  const records = [terms, valid, mainnet, valid, damaged];
  const encrypted = await Promise.all(records.map((record, index) => encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(record)!), index === 3 ? otherKey.recipient : recipient)));
  const ids = await page.evaluate(async ({ encrypted, networks }) => {
    const wallet = await window.uiFixture.wallet.open();
    try { return await Promise.all(encrypted.map((bytes, index) => wallet.saveFundedRecovery(networks[index] as "regtest" | "mainnet", Uint8Array.from(bytes)))); }
    finally { wallet.close(); }
  }, { encrypted: encrypted.map((bytes) => Array.from(bytes)), networks: records.map((record) => record.network_identity.name) });
  await page.addInitScript(() => {
    window.historyReads = 0;
    const get = IDBObjectStore.prototype.get;
    IDBObjectStore.prototype.get = function(key) { if (typeof key === "string" && key.startsWith("funded:")) window.historyReads++; return get.call(this, key); };
  });
  const requests: string[] = [], sockets: string[] = [];
  page.on("request", (request) => { if (new URL(request.url()).host !== "127.0.0.1:18765") requests.push(request.url()); });
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.reload();
  await expect(page.locator(".saved-swap")).toHaveCount(5);
  expect(await page.evaluate(() => window.historyReads)).toBe(0); // Listing at startup must not read/decrypt each encrypted backup.
  await openTool(page, "history");
  for (const index of [0, 1, 2]) {
    const row = page.locator(".saved-swap").filter({ hasText: ids[index]!.slice(-16) });
    await expect(row).toContainText("Bitcoin to Lightning");
    await expect(row.locator(".saved-swap-amount")).toHaveText(`${BigInt(records[index]!.contract_terms.economics.lightning_principal_sat).toLocaleString()} sat`);
    await expect(row.locator("time")).toHaveAttribute("datetime", new Date(records[index]!.contract_terms.invoice_binding.created_at * 1000).toISOString());
    await expect(row).toContainText(`Swap ${records[index]!.contract_hash.slice(-16)}`);
    await expect(row).not.toContainText("Completed");
  }
  for (const index of [3, 4]) {
    const row = page.locator(".saved-swap").filter({ hasText: ids[index]!.slice(-16) });
    await expect(row).toContainText("Details could not be verified");
    await expect(row).toContainText("Amount unavailable"); await expect(row).toContainText("Date unavailable");
    await expect(row.locator("time")).toHaveCount(0);
    await expect(row.getByRole("button", { name: "Open saved swap", exact: true })).toBeEnabled();
    await expect(row.getByRole("button", { name: "Prepare download", exact: true })).toBeEnabled();
  }
  const stored = await page.evaluate(async (ids) => {
    const wallet = await window.uiFixture.wallet.open();
    try { return await Promise.all(ids.map(async (id) => Array.from((await wallet.readFundedRecovery(id)).ciphertext))); }
    finally { wallet.close(); }
  }, ids);
  expect(stored).toEqual(encrypted.map((bytes) => Array.from(bytes))); expect(requests).toEqual([]); expect(sockets).toEqual([]);
});

for (const payment of ["none", "external", "route"] as const) test(`reverse History uses saved ${payment} invoice metadata without decrypting snapshots`, async ({ page }) => {
  const draft = JSON.parse(readFileSync(new URL("../tmp/preview/test-only/reverse-journal-draft.json", import.meta.url), "utf8")) as { context: ReverseIntentContext; plan: BoundedHoldPlan };
  await page.goto(PAGE);
  await page.evaluate(async ({ draft, payment }) => {
    const url = "/test-only/browserReverseJournal.js", module = await import(url) as typeof import("../src/browserReverseJournal");
    const journal = await module.BrowserReverseJournal.open();
    // Deliberately not decryptable. Journal-validated local invoice metadata is sufficient for reverse dates.
    const cipher = new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4));
    try {
      const fresh = await journal.createFresh(draft.context, cipher), terms = await journal.saveTerms(fresh, cipher);
      if (payment === "external") await journal.exposeInvoice(terms, draft.plan.invoiceBinding, cipher, "lnbcrt511u1externalwalletfixture");
      else if (payment === "route") await journal.beginPayment(terms, "http://127.0.0.1:8093", draft.plan, cipher);
    } finally { journal.close(); }
  }, { draft: { ...draft, plan: { ...draft.plan, invoiceBinding: { ...draft.plan.invoiceBinding,
    bolt11_sha256: createHash("sha256").update("lnbcrt511u1externalwalletfixture").digest("hex") } } }, payment });
  await page.reload(); await openTool(page, "history");
  const row = page.locator(".saved-swap[data-reverse-session]");
  await expect(row).toContainText("Lightning to Bitcoin"); await expect(row).toContainText("Requested Bitcoin payout");
  if (payment === "none") { await expect(row).toContainText("Terms saved"); await expect(row).toContainText("Date unavailable"); await expect(row.locator("time")).toHaveCount(0); }
  else {
    await expect(row).toContainText("Payment needs checking");
    await expect(row.locator("time")).toHaveAttribute("datetime", new Date(draft.plan.invoiceBinding.created_at * 1000).toISOString());
  }
  await expect(row.getByRole("button", { name: "Resume", exact: true })).toBeEnabled();
});

test("an older pending History refresh cannot overwrite a newer user opening", async ({ page }) => {
  await page.goto(PAGE);
  await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { await wallet.saveFundedRecovery("regtest", new TextEncoder().encode("age-encryption.org/v1\n" + "one".repeat(80))); } finally { wallet.close(); }
  });
  await page.reload(); await expect(page.locator(".saved-swap")).toHaveCount(1);
  await page.evaluate(() => {
    const prototype = window.uiFixture.wallet.prototype, original = prototype.listFundedRecoveries;
    prototype.listFundedRecoveries = async function() {
      prototype.listFundedRecoveries = original;
      const entries = await original.call(this);
      window.historyListingPending = true;
      await new Promise<void>((resolve) => { window.releaseHistoryListing = resolve; });
      return entries;
    };
  });
  await openTool(page, "history"); await page.waitForFunction(() => window.historyListingPending);
  await page.locator("#swap-history-toggle").click();
  await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { await wallet.saveFundedRecovery("regtest", new TextEncoder().encode("age-encryption.org/v1\n" + "two".repeat(80))); } finally { wallet.close(); }
  });
  await openTool(page, "history"); await expect(page.locator(".saved-swap")).toHaveCount(2);
  await page.evaluate(() => window.releaseHistoryListing());
  await expect(page.locator(".saved-swap")).toHaveCount(2);
});
