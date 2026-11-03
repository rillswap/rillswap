import { expect, openRecovery, test } from "./fixtures/swapPage";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
import { encryptCanonicalRecoveryForRecipient } from "../src/recoveryAgeContainer";
import type { RecoveryRefundCase } from "../unit/fixtures/recoveryRefundCases";
import type { ReverseIntentContext } from "../src/browserReverseJournal";
import type { BoundedHoldPlan } from "../src/swap/browserHoldPayer";

const sha256Hex = (text: string) => createHash("sha256").update(text).digest("hex");
const draft = () => JSON.parse(readFileSync(new URL("../tmp/preview/test-only/reverse-journal-draft.json", import.meta.url), "utf8")) as { context: ReverseIntentContext; plan: BoundedHoldPlan };

for (const failure of ["legacy invoice record", "incompatible store"]) {
  test(`an unavailable reverse ${failure} preserves forward recovery actions and all stored bytes`, async ({ page }) => {
    await page.goto("http://127.0.0.1:18765/test-only/wallet.html"); await page.waitForFunction(() => window.walletReady);
    const info = await page.evaluate(async () => { const wallet = await window.walletApi.BrowserRecoveryWallet.open(); try { return await wallet.info(); } finally { wallet.close(); } });
    const item = (JSON.parse(readFileSync(new URL("../tmp/preview/test-only/recovery-refund-cases.json", import.meta.url), "utf8")) as RecoveryRefundCase[])[0]!;
    item.record.funding_history = [];
    const ciphertext = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(item.record)!), info.recipient);
    const forwardId = await page.evaluate(async (bytes) => {
      const wallet = await window.walletApi.BrowserRecoveryWallet.open();
      try { return await wallet.saveFundedRecovery("regtest", Uint8Array.from(bytes)); } finally { wallet.close(); }
    }, Array.from(ciphertext));
    let expectedReverse: unknown;
    if (failure === "legacy invoice record") {
      const shown = "lnbcrt511u1externalwalletfixture";
      const saved = await page.evaluate(async ({ context, binding, shown }) => {
        const url = "/test-only/browserReverseJournal.js", module = await import(url) as typeof import("../src/browserReverseJournal");
        const journal = await module.BrowserReverseJournal.open();
        const cipher = new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4));
        try {
          const fresh = await journal.createFresh(context, cipher), terms = await journal.saveTerms(fresh, cipher);
          return await journal.exposeInvoice(terms, binding, cipher, shown);
        } finally { journal.close(); }
      }, { context: draft().context, binding: { ...draft().plan.invoiceBinding, bolt11_sha256: sha256Hex(shown) }, shown });
      const { bolt11: _text, ...payment } = saved.payment as { readonly bolt11: string };
      const fields = { id: saved.id, context: saved.context, stage: saved.stage, snapshots: saved.snapshots, payment, claim: saved.claim };
      const legacy = { ...fields, digest: sha256Hex(canonicalize(fields)!) };
      expectedReverse = await page.evaluate(async ({ legacy, paymentDigest }) => {
        const raw = await new Promise<IDBDatabase>((resolve) => { const r = indexedDB.open("rillswap-reverse-execution"); r.onsuccess = () => resolve(r.result); });
        try {
          const elections = await new Promise<{ id: string; digest: string }[]>((resolve) => { const r = raw.transaction("payments").objectStore("payments").getAll(); r.onsuccess = () => resolve(r.result); });
          const payment = { ...elections[0], digest: paymentDigest };
          await new Promise<void>((resolve) => { const tx = raw.transaction(["sessions", "payments"], "readwrite"); tx.objectStore("sessions").put(legacy); tx.objectStore("payments").put(payment); tx.oncomplete = () => resolve(); });
          return { sessions: [legacy], payments: [payment] };
        } finally { raw.close(); }
      }, { legacy, paymentDigest: sha256Hex(canonicalize(payment)!) });
    } else {
      expectedReverse = { sessions: [{ id: "preserve-incompatible-record", state: "unsupported" }], payments: null };
      await page.evaluate(async () => {
        const raw = await new Promise<IDBDatabase>((resolve) => {
          const r = indexedDB.open("rillswap-reverse-execution");
          r.onupgradeneeded = () => r.result.createObjectStore("sessions", { keyPath: "id" });
          r.onsuccess = () => resolve(r.result);
        });
        try { await new Promise<void>((resolve) => { const tx = raw.transaction("sessions", "readwrite"); tx.objectStore("sessions").add({ id: "preserve-incompatible-record", state: "unsupported" }); tx.oncomplete = () => resolve(); }); }
        finally { raw.close(); }
      });
    }
    const calls: string[] = [];
    await page.route("http://127.0.0.1:8091/**", async (route) => { calls.push(route.request().url()); await route.abort(); });
    await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await openRecovery(page);
    await page.locator("#swap-open-saved-recoveries").click();
    await expect(page.locator("#swap-saved-reverse-error")).toContainText("Could not read reverse swap recoveries");
    await expect(page.locator(".saved-swap")).toHaveCount(1);
    await expect(page.locator(".saved-swap")).toContainText(forwardId.slice(-16));
    await expect(page.locator(".saved-swap[data-reverse-session]")).toHaveCount(0);
    await expect(page.locator("#swap-saved-recoveries-list")).not.toContainText("No swaps saved");
    await page.getByRole("button", { name: "Open saved swap", exact: true }).click();
    await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
    await expect(page.locator("#swap-recovery-result")).toContainText("0 recorded funding revisions");
    const after = await page.evaluate(async (forwardId) => {
      const url = "/test-only/browserReverseJournal.js", module = await import(url) as typeof import("../src/browserReverseJournal");
      let journal, refused = false;
      try { journal = await module.BrowserReverseJournal.open(); await journal.list(); } catch { refused = true; } finally { journal?.close(); }
      const raw = await new Promise<IDBDatabase>((resolve) => { const r = indexedDB.open("rillswap-reverse-execution"); r.onsuccess = () => resolve(r.result); });
      const read = (store: string) => new Promise<unknown[]>((resolve) => { const r = raw.transaction(store).objectStore(store).getAll(); r.onsuccess = () => resolve(r.result); });
      const reverse = { sessions: await read("sessions"), payments: raw.objectStoreNames.contains("payments") ? await read("payments") : null }; raw.close();
      const wallet = await window.uiFixture.wallet.open();
      try { return { refused, reverse, fingerprint: (await wallet.info()).fingerprint, ciphertext: Array.from((await wallet.readFundedRecovery(forwardId)).ciphertext) }; }
      finally { wallet.close(); }
    }, forwardId);
    expect(after.refused).toBe(true); expect(after.reverse).toEqual(expectedReverse);
    expect(after.fingerprint).toBe(info.fingerprint); expect(after.ciphertext).toEqual(Array.from(ciphertext)); expect(calls).toEqual([]);
  });
}
