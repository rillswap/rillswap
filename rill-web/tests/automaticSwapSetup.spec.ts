import { expect, openSettings, test } from "./fixtures/swapPage";
import type { Page } from "@playwright/test";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json" with { type: "json" };
import signet from "../src/networks/signet.json" with { type: "json" };
import { testInvoice } from "../../rill-payments/tests/helpers";
import { scriptAddress } from "../src/swap/address";

const PAGE = "http://127.0.0.1:18765/test-only/swap.html";
const API = "http://127.0.0.1:8091/api";

async function liveTiming(page: Page, available = true,
  projected = [{ blockVSize: 999_000, feeRange: [1, 10] }, { blockVSize: 500_000, feeRange: [0.1, 0.5] }]): Promise<string[]> {
  const api = "https://chain.example/signet/api", requests: string[] = [];
  await page.route(`${api}/**`, async (route) => {
    requests.push(route.request().url());
    expect(route.request().postData()).toBeNull();
    const path = new URL(route.request().url()).pathname, now = Math.floor(Date.now() / 1000);
    const body = path.endsWith("/mempool-blocks")
      ? projected
      : path.endsWith("/blocks") ? Array.from({ length: 15 }, (_, i) => ({ height: 100 - i, timestamp: now - i * 600 }))
        : path.endsWith("/recommended") ? { fastestFee: 3 } : undefined;
    await route.fulfill({ status: available || body === undefined ? 200 : 503,
      body: body === undefined ? path.endsWith("/0") ? signet.genesis_hash : path.endsWith("/height") ? "100" : "a".repeat(64) : JSON.stringify(body),
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  await page.goto(PAGE);
  await page.locator("#swap-network-badge").selectOption("signet");
  await openSettings(page, "connection");
  await page.locator("#swap-chain-api").fill(api);
  await page.locator("#swap-settings-close").click();
  expect(requests).toEqual([]);
  return requests;
}

/** Announce a 2,000 sat fee, so every fixture quote is within the estimate and skips the review step. */
async function quotesWithinEstimate(page: Page): Promise<void> {
  await page.addInitScript(() => { window.uiFixtureAnnouncedFeeSat = "2000"; });
}

async function verifiedQuote(page: Page): Promise<void> {
  await mockTip(page);
  await page.goto(PAGE); await invoice(page);
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeEnabled();
}

async function delayFinalInfo(page: Page): Promise<void> {
  await page.evaluate(() => {
    const prototype = window.uiFixture.wallet.prototype, original = prototype.info;
    prototype.info = async function() {
      prototype.info = original;
      const info = await original.call(this);
      window.uiFixture.infoPending = true;
      await new Promise<void>((resolve) => { window.uiFixture.releaseInfo = resolve; });
      return info;
    };
  });
}

async function invoice(page: Page): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("automatic_setup", "1000000", now, now + 7200));
}

async function mockTip(page: Page, genesis = regtest.genesis_hash): Promise<string[]> {
  const requests: string[] = [];
  await page.route(`${API}/**`, async (route) => {
    requests.push(route.request().url());
    expect(route.request().postData()).toBeNull();
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ body: path.endsWith("/0") ? genesis : path.endsWith("/height") ? "100"
      : path.endsWith("/v1/fees/recommended") ? JSON.stringify({ fastestFee: 3, halfHourFee: 2, hourFee: 1, economyFee: 1, minimumFee: 1 }) : "a".repeat(64),
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  return requests;
}

test("defaults fetch a tip on quote action and the stored browser key approves acceptance without a backup check", async ({ page }) => {
  const requests = await mockTip(page);
  await page.goto(PAGE);
  expect(requests).toEqual([]);
  await expect(page.locator("#swap-chain-consent")).toHaveCount(0);
  await expect(page.locator("#swap-chain-disclosure")).not.toBeVisible();
  await page.locator("#swap-privacy-toggle").click();
  await expect(page.locator("#swap-chain-disclosure")).toContainText(API);
  expect(requests).toEqual([]);
  await page.locator("#swap-privacy-toggle").click();
  await invoice(page);
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeEnabled();
  expect(requests).toHaveLength(5);
  const prepared = await page.evaluate(() => window.uiFixture.requests[0]) as {
    refundScript: string; tipHeight: number; ageRecipient: string; refundAllocation: { index: number; path: string };
  };
  expect(prepared.tipHeight).toBe(100);
  expect(prepared.refundScript).toMatch(/^0014[0-9a-f]{40}$/);
  expect(prepared.ageRecipient).toMatch(/^age1/);
  expect(prepared.refundAllocation).toMatchObject({ index: 0, path: "m/84'/1'/2'/0/0" });
  expect(JSON.stringify(prepared, (_key, value) => typeof value === "bigint" ? value.toString() : value)).not.toMatch(/mnemonic|privateKey|AGE-SECRET/);
  // No checkbox or upload gate: continuing is the acceptance, and the stored key is the approval.
  await expect(page.locator("#swap-quote-backup")).toHaveCount(0);
  await expect(page.locator("#swap-quote-review input[type=checkbox]")).toHaveCount(0);
  await expect(page.locator("#swap-quote-consent")).toContainText("By continuing you accept");
  expect(await page.evaluate(async () => { const wallet = await window.uiFixture.wallet.open();
    try { return (await wallet.info()).backupVerified; } finally { wallet.close(); } })).toBe(false);
  expect(await page.evaluate(() => window.uiFixture.executed)).toBe(0);
  await page.locator("#swap-quote-accept").click();
  await expect(page.locator("#swap-error")).toContainText("Fixture stopped before funding");
  expect(await page.evaluate(() => window.uiFixture.executed)).toBe(1);
  // The started swap replaces the form with a tracking view whose link carries the encrypted record.
  await expect(page.locator("#swap-form")).toBeHidden();
  await expect(page.locator("#swap-tracking h2")).toHaveText("Bitcoin to Lightning swap");
  expect(new URL(page.url()).hash).toBe("#swap=BwcH&network=regtest");
  await expect(page.locator("#swap-link-anchor")).toHaveAttribute("href", page.url());
  await expect(page.locator('#swap-backups a[download$=".age"]')).toHaveCount(1);
  await expect(page.locator("#swap-another")).toHaveAttribute("href", "./swap.html");
  expect(requests).toHaveLength(5); // publishing the link connects nowhere
});

test("wrong chain identity prevents quote preparation", async ({ page }) => {
  await mockTip(page, "f".repeat(64));
  await page.goto(PAGE); await invoice(page);
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-status")).toContainText("genesis does not match");
  expect(await page.evaluate(() => window.uiFixture.requests)).toEqual([]);
});

test("canceling automatic setup never shows a late quote or reuses the allocated address", async ({ page }) => {
  let release: (() => void) | undefined;
  let delayed = true;
  await page.route(`${API}/**`, async (route) => {
    if (delayed) { delayed = false; await new Promise<void>((resolve) => { release = resolve; }); }
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ body: path.endsWith("/0") ? regtest.genesis_hash : path.endsWith("/height") ? "100" : "a".repeat(64),
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  await page.goto(PAGE); await invoice(page);
  await page.locator("#swap-start").click();
  await expect.poll(() => !!release).toBe(true);
  await page.locator("#swap-edit").click(); release!();
  await expect(page.locator("#swap-status")).toContainText("Ready for a new quote");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeVisible();
  const prepared = await page.evaluate(() => window.uiFixture.requests) as { refundAllocation: { index: number } }[];
  expect(prepared).toHaveLength(1);
  expect(prepared[0]!.refundAllocation.index).toBe(1);
});

test("the accepted provider stays pinned while the final wallet check is pending", async ({ page }) => {
  await verifiedQuote(page); await delayFinalInfo(page);
  await page.locator("#swap-quote-accept").click();
  await page.waitForFunction(() => window.uiFixture.infoPending);
  const options = page.locator("input[name=verified-provider]");
  await expect(options.nth(1)).toBeDisabled();
  // Even a synthetic selection event during the await cannot change the captured choice.
  await options.nth(1).evaluate((option) => option.dispatchEvent(new Event("change")));
  await page.evaluate(() => window.uiFixture.releaseInfo!());
  await expect(page.locator("#swap-error")).toContainText("Fixture stopped before funding");
  expect(await page.evaluate(() => window.uiFixture.executedProviders)).toEqual(["4".repeat(64)]);
});

for (const mutation of ["changed", "unreadable"]) {
  test(`the final persisted wallet check refuses ${mutation} state before acceptance`, async ({ page }) => {
    await verifiedQuote(page);
    await page.evaluate(async (mutation) => {
      const db = await new Promise<IDBDatabase>((resolve) => { const req = indexedDB.open("rillswap-browser-wallet-v1", 1); req.onsuccess = () => resolve(req.result); });
      await new Promise<void>((resolve) => {
        const tx = db.transaction("identity", "readwrite"), store = tx.objectStore("identity"), req = store.get("wallet");
        req.onsuccess = () => { store.put(mutation === "unreadable" ? { version: 99 } : { ...req.result,
          mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" }, "wallet"); };
        tx.oncomplete = () => resolve();
      }); db.close();
    }, mutation);
    await page.locator("#swap-quote-accept").click();
    await expect(page.locator("#swap-error")).toBeVisible();
    expect(await page.evaluate(() => window.uiFixture.executed)).toBe(0);
  });
}

test("canceling the pending final wallet check prevents execution and stale UI", async ({ page }) => {
  await verifiedQuote(page); await delayFinalInfo(page);
  await page.locator("#swap-quote-accept").click();
  await page.waitForFunction(() => window.uiFixture.infoPending);
  await page.locator("#swap-edit").click();
  await page.evaluate(() => window.uiFixture.releaseInfo!());
  await expect(page.locator("#swap-status")).toContainText("Ready for a new quote");
  await expect(page.locator("#swap-start")).toBeEnabled();
  expect(await page.evaluate(() => window.uiFixture.executed)).toBe(0);
});

test("Lightning to Bitcoin keeps estimates private and retains sessions only until continuation or cancellation", async ({ page }) => {
  const tips = await mockTip(page);
  await page.goto(PAGE);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-start").click(); // the payout address is not needed for an estimate
  await expect(page.locator("#swap-quote-review h2")).toHaveText("51,006 sat");
  await expect(page.locator("#swap-quote-review")).toContainText("receive 50,000 sat on-chain");
  await expect(page.locator("#swap-quote-review")).toContainText("Estimated price");
  await expect(page.locator("#swap-quote-review")).toContainText("Claim after 2 confirmations of funding, then wait for the claim to confirm");
  await expect(page.locator("#swap-quote-review")).toContainText("pending for up to about 288 blocks");
  await expect(page.locator("#swap-reverse-pending")).toContainText("no address or payment hash was shared");
  await expect(page.locator("#swap-quote-accept")).toHaveCount(0);
  expect(tips).toEqual([]); // estimates need no chain height
  const fixture = await page.evaluate(() => ({ requests: window.uiFixture.requests, disposed: window.uiFixture.disposed }));
  expect(fixture.disposed).toBe(0); // retained only for the explicit Continue action
  const request = fixture.requests[0] as Record<string, unknown> & { payoutSat: bigint;
    limits: { minRefundDelayBlocks: number; maxIncomingHtlcDelayBlocks: number; minClaimFeeReserveSat: bigint } };
  expect(request.payoutSat).toBe(50_000n);
  expect(Object.keys(request).sort()).toEqual(["limits", "network", "payoutSat"]);
  expect(request.limits).toMatchObject({ minRefundDelayBlocks: 72, maxIncomingHtlcDelayBlocks: 432, minClaimFeeReserveSat: 0n });
  await expect(page.locator("#swap-reverse-continue")).toBeEnabled(); // the stored browser key is the approval
  await expect(page.locator("#swap-reverse-key-backup")).toHaveCount(0);
  await expect(page.locator("#swap-start")).toBeDisabled();
  await expect(page.locator("#swap-receive-address")).toBeEnabled(); // still editable before continuation
  await page.locator("#swap-reverse-continue").click();
  await expect(page.locator("#swap-reverse-refusal")).toContainText("Enter the Bitcoin address");
  expect(await page.evaluate(() => window.uiFixture.disposed)).toBe(0);
  await page.locator("#swap-receive-address").fill("not-an-address");
  await page.locator("#swap-reverse-continue").click();
  await expect(page.locator("#swap-reverse-refusal")).not.toHaveText("");
  expect(await page.evaluate(() => window.uiFixture.disposed)).toBe(0);
  await page.locator("#swap-edit").click();
  expect(await page.evaluate(() => window.uiFixture.disposed)).toBe(2);
  await expect(page.locator("#swap-start")).toBeEnabled();
  await expect(page.locator("#swap-receive-address")).toBeEnabled();
});

test("continuing a Lightning to Bitcoin estimate sends only the address entered at continuation", async ({ page }) => {
  await mockTip(page);
  await page.goto(PAGE);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-reverse-continue")).toBeEnabled();
  await page.locator("#swap-receive-address").fill(scriptAddress(`0014${"11".repeat(20)}`, "regtest"));
  await page.locator("#swap-reverse-continue").click();
  await expect(page.locator("#swap-reverse-refusal")).toHaveText("");
  await expect(page.locator("#swap-receive-address")).toBeDisabled();
  await expect.poll(() => page.evaluate(() => window.uiFixture.disposed)).toBe(1); // the unselected estimate only
  await expect(page.locator("#swap-reverse-continue")).toHaveCount(0); // execution replaced the estimate review
  // The firm request is priced from the chain API's next-block rate (3 sat/vB).
  await expect.poll(() => page.evaluate(() => window.uiFixture.reverseClaimFeeRates)).toEqual([3000]);
});

test("without a next-block fee estimate, a Lightning to Bitcoin swap stops before the firm request", async ({ page }) => {
  await page.route(`${API}/**`, async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/v1/fees/recommended")) { await route.fulfill({ status: 503, body: "", headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } }); return; }
    await route.fulfill({ body: path.endsWith("/0") ? regtest.genesis_hash : path.endsWith("/height") ? "100" : "a".repeat(64),
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  await page.goto(PAGE);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-start").click();
  await page.locator("#swap-receive-address").fill(scriptAddress(`0014${"11".repeat(20)}`, "regtest"));
  await page.locator("#swap-reverse-continue").click();
  await expect(page.locator("#swap-reverse-prepare-error")).toContainText("unavailable");
  await expect(page.getByText("Could not prepare this swap. No payment was started.")).toBeVisible();
  expect(await page.evaluate(() => window.uiFixture.reverseClaimFeeRates)).toBeUndefined();
});

test("with announced fees loaded on open, Swap accepts a signed price within the estimate without a review step", async ({ page }) => {
  await quotesWithinEstimate(page);
  const requests = await mockTip(page);
  await page.goto(PAGE);
  await expect(page.locator("#swap-estimate")).toHaveText("Paste a Lightning invoice that includes an amount to see the fee.");
  await invoice(page);
  await expect(page.locator("#swap-estimate strong")).toHaveText("3,000 sat");
  await expect(page.locator("#swap-estimate small")).toContainText("1,000 sat invoice + 2,000 sat provider fee");
  expect(requests).toEqual([]); // the directory uses relays only, never the chain API
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-error")).toContainText("Fixture stopped before funding");
  await expect(page.locator("#swap-quote-accept")).toHaveCount(0);
  await expect(page.locator("#swap-tracking h2")).toHaveText("Bitcoin to Lightning swap");
  expect(await page.evaluate(() => window.uiFixture.executedProviders)).toEqual(["4".repeat(64)]);
});

test("offers disclose depth-based ranking without claiming fastest completion, and the setting switches to price first", async ({ page }) => {
  // Quote "4" is cheaper (1,104 sat) but waits 2 confirmations; quote "5" pays from the mempool.
  await page.addInitScript(() => { window.uiFixtureQuoteDepths = [2, 0]; });
  await verifiedQuote(page);
  const options = page.locator("#swap-quote-review details label");
  await expect(options).toHaveCount(2);
  await expect(options.nth(0)).toContainText("1105 sat");
  await expect(options.nth(0).locator(".swap-offer-tag")).toHaveText(["0 confirmations", "Fewest confirmations"]);
  await expect(options.nth(1).locator(".swap-offer-tag")).toHaveText(["2 confirmations", "Cheapest"]);
  await expect(page.locator("input[name=verified-provider]").nth(0)).toBeChecked();
  await expect(page.locator("#swap-quote-selection")).toContainText("Fewest funding confirmations among 2 responding offers");
  await expect(page.locator("#swap-quote-summary")).toContainText("pays as soon as it sees your deposit, before any confirmation");
  await options.nth(1).locator("input").check();
  await expect(page.locator("#swap-quote-selection")).toContainText("Manually selected provider");
  await expect(page.locator("#swap-quote-summary")).toContainText("after 2 confirmations of your deposit");

  await page.goto(PAGE); await invoice(page);
  await page.locator("#swap-settings-toggle").click();
  await page.locator("#swap-ranking").selectOption("price");
  await page.locator("#swap-settings-close").click();
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeEnabled();
  await expect(options.nth(0)).toContainText("1104 sat");
  await expect(options.nth(0).locator(".swap-offer-tag")).toHaveText(["2 confirmations", "Cheapest"]);
  await expect(page.locator("#swap-quote-selection")).toContainText("Lowest verified provider price among 2 responding offers");
  await page.locator("#swap-quote-accept").click();
  await expect(page.locator("#swap-error")).toContainText("Fixture stopped before funding");
  expect(await page.evaluate(() => window.uiFixture.executedProviders)).toEqual(["4".repeat(64)]);
});

test("a signed price within the estimate still needs review when it waits more confirmations than shown", async ({ page }) => {
  await quotesWithinEstimate(page);
  await page.addInitScript(() => { window.uiFixtureAnnouncedDepth = 1; window.uiFixtureQuoteDepths = [2, 2]; });
  await mockTip(page);
  await page.goto(PAGE); await invoice(page);
  await expect(page.locator("#swap-estimate")).toContainText("The provider pays after 1 confirmation of your deposit.");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeEnabled(); // no one-step swap: 2 confirmations were not shown
  expect(await page.evaluate(() => window.uiFixture.executed)).toBe(0);
});

test("with announced fees loaded and the address entered, a Lightning to Bitcoin swap continues directly", async ({ page }) => {
  await quotesWithinEstimate(page);
  await page.addInitScript(() => { window.uiFixtureAnnouncedDepth = 2; }); // the depth every fixture offer signs
  await mockTip(page);
  await page.goto(PAGE);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await expect(page.locator("#swap-estimate")).toHaveText("Enter the amount to receive to see the fee.");
  await page.locator("#swap-receive-amount").fill("50000");
  await expect(page.locator("#swap-estimate strong")).toHaveText("52,000 sat");
  await expect(page.locator("#swap-estimate small")).toContainText("50,000 sat received + 2,000 sat provider fee");
  await page.locator("#swap-receive-amount").fill("500");
  await expect(page.locator("#swap-estimate")).toHaveText("fixture ineligible"); // the directory's refusal reason replaces the estimate
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-receive-address").fill(scriptAddress(`0014${"11".repeat(20)}`, "regtest"));
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-tracking h2")).toHaveText("Lightning to Bitcoin swap");
  await expect(page.locator("#swap-reverse-continue")).toHaveCount(0);
  await expect.poll(() => page.evaluate(() => window.uiFixture.disposed)).toBe(1);
});

for (const [announced, shown] of [[null, "did not announce"], [3, "Claim after 3 confirmations"]] as const) {
  test(`a Lightning to Bitcoin price within the estimate still needs review when the claim depth was ${announced === null ? "not announced" : "shown deeper"}`, async ({ page }) => {
    await quotesWithinEstimate(page);
    // Every fixture offer signs 2 confirmations: the depth at which the client reveals its preimage.
    if (announced !== null) await page.addInitScript((depth) => { window.uiFixtureAnnouncedDepth = depth; }, announced);
    await mockTip(page);
    await page.goto(PAGE);
    await page.getByRole("button", { name: "Switch direction" }).click();
    await page.locator("#swap-receive-amount").fill("50000");
    await expect(page.locator("#swap-estimate")).toContainText(shown);
    await page.locator("#swap-receive-address").fill(scriptAddress(`0014${"11".repeat(20)}`, "regtest"));
    await page.locator("#swap-start").click();
    await expect(page.locator("#swap-reverse-continue")).toBeEnabled(); // no one-step swap
    await expect(page.locator("#swap-quote-review")).toContainText("Claim after 2 confirmations of funding, then wait for the claim to confirm");
    expect(await page.evaluate(() => window.uiFixture.disposed)).toBe(0);
  });
}

test("reverse quotes show separate maker and mining charges with fee-aware minute ranges for each provider", async ({ page }) => {
  await page.addInitScript(() => { window.uiFixtureItemizedFees = true; });
  const requests = await liveTiming(page);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("61000");
  await page.locator("#swap-start").click();
  const summary = page.locator("#swap-quote-summary"), offers = page.locator("label:has(input[name=reverse-provider])");
  await expect(summary.locator("h2")).toHaveText("61,551 sat");
  await expect(summary).toContainText("receive 61,000 sat on-chain");
  await expect(summary).toContainText("Swap cost: 551 sat");
  await expect(summary).toContainText("Maker service fee: 100 sat");
  await expect(summary).toContainText("Maker mining allowance: 308 sat");
  await expect(summary).toContainText("Claim mining fee: 143 sat (included in the total)");
  await expect(offers.nth(0)).toContainText("Estimated chain wait: 40 min");
  await expect(offers.nth(1)).toContainText("Estimated chain wait: 50 min");
  await expect(offers.nth(0).locator(".swap-time-estimate")).toHaveAttribute("title", "Modeled range: 17 to 67 min. Not a guarantee.");
  await expect(offers.nth(1).locator(".swap-time-estimate")).toHaveAttribute("title", "Modeled range: 24 to 80 min. Not a guarantee.");
  await expect(offers.nth(0)).toContainText("not a promised transaction rate");
  await expect(page.locator("#swap-reverse-selected")).toContainText("maker keeps savings and covers overruns");
  expect(requests).toHaveLength(3);
  expect(requests.every((url) => /\/v1\/(?:fees\/(?:recommended|mempool-blocks)|blocks)$/.test(url))).toBe(true);
  expect(JSON.stringify(requests)).not.toMatch(/61000|invoice|address|payment_hash/);

  await offers.nth(1).locator("input").check();
  await expect(summary.locator("h2")).toHaveText("61,420 sat");
  await expect(summary).toContainText("Swap cost: 420 sat");
  await expect(summary).toContainText("Maker service fee: 200 sat");
  await expect(summary).toContainText("Maker mining allowance: 77 sat");
  await expect(page.locator("#swap-quote-time")).toHaveText("Estimated chain wait: 50 min");
  await expect(page.locator("#swap-quote-time")).toHaveAttribute("title", "Modeled range: 24 to 80 min. Not a guarantee.");
  await expect(page.locator("#swap-quote-selection")).toContainText("Manually selected");
  expect(await page.evaluate(() => window.uiFixture.disposed)).toBe(0);
});

test("forward quote minutes model the deposit depth and disclose the assumed wallet rate", async ({ page }) => {
  await page.addInitScript(() => { window.uiFixtureQuoteDepths = [1, 3]; window.uiFixtureItemizedFees = true; });
  await liveTiming(page);
  const now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("timing", "1000000", now, now + 7200, "tbs"));
  await page.locator("#swap-start").click();
  const offers = page.locator("label:has(input[name=verified-provider])");
  await expect(offers.nth(0)).toContainText("Estimated chain wait: 10 min");
  await expect(offers.nth(1)).toContainText("Estimated chain wait: 30 min");
  await expect(offers.nth(0).locator(".swap-time-estimate")).toHaveAttribute("title", "Modeled range: 1 to 24 min. Not a guarantee.");
  await expect(offers.nth(0)).toContainText("Assumes your wallet deposits at the API's recommended 3 sat/vB");
  await expect(page.locator("#swap-quote-summary")).toContainText("deposit mining fee is extra");
  await offers.nth(1).locator("input").check();
  await expect(page.locator("#swap-quote-time")).toHaveText("Estimated chain wait: 30 min");
  await expect(page.locator("#swap-quote-time")).toHaveAttribute("title", "Modeled range: 11 to 54 min. Not a guarantee.");
});

test("unavailable advisory timing data does not block an otherwise acceptable reverse quote", async ({ page }) => {
  await liveTiming(page, false);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-time")).toHaveText("Time estimate unavailable");
  await expect(page.locator("#swap-reverse-continue")).toBeEnabled();
  await expect(page.locator("#swap-error")).toHaveCount(0);
});

test("the reverse quote selected at continuation stays pinned during the final wallet check", async ({ page }) => {
  await mockTip(page);
  await page.goto(PAGE);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-reverse-continue")).toBeEnabled();
  await page.locator("#swap-receive-address").fill(scriptAddress(`0014${"11".repeat(20)}`, "regtest"));
  await delayFinalInfo(page);
  await page.locator("#swap-reverse-continue").click();
  await page.waitForFunction(() => window.uiFixture.infoPending);
  const alternate = page.locator("input[name=reverse-provider]").nth(1);
  await expect(alternate).toBeDisabled();
  await alternate.evaluate((option) => option.dispatchEvent(new Event("change")));
  await page.evaluate(() => window.uiFixture.releaseInfo!());
  await expect(page.locator("#swap-reverse-accept")).toBeEnabled();
  await expect(page.locator("#swap-reverse-steps h2")).toHaveText("Pay 51,006 sat");
});

test("Compare quotes keeps all forward offers reviewable even when Continue would accept directly", async ({ page }) => {
  await quotesWithinEstimate(page);
  await mockTip(page);
  await page.goto(PAGE); await invoice(page);
  await page.locator("#swap-compare").click();
  await expect(page.locator("#swap-quote-accept")).toBeEnabled();
  await expect(page.locator("input[name=verified-provider]")).toHaveCount(2);
  expect(await page.evaluate(() => window.uiFixture.executed)).toBe(0);
});

test("Compare quotes retains reverse offers even with an address and a price within the preview", async ({ page }) => {
  await quotesWithinEstimate(page);
  await page.addInitScript(() => { window.uiFixtureAnnouncedDepth = 2; });
  await mockTip(page);
  await page.goto(PAGE);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-receive-address").fill(scriptAddress(`0014${"11".repeat(20)}`, "regtest"));
  await page.locator("#swap-compare").click();
  await expect(page.locator("#swap-reverse-continue")).toBeEnabled();
  await expect(page.locator("input[name=reverse-provider]")).toHaveCount(2);
  expect(await page.evaluate(() => window.uiFixture.disposed)).toBe(0);
  expect(await page.evaluate(() => window.uiFixture.reverseClaimFeeRates)).toBeUndefined();
});

test("a low-fee signet quote gets a conditional numeric wait when the projected block has spare space", async ({ page }) => {
  await page.addInitScript(() => { window.uiFixtureItemizedFees = true; window.uiFixtureFeeRates = [100, 2000]; });
  await liveTiming(page, true, [{ blockVSize: 19_858.5, feeRange: [0.1942902458, 3917] }]);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("61000");
  await page.locator("#swap-compare").click();
  await expect(page.locator("#swap-quote-time")).toHaveText("Estimated chain wait: 30 min");
  await expect(page.locator("#swap-quote-time")).toHaveAttribute("title", "Modeled range: 11 to 54 min. Not a guarantee.");
  await expect(page.locator("#swap-quote-summary")).toContainText("Maker mining allowance: 16 sat");
  await page.locator("#swap-quote-summary").getByText("Time estimate assumptions", { exact: true }).click();
  await expect(page.locator("#swap-quote-summary")).toContainText("if the broadcasting node relays it");
});

for (const width of [320, 390, 1440]) {
  test(`Providers shows both Bitcoin timing columns at ${width}px, with lazy public reads and cached reuse`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await page.addInitScript(() => { window.uiFixtureAnnouncedDepth = 1; });
    const requests = await liveTiming(page);
    await page.locator("#swap-providers-toggle").click();
    const forwardTime = page.locator('.swap-provider-group[data-profile="btc-to-ln/v1"] td[data-label="Est. time"]');
    const reverseTime = page.locator('.swap-provider-group[data-profile="ln-to-btc/v1"] td[data-label="Est. time"]');
    await expect(forwardTime).toHaveText("10 min");
    await expect(reverseTime).toHaveText("20 min");
    await forwardTime.hover();
    await expect(forwardTime).toHaveAttribute("title", "Modeled range: 1 to 24 min. Not a guarantee.");
    await reverseTime.hover();
    await expect(reverseTime).toHaveAttribute("title", "Modeled range: 5 to 39 min. Not a guarantee.");
    await expect(page.locator("#swap-providers-intro")).toContainText("Times assume recommended mining rates");
    expect(requests).toHaveLength(3);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.locator("#swap-providers-close").click();
    await page.locator("#swap-providers-toggle").click();
    await expect(forwardTime).toHaveText("10 min");
    expect(requests).toHaveLength(3);
  });
}

test("late directory timing cannot overwrite evidence for a different network and API", async ({ page }) => {
  await page.addInitScript(() => { window.uiFixtureAnnouncedDepth = 1; });
  await liveTiming(page);
  let release: (() => void) | undefined;
  await page.route("https://chain.example/signet/api/v1/blocks", async (route) => {
    await new Promise<void>((resolve) => { release = resolve; });
    const now = Math.floor(Date.now() / 1000);
    await route.fulfill({ json: Array.from({ length: 15 }, (_, i) => ({ height: 100 - i, timestamp: now - i * 600 })),
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  await page.route("https://other-chain.example/testnet4/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname, now = Math.floor(Date.now() / 1000);
    await route.fulfill({ json: path.endsWith("/blocks") ? Array.from({ length: 15 }, (_, i) => ({ height: 100 - i, timestamp: now - i * 1200 }))
      : path.endsWith("/mempool-blocks") ? [{ blockVSize: 10_000, feeRange: [1, 10] }] : { fastestFee: 3 },
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  await page.locator("#swap-providers-toggle").click();
  await expect.poll(() => !!release).toBe(true);
  await page.locator("#swap-providers-close").click();
  await openSettings(page, "connection");
  await page.locator("#swap-network").selectOption("testnet4");
  await page.locator("#swap-chain-api").fill("https://other-chain.example/testnet4/api");
  await page.locator("#swap-settings-close").click();
  await page.locator("#swap-providers-toggle").click();
  const time = page.locator('.swap-provider-group[data-profile="btc-to-ln/v1"] td[data-label="Est. time"]');
  await expect(time).toHaveText("20 min");
  await expect(time).toHaveAttribute("title", "Modeled range: 2 to 47 min. Not a guarantee.");
  const oldResponse = page.waitForResponse("https://chain.example/signet/api/v1/blocks");
  release!(); await (await oldResponse).finished();
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  await expect(time).toHaveText("20 min");
  await expect(time).toHaveAttribute("title", "Modeled range: 2 to 47 min. Not a guarantee.");
});

test("the forward funding view keeps its minute estimate even when Continue skips quote review", async ({ page }) => {
  await quotesWithinEstimate(page);
  await page.addInitScript(() => {
    window.uiFixtureQuoteDepths = [0, 0];
  });
  await liveTiming(page);
  await page.evaluate(() => { window.uiFixture.fundingScript = `512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`; });
  const now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("tracking-timing", "1000000", now, now + 7200, "tbs"));
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-funding-uri")).toBeVisible();
  await expect(page.locator("#swap-tracking-time")).toHaveText("Estimated chain wait: 0 min");
  await expect(page.locator("#swap-tracking-time")).toHaveAttribute("title", /No confirmation wait/);
  await expect(page.locator("#swap-quote-accept")).toHaveCount(0);
});

test("the final reverse payment screen shows the mean with its modeled range on hover", async ({ page }) => {
  await liveTiming(page);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-compare").click();
  await expect(page.locator("#swap-reverse-continue")).toBeEnabled();
  await page.locator("#swap-receive-address").fill(scriptAddress(`0014${"11".repeat(20)}`, "signet"));
  await page.locator("#swap-reverse-continue").click();
  await expect(page.locator("#swap-reverse-time")).toHaveText("Estimated chain wait: 30 min");
  await expect(page.locator("#swap-reverse-time")).toHaveAttribute("title", "Modeled range: 11 to 54 min. Not a guarantee.");
});
