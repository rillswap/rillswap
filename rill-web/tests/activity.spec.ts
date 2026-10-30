import { readFileSync } from "node:fs";
import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures/swapPage";
import { testInvoice } from "../../rill-payments/tests/helpers";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json" with { type: "json" };
import { scriptAddress } from "../src/swap/address";

test("local activity is timestamped and rich, but the downloaded diagnostics are redacted", async ({ page }) => {
  await page.route("http://127.0.0.1:8091/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ body: path.endsWith("/0") ? regtest.genesis_hash : path.endsWith("/height") ? "100" : path.endsWith("/recommended") ? '{"fastestFee":3}' : "a".repeat(64),
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  await page.goto("http://127.0.0.1:18765/test-only/swap.html");
  const now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("activity", "1000000", now, now + 7200));
  await page.locator("#swap-start").click();
  await page.locator("#swap-quote-accept").click();
  await expect(page.locator("#swap-error")).toContainText("Fixture stopped before funding");
  await page.locator("#swap-activity-toggle").click();
  await expect(page.locator("#swap-log")).toContainText("terms.verified");
  await expect(page.locator("#swap-log")).toContainText("Fixture coffee");
  await expect(page.locator("#swap-log")).toContainText("ab".repeat(32));
  await expect(page.locator("#swap-log")).toContainText(/\d{4}-\d\d-\d\dT\d\d:\d\d:/);
  const downloaded = page.waitForEvent("download");
  await page.locator("#swap-diagnostics-export").click();
  const path = await (await downloaded).path();
  const text = readFileSync(path!, "utf8"), parsed = JSON.parse(text);
  expect(parsed.format).toBe("rillswap-diagnostics/v1");
  expect(parsed.events.some((event: { event: string }) => event.event === "terms.verified")).toBe(true);
  expect(text).not.toContain("Fixture coffee");
  expect(text).not.toContain("ab".repeat(32));
  expect(text).not.toContain("amount_msat");
  expect(text).not.toContain("session_id");
});

async function reverse(page: Page): Promise<void> {
  await page.route("http://127.0.0.1:8091/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const confirmed = await page.evaluate(() => window.uiFixture?.reverseClaimConfirmed ?? false);
    await route.fulfill({ body: path.endsWith("/status") ? JSON.stringify({ confirmed, block_height: 99, block_hash: "a".repeat(64) }) :
      path.endsWith("/0") ? regtest.genesis_hash : path.endsWith("/height") ? "100" : path.endsWith("/recommended") ? '{"fastestFee":3}' : "a".repeat(64),
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  await page.goto("http://127.0.0.1:18765/test-only/swap.html");
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-start").click();
  await page.locator("#swap-receive-address").fill(scriptAddress(`0014${"11".repeat(20)}`, "regtest"));
  await page.locator("#swap-reverse-continue").click();
}

test("receiving signed funding is not reported as chain confirmation", async ({ page }) => {
  await reverse(page);
  await page.evaluate(() => { window.uiFixture.reverseFunded = true; window.uiFixture.reverseDepth = 0; });
  await page.locator("#swap-reverse-accept").click();
  await expect(page.locator("#swap-reverse-funding-status")).toContainText("0 of 2 confirmations");
  await expect(page.locator("#swap-log")).toContainText("funding.received");
  await expect(page.locator("#swap-log")).not.toContainText("lock.confirmed");
  expect(await page.evaluate(() => window.uiFixture.reverseEvents!.filter((event) => event === "broadcast"))).toEqual([]);
});

test("optional diagnostic fee failure cannot stop post-exposure claim tracking", async ({ page }) => {
  await reverse(page);
  await page.evaluate(() => { window.uiFixture.reverseFunded = true; window.uiFixture.reverseDepth = 2; window.uiFixture.reverseDiagnosticFeeFailure = true; });
  await page.locator("#swap-reverse-accept").click();
  await expect(page.locator("#swap-status")).toContainText("Claim accepted:");
  await page.evaluate(() => { window.uiFixture.reverseClaimConfirmed = true; });
  await page.locator("#swap-reverse-advanced summary").click();
  await page.locator("#swap-reverse-funding").click();
  await expect(page.locator("#swap-status")).toHaveText("Bitcoin claim confirmed");
  expect(await page.evaluate(() => window.uiFixture.reverseEvents!.filter((event) => event === "broadcast"))).toHaveLength(1);
});
