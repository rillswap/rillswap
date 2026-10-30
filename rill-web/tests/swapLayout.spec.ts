import { expect, openRecoveryKey, openSettings, openTool, test } from "./fixtures/swapPage";
import type { Page, TestInfo } from "@playwright/test";
import canonicalize from "canonicalize";
import { readFileSync } from "node:fs";
import { testInvoice } from "../../rill-payments/tests/helpers";
import { encryptCanonicalRecoveryForRecipient } from "../src/recoveryAgeContainer";
import { scriptAddress } from "../src/swap/address";
import { PUBLIC_RELAYS } from "../src/swap/publicRelays";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json" with { type: "json" };
import taproot from "../unit/fixtures/taproot-cases-v1.json" with { type: "json" };
import type { RecoveryRefundCase } from "../unit/fixtures/recoveryRefundCases";

const PAGE = "http://127.0.0.1:18765/test-only/swap.html";
const API = "http://127.0.0.1:8091/api";

async function mockChain(page: Page): Promise<string[]> {
  const calls: string[] = [];
  await page.route(`${API}/**`, async (route) => {
    const path = new URL(route.request().url()).pathname;
    calls.push(path);
    const confirmed = await page.evaluate(() => window.uiFixture.reverseClaimConfirmed ?? false);
    await route.fulfill({ body: path.includes("/address/") ? "[]" : path.endsWith("/status")
      ? JSON.stringify({ confirmed, block_height: 99, block_hash: "a".repeat(64) }) : path.endsWith("/0")
        ? regtest.genesis_hash : path.endsWith("/height") ? "100" : path.endsWith("/v1/fees/recommended")
          ? JSON.stringify({ fastestFee: 2, halfHourFee: 1, hourFee: 1, economyFee: 1, minimumFee: 1 }) : "a".repeat(64),
    headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  return calls;
}

async function fits(page: Page, info: TestInfo, stage: string): Promise<void> {
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(page.viewportSize()!.width);
  for (const overflow of await page.evaluate(() => [document.documentElement, document.body].map((element) => getComputedStyle(element).overflowX))) {
    expect(["hidden", "clip"]).not.toContain(overflow);
  }
  await page.screenshot({ path: info.outputPath(`${stage}.png`), fullPage: true, animations: "disabled" });
}

test("the network picker aligns its chevron and header pills without losing native keyboard behavior", async ({ page }, info) => {
  await page.goto(PAGE);
  const picker = page.getByRole("combobox", { name: "Switch network" });
  for (const width of [320, 390, 1440]) {
    await page.setViewportSize({ width, height: 844 });
    for (const network of ["mainnet", "signet", "testnet4", "regtest"]) {
      await picker.selectOption(network);
      await expect(picker).toHaveValue(network);
      const badge = (await picker.boundingBox())!, source = (await page.locator("#swap-source").boundingBox())!;
      expect(Math.abs(badge.height - source.height)).toBeLessThan(1);
      expect(Math.abs(badge.y + badge.height / 2 - source.y - source.height / 2)).toBeLessThan(1);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    }
    await fits(page, info, `network-${width}`);
  }
  await expect(picker).toHaveCSS("appearance", "none");
  await expect(picker).toHaveCSS("background-position-y", "50%");
  await picker.focus();
  await page.keyboard.press("Home");
  await expect(picker).toHaveValue("mainnet");
  await page.keyboard.press("End");
  await expect(picker).toHaveValue("regtest");
});

test("tools are persistent sibling panels with keyboard focus and unchanged inputs", async ({ page }) => {
  await page.goto(PAGE);
  await page.locator("#swap-invoice").fill("an unfinished invoice");
  await expect(page.locator("#swap-card #swap-utilities, #swap-card .utility-panel")).toHaveCount(0);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator("#swap-progress")).toBeHidden();
  await page.locator("#swap-settings-toggle").focus();
  await page.keyboard.press("Enter");
  await expect(page.locator("#swap-settings h2")).toBeFocused();
  await expect(page.locator("#swap-connection-settings")).not.toHaveAttribute("open");
  await expect(page.locator("#swap-advanced-settings")).not.toHaveAttribute("open");
  await openSettings(page, "advanced");
  await page.locator("#swap-tip").fill("12345");
  await page.keyboard.press("Escape");
  await expect(page.locator("#swap-settings")).toBeHidden();
  await expect(page.locator("#swap-settings-toggle")).toBeFocused();
  await openRecoveryKey(page);
  await openTool(page, "history");
  await expect(page.locator("#swap-recovery-tools")).toBeHidden();
  await expect(page.locator("#swap-saved-recoveries")).toBeVisible();
  await openSettings(page, "advanced");
  await expect(page.locator("#swap-tip")).toHaveValue("12345");
  await expect(page.locator("#swap-invoice")).toHaveValue("an unfinished invoice");
  expect(new URL(page.url()).hash).toBe("");
});

test("copying an encrypted link gives feedback and utility navigation preserves its authority", async ({ page, context }) => {
  await mockChain(page);
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto(PAGE);
  const now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("copy-link", "1000000", now, now + 7200));
  await page.locator("#swap-start").click();
  await page.locator("#swap-quote-accept").click();
  await expect(page.locator("#swap-link")).toBeVisible();
  const link = page.url();
  expect(new URL(link).hash).toContain("#swap=");
  await page.locator("#swap-link-copy").click();
  await expect(page.locator("#swap-link-feedback")).toHaveText("Copied");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(link);
  await openTool(page, "history");
  await page.locator("#swap-privacy-toggle").click();
  await page.locator("#swap-activity-toggle").click();
  expect(page.url()).toBe(link);
  await expect(page.locator("#swap-link-anchor")).toHaveAttribute("href", link);
  await expect(page.locator("#swap-recovery-toggle")).toBeEnabled();
  await expect(page.locator("#swap-settings-toggle")).toBeDisabled();
  await expect(page.locator("#swap-reset-connections")).toBeDisabled();
  await expect(page.locator("#swap-chain-api")).toBeDisabled();
  await expect(page.locator("#swap-refund")).toBeDisabled();
  expect(await page.evaluate(() => window.uiFixture.executed)).toBe(1);
});

for (const width of [320, 390, 1440]) {
  test(`the entire swap and recovery interface fits ${width}px without hiding overflow`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 844 });
    const calls = await mockChain(page);
    await page.goto(PAGE);
    await expect(page.locator("#swap-start")).toBeInViewport();
    await fits(page, info, "initial");
    await openSettings(page, "connection");
    await page.locator("#swap-relay").fill(PUBLIC_RELAYS.join("\n"));
    await page.locator("#swap-privacy-toggle").click();
    await expect(page.locator("#swap-relay-disclosure")).toContainText(".onion");
    await fits(page, info, "long-relays");
    await page.locator("#swap-privacy-toggle").click();
    const now = Math.floor(Date.now() / 1000);
    await page.locator("#swap-invoice").fill(testInvoice("layout", "1000000", now, now + 7200));
    await page.evaluate((script) => { window.uiFixture.fundingScript = script; }, taproot.valid[0]!.artifacts.script_pubkey);
    await page.locator("#swap-start").click();
    await expect(page.locator("#swap-quote-accept")).toBeVisible();
    await expect(page.locator("#swap-form")).toBeHidden();
    await page.locator("#swap-quote-review").getByText("Time estimate assumptions", { exact: true }).click();
    await expect(page.locator("input[name=verified-provider]").first()).toBeVisible();
    await fits(page, info, "quote");
    await page.locator("#swap-quote-accept").click();
    await expect(page.locator("#swap-funding-uri")).toBeVisible();
    await expect(page.locator("#swap-second-deposit-warning")).toBeVisible();
    await fits(page, info, "funding");

    await page.goto(PAGE);
    await page.getByRole("button", { name: "Switch direction" }).click();
    await page.locator("#swap-receive-amount").fill("50000");
    await page.locator("#swap-start").click();
    await expect(page.locator("#swap-reverse-continue")).toBeVisible();
    await expect(page.locator("#swap-receive-address")).toBeVisible();
    await expect(page.locator("#swap-receive-amount")).toBeHidden();
    await fits(page, info, "reverse-estimate");
    await page.locator("#swap-receive-address").fill(scriptAddress(`0014${"11".repeat(20)}`, "regtest"));
    await page.locator("#swap-reverse-continue").click();
    await expect(page.locator("#swap-reverse-accept")).toBeVisible();
    await fits(page, info, "reverse-review");
    await page.locator("#swap-reverse-accept").click();
    await expect(page.locator("#swap-reverse-invoice")).toBeVisible();
    await expect(page.locator("#swap-reverse-invoice-notes")).toBeVisible();
    await openTool(page, "history");
    await expect(page.locator("#swap-reverse-invoice")).toBeVisible();
    await fits(page, info, "reverse-invoice");
    await page.evaluate(() => { window.uiFixture.reverseFunded = true; });
    await expect(page.locator("#swap-reverse-funding-status")).toContainText("0 of 2", { timeout: 10000 });
    await fits(page, info, "confirmations");
    await page.locator("#swap-reverse-advanced summary").click();
    await page.evaluate(() => { window.uiFixture.reverseDepth = 2; });
    await page.locator("#swap-reverse-funding").click();
    await expect(page.locator("#swap-status")).toContainText("Claim accepted:");
    await fits(page, info, "claim");
    await page.evaluate(() => { window.uiFixture.reverseClaimConfirmed = true; });
    await page.locator("#swap-reverse-funding").click();
    await expect(page.locator("#swap-reverse-steps h2")).toHaveText("Bitcoin received");
    await fits(page, info, "complete");
    expect(await page.evaluate(() => window.uiFixture.reverseEvents!.filter((event) => event === "broadcast").length)).toBe(1);

    await page.goto(PAGE);
    const recipient = await page.evaluate(async () => {
      const wallet = await window.uiFixture.wallet.open();
      try { return (await wallet.recoveryKey()).recipient; } finally { wallet.close(); }
    });
    const item = (JSON.parse(readFileSync(new URL("../tmp/preview/test-only/recovery-refund-cases.json", import.meta.url), "utf8")) as RecoveryRefundCase[])[0]!;
    const encrypted = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(item.record)!), recipient);
    await page.evaluate(async (bytes) => {
      const wallet = await window.uiFixture.wallet.open();
      try { await wallet.saveFundedRecovery("regtest", Uint8Array.from(bytes)); } finally { wallet.close(); }
    }, Array.from(encrypted));
    await page.reload();
    const before = calls.length;
    await openTool(page, "history");
    await expect(page.locator(".saved-swap h3")).toHaveText("Saved checkpoint");
    await expect(page.locator(".saved-swap")).not.toContainText("Completed");
    await fits(page, info, "history");
    await page.getByRole("button", { name: "Open saved swap", exact: true }).click();
    await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
    await expect(page.locator("#swap-recovery-tools")).toBeVisible();
    await fits(page, info, "recovery");
    expect(calls).toHaveLength(before);
  });
}
