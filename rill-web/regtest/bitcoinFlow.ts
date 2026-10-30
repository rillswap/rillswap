import { expect, type Page } from "@playwright/test";
import { command } from "./stack";

/** Fund an accepted browser quote using real Core transactions, never mock chain responses. */
export async function fundBitcoinQuote(page: Page, funding: "psbt" | "send-btc" = "psbt", beforeMining?: () => Promise<void>): Promise<string> {
  await expect(page.locator("#swap-funding-uri")).toBeVisible();
  const uri = new URL((await page.locator("#swap-funding-uri").getAttribute("href"))!);
  const amount = uri.searchParams.get("amount")!;
  expect(Number(amount)).toBeGreaterThan(0);
  if (funding === "send-btc") {
    const chain = `http://127.0.0.1:${process.env.RILL_DEV_CHAIN_PORT}/`;
    command("miner", "pause");
    let txid: string;
    try {
      txid = command("send-btc", uri.pathname, amount);
      expect(txid).toMatch(/^[0-9a-f]{64}$/);
      const pending = await page.request.get(`${chain}tx/${txid}`);
      expect(pending.ok()).toBe(true);
      expect(await pending.text()).toContain("Not confirmed on the active chain");
      const history = await page.request.get(`${chain}api/address/${uri.pathname}/txs`);
      expect(history.ok()).toBe(true);
      expect((await history.json()).find((tx: { txid: string }) => tx.txid === txid).status.confirmed).toBe(false);
      await beforeMining?.();
      command("mine", "1");
      const confirmed = await page.request.get(`${chain}tx/${txid}`);
      expect(confirmed.ok()).toBe(true);
      expect(await confirmed.text()).toContain("1 confirmation(s)");
    } finally { command("miner", "resume"); }
    await expect(page.locator("#swap-stage h2")).toHaveText("Invoice paid", { timeout: 120000 });
    return txid;
  }
  // Retain explicit PSBT validation and provider consent as a separate path.
  const psbt = command("fund-psbt", uri.pathname, amount);
  await page.locator("#swap-funding-advanced summary").click();
  await page.locator("#swap-psbt").fill(psbt);
  await page.getByRole("button", { name: "Check funding", exact: true }).click();
  await expect(page.locator("#swap-funding-raw")).toBeVisible();
  const txid = command("broadcast", (await page.locator("#swap-funding-raw").textContent())!.trim());
  await beforeMining?.();
  command("mine", "1");
  await page.getByRole("button", { name: "I broadcast it", exact: true }).click();
  await expect(page.locator("#swap-stage h2")).toHaveText("Invoice paid", { timeout: 120000 });
  return txid;
}
