/** Opt-in isolated real node acceptance. Never resets or mines the default dev project. */
import { test, expect, type Page } from "@playwright/test";
import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { assertDisposableStack, assertRelayFaultStack, compose, composeEnabled } from "./stack";
import { stopPaymentProcess } from "./paymentProcess";
import { openRecoveryKey } from "../tests/fixtures/swapPage";

const root = resolve(import.meta.dirname, "../.."), artifacts = resolve(root, "tmp/reverse-live");
const enabled = process.env.RILLSWAP_RUN_BROWSER_REVERSE_REGTEST === "1";
const project = process.env.COMPOSE_PROJECT_NAME;
const command = (...args: string[]): string => execFileSync(resolve(root, "dev/devctl"), args, { cwd: root, env: process.env, encoding: "utf8", timeout: 30000 }).trim();
async function download(page: Page, selector: string, filename: string): Promise<string> {
  const event = page.waitForEvent("download"); await page.locator(selector).click(); const value = await event, target = resolve(artifacts, filename); await value.saveAs(target); return target;
}
function inspectBackup(wallet: string, recovery: string): { paymentHash: string; requiredDepth: number; settlementDepth: number; contractHash: string } {
  const script = `import { parseWalletBackup, walletRecoveryKey } from "./src/browserRecoveryWallet";
    import { decryptRecoveryContainer } from "./src/recoveryKeys";
    const key = await walletRecoveryKey(parseWalletBackup(await Bun.file(process.argv[1]).text()));
    const plaintext = await decryptRecoveryContainer(new Uint8Array(await Bun.file(process.argv[2]).arrayBuffer()), key.identity);
    const doc = JSON.parse(new TextDecoder().decode(plaintext)); plaintext.fill(0); key.file.fill(0);
    console.log(JSON.stringify({ paymentHash: doc.contract_terms.invoice_binding.payment_hash, requiredDepth: doc.contract_terms.funding_confirmations, settlementDepth: doc.contract_terms.settlement_confirmations, contractHash: doc.contract_hash }));`;
  return JSON.parse(execFileSync("bun", ["-e", script, wallet, recovery], { cwd: resolve(root, "rill-web"), encoding: "utf8", timeout: 30000 }));
}

const cases = [{ nodePayment: false, refusal: false, relayLoss: false }, { nodePayment: true, refusal: false, relayLoss: false },
  { nodePayment: false, refusal: true, relayLoss: false },
  ...(process.env.RILLSWAP_RUN_RELAY_RESILIENCE === "1" ? [{ nodePayment: true, refusal: false, relayLoss: true }] : [])];
for (const { nodePayment, refusal, relayLoss } of cases) {
test(`real browser reverse swap (${nodePayment ? "configured node" : "external wallet"}, ${refusal ? "cooperation unavailable" : relayLoss ? "relay failover during confirmations" : "cooperative key path"}) pays once and settles`, async ({ page }) => {
  test.skip(!enabled && !composeEnabled, "Explicit disposable-regtest opt-in required");
   assertDisposableStack();
   if (relayLoss) assertRelayFaultStack();
  expect(project).toMatch(/^rill-reverse-browser-[a-z0-9-]+$/); // refuse the existing/default development project
  expect(process.env.RILL_DEV_WEB_PORT).toMatch(/^[0-9]{4,5}$/);
  expect(process.env.RILL_DEV_WEB_PORT).not.toBe("5273"); mkdirSync(artifacts, { recursive: true });
  let payer: ReturnType<typeof spawn> | undefined;
  try {
   command("miner", "pause");
   const usedRelays = new Set<string>(), closedRelays = new Set<string>();
   page.on("websocket", (socket) => {
     socket.on("framesent", ({ payload }) => {
       if (typeof payload === "string" && payload.startsWith('["EVENT",')) usedRelays.add(socket.url());
     });
     socket.on("close", () => closedRelays.add(socket.url()));
   });
  const address = command("address", "--wallet", "user");
  let payments = 0, broadcasts = 0;
  const errors: string[] = []; page.on("pageerror", (error) => errors.push(error.message));
  page.on("request", (request) => { if (request.method() === "POST" && request.url().includes("/v2/router/route/send")) payments++;
    if (request.method() === "POST" && request.url().endsWith("/api/tx")) broadcasts++; });
  await page.goto(`http://127.0.0.1:${process.env.RILL_DEV_WEB_PORT}/swap.html`);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-reverse-continue")).toBeEnabled(); // no backup check gate; the address is entered before continuing
   await openRecoveryKey(page);
  const wallet = await download(page, '#swap-wallet-actions a[download="rillswap-recovery-key.json"]', "wallet.json");
  await page.locator("#swap-receive-address").fill(address);
  await page.locator("#swap-reverse-continue").click();
   await page.locator("#swap-reverse-advanced summary").click();
   const backup = await download(page, '#swap-reverse-backups a', "terms.age"), signed = inspectBackup(wallet, backup);
  if (nodePayment) {
     await page.locator("#swap-reverse-connect").click();
    await expect(page.locator("#swap-reverse-pay")).toBeEnabled();
    await page.locator("#swap-reverse-pay").click();
  } else {
    // Any external Lightning wallet can pay the explicitly accepted hold invoice.
    await page.locator("#swap-reverse-accept").click();
    const invoice = (await page.locator("#swap-reverse-invoice").textContent())!.trim();
    payer = spawn(resolve(root, "dev/devctl"), ["lncli", "user", "payinvoice", "--force", invoice], {
      cwd: root, env: process.env, timeout: 150000, detached: true, stdio: "ignore",
    });
    payer.on("error", () => {}); // exit-code assertion below still refuses a failed payer
  }
   await expect(page.locator("#swap-reverse-steps h2")).toHaveText("Locking Bitcoin", { timeout: 90000 });
   await expect(page.getByRole("link", { name: "View deposit transaction", exact: true })).toBeVisible({ timeout: 90000 });
   if (relayLoss) {
     const primary = `ws://127.0.0.1:${process.env.RILL_DEV_RELAY_PORT}/`;
     const alternate = `ws://127.0.0.1:${process.env.RILL_DEV_RELAY_ALT_PORT}/`;
     // Prove these paths carried private session traffic, not just discovery queries.
     await expect.poll(() => usedRelays.has(primary) && usedRelays.has(alternate)).toBe(true);
     compose("stop", "relay");
     await expect.poll(() => closedRelays.has(primary)).toBe(true);
   }
   // A funded client retains unilateral recovery even if the cooperative peer disappears.
   if (refusal) execFileSync("docker", ["compose", "stop", "maker-ln-to-btc"], { cwd: root, env: process.env, timeout: 30000, stdio: "ignore" });
   command("mine", String(signed.requiredDepth));
   // Confirmations trigger signing and one automatic broadcast, without another approval button.
   await expect(page.locator("#swap-status")).toContainText("Claim accepted:", { timeout: 60000 });
   await download(page, '#swap-reverse-backups a', "claim.age");
   const text = await page.locator("#swap-status").textContent(), txid = text!.match(/Claim accepted: ([0-9a-f]{64})/)![1]!;
    if (refusal) execFileSync("docker", ["compose", "start", "maker-ln-to-btc"], { cwd: root, env: process.env, timeout: 30000, stdio: "ignore" });
   command("mine", String(signed.settlementDepth));
  await expect.poll(() => JSON.parse(command("lncli", "maker", "lookupinvoice", signed.paymentHash)).state).toBe("SETTLED");
  await expect.poll(() => {
    const all = JSON.parse(command("lncli", "user", "listpayments", "--include_incomplete")); return all.payments.find((value: { payment_hash: string }) => value.payment_hash === signed.paymentHash)?.status;
  }).toBe("SUCCEEDED");
  await expect.poll(() => execFileSync("docker", ["exec", `${project}-tools-1`, "python", "-c",
    "import sqlite3,sys; c=sqlite3.connect('file:/state/makers/ln-to-btc/provider-store/live.sqlite?mode=ro',uri=True); print(c.execute('select state from swaps where contract_hash=?',(sys.argv[1],)).fetchone()[0])", signed.contractHash],
    { encoding: "utf8", timeout: 10000 }).trim()).toBe("SETTLED");
  const raw = JSON.parse(command("bitcoin-cli", "getrawtransaction", txid, "true")); expect(raw.confirmations).toBeGreaterThanOrEqual(1);
  expect(raw.vout).toHaveLength(1); expect(Math.round(Number(raw.vout[0].value) * 1e8)).toBeGreaterThanOrEqual(50000); expect(raw.vout[0].scriptPubKey.address).toBe(address);
   expect(raw.vin[0].txinwitness).toHaveLength(refusal ? 4 : 1);
   if (refusal) expect(raw.vin[0].txinwitness[1]).toMatch(/^[0-9a-f]{64}$/);
   else expect(raw.vin[0].txinwitness[0]).toMatch(/^[0-9a-f]{128}$/);
   // The swap log says which claim was used and, on the fallback, why.
   if (refusal) await expect(page.locator("#swap-log")).toContainText("; claiming with the signed script-path transaction");
   else await expect(page.locator("#swap-log")).toContainText("cooperation: the provider cosigned; claiming with the private key-path transaction");
  expect(payments).toBe(nodePayment ? 1 : 0); expect(broadcasts).toBe(1); expect(errors).toEqual([]);
   await expect(page.locator("#swap-status")).toContainText(nodePayment ? "Swap complete" : "Bitcoin claim confirmed");
  if (payer) {
    await new Promise<void>((done) => { if (payer!.exitCode !== null || payer!.signalCode !== null) done(); else payer!.once("exit", () => done()); });
    expect(payer.exitCode).toBe(0);
  }
  // Reload never renews payment or claim submission. Recover the exact saved
  // bytes through the real page and persistent browser identity/journal.
  await page.reload();
  // The encrypted swap link opens recovery automatically. Clicking its summary
  // here would close the panel instead of preparing the explicit file import.
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Lightning to Bitcoin recovery verified");
  await page.locator("#swap-recovery-file").setInputFiles(resolve(artifacts, "claim.age")); await page.locator("#swap-recovery-inspect").click();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Lightning to Bitcoin recovery verified");
  await page.locator("#swap-reverse-recovery-local").click(); await expect(page.locator("#swap-reverse-recovery-message")).toContainText("Local state: accepted");
  await expect(page.locator("#swap-reverse-recovery-broadcast")).toBeDisabled();
  await page.locator("#swap-reverse-recovery-export").click();
  const savedClaim = page.locator('a[download="rillswap-recovered-claim.hex"]'); await expect(savedClaim).toBeVisible();
  const exportedPath = await download(page, 'a[download="rillswap-recovered-claim.hex"]', "recovered-claim.hex");
   const exported = readFileSync(exportedPath, "utf8"), decodedFallback = JSON.parse(command("bitcoin-cli", "decoderawtransaction", exported));
   expect(decodedFallback.txid).toBe(txid); expect(decodedFallback.vin[0].txinwitness).toHaveLength(4);
   // The durable fallback is byte-identical when broadcast unilaterally, or has the
   // same txid and a different witness after the privacy-preserving key-path claim.
   if (refusal) expect(exported).toBe(raw.hex); else expect(exported).not.toBe(raw.hex);
  expect(payments).toBe(nodePayment ? 1 : 0); expect(broadcasts).toBe(1); expect(errors).toEqual([]);
  } finally {
    // Own the host command group, even if a browser assertion fails after dispatch.
    // Killing it does not establish that LND canceled an already-dispatched payment.
   if (payer) await stopPaymentProcess(payer);
    if (refusal) execFileSync("docker", ["compose", "start", "maker-ln-to-btc"], { cwd: root, env: process.env, timeout: 30000, stdio: "ignore" });
    if (relayLoss) compose("start", "relay");
    command("miner", "resume");
  }
});
}
