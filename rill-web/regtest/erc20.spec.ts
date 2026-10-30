/**
 * Opt-in acceptance of both browser ERC20 swap directions against the running dev stack. A fake
 * EIP-1193 wallet forwards signing to Anvil's unlocked user account (account 1); it spends dev fUSDC only.
 */
import { test, expect, type Page } from "@playwright/test";
import { execFile, execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { assertDisposableStack, composeEnabled, run } from "./stack";
import { EvmRpc, type Eip1193Provider } from "../src/swap/evmHtlc";
import { openSettings } from "../tests/fixtures/swapPage";

const root = resolve(import.meta.dirname, "../..");
const enabled = process.env.RILLSWAP_RUN_BROWSER_ERC20_REGTEST === "1" || composeEnabled;
const project = process.env.COMPOSE_PROJECT_NAME ?? "rillswap-dev";
const webPort = process.env.RILL_DEV_WEB_PORT ?? "5273", anvilPort = process.env.RILL_DEV_ANVIL_PORT ?? "8545";
const USER = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"; // Anvil account 1, funded with fUSDC by bootstrap
test.beforeEach(() => { if (enabled) assertDisposableStack(); });
const command = (...args: string[]): string => execFileSync(resolve(root, "dev/devctl"), args, { cwd: root, env: process.env, encoding: "utf8", timeout: 30000 }).trim();
const makerState = (lockTxHash: string): string => execFileSync("docker", ["exec", `${project}-tools-1`, "python", "-c",
  "import sqlite3,sys; c=sqlite3.connect('file:/state/makers/erc20-to-ln/provider-store/live.sqlite?mode=ro',uri=True); "
  + "r=c.execute(\"select s.state from swaps s join evm_swaps e on e.session_id=s.session_id where lower(replace(e.lock_tx_hash,'0x',''))=?\",(sys.argv[1],)).fetchone(); print(r[0] if r else '')",
  lockTxHash], { encoding: "utf8", timeout: 10000 }).trim();

async function injectWallet(page: Page): Promise<string[]> {
  const walletCalls: string[] = [];
  await page.exposeFunction("__walletCall", (method: string) => { walletCalls.push(method); });
  await page.addInitScript(({ rpc, account }) => {
    (window as unknown as { ethereum: unknown }).ethereum = {
      request: async ({ method, params }: { method: string; params?: unknown[] }) => {
        (window as unknown as { __walletCall: (m: string) => void }).__walletCall(method);
        if (method === "eth_chainId" && (window as unknown as { __changedWalletChain?: string }).__changedWalletChain) {
          return (window as unknown as { __changedWalletChain: string }).__changedWalletChain;
        }
        if (method === "eth_requestAccounts" || method === "eth_accounts") return [account];
        if (method === "wallet_switchEthereumChain") return null;
        // Anvil runs with --base-fee 0; its eth_sendTransaction defaults would otherwise pick a priority fee above the max fee.
        // Reserve gas for state changes before inclusion: a sibling claim can empty the HTLC's token balance,
        // making the next lock's zero-to-nonzero storage write cost more than Anvil's exact estimate.
        if (method === "eth_sendTransaction") params = [{ gas: "0xf4240", ...(params![0] as object), maxFeePerGas: "0x0", maxPriorityFeePerGas: "0x0" }];
        const response = await fetch(rpc, { method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params ?? [] }) });
        const body = await response.json() as { result?: unknown; error?: { message: string } };
        if (body.error) throw new Error(body.error.message);
        return body.result;
      },
    };
  }, { rpc: `http://127.0.0.1:${anvilPort}`, account: USER });
  return walletCalls;
}

/** The dev build configures the gas sponsor; wallet-claim tests opt out of it explicitly. */
async function disableSponsor(page: Page): Promise<void> {
  await openSettings(page, "evm");
  for (const id of ["swap-evm-sponsor", "swap-evm-entry-point", "swap-evm-delegate"]) await page.locator(`#${id}`).fill("");
  await page.locator("#swap-settings-close").click();
}

test("the injected Anvil wallet reserves gas and preserves explicit transaction limits", async ({ page }) => {
  test.skip(!enabled, "Explicit disposable Compose opt-in required");
  const calls = await injectWallet(page);
  await page.goto(`http://127.0.0.1:${webPort}/swap.html`);
  const hashes = await page.evaluate(async (account) => {
    const wallet = (window as unknown as { ethereum: Eip1193Provider }).ethereum;
    const transaction = { from: account, to: account, value: "0x0" };
    return [await wallet.request({ method: "eth_sendTransaction", params: [transaction] }),
      await wallet.request({ method: "eth_sendTransaction", params: [{ ...transaction, gas: "0x186a0" }] })];
  }, USER);
  const rpc = new EvmRpc(`http://127.0.0.1:${anvilPort}`);
  for (const [index, hash] of hashes.entries()) {
    expect(await rpc.call("eth_getTransactionByHash", [hash])).toMatchObject({ from: USER, to: USER,
      value: "0x0", gas: index === 0 ? "0xf4240" : "0x186a0", maxFeePerGas: "0x0", maxPriorityFeePerGas: "0x0" });
    await expect.poll(() => rpc.call("eth_getTransactionReceipt", [hash])).toMatchObject({ status: "0x1" });
  }
  expect(calls.filter((method) => method === "eth_sendTransaction")).toHaveLength(2);
});

for (const direction of ["erc20-to-ln", "ln-to-erc20"] as const) {
  test(`two simultaneous browser ${direction} swaps settle independently`, async ({ context }) => {
    test.skip(!enabled, "Explicit disposable Compose opt-in required");
    test.setTimeout(300000);
    const pages = await Promise.all([context.newPage(), context.newPage()]);
    const errors: string[] = [];
    const hashes: string[] = [];
    await Promise.all(pages.map(async (page, index) => {
      page.on("pageerror", (error) => errors.push(error.message));
      await injectWallet(page);
      await page.goto(`http://127.0.0.1:${webPort}/swap.html`);
      if (direction === "erc20-to-ln") {
        await page.locator("#swap-from").selectOption("usdc");
        const invoice = command("invoice", String(20000 + index * 1000), "--node", "user");
        hashes[index] = JSON.parse(command("lncli", "user", "decodepayreq", invoice)).payment_hash;
        await page.locator("#swap-invoice").fill(invoice);
      } else {
        await disableSponsor(page);
        await page.locator("#swap-from").selectOption("ln");
        await page.locator("#swap-to").selectOption("usdc");
        await page.locator("#swap-receive-amount").fill(String(20 + index));
      }
      await page.locator("#swap-start").click();
      await expect(page.locator("#swap-quote-accept")).toBeVisible({ timeout: 60000 });
    }));
    // Both sessions have firm terms before either user commits funds.
    await Promise.all(pages.map((page) => page.locator("#swap-quote-accept").click()));
    if (direction === "erc20-to-ln") {
      await Promise.all(pages.map((page) => expect(page.locator("#swap-status"))
        .toContainText("Lightning invoice paid", { timeout: 150000 })));
      const locks = await Promise.all(pages.map(async (page) =>
        (await page.locator("#swap-erc20-paid").textContent())!.match(/Lock ([0-9a-f]{64})/)![1]!));
      expect(new Set(locks).size).toBe(2);
      for (const [index, lock] of locks.entries()) {
        expect(JSON.parse(command("lncli", "user", "lookupinvoice", hashes[index]!)).state).toBe("SETTLED");
        await expect.poll(() => makerState(lock), { timeout: 60000 }).toBe("CLAIMED");
      }
    } else {
      const invoices = await Promise.all(pages.map(async (page) => {
        await expect(page.locator("#swap-reverse-invoice")).toBeVisible({ timeout: 60000 });
        return (await page.locator("#swap-reverse-invoice").textContent())!.trim();
      }));
      expect(new Set(invoices).size).toBe(2);
      const payments = invoices.map((invoice) => run("pay", invoice, "--node", "user").then(
        (output) => ({ output, error: undefined }), (error: unknown) => ({ output: "", error })));
      await Promise.all(pages.map((page) => expect(page.locator("#swap-status"))
        .toContainText("Stablecoins received", { timeout: 150000 })));
      for (const result of await Promise.all(payments)) {
        if (result.error) throw result.error;
        expect(result.output).toContain("paid, preimage");
      }
      for (const invoice of invoices) {
        const hash = JSON.parse(command("lncli", "user", "decodepayreq", invoice)).payment_hash;
        expect(JSON.parse(command("lncli", "maker", "lookupinvoice", hash)).state).toBe("SETTLED");
      }
    }
    for (const page of pages) {
      await page.reload();
      await expect(page.locator("#swap-recovery-result h3")).toHaveText(direction === "erc20-to-ln"
        ? "fUSDC to Lightning recovery verified" : "Lightning to fUSDC recovery verified");
    }
    expect(errors).toEqual([]);
  });
}

test("forward execution refuses changed real HTLC runtime before any approval", async ({ page }) => {
  test.skip(!enabled, "Explicit dev-stack opt-in required");
  const deployment = JSON.parse(execFileSync("docker", ["exec", `${project}-tools-1`, "cat", "/state/evm/contracts.json"],
    { encoding: "utf8", timeout: 10000 })) as { htlc_contract: string };
  const calls = await injectWallet(page);
  await page.goto(`http://127.0.0.1:${webPort}/swap.html`);
  await page.locator("#swap-from").selectOption("usdc");
  await page.locator("#swap-invoice").fill(command("invoice", "20000", "--node", "user"));
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeVisible({ timeout: 60000 });
  const original = command("cast", "code", deployment.htlc_contract);
  try {
    command("cast", "rpc", "anvil_setCode", deployment.htlc_contract, "0x00");
    await page.locator("#swap-quote-accept").click();
    await expect(page.locator("#swap-error")).toContainText("HTLC bytecode does not match", { timeout: 30000 });
    expect(calls.filter((method) => method === "eth_sendTransaction")).toHaveLength(0);
  } finally {
    command("cast", "rpc", "anvil_setCode", deployment.htlc_contract, original);
  }
});

test("a wallet chain change after quoting cannot authorize approval or locking", async ({ page }) => {
  test.skip(!enabled, "Explicit dev-stack opt-in required");
  const calls = await injectWallet(page);
  await page.goto(`http://127.0.0.1:${webPort}/swap.html`);
  await page.locator("#swap-from").selectOption("usdc");
  await page.locator("#swap-invoice").fill(command("invoice", "20000", "--node", "user"));
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeVisible({ timeout: 60000 });
  await page.evaluate(() => { (window as unknown as { __changedWalletChain: string }).__changedWalletChain = "0x1"; });
  await page.locator("#swap-quote-accept").click();
  await expect(page.locator("#swap-error")).toContainText("Wallet account or chain changed", { timeout: 30000 });
  expect(calls.filter((method) => method === "eth_sendTransaction")).toHaveLength(0);
});

test("browser locks fUSDC through an injected wallet and the provider pays the invoice", async ({ page }) => {
  test.skip(!enabled, "Explicit dev-stack opt-in required");
  const invoice = command("invoice", "20000", "--node", "user");
  const paymentHash = JSON.parse(command("lncli", "user", "decodepayreq", invoice)).payment_hash as string;
  const errors: string[] = []; page.on("pageerror", (error) => errors.push(error.message));
  const walletCalls = await injectWallet(page);
  await page.goto(`http://127.0.0.1:${webPort}/swap.html`);
  await page.locator("#swap-from").selectOption("usdc");
  await expect(page.locator("#swap-to")).toHaveValue("ln");
  await page.locator("#swap-invoice").fill(invoice);
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeVisible({ timeout: 60000 });
  await expect(page.locator("#swap-quote-summary h2")).toContainText("fUSDC");
  const lockText = (await page.locator("#swap-quote-summary h2").textContent())!;
  expect(Number(lockText.split(" ")[0])).toBeGreaterThanOrEqual(20); // 20,000 sat at 100,000 fUSDC/BTC plus the fee
  await page.locator("#swap-quote-accept").click();
  await expect(page.locator("#swap-status")).toContainText("Lightning invoice paid", { timeout: 150000 });
  const paid = await page.locator("#swap-erc20-paid").textContent();
  const lockTx = paid!.match(/Lock ([0-9a-f]{64})/)![1]!;
  const receipt = JSON.parse(command("cast", "receipt", `0x${lockTx}`, "--json"));
  expect(receipt.status).toBe("0x1");
  expect(walletCalls.filter((method) => method === "eth_sendTransaction").length).toBe(2); // approve, lock
  await expect.poll(() => JSON.parse(command("lncli", "user", "lookupinvoice", paymentHash)).state).toBe("SETTLED");
  await expect(page.locator('#swap-erc20-files a[download="rillswap-fusdc-to-ln-paid.age"]')).toBeVisible();
  expect(errors).toEqual([]);
  // The provider's store converges on CLAIMED once its claim confirms.
  await expect.poll(() => makerState(lockTx), { timeout: 60000 }).toBe("CLAIMED");
  // The swap link reopens the encrypted record locally; the chain check sees the provider's claim, so no refund is offered.
  expect(page.url()).toContain("#");
  await page.reload();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("fUSDC to Lightning recovery verified");
  await expect(page.locator("#swap-recovery-result")).toContainText(`Lock transaction ${lockTx}`);
  await page.locator("#swap-evm-recovery-check").click();
  await expect(page.locator("#swap-evm-recovery-message")).toContainText("Claimed by the provider");
  await expect(page.locator("#swap-evm-recovery-refund")).toBeDisabled();
  expect(errors).toEqual([]);
});

test("unexposed reverse recovery resumes explicitly after reload without creating another hold invoice", async ({ page }) => {
  test.skip(!enabled, "Explicit dev-stack opt-in required");
  const calls = await injectWallet(page);
  await page.goto(`http://127.0.0.1:${webPort}/swap.html`); await disableSponsor(page);
  await page.locator("#swap-from").selectOption("ln"); await page.locator("#swap-to").selectOption("usdc");
  await page.locator("#swap-receive-amount").fill("20"); await page.locator("#swap-start").click();
  await page.locator("#swap-quote-accept").click({ timeout: 60000 });
  await expect(page.locator("#swap-reverse-invoice")).toBeVisible({ timeout: 60000 });
  const invoice = (await page.locator("#swap-reverse-invoice").textContent())!;
  await page.reload();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Lightning to fUSDC recovery verified");
  await expect(page.locator("#swap-reverse-invoice")).not.toBeVisible();
  expect(calls.filter((method) => method === "eth_sendTransaction")).toHaveLength(0);
  const paid = new Promise<{ output: string; error: Error | null }>((resolve) => execFile(`${root}/dev/devctl`, ["pay", invoice, "--node", "user"],
    { cwd: root, env: process.env, encoding: "utf8", timeout: 150000 }, (error, output) => resolve({ output, error })));
  // Check is always explicit; an old file never authorizes automatic submission after reload.
  await expect(async () => {
    await page.locator("#swap-evm-recovery-check").click();
    await expect(page.locator("#swap-evm-recovery-check")).toBeEnabled();
    await expect(page.locator("#swap-evm-recovery-claim")).toBeEnabled({ timeout: 2000 });
  }).toPass({ timeout: 60000 });
  await page.locator("#swap-evm-recovery-claim").click();
  await expect(page.locator("#swap-evm-recovery-message")).toContainText("Tokens claimed", { timeout: 60000 });
  const result = await paid; if (result.error) throw result.error;
  expect(result.output).toContain("paid, preimage");
  expect(calls.filter((method) => method === "eth_sendTransaction")).toHaveLength(1);
});

test("browser pays Lightning from an external wallet and claims the provider's fUSDC lock", async ({ page }) => {
  test.skip(!enabled, "Explicit dev-stack opt-in required");
  const errors: string[] = []; page.on("pageerror", (error) => errors.push(error.message));
  const calls = await injectWallet(page);
  await page.goto(`http://127.0.0.1:${webPort}/swap.html`); await disableSponsor(page);
  await page.locator("#swap-from").selectOption("ln"); await page.locator("#swap-to").selectOption("usdc");
  await page.locator("#swap-receive-amount").fill("20"); await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeVisible({ timeout: 60000 });
  expect(calls).not.toContain("eth_requestAccounts"); // shopping needs neither a destination nor wallet access
  await page.locator("#swap-quote-accept").click();
  await expect(page.locator("#swap-reverse-invoice")).toBeVisible({ timeout: 60000 });
  const invoice = (await page.locator("#swap-reverse-invoice").textContent())!;
  // An external LN wallet pays asynchronously; no LN-node connection is configured in the browser.
  const payment = new Promise<string>((resolve, reject) => execFile(`${root}/dev/devctl`, ["pay", invoice, "--node", "user"],
    { cwd: root, env: process.env, encoding: "utf8", timeout: 150000 }, (error, stdout, stderr) => error ? reject(new Error(stderr || error.message)) : resolve(stdout)));
  // Avoid an unhandled rejection while Playwright waits on the browser.
  const paid = payment.then((output) => ({ output, error: null }), (error: unknown) => ({ output: "", error }));
  await expect(page.locator("#swap-status")).toContainText("Stablecoins received", { timeout: 150000 });
  const result = await paid; if (result.error) throw result.error;
  expect(result.output).toContain("paid, preimage");
  expect(calls.filter((method) => method === "eth_sendTransaction")).toHaveLength(1); // claim only
  await expect(page.locator('#swap-erc20-files a[download="rillswap-ln-to-fusdc-claimed.age"]')).toBeVisible();
  await page.reload();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Lightning to fUSDC recovery verified");
  await page.locator("#swap-evm-recovery-check").click();
  await expect(page.locator("#swap-evm-recovery-message")).toContainText("Tokens claimed");
  await expect(page.locator("#swap-evm-recovery-claim")).toBeDisabled();
  expect(errors).toEqual([]);
});

test("browser receives fUSDC at a typed address with no wallet extension, through the gas sponsor", async ({ page }) => {
  test.skip(!enabled, "Explicit dev-stack opt-in required");
  const TOKEN = JSON.parse(execFileSync("docker", ["exec", `${project}-tools-1`, "cat", "/state/evm/contracts.json"],
    { encoding: "utf8", timeout: 10000 })).token_contract as string;
  const errors: string[] = []; page.on("pageerror", (error) => errors.push(error.message));
  const destination = `0x${"d0".repeat(19)}${Math.floor(Math.random() * 256).toString(16).padStart(2, "0")}`;
  const balanceOf = async (): Promise<bigint> => {
    const response = await fetch(`http://127.0.0.1:${anvilPort}`, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: TOKEN, data: `0x70a08231${destination.slice(2).padStart(64, "0")}` }, "latest"] }) });
    return BigInt(((await response.json()) as { result: string }).result);
  };
  const before = await balanceOf();
  await page.goto(`http://127.0.0.1:${webPort}/swap.html`);
  await page.locator("#swap-from").selectOption("ln"); await page.locator("#swap-to").selectOption("usdc");
  await expect(page.locator('label[for="swap-receive-address"]')).toHaveText("EVM address to receive USDC");
  await page.locator("#swap-receive-address").fill(destination);
  await page.locator("#swap-receive-amount").fill("20"); await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeVisible({ timeout: 60000 });
  await expect(page.locator("#swap-quote-review")).toContainText(`sent to ${destination}`);
  await page.locator("#swap-quote-accept").click();
  await expect(page.locator("#swap-reverse-invoice")).toBeVisible({ timeout: 60000 });
  const invoice = (await page.locator("#swap-reverse-invoice").textContent())!;
  const payment = new Promise<string>((resolve, reject) => execFile(`${root}/dev/devctl`, ["pay", invoice, "--node", "user"],
    { cwd: root, env: process.env, encoding: "utf8", timeout: 150000 }, (error, stdout, stderr) => error ? reject(new Error(stderr || error.message)) : resolve(stdout)));
  const paid = payment.then((output) => ({ output, error: null }), (error: unknown) => ({ output: "", error }));
  await expect(page.locator("#swap-status")).toContainText("Stablecoins received", { timeout: 150000 });
  const result = await paid; if (result.error) throw result.error;
  expect(result.output).toContain("paid, preimage");
  expect(await balanceOf() - before).toBe(20_000_000n); // 20 fUSDC, six decimals, forwarded in the claim batch
  await page.reload();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Lightning to fUSDC recovery verified");
  await expect(page.locator("#swap-recovery-result")).toContainText(`forwarded to ${destination}`);
  await page.locator("#swap-evm-recovery-check").click();
  await expect(page.locator("#swap-evm-recovery-message")).toContainText("sponsored completion is unverified");
  await expect(page.locator("#swap-evm-recovery-claim")).toBeDisabled();
  expect(errors).toEqual([]);
});

test("sponsored recovery rejects an old real transfer while its new lock remains active", async ({ page }) => {
  test.skip(!enabled, "Explicit dev-stack opt-in required");
  test.setTimeout(240000);
  const deployment = JSON.parse(execFileSync("docker", ["exec", `${project}-tools-1`, "cat", "/state/evm/contracts.json"],
    { encoding: "utf8", timeout: 10000 })) as { token_contract: string; htlc_contract: string };
  const destination = `0x${"d1".repeat(20)}`;
  const old = JSON.parse(command("cast", "send", deployment.token_contract, "transfer(address,uint256)", destination,
    "20000000", "--unlocked", "--from", USER, "--legacy", "--gas-price", "0", "--json")) as { transactionHash: string };
  const rpc = new EvmRpc(`http://127.0.0.1:${anvilPort}`);
  expect(await rpc.transferred(old.transactionHash.slice(2), deployment.token_contract, destination)).toBe(20_000_000n);
  await page.goto(`http://127.0.0.1:${webPort}/swap.html`);
  await page.locator("#swap-from").selectOption("ln"); await page.locator("#swap-to").selectOption("usdc");
  await page.locator("#swap-receive-address").fill(destination);
  await page.locator("#swap-receive-amount").fill("20"); await page.locator("#swap-start").click();
  await page.locator("#swap-quote-accept").click({ timeout: 60000 });
  await expect(page.locator("#swap-reverse-invoice")).toBeVisible({ timeout: 60000 });
  const invoice = (await page.locator("#swap-reverse-invoice").textContent())!;
  const paymentHash = JSON.parse(command("lncli", "user", "decodepayreq", invoice)).payment_hash as string;
  await page.reload(); // Recovery must be explicit; do not execute the live claim.
  const paid = new Promise<{ output: string; error: Error | null }>((resolve) => execFile(`${root}/dev/devctl`, ["pay", invoice, "--node", "user"],
    { cwd: root, env: process.env, encoding: "utf8", timeout: 150000 }, (error, output) => resolve({ output, error })));
  await expect(async () => {
    await page.locator("#swap-evm-recovery-check").click();
    await expect(page.locator("#swap-evm-recovery-check")).toBeEnabled();
    await expect(page.locator("#swap-evm-recovery-claim")).toBeEnabled({ timeout: 2000 });
  }).toPass({ timeout: 60000 });
  const [funded] = await rpc.findLockups(deployment.htlc_contract, paymentHash, 0, await rpc.blockNumber());
  expect(funded).toBeDefined();
  try {
    const sponsorPort = process.env.RILL_DEV_SPONSOR_PORT ?? "8094";
    await page.route(`http://127.0.0.1:${sponsorPort}/**`, async (route) => {
      const request = route.request().postDataJSON() as { id: number; method: string };
      if (request.method === "wallet_sendPreparedCalls" || request.method === "wallet_getCallsStatus") {
        await route.fulfill({ json: { jsonrpc: "2.0", id: request.id, result: request.method === "wallet_sendPreparedCalls"
          ? { id: "withheld-security-claim" } : { status: 200, receipts: [{ transactionHash: old.transactionHash }] } } });
      } else await route.fallback(); // Actual sponsor preparation and all chain reads remain real.
    });
    await page.locator("#swap-evm-recovery-claim").click();
    await expect(page.locator("#swap-evm-recovery-message")).toContainText("operation is not proven", { timeout: 30000 });
    expect(await rpc.lockActive(deployment.htlc_contract, funded!.lock)).toBe(true);
    expect(await rpc.findClaim(deployment.htlc_contract, paymentHash, 0, await rpc.blockNumber())).toBeNull();
    await page.reload();
    await page.locator("#swap-evm-recovery-check").click();
    await expect(page.locator("#swap-evm-recovery-message")).toContainText("Claim exposure is unknown");
    await expect(page.locator("#swap-evm-recovery-claim")).toBeDisabled();
  } finally {
    await page.unrouteAll({ behavior: "wait" });
    // Resolve the real held payment only after the real provider refund, not via unsafe early cancellation.
    const blocks = Math.max(1, funded!.lock.timelock - await rpc.blockNumber() + 2);
    command("cast", "rpc", "anvil_mine", `0x${blocks.toString(16)}`);
    await expect.poll(() => rpc.lockActive(deployment.htlc_contract, funded!.lock), { timeout: 60000 }).toBe(false);
    const result = await paid;
    expect(result.error).not.toBeNull();
  }
});
