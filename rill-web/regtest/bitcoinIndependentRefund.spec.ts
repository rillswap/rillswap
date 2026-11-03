/** Original-backup recovery with real Core/LND, no live client, provider or relays. */
import { expect, test } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { serializeTransaction } from "../src/swap/transaction";
import { assertRelayFaultStack, command, compose, composeEnabled, providerState, root, webURL } from "./stack";
import { openRecovery, openRecoveryKey } from "../tests/fixtures/swapPage";

function inspectTestBackup(keyPath: string, termsPath: string): {
  fundingHistoryCount: number; contract_terms: { refund_lock_height: number; max_refund_fee_sat: string; client_destination_script: string };
} {
  // Use the browser's Bun-compatible modules, returning only public test metadata.
  const script = `import { parseWalletBackup, walletRecoveryKey } from "./src/browserRecoveryWallet";
    import { decryptRecoveryContainer } from "./src/recoveryKeys";
    const key = await walletRecoveryKey(parseWalletBackup(await Bun.file(process.argv[1]).text()));
    const plaintext = await decryptRecoveryContainer(new Uint8Array(await Bun.file(process.argv[2]).arrayBuffer()), key.identity);
    const doc = JSON.parse(new TextDecoder().decode(plaintext)); plaintext.fill(0); key.file.fill(0);
    const { refund_lock_height, max_refund_fee_sat, client_destination_script } = doc.contract_terms;
    console.log(JSON.stringify({ fundingHistoryCount: doc.funding_history.length, contract_terms: { refund_lock_height, max_refund_fee_sat, client_destination_script } }));`;
  return JSON.parse(execFileSync("bun", ["-e", script, keyPath, termsPath], { cwd: resolve(root, "rill-web"), encoding: "utf8", timeout: 30000 }));
}

for (const scenario of ["ordinary deposit", "wallet replacement", "different amount", "duplicate outputs", "browser-stored terms"]) {
  test(`original terms-only backup refunds ${scenario} with provider and relays stopped`, async ({ page, browser }, testInfo) => {
    test.skip(!composeEnabled, "Explicit disposable Compose opt-in required");
    test.setTimeout(300000); assertRelayFaultStack();
    const invoice = command("invoice", "20000", "--node", "user");
    const paymentHash = JSON.parse(command("lncli", "user", "decodepayreq", invoice)).payment_hash;
    command("miner", "pause");
    let confirmed = false;
    const originalContext = page.context();
    const recoveryContext = await browser.newContext({ acceptDownloads: true });
    const assertOffline = () => {
      const running = compose("ps", "--status", "running", "--services").split("\n");
      for (const service of ["maker-btc-to-ln", "relay", "relay-alt"]) expect(running).not.toContain(service);
    };
    try {
      await page.goto(webURL()); await page.locator("#swap-invoice").fill(invoice);
      await expect(page.locator("#swap-estimate strong")).toHaveText(/^[0-9,]+ sat$/, { timeout: 60000 });
      await page.locator("#swap-start").click();
      await expect(page.locator("#swap-funding-uri")).toBeVisible({ timeout: 60000 });
      await expect.poll(() => providerState("btc-to-ln", paymentHash)).toBe("ACCEPTED");
      const uri = new URL((await page.locator("#swap-funding-uri").getAttribute("href"))!);
      await page.locator("#swap-backups summary").click();
      const termsDownload = page.waitForEvent("download");
      await page.locator('#swap-backups a[download*="terms-recovery"]').click();
      const termsPath = testInfo.outputPath("original-terms.age"); await (await termsDownload).saveAs(termsPath);
      await openRecoveryKey(page);
      const keyDownload = page.waitForEvent("download");
      await page.locator('#swap-wallet-actions a[download="rillswap-recovery-key.json"]').click();
      const keyPath = testInfo.outputPath("test-recovery-key.json"); await (await keyDownload).saveAs(keyPath);
      const ciphertext = readFileSync(termsPath);
      const record = inspectTestBackup(keyPath, termsPath);
      expect(record.fundingHistoryCount).toBe(0);
      await page.close(); // The live browser never sees or announces a funding transaction.
      compose("stop", "maker-btc-to-ln", "relay", "relay-alt"); assertOffline();
      let txid: string;
      const amount = uri.searchParams.get("amount")!;
      if (scenario === "duplicate outputs") {
        // Core's createrawtransaction RPC rejects duplicate address arguments,
        // although two outputs with the same script are consensus-valid.
        const script = JSON.parse(command("bitcoin-cli", "validateaddress", uri.pathname)).scriptPubKey;
        const output = { value: BigInt(Math.round(Number(amount) * 1e8)), script: hexToBytes(script) };
        const raw = bytesToHex(serializeTransaction({ version: 2, locktime: 0, inputs: [], outputs: [output, output] }, false));
        const funded = JSON.parse(command("bitcoin-cli", "-rpcwallet=user", "fundrawtransaction", raw));
        const signed = JSON.parse(command("bitcoin-cli", "-rpcwallet=user", "signrawtransactionwithwallet", funded.hex));
        expect(signed.complete).toBe(true); txid = command("bitcoin-cli", "sendrawtransaction", signed.hex);
      } else {
        txid = command("send-btc", uri.pathname, scenario === "different amount" ? (Number(amount) / 2).toFixed(8) : amount);
      }
      if (scenario === "wallet replacement") {
        const entry = JSON.parse(command("bitcoin-cli", "getmempoolentry", txid));
        const replacement = JSON.parse(command("bitcoin-cli", "-rpcwallet=user", "bumpfee", txid,
          JSON.stringify({ fee_rate: Math.ceil(Number(entry.fees.base) * 1e8 / entry.vsize) + 2 })));
        expect(replacement.txid).not.toBe(txid); txid = replacement.txid;
      }
      command("mine", "1");
      const funding = JSON.parse(command("bitcoin-cli", "getrawtransaction", txid, "true"));
      const outputs = funding.vout.filter((output: { scriptPubKey: { address?: string } }) => output.scriptPubKey.address === uri.pathname) as { n: number; value: number }[];
      expect(outputs).toHaveLength(scenario === "duplicate outputs" ? 2 : 1);
      const remaining = record.contract_terms.refund_lock_height + 1 - Number(command("bitcoin-cli", "getblockcount"));
      expect(remaining).toBeLessThan(10000); if (remaining > 0) command("mine", String(remaining));
      assertOffline(); expect(providerState("btc-to-ln", paymentHash)).toBe("ACCEPTED");
      const fromStorage = scenario === "browser-stored terms";
      const recovery = await (fromStorage ? originalContext : recoveryContext).newPage(); let posts = 0;
      recovery.on("request", (request) => { if (request.method() === "POST" && request.url().endsWith("/api/tx")) posts++; });
      await recovery.goto(webURL()); await openRecovery(recovery);
      if (fromStorage) {
        await recovery.locator("#swap-open-saved-recoveries").click();
        await expect(recovery.locator(".saved-swap")).toHaveCount(1);
        await recovery.getByRole("button", { name: "Open saved swap", exact: true }).click();
        // No file selection, mnemonic entry, key import or bookmarked link.
        expect(new URL(recovery.url()).hash).toBe("");
      } else {
        await recovery.locator("#swap-recovery-file").setInputFiles(termsPath);
        await recovery.locator("#swap-recovery-key-file").setInputFiles(keyPath);
        await recovery.locator("#swap-recovery-inspect").click();
      }
      await expect(recovery.locator("#swap-recovery-result")).toContainText("0 recorded funding revisions");
      expect(posts).toBe(0);
      if (scenario === "wallet replacement") await recovery.locator("#swap-recovery-deposit-txid").fill(txid);
      await recovery.locator("#swap-recovery-find-deposits").click();
      await expect(recovery.locator("#swap-recovery-discovery-result")).toContainText(`Found ${outputs.length} matching output`);
      await expect(recovery.locator("#swap-recovery-revision")).toHaveValue("");
      await expect(recovery.locator("#swap-refund-prepare")).toBeDisabled();
      for (const output of outputs) {
        await recovery.locator("#swap-recovery-revision").selectOption(`outpoint:${txid}:${output.n}`);
        const fee = Math.min(1000, Number(record.contract_terms.max_refund_fee_sat));
        await recovery.locator("#swap-refund-controls #swap-refund-fee").fill(String(fee));
        await recovery.locator("#swap-recovery-check-funding").click();
        await expect(recovery.locator("#swap-recovery-funding-result")).toContainText("refund lock has passed");
        await recovery.locator("#swap-refund-prepare").click();
        await expect(recovery.locator("#swap-refund-result h3")).toHaveText("Refund prepared and saved");
        assertOffline(); await recovery.locator("#swap-refund-broadcast").click();
        await expect(recovery.locator("#swap-refund-result h3")).toHaveText("Refund accepted by the API");
        const refundTxid = (await recovery.locator("#swap-refund-result").innerText()).match(/Transaction ID: ([0-9a-f]{64})/)![1]!;
        const refund = JSON.parse(command("bitcoin-cli", "getrawtransaction", refundTxid, "true"));
        expect(refund.vin).toHaveLength(1); expect(refund.vin[0].txid).toBe(txid); expect(refund.vin[0].vout).toBe(output.n);
        expect(refund.vout).toHaveLength(1); expect(refund.vout[0].scriptPubKey.hex).toBe(record.contract_terms.client_destination_script);
        expect(Math.round(refund.vout[0].value * 1e8)).toBe(Math.round(output.value * 1e8) - fee);
        command("mine", "1");
        expect(JSON.parse(command("bitcoin-cli", "getrawtransaction", refundTxid, "true")).confirmations).toBeGreaterThanOrEqual(1);
        assertOffline();
      }
      expect(posts).toBe(outputs.length);
      expect(JSON.parse(command("lncli", "user", "lookupinvoice", paymentHash)).state).not.toBe("SETTLED");
      const payments = JSON.parse(command("lncli", "maker", "listpayments", "--include_incomplete")).payments;
      expect(payments.filter((payment: { payment_hash: string }) => payment.payment_hash === paymentHash)).toHaveLength(0);
      expect(readFileSync(termsPath)).toEqual(ciphertext);
      confirmed = true;
    } finally {
      await recoveryContext.close();
      // A failed recovery leaves the peer stopped, never give it a chance to claim test funds.
      // Restore the disposable suite only AFTER every selected refund is confirmed.
      if (confirmed) { compose("start", "relay", "relay-alt", "maker-btc-to-ln"); command("miner", "resume"); }
    }
  });
}
