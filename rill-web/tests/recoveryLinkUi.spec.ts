import { expect, test } from "./fixtures/swapPage";
import canonicalize from "canonicalize";
import { readFileSync } from "node:fs";
import { encryptCanonicalRecoveryForRecipient } from "../src/recoveryAgeContainer";
import { swapLinkFragment } from "../src/swapLink";
import type { RecoveryRefundCase } from "../unit/fixtures/recoveryRefundCases";

const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PAGE = "http://127.0.0.1:18765/test-only/swap.html";

for (const source of ["words", "key backup"] as const) {
  test(`a saved link asks for the original ${source}, not another recovery file`, async ({ page }, info) => {
    const requests: string[] = [], sockets: string[] = [], output: string[] = [];
    page.on("request", (request) => requests.push(request.url()));
    page.on("websocket", (socket) => sockets.push(socket.url()));
    page.on("console", (message) => output.push(message.text()));
    await page.goto(PAGE);
    const key = await page.evaluate(async (mnemonic) => {
      const url = "/test-only/browserRecoveryWallet.js", module = await import(url) as typeof import("../src/browserRecoveryWallet");
      const key = await module.recoveryKeyFromWords(mnemonic); key.file.fill(0);
      return { recipient: key.recipient, scheme: module.WALLET_SCHEME };
    }, mnemonic);
    const item = (JSON.parse(readFileSync(new URL("../tmp/preview/test-only/recovery-refund-cases.json", import.meta.url), "utf8")) as RecoveryRefundCase[])[0]!;
    item.record.funding_history = [];
    const encrypted = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(item.record)!), key.recipient);
    const fragment = swapLinkFragment({ file: encrypted, network: "regtest" });
    await page.goto(PAGE + fragment);
    await expect(page.locator("#swap-recovery-loaded")).toContainText("Encrypted swap loaded from your saved link");
    await expect(page.locator("#swap-recovery-loaded")).toContainText("do not need to choose a separate .age file");
    await expect(page.locator("#swap-recovery-result")).toContainText("encrypted file could not be opened with this key");
    await expect(page.locator("#swap-recovery-words")).toBeVisible();
    await expect(page.locator("#swap-recovery-file")).toBeHidden();
    await page.screenshot({ path: info.outputPath("loaded-link.png"), fullPage: true });
    const before = await page.evaluate(async () => {
      const wallet = await window.uiFixture.wallet.open();
      try { return new TextDecoder().decode(await wallet.exportBackup()); } finally { wallet.close(); }
    });
    if (source === "words") await page.locator("#swap-recovery-words").fill(mnemonic);
    else await page.locator("#swap-recovery-key-file").setInputFiles({ name: "original-key.json", mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify({ format: "rillswap-browser-recovery", version: 1, scheme: key.scheme, mnemonic })) });
    await page.getByRole("button", { name: "Unlock and inspect swap", exact: true }).click();
    await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
    await expect(page.locator("#swap-recovery-result")).toContainText("0 recorded funding revisions");
    await expect(page.locator("#swap-refund-download")).toBeHidden();
    await expect(page.locator("#swap-refund-broadcast")).toBeHidden();
    expect(new URL(page.url()).hash).toBe(fragment);
    expect(await page.evaluate(async () => {
      const wallet = await window.uiFixture.wallet.open();
      try { return new TextDecoder().decode(await wallet.exportBackup()); } finally { wallet.close(); }
    })).toBe(before);
    for (const url of requests) { expect(new URL(url).host).toBe("127.0.0.1:18765"); expect(url).not.toContain("#swap="); }
    expect(sockets).toEqual([]); expect(output.join("\n")).not.toContain(mnemonic); expect(output.join("\n")).not.toContain("AGE-SECRET-KEY");

    await page.locator("#swap-recovery-file-choice summary").click();
    await page.locator("#swap-recovery-file").setInputFiles({ name: "other.age", mimeType: "application/octet-stream", buffer: Buffer.from(encrypted) });
    await expect(page.locator("#swap-recovery-loaded")).toBeHidden();
    await expect(page.locator("#swap-recovery-inspect")).toHaveText("Inspect recovery file");
    await expect(page.locator("#swap-recovery-result h3")).toHaveCount(0);
    await expect(page.locator("#swap-recovery-funding-controls")).toBeHidden();
  });
}
