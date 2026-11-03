import { expect, openRecovery, test } from "./fixtures/swapPage";
import canonicalize from "canonicalize";
import { readFileSync } from "node:fs";
import { encryptCanonicalRecoveryForRecipient } from "../src/recoveryAgeContainer";
import type { RecoveryRefundCase } from "../unit/fixtures/recoveryRefundCases";
import type { ReverseRecoveryCase } from "../unit/fixtures/reverseRecoveryCases";

for (const width of [320, 390, 1440]) {
  test(`recovery actions have usable spacing and wrap at ${width}px`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("http://127.0.0.1:18765/test-only/swap.html");
    const recipient = await page.evaluate(async () => {
      const wallet = await window.uiFixture.wallet.open();
      try { return (await wallet.recoveryKey()).recipient; } finally { wallet.close(); }
    });
    const forward = (JSON.parse(readFileSync(new URL("../tmp/preview/test-only/recovery-refund-cases.json", import.meta.url), "utf8")) as RecoveryRefundCase[])[0]!;
    const reverse = JSON.parse(readFileSync(new URL("../tmp/preview/test-only/reverse-recovery.json", import.meta.url), "utf8")) as ReverseRecoveryCase;
    await openRecovery(page);
    for (const [direction, record] of [["forward", forward.record], ["reverse", reverse.record]] as const) {
      const encrypted = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(record)!), recipient);
      await page.locator("#swap-recovery-file").setInputFiles({ name: "synthetic-layout.age", mimeType: "application/octet-stream", buffer: Buffer.from(encrypted) });
      await page.locator("#swap-recovery-inspect").click();
      await expect(page.locator("#swap-recovery-result h3")).toContainText(direction === "forward" ? "Recovery record verified" : "Lightning to Bitcoin recovery verified");
      if (direction === "forward") {
        await expect(page.locator("#swap-refund-download")).toBeHidden();
        await expect(page.locator("#swap-refund-broadcast")).toBeHidden();
        await page.locator("#swap-recovery-deposit-txid").fill("f".repeat(64));
        // Layout only: reveal the post-prepare buttons without preparing, exporting, or broadcasting anything.
        await page.evaluate(() => { for (const id of ["swap-refund-download", "swap-refund-broadcast"]) document.getElementById(id)!.hidden = false; });
      } else {
        await page.locator(".recovery-backups").evaluate((root) => {
          for (const name of ["rillswap-reverse-latest.age", "rillswap-reverse-claim.age"]) {
            const link = document.createElement("a"); link.textContent = "Download " + name; link.href = "#layout-only"; root.append(link);
          }
        });
      }
      const layout = await page.locator("#swap-recovery").evaluate((root) => {
        const visible = (node: HTMLElement) => node.getBoundingClientRect().height > 0;
        const groups = [...root.querySelectorAll<HTMLElement>(".recovery-actions")].map((group) => {
          const box = group.getBoundingClientRect();
          return { width: box.width, buttons: [...group.querySelectorAll<HTMLButtonElement>("button")].filter(visible).map((button) => {
            const b = button.getBoundingClientRect(); return { x: b.x, y: b.y, right: b.right, bottom: b.bottom, width: b.width, height: b.height };
          }) };
        });
        return { groups, pageWidth: document.documentElement.scrollWidth, viewport: innerWidth, overflow: getComputedStyle(document.body).overflowX };
      });
      expect(layout.pageWidth).toBeLessThanOrEqual(layout.viewport); expect(layout.overflow).not.toBe("hidden");
      for (const group of layout.groups) for (const [index, button] of group.buttons.entries()) {
        expect(button.height).toBeGreaterThanOrEqual(44);
        if (width <= 520) expect(Math.abs(button.width - group.width)).toBeLessThan(1);
        for (const previous of group.buttons.slice(0, index)) {
          expect(button.x >= previous.right + 8 || button.y >= previous.bottom + 8).toBe(true);
        }
      }
      await page.screenshot({ path: info.outputPath(`${direction}-${width}.png`), fullPage: true });
    }
  });
}
