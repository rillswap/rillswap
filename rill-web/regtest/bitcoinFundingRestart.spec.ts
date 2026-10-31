import { expect, test } from "@playwright/test";
import { assertDisposableStack, command, compose, composeEnabled, providerState, webURL } from "./stack";

function retained(paymentHash: string): {
  session: string; state: string; bound: boolean; watched: boolean; selected: boolean;
  claim: string | null; funding: string | null;
} {
  return JSON.parse(compose("exec", "-T", "tools", "python", "-c",
    "import json,sqlite3,sys; "
    + "c=sqlite3.connect('file:/state/makers/btc-to-ln/provider-store/live.sqlite?mode=ro',uri=True); "
    + "rows=c.execute(\"SELECT w.session_id,w.state,w.funding_binding IS NOT NULL,f.session_id IS NOT NULL,f.selected_binding IS NOT NULL,w.claim_txid,json_extract(CAST(f.selected_binding AS TEXT),'$.funding_txid'),w.terms_offer FROM swaps w LEFT JOIN forward_funding f ON f.session_id=w.session_id\").fetchall(); "
    + "print(json.dumps(next((dict(zip(('session','state','bound','watched','selected','claim','funding'),r[:7])) for r in rows if json.loads(r[7])['payload']['terms']['contract_terms']['invoice_binding']['payment_hash']==sys.argv[1]),{})))",
    paymentHash));
}

function payments(paymentHash: string): { payment_hash: string; status: string }[] {
  return JSON.parse(command("lncli", "maker", "listpayments", "--include_incomplete")).payments
    .filter((entry: { payment_hash: string }) => entry.payment_hash === paymentHash);
}

for (const replaceDeposit of [false, true]) {
test(`provider finds offline funding after restart with no browser or funding binding, and pays once${replaceDeposit ? " after a wallet fee bump" : ""}`, async ({ page }, testInfo) => {
  test.skip(!composeEnabled, "Explicit disposable Compose opt-in required");
  test.setTimeout(300000);
  const project = assertDisposableStack();
  if (!/^rill-reverse-browser-(funding-restart|ci)-[a-z0-9-]+$/.test(project)) {
    throw new Error("Provider stop/start requires a dedicated funding-restart or CI stack");
  }
  await expect.poll(async () => {
    try { return (await page.request.get(webURL())).status(); } catch { return 0; }
  }, { timeout: 60000 }).toBe(200);
  const invoice = command("invoice", "20000", "--node", "user");
  const hash = JSON.parse(command("lncli", "user", "decodepayreq", invoice)).payment_hash;
  command("miner", "pause");
  try {
    await page.goto(webURL());
    await page.locator("#swap-invoice").fill(invoice);
    await expect(page.locator("#swap-estimate strong")).toHaveText(/^[0-9,]+ sat$/, { timeout: 60000 });
    await page.locator("#swap-start").click();
    await expect(page.locator("#swap-funding-uri")).toBeVisible({ timeout: 60000 });
    await expect.poll(() => providerState("btc-to-ln", hash)).toBe("ACCEPTED");
    const initial = retained(hash);
    expect(initial.watched).toBeTruthy();
    expect(initial.bound).toBeFalsy();
    const uri = new URL((await page.locator("#swap-funding-uri").getAttribute("href"))!);
    await page.locator("#swap-backups summary").click();
    const downloading = page.waitForEvent("download");
    await page.locator('#swap-backups a[download*="terms-recovery"]').click();
    await (await downloading).saveAs(testInfo.outputPath("terms-recovery.age"));
    await page.close(); // No client remains to discover or announce this deposit.
    compose("stop", "maker-btc-to-ln");
    let txid = command("send-btc", uri.pathname, uri.searchParams.get("amount")!);
    expect(JSON.parse(command("bitcoin-cli", "getrawtransaction", txid, "true")).confirmations ?? 0).toBe(0);
    compose("start", "maker-btc-to-ln");
    await expect.poll(() => {
      const logs = compose("logs", "--since", "2m", "maker-btc-to-ln");
      return logs.split("\n").some((line) => line.includes(initial.session.slice(0, 16))
        && line.includes('reason="mempool_seen"'));
    }, { timeout: 60000 }).toBe(true);
    expect(retained(hash).bound).toBeFalsy();
    expect(providerState("btc-to-ln", hash)).toBe("ACCEPTED");
    expect(payments(hash)).toHaveLength(0); // Mempool detection is not payment permission.
    if (replaceDeposit) {
      const entry = JSON.parse(command("bitcoin-cli", "getmempoolentry", txid));
      const rate = Math.ceil(Number(entry.fees.base) * 1e8 / entry.vsize) + 2;
      const replacement = JSON.parse(command("bitcoin-cli", "-rpcwallet=user", "bumpfee", txid,
        JSON.stringify({ fee_rate: rate })));
      expect(replacement.txid).not.toBe(txid);
      txid = replacement.txid;
    }
    command("mine", "1");
    await expect.poll(() => JSON.parse(command("lncli", "user", "lookupinvoice", hash)).state,
      { timeout: 60000 }).toBe("SETTLED");
    await expect.poll(() => providerState("btc-to-ln", hash), { timeout: 60000 }).toBe("CLAIMING");
    const selected = retained(hash);
    expect(selected.session).toBe(initial.session);
    expect(selected.selected).toBeTruthy();
    expect(selected.funding).toBe(txid);
    expect(selected.bound).toBeFalsy();
    expect(selected.claim).toMatch(/^[0-9a-f]{64}$/);
    command("mine", "3");
    await expect.poll(() => providerState("btc-to-ln", hash), { timeout: 60000 }).toBe("CLAIMED");
    expect(JSON.parse(command("bitcoin-cli", "getrawtransaction", selected.claim!, "true")).confirmations).toBeGreaterThanOrEqual(3);
    expect(payments(hash)).toHaveLength(1);
    expect(payments(hash)[0]!.status).toBe("SUCCEEDED");
    compose("restart", "maker-btc-to-ln");
    await expect.poll(() => providerState("btc-to-ln", hash)).toBe("CLAIMED");
    expect(retained(hash).claim).toBe(selected.claim);
    expect(payments(hash)).toHaveLength(1);
  } finally {
    compose("start", "maker-btc-to-ln");
    command("miner", "resume");
  }
});
}
