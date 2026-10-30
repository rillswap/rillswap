import { directorySettled, expect, MAINNET_RELAYS, openRecoveryKey, openSettings, test } from "./fixtures/swapPage";
import { buildCommit } from "../scripts/build-commit";

test("merchant invoice fragments prefill locally without connecting and are removed from the address bar", async ({ page, relaySockets: sockets }) => {
  const requests: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  await page.goto("http://127.0.0.1:18765/swap.html#invoice=ln-public-test-handoff");
  await expect(page.locator("#swap-invoice")).toHaveValue("ln-public-test-handoff");
  await directorySettled(page);
  expect(new URL(page.url()).hash).toBe(""); for (const url of sockets) expect(MAINNET_RELAYS).toContain(url);
  for (const request of requests) { expect(request).not.toContain("ln-public-test-handoff"); expect(new URL(request).host).toBe("127.0.0.1:18765"); }
  await page.goto("about:blank");
  await page.goto("http://127.0.0.1:18765/swap.html#invoice=" + "x".repeat(4097));
  await expect(page.locator("#swap-invoice")).toHaveValue(""); expect(new URL(page.url()).hash).toBe("");
});

test("address and amount fragments prefill a Lightning to Bitcoin swap locally and are removed from the address bar", async ({ page, relaySockets: sockets }) => {
  const requests: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  await page.goto("http://127.0.0.1:18765/swap.html#address=bcrt1qtest-handoff&amount=50000");
  await expect(page.locator("#swap-from")).toHaveValue("ln"); await expect(page.locator("#swap-to")).toHaveValue("btc");
  await expect(page.locator("#swap-receive-address")).toHaveValue("bcrt1qtest-handoff");
  await expect(page.locator("#swap-receive-amount")).toHaveValue("50000");
  await expect(page.locator("#swap-invoice")).toBeHidden();
  await directorySettled(page);
  expect(new URL(page.url()).hash).toBe(""); for (const url of sockets) expect(MAINNET_RELAYS).toContain(url);
  for (const request of requests) { expect(request).not.toContain("test-handoff"); expect(new URL(request).host).toBe("127.0.0.1:18765"); }
  await page.goto("about:blank");
  await page.goto("http://127.0.0.1:18765/swap.html#amount=12.5&address=" + "x".repeat(129));
  await expect(page.locator("#swap-from")).toHaveValue("ln");
  await expect(page.locator("#swap-receive-amount")).toHaveValue(""); await expect(page.locator("#swap-receive-address")).toHaveValue("");
  expect(new URL(page.url()).hash).toBe("");
});
import { testInvoice } from "../../rill-payments/tests/helpers";
import { scriptAddress } from "../src/swap/address";

const SWAP = "http://127.0.0.1:18765/swap.html";

test("direction flips between Bitcoin and Lightning, and stablecoins pair with Lightning only", async ({ page, relaySockets: sockets }) => {
  const requests: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  await page.goto(SWAP);
  await openSettings(page, "connection");
  await page.locator("#swap-network").selectOption("regtest");
  await page.locator("#swap-settings-close").click();
  await directorySettled(page);
  const directorySockets = sockets.length;
  await expect(page.locator("#swap-from")).toHaveValue("btc");
  await expect(page.locator("#swap-to")).toHaveValue("ln");
  await expect(page.locator("#swap-invoice")).toBeVisible();
  await expect(page.locator("#swap-receive-address")).not.toBeVisible();
  await expect(page.locator("#swap-pair-note")).not.toBeVisible();
  await expect(page.locator("#swap-start")).toBeEnabled();

  await page.getByRole("button", { name: "Switch direction" }).click();
  await expect(page.locator("#swap-from")).toHaveValue("ln");
  await expect(page.locator("#swap-to")).toHaveValue("btc");
  await expect(page.getByRole("heading", { name: "Lightning in. Bitcoin out." })).toBeVisible();
  await expect(page.locator("#swap-invoice")).not.toBeVisible();
  await expect(page.locator("#swap-recovery-toggle")).toBeVisible(); // the recovery key serves both directions
  await expect(page.locator("#swap-forward-overrides")).not.toBeVisible();
  await expect(page.locator("#swap-receive-address")).toBeVisible();
  await expect(page.locator("#swap-receive-amount")).toBeVisible();
  await expect(page.locator("#swap-pair-note")).not.toBeVisible();
  await expect(page.locator("#swap-start")).toBeEnabled();
  // Invalid reverse input is refused locally, before any connection.
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-status")).toContainText("Amount to receive must be a whole number");

  // Choosing the asset already on the other side swaps them.
  await page.locator("#swap-to").selectOption("ln");
  await expect(page.locator("#swap-from")).toHaveValue("btc");
  await expect(page.getByRole("heading", { name: "Bitcoin in. Lightning out." })).toBeVisible();

  // Stablecoins pair with Lightning only, in both directions.
  await page.locator("#swap-to").selectOption("usdt");
  await expect(page.locator("#swap-to option[value=usdt]")).toHaveText("USDT");
  await expect(page.locator("#swap-pair-note")).toHaveText("Bitcoin to Tether swaps are not offered.");
  await expect(page.locator("#swap-start")).toHaveText("Pair unavailable");
  await expect(page.locator("#swap-start")).toBeDisabled();
  await page.locator("#swap-from").selectOption("usdc");
  await page.locator("#swap-to").selectOption("ln");
  await expect(page.getByRole("heading", { name: "USD Coin in. Lightning out." })).toBeVisible();
  await expect(page.locator("#swap-pair-note")).not.toBeVisible();
  await expect(page.locator("#swap-invoice")).toBeVisible();
  await expect(page.locator("#swap-forward-overrides")).not.toBeVisible();
  await expect(page.locator("#swap-start")).toBeEnabled();
  await page.locator("#swap-start").click(); // an empty invoice is refused locally, before any connection
  await expect(page.locator("#swap-status")).toContainText("Invoice refused");
  await page.getByRole("button", { name: "Switch direction" }).click();
  await expect(page.locator("#swap-pair-note")).not.toBeVisible();
  await expect(page.locator("#swap-start")).toBeEnabled();
  await expect(page.locator("#swap-receive-amount")).toBeVisible();
  await expect(page.locator("#swap-receive-address")).not.toBeVisible();
  await expect(page.locator('label[for="swap-receive-amount"]')).toHaveText("Amount to receive (USDC)");
  // A configured gas sponsor turns receiving into "amount plus address": no wallet extension, no gas.
  await openSettings(page, "evm");
  await page.locator("#swap-evm-sponsor").fill("http://127.0.0.1:8094");
  await page.locator("#swap-evm-entry-point").fill("0x0000000071727de22e5e9d8baf0edac6f37da032");
  await page.locator("#swap-evm-delegate").fill("0x77021100bd87b7008e5e1989d0eb38555d0d0000");
  await page.locator("#swap-settings-close").click();
  await page.locator("#swap-to").selectOption("usdc");
  await expect(page.locator("#swap-receive-address")).toBeVisible();
  await expect(page.locator('label[for="swap-receive-address"]')).toHaveText("EVM address to receive USDC");
  await expect(page.locator("#swap-pair-note")).not.toBeVisible();
  await page.locator("#swap-receive-amount").fill("20"); await page.locator("#swap-start").click();
  await expect(page.locator("#swap-status")).toContainText("Enter the 0x address that should receive USDC");
  expect(sockets).toHaveLength(directorySockets);
  await page.locator("#swap-to").selectOption("btc");
  await expect(page.locator('label[for="swap-receive-address"]')).toHaveText("Bitcoin address to receive");

  await page.locator("#swap-from").selectOption("btc");
  await page.locator("#swap-to").selectOption("ln");
  await expect(page.locator("#swap-start")).toBeEnabled();
  for (const url of requests) expect(new URL(url).host).toBe("127.0.0.1:18765");
  expect(sockets).toHaveLength(directorySockets);
});

test("the swap page enables mainnet and only loads provider listings when it opens", async ({ page, relaySockets: sockets }) => {
  const requests: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  await page.goto(SWAP);
  await expect(page.getByRole("heading", { name: "Bitcoin in. Lightning out." })).toBeVisible();
  const options = await page.locator("#swap-network option").allTextContents();
  expect(options).toEqual(["mainnet", "signet", "testnet4", "regtest"]);
  await expect(page.locator("#swap-start")).toBeEnabled();
  await expect(page.locator("#swap-network-badge")).toContainText("Mainnet");
  await expect(page.locator("#swap-success-fee")).not.toBeVisible();
  await expect(page.locator("#swap-provider")).not.toBeVisible();
  await expect(page.locator("#swap-log")).not.toBeVisible();
  await expect(page.locator("#swap-chain-disclosure")).not.toBeVisible();
  await expect(page.locator("#swap-chain-consent")).toHaveCount(0);
  await page.locator("#swap-privacy-toggle").click();
  await expect(page.locator("#swap-chain-disclosure")).toContainText("https://mempool.space/api");
  await page.locator("#swap-privacy-toggle").click();
  await openRecoveryKey(page);
  await expect(page.locator("#swap-prerequisites")).toContainText("PSBT");
  await expect(page.locator("#swap-wallet-status")).toContainText("New browser recovery key created");
  await expect(page.getByRole("link", { name: "Download rillswap-recovery-key.json" })).toBeVisible();
  await expect(page.locator("#swap-refund")).toHaveValue("");
  await expect(page.locator("#swap-tip")).toHaveValue("");
  await expect(page.locator("#swap-age")).toHaveValue("");
  await expect(page.locator("#swap-safety")).toHaveCount(0);
  const csp = await page.locator("meta[http-equiv='Content-Security-Policy']").getAttribute("content");
  // Any https mempool instance can be configured; plain http only for local endpoints.
  expect(csp).toContain("connect-src 'self' wss: ws://*.onion:* ws://127.0.0.1:* ws://localhost:* https: http://127.0.0.1:8091");
  expect(csp).not.toMatch(/\shttp:(?:\s|;)/);
  expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval';");
  await directorySettled(page);
  for (const url of requests) expect(new URL(url).host).toBe("127.0.0.1:18765");
  expect([...new Set(sockets)].sort()).toEqual([...MAINNET_RELAYS].sort());
});

test("the CSP admits the same-origin MuSig2 WASM and the cooperation journal APIs", async ({ page }) => {
  await page.goto(SWAP);
  const result = await page.evaluate(async () => {
    const listing = await (await fetch("assets/")).text();
    const name = /rill_crypto_wasm-[\w-]+\.wasm/.exec(listing)?.[0];
    if (!name) return "wasm asset missing";
    const module = await WebAssembly.compile(await (await fetch(`assets/${name}`)).arrayBuffer());
    if (WebAssembly.Module.exports(module).length < 10) return "wasm exports missing"; // names are minified
    if (!navigator.locks) return "web locks missing";
    let blocked = "no";
    try {
      await fetch("https://example.invalid/");
    } catch {
      blocked = "yes";
    }
    return `ok ${blocked}`;
  });
  expect(result).toBe("ok yes");
});

test("invalid input is refused before any relay connection", async ({ page, relaySockets: sockets }) => {
 
  await page.goto(SWAP);
  await openSettings(page, "connection");
  await page.locator("#swap-network").selectOption("signet");
  await page.locator("#swap-relay").fill("wss://relay.invalid");
  await page.locator("#swap-settings-close").click();
  await directorySettled(page);
  const directorySockets = sockets.length;
  await openSettings(page, "advanced");
  await page.locator("#swap-refund").fill("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
  await page.locator("#swap-tip").fill("1000");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-log")).toContainText("refused: Address refused: not for this network");
  await page.locator("#swap-refund").fill("tb1qw508d6qejxtdg4y5r3zarvary0c5xdrpezj");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-log")).toContainText("refused:");
  expect(sockets).toHaveLength(directorySockets);
});

test("invalid mainnet programmatic submission is refused before opening a swap relay", async ({ page, relaySockets: sockets }) => {
 
  await page.goto(SWAP);
  await directorySettled(page);
  const directorySockets = sockets.length;
  await page.locator("#swap-form").evaluate((form) => form.dispatchEvent(new Event("submit", { cancelable: true })));
  await expect(page.locator("#swap-status")).toContainText("refused:");
  expect(sockets).toHaveLength(directorySockets);
});

test("mainnet admission still pins invoice currency and opens no chain connection before an explicit swap", async ({ page, relaySockets: sockets }) => {
  const external: string[] = [];
  page.on("request", (request) => { if (new URL(request.url()).protocol === "https:") external.push(request.url()); });
  await page.route("https://**/*", (route) => route.abort());
  await page.goto(SWAP); await directorySettled(page);
  expect(external).toEqual([]);
  const directorySockets = sockets.length, now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("wrong-mainnet-currency", "1000000", now, now + 7200, "tbs"));
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-status")).toContainText("refused:");
  expect(sockets).toHaveLength(directorySockets); expect(external).toEqual([]);
  await openSettings(page, "advanced");
  await expect(page.locator("#swap-refund")).toBeVisible();
  await page.locator("#swap-refund").fill("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  await page.locator("#swap-tip").fill("900000");
  await page.locator("#swap-invoice").fill(testInvoice("mainnet-admission", "1000000", now, now + 7200, "bc"));
  await page.locator("#swap-start").click();
  await expect.poll(() => sockets.length).toBeGreaterThan(directorySockets);
  expect(external).toEqual([]); // The explicit height override avoids any real chain request.
  await page.goto("about:blank");
});

test("settings are keyboard accessible and switching networks resets local relays", async ({ page, relaySockets: sockets }) => {
 
  await page.goto(SWAP);
  await page.locator("#swap-settings-toggle").focus();
  await page.keyboard.press("Enter");
  await expect(page.locator("#swap-settings")).toBeVisible();
  await expect(page.locator("#swap-settings h2")).toBeFocused();
  await expect(page.locator("#swap-settings-toggle")).toHaveAttribute("aria-expanded", "true");
  await openSettings(page, "connection");
  await page.locator("#swap-network").selectOption("regtest");
  await expect(page.locator("#swap-relay")).toHaveValue("ws://127.0.0.1:7777/");
  await expect(page.locator("#swap-chain-api")).toHaveValue("http://127.0.0.1:8091/api");
  await page.locator("#swap-network").selectOption("signet");
  await expect(page.locator("#swap-relay")).toHaveValue(MAINNET_RELAYS.join("\n"));
  await expect(page.locator("#swap-chain-api")).toHaveValue("https://mempool.space/signet/api");
  await page.keyboard.press("Escape");
  await expect(page.locator("#swap-settings")).not.toBeVisible();
  await expect(page.locator("#swap-settings-toggle")).toBeFocused();
  await expect(page.locator("#swap-start")).toBeEnabled();
  await page.locator("#swap-privacy-toggle").click();
  await expect(page.locator("#swap-chain-disclosure")).toContainText("https://mempool.space/signet/api");
  await directorySettled(page);
  for (const url of sockets) expect([...MAINNET_RELAYS, "ws://127.0.0.1:7777/"]).toContain(url);
});

test("the header network indicator switches an unpublished network in place and follows settings", async ({ page }) => {
  await page.goto(SWAP);
  await directorySettled(page);
  const picker = page.getByRole("combobox", { name: "Switch network" });
  await expect(picker).toHaveValue("mainnet");
  expect(await picker.locator("option").allTextContents()).toEqual(["Mainnet", "signet · test funds", "testnet4 · test funds", "regtest · test funds"]);
  await picker.selectOption("signet");
  await expect(page).toHaveURL(SWAP); // no deployment map in this build: nothing navigates
  await openSettings(page, "connection");
  await expect(page.locator("#swap-network")).toHaveValue("signet");
  await expect(page.locator("#swap-chain-api")).toHaveValue("https://mempool.space/signet/api");
  await page.locator("#swap-network").selectOption("regtest");
  await page.locator("#swap-settings-close").click();
  await expect(picker).toHaveValue("regtest");
});

test("the header links to the source code in a new tab, beside the network picker", async ({ page }) => {
  await page.goto(SWAP);
  const source = page.getByRole("link", { name: "RillSwap source code on GitHub" });
  await expect(source).toHaveAttribute("href", "https://github.com/rillswap/rillswap");
  await expect(source).toHaveAttribute("target", "_blank"); // never navigates away from a swap in progress
  await expect(source).toHaveAttribute("rel", "noopener noreferrer");
  await expect(page.locator("header #swap-toolbar")).toContainText("GitHub");
  await expect(page.locator(".swap-intro")).toContainText("open, permissionless market");
});

test("the footer links the short build revision to its full GitHub commit in a new tab", async ({ page }) => {
  await page.goto(SWAP);
  const commit = buildCommit(), revision = page.locator("footer #swap-build-commit");
  if (!commit) { await expect(revision).toHaveCount(0); return; }
  await expect(revision).toHaveText(commit.slice(0, 7));
  await expect(revision).toHaveAttribute("href", `https://github.com/rillswap/rillswap/commit/${commit}`);
  await expect(revision).toHaveAttribute("target", "_blank");
  await expect(revision).toHaveAttribute("rel", "noopener noreferrer");
});

test("missing or malformed build metadata leaves the swap usable without a commit link", async ({ page }) => {
  for (const metadata of ["", '<meta name="rillswap-build-commit" content="not-a-commit">']) {
    await page.route(SWAP, async (route) => {
      const response = await route.fetch();
      const html = (await response.text()).replace(/<meta name="rillswap-build-commit"[^>]*>/g, "");
      await route.fulfill({ response, body: html.replace("</head>", `${metadata}</head>`) });
    });
    await page.goto(SWAP);
    await directorySettled(page);
    await expect(page.locator("#swap-build-commit")).toHaveCount(0);
    await expect(page.locator("#swap-start")).toBeEnabled();
    await page.unroute(SWAP);
  }
});

test("the minimal swap card fits a mobile viewport", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto(SWAP);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  await expect(page.locator("#swap-invoice")).toBeVisible();
  await expect(page.locator("#swap-progress")).toBeHidden();
  await expect(page.locator("#swap-start")).toBeInViewport();
});

test("automatic discovery uses every configured relay and restores inputs when no provider is found", async ({ page }) => {
  const sockets: string[] = [];
  await page.routeWebSocket(/ws:\/\/127\.0\.0\.1:777[78]\//, (socket) => {
    sockets.push(socket.url());
    socket.onMessage((message) => {
      const frame = JSON.parse(String(message));
      if (frame[0] === "REQ") socket.send(JSON.stringify(["EOSE", frame[1]]));
    });
  });
  await page.goto(SWAP);
  await openSettings(page, "connection");
  await page.locator("#swap-network").selectOption("regtest");
  await page.locator("#swap-relay").fill("ws://127.0.0.1:7777\nws://127.0.0.1:7778");
  await page.locator("#swap-settings-close").click();
  await directorySettled(page);
  sockets.length = 0; // the regtest provider directory loaded on network change
  const now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("browser_discovery", "1000000", now, now + 7200));
  await openSettings(page, "advanced");
  await page.locator("#swap-refund").fill(scriptAddress("0014" + "11".repeat(20), "regtest"));
  await page.locator("#swap-tip").fill("1000");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-status")).toContainText("No provider announced this swap direction");
  await expect(page.locator("#swap-start")).toBeEnabled();
  expect(sockets.sort()).toEqual(["ws://127.0.0.1:7777/", "ws://127.0.0.1:7778/"]);
});

test("canceling discovery closes its relay and a new search cannot show stale results", async ({ page }) => {
  let requests = 0, closed = 0, armed = false;
  await page.routeWebSocket("ws://127.0.0.1:7777/", (socket) => {
    socket.onClose(() => { if (armed) closed++; });
    socket.onMessage((message) => {
      const frame = JSON.parse(String(message));
      if (frame[0] === "REQ") {
        if (!armed) { socket.send(JSON.stringify(["EOSE", frame[1]])); return; } // page-load provider directory
        requests++;
        if (requests > 1) socket.send(JSON.stringify(["EOSE", frame[1]]));
      }
    });
  });
  await page.goto(SWAP);
  await openSettings(page, "connection");
  await page.locator("#swap-network").selectOption("regtest");
  await page.locator("#swap-settings-close").click();
  await directorySettled(page);
  armed = true;
  const now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("browser_cancel", "1000000", now, now + 7200));
  await openSettings(page, "advanced");
  await page.locator("#swap-refund").fill(scriptAddress("0014" + "11".repeat(20), "regtest"));
  await page.locator("#swap-tip").fill("1000");
  await page.locator("#swap-start").click();
  await expect.poll(() => requests).toBe(1);
  await page.locator("#swap-edit").click();
  await expect.poll(() => closed).toBe(1);
  await expect(page.locator("#swap-status")).toContainText("Ready for a new quote");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-status")).toContainText("No provider announced this swap direction");
  await expect(page.locator("#swap-start")).toBeEnabled();
  expect(requests).toBe(2);
});

test("the preview page links to the swap page", async ({ page }) => {
  await page.goto("http://127.0.0.1:18765/");
  await page.getByRole("link", { name: "Open swap app", exact: true }).click();
  await expect(page).toHaveURL(SWAP);
});

test("the swap page installs no service worker, so no release replaces it mid-swap", async ({ page }) => {
  await page.goto(SWAP);
  await expect(page.locator("#swap-start")).toBeVisible();
  const registrations = await page.evaluate(async () =>
    "serviceWorker" in navigator ? (await navigator.serviceWorker.getRegistrations()).length : 0);
  expect(registrations).toBe(0);
  const scripts = await page.locator("script").evaluateAll((nodes) =>
    nodes.map((node) => (node as HTMLScriptElement).src));
  for (const src of scripts) expect(new URL(src).host).toBe("127.0.0.1:18765");
});

/** A signed regtest provider announcement (both Bitcoin directions) that expires `expiresIn` seconds from now. */
async function regtestAnnouncement(expiresIn: number): Promise<{ event: unknown; identity: string }> {
  const { schnorr } = await import("@noble/curves/secp256k1.js");
  const { sha256 } = await import("@noble/hashes/sha2.js");
  const { default: canonicalize } = await import("canonicalize");
  const { finalizeEvent, getPublicKey } = await import("nostr-tools");
  const { default: application } = await import("../unit/fixtures/manual-advertisement-regtest-v1.json", { with: { type: "json" } });
  const { default: vector } = await import("../unit/fixtures/nostr-announcement-regtest-v1.json", { with: { type: "json" } });
  const secret = new Uint8Array(32); secret[31] = 2;
  const wrapper = structuredClone(application);
  wrapper.advertisement.provider_identity_xonly_key = getPublicKey(secret);
  wrapper.advertisement.expires_at = Math.floor(Date.now() / 1000) + expiresIn;
  wrapper.advertisement.created_at = Math.floor(Date.now() / 1000) - 60;
  const tag = sha256(new TextEncoder().encode("RillSwap/advertisement/v1"));
  const content = new TextEncoder().encode(canonicalize(wrapper.advertisement)!);
  const digest = new Uint8Array(64 + content.length); digest.set(tag); digest.set(tag, 32); digest.set(content, 64);
  wrapper.signature = Buffer.from(schnorr.sign(sha256(digest), secret)).toString("hex");
  const event = finalizeEvent({ kind: vector.kind, created_at: wrapper.advertisement.created_at, tags: structuredClone(vector.tags), content: canonicalize(wrapper)! }, secret);
  return { event, identity: wrapper.advertisement.provider_identity_xonly_key };
}

test("the provider directory loads by itself, groups providers by swap type and chooses the pinned provider", async ({ page }) => {
  const { event, identity } = await regtestAnnouncement(3600);
  let requests = 0;
  await page.routeWebSocket("ws://127.0.0.1:7777/", (socket) => {
    socket.onMessage((message) => {
      const frame = JSON.parse(String(message));
      if (frame[0] === "REQ") { requests++; socket.send(JSON.stringify(["EVENT", frame[1], event])); socket.send(JSON.stringify(["EOSE", frame[1]])); }
    });
  });
  await page.goto(SWAP);
  await openSettings(page, "connection");
  await page.locator("#swap-network").selectOption("regtest");
  await page.locator("#swap-settings-close").click();
  await expect(page.locator("#swap-provider-choice")).toHaveText("Provider: automatic, fewest confirmations, then lowest price");
  // Switching to regtest loads its directory without opening the dialog.
  await expect(page.locator("#swap-providers-status")).toHaveText("1 provider on regtest.");
  expect(requests).toBe(1);
  await page.locator("#swap-providers-toggle").click();
  await expect(page.locator("#swap-providers")).toBeVisible();
  // One table per swap type the provider serves.
  await expect(page.locator(".swap-provider-group")).toHaveCount(2);
  await expect(page.locator(".swap-provider-group h3")).toHaveText(["Bitcoin → Lightning", "Lightning → Bitcoin"]);
  const group = page.locator('.swap-provider-group[data-profile="ln-to-btc/v1"]');
  await expect(group.locator("th")).toHaveText(["Provider", "Limits (sat)", "Fee", "On 100,000 sat", "Confirmations", "Listed until", ""]);
  const entry = group.locator("tbody tr");
  await expect(entry).toHaveCount(1);
  await expect(entry.locator("td").nth(0)).toHaveText(`${identity.slice(0, 12)}…`);
  await expect(entry.locator("td").nth(0)).toHaveAttribute("title", new RegExp(`^${identity}`));
  await expect(entry.locator("td").nth(1)).toHaveText("1,000 – 100,000");
  await expect(entry.locator("td").nth(2)).toHaveText("50 sat + 0.10%");
  await expect(entry.locator("td").nth(3)).toHaveText("150 sat");
  await expect(entry.locator("td").nth(4)).toHaveText("unknown"); // this announcement predates the depth extension
  await expect(page.locator("#swap-provider-automatic button")).toHaveText("Selected");
  await entry.getByRole("button", { name: "Choose" }).click();
  // The choice applies to every table the provider appears in.
  await expect(page.locator(".swap-provider.selected")).toHaveCount(2);
  await expect(page.locator("#swap-provider-automatic button")).toHaveText("Use automatic");
  await page.locator("#swap-providers-load").click();
  await expect.poll(() => requests).toBe(2);
  await page.locator("#swap-providers-close").click();
  await expect(page.locator("#swap-provider-choice")).toHaveText(`Provider: ${identity.slice(0, 12)}… (chosen by you)`);
  await openSettings(page, "advanced");
  await expect(page.locator("#swap-provider")).toHaveValue(identity);
  await page.locator("#swap-provider").fill("");
  await expect(page.locator("#swap-ranking")).toHaveValue("time"); // fewest confirmations first by default
  await page.locator("#swap-ranking").selectOption("price");
  await page.locator("#swap-settings-close").click();
  await expect(page.locator("#swap-provider-choice")).toHaveText("Provider: automatic, lowest price, then fewest confirmations");
  await page.locator("#swap-providers-toggle").click();
  await expect(page.locator("#swap-provider-automatic p")).toContainText("(lowest price, then fewest confirmations)");
});


test("the provider directory reloads itself while idle and drops offers once they expire", async ({ page }) => {
  await page.clock.install();
  const { event } = await regtestAnnouncement(150);
  let requests = 0;
  await page.routeWebSocket("ws://127.0.0.1:7777/", (socket) => {
    socket.onMessage((message) => {
      const frame = JSON.parse(String(message));
      if (frame[0] === "REQ") { requests++; socket.send(JSON.stringify(["EVENT", frame[1], event])); socket.send(JSON.stringify(["EOSE", frame[1]])); }
    });
  });
  await page.goto(SWAP);
  await openSettings(page, "connection");
  await page.locator("#swap-network").selectOption("regtest");
  await page.locator("#swap-settings-close").click();
  const status = page.locator("#swap-providers-status");
  await expect(status).toHaveText("1 provider on regtest.");
  await expect(page.locator(".swap-provider")).toHaveCount(2);
  // The offer expires before the next reload is due: it leaves the list without contacting any relay.
  await page.clock.fastForward("03:00");
  await expect(status).toHaveText("No providers found on your relays.");
  await expect(page.locator(".swap-provider")).toHaveCount(0);
  expect(requests).toBe(1);
  // Five minutes after the last load, the directory asks the relays again.
  await page.clock.fastForward("02:30");
  await expect.poll(() => requests).toBe(2);
});

test("discovery uses only portable relay filters, so relays that refuse multi-letter tag filters still find providers", async ({ page }) => {
  const { schnorr } = await import("@noble/curves/secp256k1.js");
  const { sha256 } = await import("@noble/hashes/sha2.js");
  const { default: canonicalize } = await import("canonicalize");
  const { finalizeEvent } = await import("nostr-tools");
  const { default: application } = await import("../unit/fixtures/manual-advertisement-regtest-v1.json", { with: { type: "json" } });
  const { default: vector } = await import("../unit/fixtures/nostr-announcement-regtest-v1.json", { with: { type: "json" } });
  const secret = new Uint8Array(32); secret[31] = 3;
  const wrapper = structuredClone(application);
  wrapper.advertisement.provider_identity_xonly_key = Buffer.from(schnorr.getPublicKey(secret)).toString("hex");
  wrapper.advertisement.created_at = Math.floor(Date.now() / 1000) - 60;
  wrapper.advertisement.expires_at = wrapper.advertisement.created_at + 3660;
  const tag = sha256(new TextEncoder().encode("RillSwap/advertisement/v1"));
  const content = new TextEncoder().encode(canonicalize(wrapper.advertisement)!);
  const digest = new Uint8Array(64 + content.length); digest.set(tag); digest.set(tag, 32); digest.set(content, 64);
  wrapper.signature = Buffer.from(schnorr.sign(sha256(digest), secret)).toString("hex");
  const event = finalizeEvent({ kind: vector.kind, created_at: wrapper.advertisement.created_at, tags: structuredClone(vector.tags), content: canonicalize(wrapper)! }, secret);
  const filters: Record<string, unknown>[] = [];
  await page.routeWebSocket("ws://127.0.0.1:7777/", (socket) => {
    socket.onMessage((message) => {
      const frame = JSON.parse(String(message));
      if (frame[0] !== "REQ") return;
      filters.push(frame[2]);
      // NIP-01 only standardizes single-letter tag filters; strict relays close the rest.
      const unindexed = Object.keys(frame[2]).find((key) => /^#.{2,}$/.test(key));
      if (unindexed) { socket.send(JSON.stringify(["CLOSED", frame[1], `error: unindexed tag filter ${unindexed}`])); return; }
      socket.send(JSON.stringify(["EVENT", frame[1], event]));
      socket.send(JSON.stringify(["EOSE", frame[1]]));
    });
  });
  await page.goto(SWAP);
  await openSettings(page, "connection");
  await page.locator("#swap-network").selectOption("regtest");
  await page.locator("#swap-settings-close").click();
  await expect(page.locator("#swap-providers-status")).toHaveText("1 provider on regtest.");
  expect(filters.length).toBeGreaterThan(0);
  for (const filter of filters) expect(Object.keys(filter).filter((key) => key.startsWith("#"))).toEqual([]);
});
