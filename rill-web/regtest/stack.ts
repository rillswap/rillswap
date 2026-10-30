/** Host-side helpers for real, explicitly disposable Compose acceptance tests. */
import { execFile, execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { promisify } from "node:util";

export const root = resolve(import.meta.dirname, "../..");
export const composeEnabled = process.env.RILLSWAP_RUN_COMPOSE_E2E === "1";

export function assertDisposableStack(env: Record<string, string | undefined> = process.env): string {
  const project = env.COMPOSE_PROJECT_NAME;
  if (!project || !/^rill-reverse-browser-[a-z0-9-]+$/.test(project)) {
    throw new Error("Use an isolated rill-reverse-browser-* Compose project, never the default dev stack");
  }
  const port = env.RILL_DEV_WEB_PORT;
  if (!port || !/^[1-9]\d{3,4}$/.test(port) || Number(port) < 1024 || Number(port) > 65535 || port === "5273") {
    throw new Error("Set an explicit nondefault RILL_DEV_WEB_PORT for disposable acceptance tests");
  }
  return project;
}

export function assertRelayFaultStack(env: Record<string, string | undefined> = process.env): void {
  if (!/^rill-reverse-browser-(relays|ci)-[a-z0-9-]+$/.test(assertDisposableStack(env))) {
    throw new Error("Relay faults require a dedicated relays or CI project, never an existing UI stack");
  }
}

export const webURL = () => `http://127.0.0.1:${process.env.RILL_DEV_WEB_PORT}/swap.html`;
export const shopURL = () => `http://127.0.0.1:${process.env.RILL_DEV_SHOP_PORT ?? "8090"}`;

export function command(...args: string[]): string {
  assertDisposableStack();
  return execFileSync(resolve(root, "dev/devctl"), args, {
    cwd: root, env: process.env, encoding: "utf8", timeout: 30000,
  }).trim();
}

export async function run(...args: string[]): Promise<string> {
  assertDisposableStack();
  const result = await promisify(execFile)(resolve(root, "dev/devctl"), args, {
    cwd: root, env: process.env, encoding: "utf8", timeout: 240000, maxBuffer: 4 * 1024 * 1024,
  });
  return result.stdout.trim();
}

export function compose(...args: string[]): string {
  const project = assertDisposableStack();
  const files = process.env.COMPOSE_FILE ? [] : ["-f", resolve(root, "dev/compose.yaml")];
  return execFileSync("docker", ["compose", "-p", project, ...files, ...args], {
    cwd: root, env: process.env, encoding: "utf8", timeout: 60000,
  }).trim();
}

export function providerState(direction: "btc-to-ln" | "ln-to-btc", paymentHash: string): string {
  return compose("exec", "-T", "tools", "python", "-c",
    "import sqlite3,sys,json; c=sqlite3.connect('file:/state/makers/'+sys.argv[1]+'/provider-store/live.sqlite?mode=ro',uri=True); "
    + "rows=c.execute('select state,terms_offer from swaps').fetchall(); "
    + "print(next((state for state,offer in rows if json.loads(offer)['payload']['terms']['contract_terms']['invoice_binding']['payment_hash']==sys.argv[2]),''))",
    direction, paymentHash);
}
