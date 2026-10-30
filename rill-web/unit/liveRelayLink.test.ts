import { expect, test } from "bun:test";
import type { NostrEvent } from "nostr-tools";
import { LiveRelayLink } from "../src/swap/liveRelayLink";
import type { PublicationOptions } from "../src/swap/session";

class Socket {
  readonly guardedPublication = true;
  isClosed = false;
  filters: Record<string, unknown>[] = [];
  sent: NostrEvent[] = [];
  queue: string[] = [];
  wake: (() => void) | undefined;
  async subscribe(filter: Record<string, unknown>) { this.filters.push(structuredClone(filter)); }
  async query() { return { events: [], truncated: false }; }
  async publish(event: NostrEvent, options: PublicationOptions = {}) {
    options.signal?.throwIfAborted(); options.beforePublish?.(); this.sent.push(event); return !this.isClosed;
  }
  async next(_deadline: number, signal?: AbortSignal): Promise<string | null> {
    if (this.queue.length) return this.queue.shift()!;
    if (this.isClosed || signal?.aborted) return null;
    await new Promise<void>((resolve) => { this.wake = resolve; signal?.addEventListener("abort", () => resolve(), { once: true }); });
    return this.queue.shift() ?? null;
  }
  deliver(raw: string) { this.queue.push(raw); this.wake?.(); }
  close() { this.isClosed = true; this.wake?.(); }
}
const eventually = async (check: () => boolean) => {
  for (let i = 0; i < 100 && !check(); i++) await Bun.sleep(2);
  expect(check()).toBe(true);
};

test("a long-lived mailbox reconnects with its original history floor and queued messages", async () => {
  const first = new Socket(), reopened = new Socket(); let opens = 0;
  const link = new LiveRelayLink("wss://one/", first, [], async () => { opens++; return reopened; }, 1);
  const filter = { kinds: [1059], "#p": ["session mailbox"], since: 1_700_000_000 - 172800 };
  try {
    await link.subscribe(filter); await eventually(() => first.filters.length === 1);
    first.deliver("before disconnect"); await eventually(() => first.queue.length === 0);
    first.close(); await eventually(() => opens === 1 && reopened.filters.length === 1);
    expect(reopened.filters).toEqual([filter]);
    reopened.deliver("after reconnect");
    expect(await link.next(Date.now() + 100)).toBe("before disconnect");
    expect(await link.next(Date.now() + 100)).toBe("after reconnect");
  } finally { link.close(); }
});

test("another permitted relay survives primary loss without replacing application messages", async () => {
  const first = new Socket(), alternate = new Socket(), opened: string[] = [];
  const link = new LiveRelayLink("wss://one/", first, ["wss://two/"], async (url) => { opened.push(url); return alternate; }, 10);
  try {
    await link.subscribe({ kinds: [1059], "#p": ["mailbox"], since: 123 });
    await eventually(() => alternate.filters.length === 1);
    first.close();
    const event = { id: "same wrapper" } as NostrEvent;
    expect(await link.publish(event)).toBe(true);
    expect(alternate.sent).toEqual([event]); expect(opened).toEqual(["wss://two/"]);
  } finally { link.close(); }
});

test("a guard that expires during reconnection prevents the actual write", async () => {
  const first = new Socket(), reopened = new Socket(); first.close(); let allowed = true;
  const link = new LiveRelayLink("wss://one/", first, [], async () => { allowed = false; return reopened; }, 1);
  try {
    await link.subscribe({ kinds: [1059] });
    await expect(link.publish({ id: "never disclose" } as NostrEvent, {
      beforePublish: () => { if (!allowed) throw new Error("expired"); },
    })).rejects.toThrow("expired");
    expect(reopened.sent).toEqual([]);
  } finally { link.close(); }
});

test("closing a live link cancels an outstanding reconnect and its receive waiter", async () => {
  const first = new Socket(); first.close(); let openedSignal: AbortSignal | undefined;
  const link = new LiveRelayLink("wss://one/", first, [], async (_url, signal) => {
    openedSignal = signal;
    return await new Promise<Socket>((_resolve, reject) => signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true }));
  }, 1);
  await link.subscribe({ kinds: [1059] });
  await eventually(() => openedSignal !== undefined);
  const reading = link.next(Date.now() + 10_000); link.close();
  expect(await reading).toBeNull(); expect(openedSignal!.aborted).toBe(true);
});

test("a reply canceling its pending relay acknowledgments does not disconnect healthy paths", async () => {
  class SlowAck extends Socket {
    override async publish(_event: NostrEvent, options: PublicationOptions = {}) {
      return await new Promise<boolean>((resolve) => options.signal!.addEventListener("abort", () => resolve(false), { once: true }));
    }
  }
  const first = new SlowAck(), second = new SlowAck(), controller = new AbortController();
  const link = new LiveRelayLink("wss://one/", first, ["wss://two/"], async () => second, 1);
  try {
    await link.subscribe({ kinds: [1059] }); await eventually(() => second.filters.length === 1);
    const pending = link.publish({ id: "reply already arrived" } as NostrEvent, { signal: controller.signal });
    controller.abort(); expect(await pending).toBe(false);
    expect(first.isClosed).toBe(false); expect(second.isClosed).toBe(false);
  } finally { link.close(); }
});

test("waiting for an unavailable relay does not mark a preimage as published", async () => {
  const { Session } = await import("../src/swap/session");
  const network = (await import("../src/networks/signet.json")).default;
  const first = new Socket(); first.close(); let disclosures = 0;
  const link = new LiveRelayLink("wss://one/", first, [], async (_url, signal) =>
    await new Promise<Socket>((_resolve, reject) => signal.addEventListener("abort", () => reject(new Error("closed")), { once: true })), 1);
  try {
    const client = new Session(link, network, "ln-to-btc/v1"), peer = new Session(link, network, "ln-to-btc/v1");
    await client.listen();
    await expect(client.send(client.envelope("action_request", {}), peer.key, () => { disclosures++; }, { timeoutMs: 2 })).rejects.toThrow("relay did not accept");
    expect(disclosures).toBe(0);
  } finally { link.close(); }
});
