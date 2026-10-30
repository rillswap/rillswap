import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import canonicalize from "canonicalize";
import { finalizeEvent, getPublicKey } from "nostr-tools";
import type { NostrEvent } from "nostr-tools";

import { discoverProvider } from "../src/swap/discovery";
import { checkRelayUrl, RelayConnection, RelayError } from "../src/swap/relay";
import { SwapError } from "../src/swap/session";
import application from "./fixtures/manual-advertisement-regtest-v1.json";
import vector from "./fixtures/nostr-announcement-regtest-v1.json";

const IDENTITY = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const NETWORK = application.advertisement.network_identities[0];
const ANNOUNCEMENT = JSON.stringify({
  id: vector.id, pubkey: vector.pubkey, created_at: vector.created_at, kind: vector.kind,
  tags: vector.tags, content: canonicalize(application), sig: vector.sig,
});
const originalNow = Date.now;
afterEach(() => { Date.now = originalNow; });

class FakeSocket extends EventTarget {
  readonly sent: unknown[][] = [];
  send(text: string): void {
    this.sent.push(JSON.parse(text) as unknown[]);
  }
  close(): void {
    this.dispatchEvent(new Event("close"));
  }
  deliver(frame: unknown): void {
    this.dispatchEvent(new MessageEvent("message", { data: JSON.stringify(frame) }));
  }
}

async function connect(): Promise<{ relay: RelayConnection; socket: FakeSocket }> {
  const socket = new FakeSocket();
  const opening = RelayConnection.open("ws://127.0.0.1:7000", 1000, () => socket as unknown as WebSocket);
  socket.dispatchEvent(new Event("open"));
  return { relay: await opening, socket };
}

test("relay URLs must be wss unless loopback or a v3 onion", () => {
  expect(checkRelayUrl("wss://relay.example.org")).toBe("wss://relay.example.org/");
  expect(checkRelayUrl("ws://127.0.0.1:7000")).toBe("ws://127.0.0.1:7000/");
  const onion = "ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion";
  expect(checkRelayUrl(onion)).toBe(`${onion}/`);
  for (const bad of ["ws://relay.example.org", "ws://short.onion", "ws://relay.example.org.onion", "https://relay.example.org", "nonsense"]) {
    expect(() => checkRelayUrl(bad)).toThrow(RelayError);
  }
});

describe("relay connection", () => {
  test("a socket already closing cannot mark a proposal as disclosed", async () => {
    const { relay, socket } = await connect(); let disclosures = 0;
    Object.assign(socket, { readyState: 2 });
    expect(await relay.publish({ id: "private" } as NostrEvent, { beforePublish: () => { disclosures++; } })).toBe(false);
    expect(disclosures).toBe(0); expect(socket.sent).toEqual([]); relay.close();
  });
  test("canceling opening or connected relays closes their sockets", async () => {
    const cancellation = new AbortController();
    const socket = new FakeSocket();
    const opening = RelayConnection.open("ws://localhost:7000", 1000, () => socket as unknown as WebSocket, cancellation.signal);
    cancellation.abort();
    await expect(opening).rejects.toThrow("canceled");
    const activeCancellation = new AbortController();
    const activeSocket = new FakeSocket();
    const activeOpening = RelayConnection.open("ws://localhost:7000", 1000, () => activeSocket as unknown as WebSocket, activeCancellation.signal);
    activeSocket.dispatchEvent(new Event("open"));
    const relay = await activeOpening;
    const waiting = relay.next(Date.now() + 1000);
    activeCancellation.abort();
    expect(await waiting).toBeNull();
  });
  test("publish resolves on the relay's OK for that event", async () => {
    const { relay, socket } = await connect();
    const accepted = relay.publish({ id: "aa" } as NostrEvent);
    const refused = relay.publish({ id: "bb" } as NostrEvent);
    socket.deliver(["OK", "bb", false, "blocked"]);
    socket.deliver(["OK", "aa", true, ""]);
    expect(await accepted).toBe(true);
    expect(await refused).toBe(false);
  });

  test("an AUTH challenge never triggers stable-key authentication", async () => {
    const { relay, socket } = await connect();
    await relay.subscribe({ kinds: [1059] });
    socket.deliver(["AUTH", "relay-challenge"]);
    const published = relay.publish({ id: "aa" } as NostrEvent);
    socket.deliver(["OK", "aa", false, "auth-required"]);
    expect(await published).toBe(false);
    expect(socket.sent.map((frame) => frame[0])).toEqual(["REQ", "EVENT"]);
    relay.close();
  });

  test("live events are queued only for the current subscription", async () => {
    const { relay, socket } = await connect();
    await relay.subscribe({ kinds: [1059] });
    const [, live] = socket.sent.at(-1) as [string, string];
    socket.deliver(["EVENT", "other", { id: "x" }]);
    socket.deliver(["EVENT", live, { id: "y" }]);
    expect(await relay.next(Date.now() + 50)).toBe(JSON.stringify({ id: "y" }));
    expect(await relay.next(Date.now() + 20)).toBeNull();
    const waiting = relay.next(Date.now() + 1000);
    socket.deliver(["EVENT", live, { id: "z" }]);
    expect(await waiting).toBe(JSON.stringify({ id: "z" }));
  });

  test("a query collects stored events until EOSE and reports a flood", async () => {
    const { relay, socket } = await connect();
    const small = relay.query({ kinds: [39417] }, 2);
    const [, id] = socket.sent.at(-1) as [string, string];
    socket.deliver(["EVENT", id, { id: 1 }]);
    socket.deliver(["EOSE", id]);
    expect(await small).toEqual({ events: [JSON.stringify({ id: 1 })], truncated: false });
    const flood = relay.query({ kinds: [39417] }, 1);
    const [, second] = socket.sent.at(-1) as [string, string];
    socket.deliver(["EVENT", second, { id: 1 }]);
    socket.deliver(["EVENT", second, { id: 2 }]);
    expect((await flood).truncated).toBe(true);
  });
  test("detailed queries distinguish EOSE, timeout, closure, and send failure", async () => {
    const { relay, socket } = await connect();
    const complete = relay.queryDetailed({}, 2);
    const [, id] = socket.sent.at(-1) as [string, string];
    socket.deliver(["EOSE", id]);
    expect((await complete).completion).toBe("eose");
    expect((await relay.queryDetailed({}, 2, 1)).completion).toBe("timeout");
    const closed = relay.queryDetailed({}, 2);
    socket.close();
    expect((await closed).completion).toBe("closed");
    expect((await relay.queryDetailed({}, 2)).completion).toBe("error");
  });
  test("detailed query overflow is explicit and its retained prefix cannot look complete", async () => {
    const { relay, socket } = await connect();
    const query = relay.queryDetailed({}, 1);
    const [, id] = socket.sent.at(-1) as [string, string];
    socket.deliver(["EVENT", id, { id: 1 }]);
    socket.deliver(["EVENT", id, { id: 2 }]);
    const result = await query;
    expect(result.completion).toBe("limit");
    expect(result.truncated).toBe(true);
    relay.close();
  });
});

describe("provider discovery", () => {
  const at = (events: string[], truncated = false) => ({ query: async () => ({ events, truncated }) });

  test("the signed announcement is selected and garbage ignored", async () => {
    spyOn(Date, "now").mockReturnValue(1703021600 * 1000);
    const found = await discoverProvider(at(["{}", ANNOUNCEMENT, ANNOUNCEMENT]), IDENTITY, NETWORK, "btc-to-ln/v1");
    expect(found.identityXOnlyKey).toBe(IDENTITY);
  });

  test("floods, absence, and another identity are refused", async () => {
    spyOn(Date, "now").mockReturnValue(1703021600 * 1000);
    await expect(discoverProvider(at([ANNOUNCEMENT], true), IDENTITY, NETWORK, "btc-to-ln/v1")).rejects
      .toThrow(SwapError);
    await expect(discoverProvider(at([]), IDENTITY, NETWORK, "btc-to-ln/v1")).rejects.toThrow(SwapError);
    const other = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    await expect(discoverProvider(at([ANNOUNCEMENT]), other, NETWORK, "btc-to-ln/v1")).rejects.toThrow(SwapError);
  });

  test("two independent identities on different relays need no shared registry", async () => {
    spyOn(Date, "now").mockReturnValue(1703021600 * 1000);
    const secondSecret = Uint8Array.from({ length: 32 }, (_, index) => index === 31 ? 7 : 0);
    const secondIdentity = getPublicKey(secondSecret);
    const secondApplication = structuredClone(application);
    secondApplication.advertisement.provider_identity_xonly_key = secondIdentity;
    const tag = sha256(new TextEncoder().encode("RillSwap/advertisement/v1"));
    const signedBytes = new TextEncoder().encode(canonicalize(secondApplication.advertisement)!);
    const digest = sha256(new Uint8Array([...tag, ...tag, ...signedBytes]));
    secondApplication.signature = Buffer.from(schnorr.sign(digest, secondSecret)).toString("hex");
    const secondEvent = finalizeEvent({
      kind: 39417,
      created_at: vector.created_at,
      tags: vector.tags,
      content: canonicalize(secondApplication)!,
    }, secondSecret);
    const sources = [at([ANNOUNCEMENT]), at([JSON.stringify(secondEvent)])];
    const identities = [IDENTITY, secondIdentity];
    for (const [index, source] of sources.entries()) {
      const found = await discoverProvider(source, identities[index]!, NETWORK, "btc-to-ln/v1");
      expect(found.identityXOnlyKey).toBe(identities[index]!);
      await expect(discoverProvider(source, identities[1 - index]!, NETWORK, "btc-to-ln/v1"))
        .rejects.toThrow(SwapError);
    }
  });
});
