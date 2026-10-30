import { expect, test } from "bun:test";
import type { NostrEvent } from "nostr-tools";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json";
import { Session, type Envelope, type RelayLink } from "../src/swap/session";

test("cross-relay reordering waits for gaps and deduplicates authenticated logical messages", async () => {
  const events: string[] = [], relay: RelayLink = {
    async publish(event: NostrEvent) { events.push(JSON.stringify(event)); return true; },
    async subscribe() {}, async next() { return events.shift() ?? null; },
  };
  const client = new Session(relay, regtest, "btc-to-ln/v1"), provider = new Session(relay, regtest, "btc-to-ln/v1");
  provider.sessionId = client.sessionId; client.providerKey = provider.key;
  const first = provider.envelope("ack", { acknowledged_message_id: "00".repeat(32) });
  const second = provider.envelope("ack", { acknowledged_message_id: "11".repeat(32) });
  await provider.send(second, client.key); const replay = events[0]!;
  expect(client.admit(events.shift()!)).toBeNull();
  await provider.send(first, client.key);
  expect(client.admit(events.shift()!)).toEqual(first);
  expect(await client.receive(() => true)).toEqual(second);
  expect(client.admit(replay)).toBeNull();
  const conflict = { ...second, message_id: "ff".repeat(32) } as Envelope;
  // Re-envelope to obtain a genuine provider signature at the conflicting sequence.
  const unsigned = provider.envelope("ack", conflict.payload);
  const { schnorr } = await import("@noble/curves/secp256k1.js");
  const { bytesToHex } = await import("@noble/hashes/utils.js");
  const { unsignedEnvelopeHash } = await import("../src/swap/hashes");
  const changed = { ...unsigned, sequence: second.sequence };
  const signed = { ...changed, signature: bytesToHex(schnorr.sign(unsignedEnvelopeHash(changed), provider.secret)) };
  await provider.send(signed, client.key);
  expect(() => client.admit(events.shift()!)).toThrow("conflicting provider sequence or message ID");
});
