import { mock } from "bun:test";
const alternatives: string[][] = [];
class FakeRelay {
  static async open() { return new FakeRelay(); }
  resilient(_url: string, urls: string[]) { alternatives.push(urls); return this; }
  close() {}
}
mock.module("../../src/swap/relay", () => ({ RelayConnection: FakeRelay }));
mock.module("../../src/swap/swap", () => ({ prepareSwap: async () => ({ dispose() {} }) }));
const { quoteProviders } = await import("../../src/swap/marketplace");
const result = await quoteProviders([{
  announcement: { identityXOnlyKey: "provider", advertisedEndpoints: ["wss://allowed", "not a URL", "wss://not-permitted/"] },
  relayUrls: ["wss://primary/"], permittedRelayUrls: ["wss://primary/", "wss://allowed/"], rawAnnouncement: "fixture",
}] as never, {} as never);
for (const quote of result.quotes) quote.dispose();
console.log(JSON.stringify({ count: result.quotes.length, alternatives }));
