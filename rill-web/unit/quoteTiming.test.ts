import { expect, test } from "bun:test";
import { blockWaitQuantile, directoryTiming, quoteTiming, readTimingMarket, type TimingMarket } from "../src/swap/quoteTiming";
import type { ChainFetch } from "../src/swap/chainTip";

const now = 1_793_355_200_000;
const market: TimingMarket = { observedAt: now, blockMinutes: 10, nextBlockRate: 10,
  projectedBlocks: [10, 3, 1].map((minimumRate) => ({ minimumRate, vbytes: 999_000 })) };
const forward = { profile: "btc-to-ln/v1" as const, fundingConfirmations: 1 };
const reverse = { profile: "ln-to-btc/v1" as const, fundingConfirmations: 1, fundingRate: 3, claimFeeSat: 143n, destinationScriptBytes: 22 };

test("block-clock quantiles match exponential and Erlang reference values", () => {
  expect(blockWaitQuantile(1, 0.1, 10)).toBeCloseTo(1.053605, 5);
  expect(blockWaitQuantile(1, 0.9, 10)).toBeCloseTo(23.025851, 5);
  expect(blockWaitQuantile(2, 0.1, 10)).toBeCloseTo(5.318116, 5);
  expect(blockWaitQuantile(2, 0.9, 10)).toBeCloseTo(38.897202, 5);
  expect(blockWaitQuantile(1008, 0.9, 10)).toBeGreaterThan(10_080);
  for (const blocks of [-1, 0, 1.5, 1009]) expect(() => blockWaitQuantile(blocks, 0.9, 10)).toThrow();
});

test("forward waits for the wallet deposit and required depth, not the maker's later claim", () => {
  const one = quoteTiming(forward, market, now);
  expect(one.text).toBe("Estimated chain wait: 10 min");
  expect(one.tooltip).toBe("Modeled range: 1 to 24 min. Not a guarantee.");
  expect(one.detail).toContain("Assumes your wallet deposits");
  expect(one.detail).toContain("not a completion guarantee");
  expect(quoteTiming({ ...forward, fundingConfirmations: 2 }, market, now).text).toBe("Estimated chain wait: 20 min");
  expect(quoteTiming({ ...forward, fundingRate: 0.1, claimFeeSat: 1n }, market, now)).toEqual(one);
});

test("reverse waits sequentially for funding and first claim confirmation using their rates", () => {
  const estimate = quoteTiming(reverse, market, now);
  const expectedLow = Math.floor(blockWaitQuantile(5, 0.1, 10));
  const expectedHigh = Math.ceil(blockWaitQuantile(5, 0.9, 10));
  expect(estimate.text).toBe("Estimated chain wait: 50 min"); // k * mean interval, not the range's midpoint
  expect(estimate.tooltip).toBe(`Modeled range: ${expectedLow} to ${expectedHigh} min. Not a guarantee.`);
  expect(estimate.detail).toContain("quoted 3 sat/vB funding estimate, not a promised");
  expect(estimate.detail).toContain("143 sat (1.00 sat/vB");
  expect(estimate.detail).toContain("first claim confirmation");
  const faster = quoteTiming({ ...reverse, fundingRate: 10, claimFeeSat: 1430n }, market, now);
  expect(faster.text).toBe("Estimated chain wait: 20 min");
  expect(quoteTiming({ ...reverse, destinationScriptBytes: 34 }, market, now).text).toContain("unavailable");
});

test("unknown funding rates use an explicit assumption, never an advertised ceiling", () => {
  const { fundingRate: _rate, ...unquoted } = reverse;
  const estimate = quoteTiming(unquoted, market, now);
  expect(estimate.detail).toContain("Provider funding rate is not quoted; assumes");
  expect(estimate.detail).toContain("10 sat/vB");
});

test("a 0.1 sat/vB deposit model pays 16 sat for 154 vB, matching rounded projected fee bands", () => {
  const signet = { ...market, nextBlockRate: 1, projectedBlocks: [{ minimumRate: 16 / 154, vbytes: 20_000 }] };
  const estimate = quoteTiming({ ...reverse, fundingRate: 0.1 }, signet, now);
  expect(estimate.text).toBe("Estimated chain wait: 20 min");
  expect(estimate.detail).toContain("quoted 0.1 sat/vB");
  expect(estimate.detail).toContain("154 vB pricing model with whole-satoshi fee rounding");
});

test("zero depth does not invent sequential confirmation waits or change the risk choice", () => {
  expect(quoteTiming({ ...forward, fundingConfirmations: 0 }, null, now).text).toBe("Estimated chain wait: 0 min");
  expect(quoteTiming({ ...forward, fundingConfirmations: 0 }, null, now).tooltip).toContain("No confirmation wait");
  expect(quoteTiming({ ...reverse, fundingConfirmations: 0 }, market, now).detail).toContain("package needs a separate estimate");
  expect(quoteTiming({ ...reverse, fundingConfirmations: 2 }, market, now).text).not.toBe(quoteTiming(reverse, market, now).text);
});

test("missing, stale, below-horizon, and nonpositive fee evidence cannot produce a number", () => {
  for (const data of [null, { ...market, observedAt: now - 180_001 }, { ...market, observedAt: now + 1 }]) {
    expect(quoteTiming(forward, data, now).text).toContain("unavailable");
  }
  for (const fundingRate of [0, -1, NaN, Infinity, 0.1]) {
    expect(quoteTiming({ ...reverse, fundingRate }, market, now).text).toContain("unavailable");
  }
  expect(quoteTiming({ ...reverse, claimFeeSat: 0n }, market, now).text).toContain("unavailable");
  expect(quoteTiming({ ...forward, fundingConfirmations: 1009 }, market, now).text).toContain("unavailable");
});

const recent = () => Array.from({ length: 15 }, (_, i) => ({ height: 100 - i, timestamp: now / 1000 - i * 600 }));
const projected = [{ blockVSize: 999_000, feeRange: [10, 20] }, { blockVSize: 900_000, feeRange: [1, 3] }];
const read = (blocks: unknown = recent(), queue: unknown = projected, extra: { signal?: AbortSignal } = {}) => {
  const requests: { url: string; options: RequestInit | undefined }[] = [];
  const fetch = (async (url, options) => {
    requests.push({ url: String(url), options });
    return new Response(JSON.stringify(String(url).endsWith("/mempool-blocks") ? queue : String(url).endsWith("/blocks") ? blocks : { fastestFee: 2 }));
  }) as ChainFetch;
  return { requests, result: readTimingMarket("https://chain.example/signet/api", "signet", { fetch, now: () => now, ...extra }) };
};

test("quote-time reads use only the configured network API and public bounded GETs", async () => {
  const { result, requests } = read();
  expect(await result).toEqual({ observedAt: now, blockMinutes: 10, nextBlockRate: 2,
    projectedBlocks: [{ minimumRate: 10, vbytes: 999_000 }, { minimumRate: 1, vbytes: 900_000 }] });
  expect(requests).toHaveLength(3);
  for (const request of requests) {
    expect(request.url.startsWith("https://chain.example/signet/api/v1/")).toBe(true);
    expect(request.options).toMatchObject({ credentials: "omit", redirect: "error", referrerPolicy: "no-referrer", cache: "no-store" });
    expect(request.options?.body).toBeUndefined();
  }
});

test("recent cadence must be contiguous and fresh; malformed or unavailable data stays advisory", async () => {
  for (const blocks of [[], recent().slice(0, 5), recent().map((block, i) => i === 2 ? { ...block, height: 1 } : block),
    recent().map((block) => ({ ...block, timestamp: block.timestamp - 20_000 })),
    recent().map((block) => ({ ...block, timestamp: 0 })), recent().map((block) => ({ ...block, timestamp: now / 1000 }))]) {
    expect(await read(blocks).result).toBeNull();
  }
  for (const queue of [[], null, [{ blockVSize: -1, feeRange: [1] }], [{ blockVSize: 100, feeRange: [NaN] }]]) {
    expect(await read(recent(), queue).result).toBeNull();
  }
  expect(await readTimingMarket("https://chain.example/signet/api", "signet", {
    fetch: (async () => new Response("", { status: 503 })) as ChainFetch,
  })).toBeNull();
});

test("sparse signet projects a low-fee deposit into spare space instead of treating observed fees as a relay floor", async () => {
  const snapshot = await read(recent(), [{ blockVSize: 19_858.5, feeRange: [0.1942902458, 3917] }]).result;
  const estimate = quoteTiming({ ...reverse, fundingRate: 0.1 }, snapshot, now);
  expect(estimate.text).toBe("Estimated chain wait: 20 min");
  expect(estimate.tooltip).toBe("Modeled range: 5 to 39 min. Not a guarantee.");
  expect(estimate.detail).toContain("fits projected spare space if the broadcasting node relays it");
  expect(estimate.detail).toContain("not a completion guarantee");
  for (const fundingRate of [0, -1, NaN, Infinity]) {
    expect(quoteTiming({ ...reverse, fundingRate }, snapshot, now).text).toContain("unavailable");
  }
});

test("spare space can occur before the last projection; full forecasts and stacked tails do not invent a target", async () => {
  const sparse = await read(recent(), [{ blockVSize: 100, feeRange: [2, 10] }, { blockVSize: 999_000, feeRange: [1, 2] }]).result;
  expect(quoteTiming({ ...reverse, fundingRate: 1 }, sparse, now).text).toBe("Estimated chain wait: 20 min");
  const stacked = await read(recent(), [{ blockVSize: 999_000, feeRange: [2, 10] }, { blockVSize: 2_000_000, feeRange: [0.1, 1] }]).result;
  expect(quoteTiming({ ...reverse, fundingRate: 1 }, stacked, now).text).toContain("unavailable");
  expect(await read(recent(), [{ blockVSize: 2_000_000, feeRange: [1] }, { blockVSize: 100, feeRange: [1] }]).result).toBeNull();
});

test("capacity estimates leave 10 kvB slack and require space for the modeled transaction", () => {
  const boundary = (vbytes: number): TimingMarket => ({ ...market, projectedBlocks: [{ minimumRate: 2, vbytes }] });
  expect(quoteTiming({ ...reverse, fundingRate: 1, claimFeeSat: 286n }, boundary(990_000 - 154), now).detail).toContain("fits projected spare space");
  expect(quoteTiming({ ...reverse, fundingRate: 1, claimFeeSat: 286n }, boundary(990_000 - 153), now).text).toContain("unavailable");
});

test("the directory models both directions at recommended rates without inventing quoted claim fees or unknown depths", () => {
  expect(directoryTiming("btc-to-ln/v1", 1, market, now).text).toBe("Estimated chain wait: 10 min");
  const reverseDirectory = directoryTiming("ln-to-btc/v1", 1, market, now);
  expect(reverseDirectory.text).toBe("Estimated chain wait: 20 min");
  expect(reverseDirectory.detail).toContain("No claim quote yet; assumes");
  expect(reverseDirectory.detail).not.toContain("Claim: 155 sat");
  expect(directoryTiming("btc-to-ln/v1", null, market, now).detail).toContain("has not announced");
  expect(directoryTiming("btc-to-ln/v1", 0, null, now).text).toContain("0 min");
});

test("sub-minute expected values and rounded hover bounds remain consistent", () => {
  const estimate = quoteTiming(forward, { ...market, blockMinutes: 0.1 }, now);
  expect(estimate.text).toBe("Estimated chain wait: <1 min");
  expect(estimate.tooltip).toBe("Modeled range: 0 to 1 min. Not a guarantee.");
  expect(estimate.detail).toContain("0 to 1 min (10th to 90th percentile");
});

test("regtest has no block clock, and cancellation makes no requests", async () => {
  let requests = 0;
  expect(await readTimingMarket("http://127.0.0.1:8091/api", "regtest", { fetch: (async () => { requests++; throw new Error(); }) as ChainFetch })).toBeNull();
  expect(requests).toBe(0);
  const cancellation = new AbortController(); cancellation.abort();
  const canceled = read(recent(), projected, { signal: cancellation.signal });
  expect(await canceled.result).toBeNull();
  expect(canceled.requests).toEqual([]);
});
