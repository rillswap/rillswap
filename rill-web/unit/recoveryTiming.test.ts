import { describe, expect, test } from "bun:test";
import { expiryDatetime, recoveryDefaults, recoveryTiming, reverseQuoteRecoveryTiming } from "../src/recoveryTiming";

const NOW = Date.UTC(2026, 9, 30, 12);
const observation = { height: 1000, observedAt: NOW };

describe("advisory recovery boundaries", () => {
  test("Bitcoin refunds first mine at T+1; minutes and datetime use the sampled tip", () => {
    const text = recoveryTiming({ profile: "btc-to-ln/v1", network: "mainnet", refundLockHeight: 1287, observation }, NOW);
    expect(text).toContain("Your refund becomes eligible from Bitcoin block 1288");
    expect(text).toContain("288 blocks remaining");
    expect(text).toContain("2,880 min / 48 h");
    expect(text).toContain(expiryDatetime((NOW + 288 * 600_000) / 1000));
    expect(text).toContain("not guaranteed");
  });

  test("reverse Bitcoin shows first blocked disclosure tip, not an inclusive claim expiry", () => {
    const input = { profile: "ln-to-btc/v1" as const, network: "signet", refundLockHeight: 1143, claimMarginBlocks: 6 };
    const text = recoveryTiming({ ...input, observation }, NOW);
    expect(text).toContain("Provider refund becomes eligible from Bitcoin block 1144");
    expect(text).toContain("tip below Bitcoin block 1138 (6-block safety margin)");
    expect(text).toContain("Claims do not expire automatically, but can race refunds");
    expect(recoveryTiming({ ...input, observation: { height: 1138, observedAt: NOW } }, NOW)).toContain("Observed tip 1138 has reached this height");
    expect(recoveryTiming({ ...input, observation: { height: 1144, observedAt: NOW } }, NOW)).toContain("Observed tip 1144 has reached this height");
  });

  test("both EVM directions use T itself and signed block cadence", () => {
    for (const profile of ["erc20-to-ln/v1", "ln-to-erc20/v1"] as const) {
      const text = recoveryTiming({ profile, network: "mainnet", refundLockHeight: 1300, blockSeconds: 12,
        claimMarginBlocks: 50, observation }, NOW);
      expect(text).toContain("eligible from EVM block 1300");
      expect(text).toContain("300 blocks remaining");
      expect(text).toContain("60 min / 1 h");
      if (profile === "ln-to-erc20/v1") expect(text).toContain("tip below EVM block 1250");
      else expect(text).not.toContain("First claim disclosure");
    }
  });

  test("missing, stale, or future samples never invent an expiry date", () => {
    for (const sample of [undefined, { height: 1000, observedAt: NOW - 180_001 }, { height: 1000, observedAt: NOW + 1 }, { height: NaN, observedAt: NOW }]) {
      const text = recoveryTiming({ profile: "btc-to-ln/v1", network: "mainnet", refundLockHeight: 1287, observation: sample }, NOW);
      expect(text).toContain("Bitcoin block 1288");
      expect(text).toContain("Time estimate unavailable");
      expect(text).not.toContain("estimated ");
    }
  });

  test("regtest preserves heights and remaining blocks without a clock forecast", () => {
    for (const profile of ["btc-to-ln/v1", "ln-to-btc/v1", "erc20-to-ln/v1", "ln-to-erc20/v1"] as const) {
      const text = recoveryTiming({ profile, network: "regtest", refundLockHeight: 1287, blockSeconds: 12, observation }, NOW);
      expect(text).toContain(profile.includes("erc20") ? "287 blocks remaining" : "288 blocks remaining");
      expect(text).toContain("mining is on demand");
      expect(text).not.toContain("estimated ");
      expect(text).not.toContain(" min");
    }
  });

  test("invalid and out-of-range dates degrade without throwing or granting authority", () => {
    expect(expiryDatetime(Number.MAX_SAFE_INTEGER)).toBe("unavailable");
    expect(expiryDatetime(NaN)).toBe("unavailable");
    expect(recoveryTiming({ profile: "erc20-to-ln/v1", network: "mainnet", refundLockHeight: 10 })).toBe("Recovery timing unavailable.");
    const text = recoveryTiming({ profile: "btc-to-ln/v1", network: "mainnet", refundLockHeight: Number.MAX_SAFE_INTEGER - 1, observation }, NOW);
    expect(text).not.toContain("Invalid Date");
    expect(text).not.toContain("estimated ");
    expect(text).not.toContain("you can refund");
  });
});

test("badges compare explicit reverse deltas, never missing data or EVM delays to an invented default", () => {
  const input = { profile: "ln-to-btc/v1" as const, network: "mainnet", refundDelayBlocks: 144, incomingHtlcExpiryDeltaBlocks: 185 };
  expect(reverseQuoteRecoveryTiming(input).badges).toEqual([]);
  expect(reverseQuoteRecoveryTiming(input).text).toContain("at least 185 Bitcoin blocks");
  expect(reverseQuoteRecoveryTiming({ ...input, refundDelayBlocks: 72, incomingHtlcExpiryDeltaBlocks: 288 }).badges)
    .toEqual(["Non-default refund delay", "Non-default Lightning delta"]);
  expect(reverseQuoteRecoveryTiming({ ...input, refundDelayBlocks: NaN, incomingHtlcExpiryDeltaBlocks: NaN }).badges).toEqual([]);
  const evm = reverseQuoteRecoveryTiming({ ...input, profile: "ln-to-erc20/v1", blockSeconds: 12, refundDelayBlocks: 600 });
  expect(evm.badges).toEqual(["Provider-set timeout"]);
  expect(evm.text).toContain("600 EVM blocks (about 120 min / 2 h)");
  expect(reverseQuoteRecoveryTiming({ ...input, network: "regtest" }).text).not.toContain("about ");
});

test("all direction documentation separates roles, defaults, client limits, and payment expiry", () => {
  for (const profile of ["btc-to-ln/v1", "ln-to-btc/v1", "erc20-to-ln/v1", "ln-to-erc20/v1"] as const) {
    const text = recoveryDefaults(profile);
    expect(text).toContain("client limits are not provider defaults");
    expect(text).toContain("invoice payment expiries are separate");
    if (profile.includes("erc20")) expect(text).toContain("no universal default");
    else expect(text).toContain(profile === "btc-to-ln/v1" ? "288 Bitcoin blocks" : "144 Bitcoin blocks");
  }
});
