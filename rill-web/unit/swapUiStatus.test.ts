import { expect, test } from "bun:test";
import {
  confirmationsLabel, fundingFeeClause, fundingWaitText, makerCostText, miningAllowanceDetails, quoteSelectionLabel, signedFeeText, stoppedSwapAdvice,
} from "../src/swapUiStatus";
import type { FeeBreakdown } from "../src/swap/feePolicy";

test("failure before sharing does not claim independently broadcast funds are uncommitted", () => {
  const advice = stoppedSwapAdvice(false);
  expect(advice).toContain("has not shared");
  expect(advice).toContain("If you broadcast separately, do not fund again");
  expect(advice).not.toContain("no funds are committed");
});

test("failure after commitment but before broadcast directs the user to funded recovery", () => {
  const advice = stoppedSwapAdvice(true);
  expect(advice).toContain("Do not fund this swap again");
  expect(advice).toContain("funded recovery file");
  expect(advice).toContain("may already be broadcast");
  expect(advice).not.toContain("reload");
});

test("manual selection does not retain the automatic best-price claim", () => {
  expect(quoteSelectionLabel(true, 2, "price")).toContain("Lowest verified provider price");
  expect(quoteSelectionLabel(false, 2, "price")).toContain("Manually selected");
  expect(quoteSelectionLabel(false, 2, "price")).not.toContain("Lowest");
});

test("the automatic claim names the active ranking, and manual picks claim neither", () => {
  expect(quoteSelectionLabel(true, 3, "time")).toContain("Fewest funding confirmations");
  expect(quoteSelectionLabel(true, 3, "time")).toContain("not a fastest-completion guarantee");
  expect(quoteSelectionLabel(true, 3, "time")).not.toContain("Lowest verified");
  expect(quoteSelectionLabel(false, 3, "time")).not.toMatch(/Fastest|Lowest/);
});

test("funding waits never present an unannounced depth as zero or one", () => {
  expect(confirmationsLabel(null)).toBe("confirmations unknown");
  expect(confirmationsLabel(0)).toBe("0 confirmations");
  expect(confirmationsLabel(1)).toBe("1 confirmation");
  expect(fundingWaitText("btc-to-ln/v1", null)).toContain("did not announce");
  expect(fundingWaitText("btc-to-ln/v1", 0)).toContain("before any confirmation");
  expect(fundingWaitText("btc-to-ln/v1", 2)).toBe("The provider pays after 2 confirmations of your deposit.");
  expect(fundingWaitText("ln-to-btc/v1", 1)).toBe("Claim after 1 confirmation of funding, then wait for the claim to confirm.");
});

test("a negative provider fee is shown as a rebate of its magnitude", () => {
  const sat = (value: bigint) => `${value} sat`;
  expect(signedFeeText("Provider", 1_000n, sat)).toBe("Provider fee: 1000 sat");
  expect(signedFeeText("Provider", 0n, sat)).toBe("Provider fee: 0 sat");
  expect(signedFeeText("Provider", -100n, sat)).toBe("Provider rebate: 100 sat");
  expect(signedFeeText("Service", -5n, sat)).toBe("Service rebate: 5 sat");
});

test("funding instructions explain whether the amount includes a fee or reflects a rebate", () => {
  expect(fundingFeeClause(900n)).toBe("including the 900 sat provider fee");
  expect(fundingFeeClause(-100n)).toBe("after the 100 sat provider rebate");
});

test("maker service, fixed mining allowance, and unitemized legacy charges are not conflated", () => {
  const fee = { service_fee_sat: "-100", network_fee_sat: "308", feerate_sat_kvb: "2000" } as FeeBreakdown;
  expect(makerCostText(208n, fee)).toBe("Maker service rebate: 100 sat. Maker mining allowance: 308 sat.");
  expect(miningAllowanceDetails(fee)).toContain("fixed charge paid to the maker, not its actual miner fee");
  expect(miningAllowanceDetails(fee)).toContain("keeps savings and covers overruns");
  expect(makerCostText(100n)).toBe("Maker fee: 100 sat (service and mining costs not itemized).");
  expect(miningAllowanceDetails()).toBe("");
});
