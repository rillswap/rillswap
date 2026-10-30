import type { FeeBreakdown } from "./swap/feePolicy";

/** A shared signed transaction can commit funds before a broadcast acknowledgment. */
export function stoppedSwapAdvice(fundsMayBeCommitted: boolean): string {
  return fundsMayBeCommitted
    ? "Do not fund this swap again. Keep the funded recovery file and its age key: if the invoice is " +
      "not paid, the signed transaction may already be broadcast. After the refund height, open Recover a swap " +
      "below with the funded recovery file to check funding and prepare your refund."
    : "This page has not shared your signed transaction. If you broadcast separately, do not fund again. " +
      "Otherwise, reload the page to start a new swap.";
}

/** `automatic`: the first offer in the chosen ranking, not a manual pick. */
export function quoteSelectionLabel(automatic: boolean, count: number, mode: "time" | "price"): string {
  if (!automatic) return `Manually selected provider (${count} verified offers available).`;
  return mode === "time"
    ? `Fewest funding confirmations among ${count} responding offers, then lowest price (not a fastest-completion guarantee).`
    : `Lowest verified provider price among ${count} responding offers.`;
}

/** Short funding depth for lists and tables; null means the provider did not announce it. */
export function confirmationsLabel(depth: number | null): string {
  return depth === null ? "confirmations unknown" : `${depth} confirmation${depth === 1 ? "" : "s"}`;
}

/** When the provider acts on the funding, in the wording of each Bitcoin direction. */
export function fundingWaitText(profile: "btc-to-ln/v1" | "ln-to-btc/v1", depth: number | null): string {
  if (depth === null) return "The provider did not announce how many confirmations it waits for.";
  if (profile === "ln-to-btc/v1") return `Claim after ${confirmationsLabel(depth)} of funding, then wait for the claim to confirm.`;
  return depth === 0
    ? "The provider pays as soon as it sees your deposit, before any confirmation."
    : `The provider pays after ${confirmationsLabel(depth)} of your deposit.`;
}

/** A maker's quoted mining allowance is revenue, not a pass-through of its actual miner fee. */
export function makerCostText(total: bigint, fees?: FeeBreakdown): string {
  const sat = (value: bigint): string => `${value.toLocaleString()} sat`;
  return fees
    ? `${signedFeeText("Maker service", BigInt(fees.service_fee_sat), sat)}. Maker mining allowance: ${sat(BigInt(fees.network_fee_sat))}.`
    : `${signedFeeText("Maker", total, sat)} (service and mining costs not itemized).`;
}

export function miningAllowanceDetails(fees?: FeeBreakdown): string {
  return fees ? `The mining allowance is a fixed charge paid to the maker, not its actual miner fee; the maker keeps savings and covers overruns. ` +
    `Pricing model: 154 vB at ${Number(fees.feerate_sat_kvb) / 1000} sat/vB.` : "";
}

/** A negative fee is a rebate the provider pays: name it and show its magnitude. */
export function signedFeeText(label: string, fee: bigint, format: (amount: bigint) => string): string {
  return fee < 0n ? `${label} rebate: ${format(-fee)}` : `${label} fee: ${format(fee)}`;
}

/** The clause after "Send exactly X BTC (Y sat, ...". */
export function fundingFeeClause(feeSat: bigint): string {
  return feeSat < 0n
    ? `after the ${(-feeSat).toLocaleString()} sat provider rebate`
    : `including the ${feeSat.toLocaleString()} sat provider fee`;
}
