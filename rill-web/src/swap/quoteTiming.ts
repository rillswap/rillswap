/** Advisory queue and block-clock estimates. Never authorizes pricing, signing, or payment. */
import { readBoundedChainText, readNextBlockFeeRate, type ChainFetch } from "./chainTip";
import { validateMempoolApi, type NetworkName } from "./config";
import { NETWORK_FEE_VBYTES } from "./feePolicy";
import { parseStrictEventJson } from "../strictEventJson";

export interface TimingMarket {
  readonly observedAt: number;
  readonly blockMinutes: number;
  readonly nextBlockRate: number;
  readonly projectedMinimumRates: readonly number[];
}

export interface QuoteTimingInput {
  readonly profile: "btc-to-ln/v1" | "ln-to-btc/v1";
  readonly fundingConfirmations: number;
  /** A quote-time estimator sample, not a commitment to the eventual funding transaction's rate. */
  readonly fundingRate?: number;
  readonly claimFeeSat?: bigint;
  readonly destinationScriptBytes?: number;
}

export interface QuoteTiming {
  readonly text: string;
  readonly detail: string;
}

const MAX_AGE_MS = 180_000;
const MAX_BLOCKS = 1008;
const record = (value: unknown): Record<string, unknown> => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Timing data unavailable");
  return value as Record<string, unknown>;
};
const positive = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value > 0;

/** Public GETs only, made on quote action to the selected API. Failure never blocks a swap. */
export async function readTimingMarket(base: string, network: NetworkName,
  options: { readonly signal?: AbortSignal; readonly fetch?: ChainFetch; readonly now?: () => number } = {}): Promise<TimingMarket | null> {
  // Blocks are mined on demand on regtest, so a clock forecast would be misleading.
  if (network === "regtest") return null;
  try {
    const api = validateMempoolApi(base, network), now = options.now ?? Date.now;
    const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(5_000)]) : AbortSignal.timeout(5_000);
    const get = async (path: string, limit: number): Promise<unknown> => {
      signal.throwIfAborted();
      const response = await (options.fetch ?? fetch)(`${api}${path}`, {
        signal, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
      });
      return parseStrictEventJson(await readBoundedChainText(response, signal, limit), limit);
    };
    const [projected, recent, nextBlockRate] = await Promise.all([
      get("/v1/fees/mempool-blocks", 32_768), get("/v1/blocks", 262_144),
      readNextBlockFeeRate(base, network, { ...options, signal }),
    ]);
    if (!Array.isArray(projected) || projected.length === 0 || projected.length > 32 ||
      !Array.isArray(recent) || recent.length < 6 || recent.length > 32) return null;
    const minimumRates = projected.map((value) => {
      const block = record(value), fees = block.feeRange;
      if (!positive(block.blockVSize) || !Array.isArray(fees) || fees.length === 0 || fees.length > 100 ||
        !fees.every((fee) => typeof fee === "number" && Number.isFinite(fee) && fee >= 0 && fee <= 1_000_000)) throw new Error("Timing projection unavailable");
      // A stacked tail is not a single block. Do not pretend it bounds inclusion time.
      return block.blockVSize > 1_000_000 ? Infinity : Math.min(...fees);
    });
    const blocks = recent.map(record);
    if (!blocks.every((block, i) => Number.isSafeInteger(block.height) && Number(block.height) >= 0 &&
      Number.isSafeInteger(block.timestamp) && positive(block.timestamp) &&
      (i === 0 || Number(blocks[i - 1]!.height) === Number(block.height) + 1))) return null;
    const latest = Number(blocks[0]!.timestamp), oldest = Number(blocks.at(-1)!.timestamp), observedAt = now();
    const blockMinutes = (latest - oldest) / (blocks.length - 1) / 60;
    if (latest * 1000 < observedAt - 3 * 60 * 60_000 || latest * 1000 > observedAt + 2 * 60 * 60_000 ||
      !positive(blockMinutes) || blockMinutes > 120) return null;
    return { observedAt, blockMinutes, nextBlockRate: nextBlockRate / 1000, projectedMinimumRates: minimumRates };
  } catch { return null; }
}

/** Erlang quantile for independent exponential block arrivals with a fixed mean. */
export function blockWaitQuantile(blocks: number, probability: number, blockMinutes: number): number {
  if (!Number.isSafeInteger(blocks) || blocks < 1 || blocks > MAX_BLOCKS ||
    !positive(blockMinutes) || !(probability > 0 && probability < 1)) throw new Error("Invalid block wait");
  const cdf = (x: number): number => {
    if (x === 0) return 0;
    // Log-space Poisson tail avoids overflow for larger confirmation requirements.
    let term = -x, sum = term;
    for (let i = 1; i < blocks; i++) {
      term += Math.log(x) - Math.log(i);
      const high = Math.max(sum, term);
      sum = high + Math.log1p(Math.exp(Math.min(sum, term) - high));
    }
    return Math.max(0, 1 - Math.exp(sum));
  };
  let low = 0, high = blocks * 2;
  while (cdf(high) < probability) high *= 2;
  for (let i = 0; i < 50; i++) {
    const middle = (low + high) / 2;
    if (cdf(middle) < probability) low = middle; else high = middle;
  }
  return (low + high) / 2 * blockMinutes;
}

/** Fee bands are a queue-position heuristic, not measured inclusion probabilities. */
export function quoteTiming(input: QuoteTimingInput, market: TimingMarket | null, now = Date.now()): QuoteTiming {
  const unavailable = (detail: string): QuoteTiming => ({ text: "Time estimate unavailable", detail });
  const depth = input.fundingConfirmations;
  if (!Number.isSafeInteger(depth) || depth < 0 || depth > MAX_BLOCKS) return unavailable("Confirmation requirement unavailable.");
  if (depth === 0) return input.profile === "btc-to-ln/v1"
    ? { text: "No confirmation wait", detail: "Payment starts when the provider sees the deposit; provider processing time is unknown." }
    : unavailable("An unconfirmed funding and claim package needs a separate estimate; early claiming increases double-spend risk.");
  if (!market || now < market.observedAt || now - market.observedAt > MAX_AGE_MS) return unavailable("Fresh public fee-queue and block data are unavailable.");
  const target = (rate: number): number | null => {
    if (!positive(rate)) return null;
    const index = market.projectedMinimumRates.findIndex((minimum) => rate >= minimum);
    return index < 0 ? null : index + 1;
  };
  const fundingRate = input.profile === "btc-to-ln/v1" ? market.nextBlockRate : input.fundingRate ?? market.nextBlockRate;
  // Projected rates include integer miner-fee rounding. At 0.1 sat/vB, the
  // quote's 154 vB model pays 16 sat (0.103896 sat/vB), not a fractional 15.4.
  const fundingQueueRate = input.profile === "ln-to-btc/v1" && input.fundingRate !== undefined
    ? Math.ceil(fundingRate * Number(NETWORK_FEE_VBYTES)) / Number(NETWORK_FEE_VBYTES) : fundingRate;
  const fundingTarget = target(fundingQueueRate);
  if (fundingTarget === null) return unavailable("The estimated deposit rate is below the current fee forecast; inclusion time is unknown.");
  let blocks = fundingTarget + depth - 1;
  let rates = input.profile === "btc-to-ln/v1"
    ? `Assumes your wallet deposits at the API's recommended ${fundingRate.toLocaleString()} sat/vB.`
    : input.fundingRate === undefined
      ? `Provider funding rate is not quoted; assumes the API's recommended ${fundingRate.toLocaleString()} sat/vB.`
      : `Uses the quoted ${fundingRate.toLocaleString()} sat/vB funding estimate, not a promised transaction rate.`;
  if (input.profile === "ln-to-btc/v1" && input.fundingRate !== undefined) rates += " Deposit queue position assumes the 154 vB pricing model with whole-satoshi fee rounding.";
  if (input.profile === "ln-to-btc/v1") {
    const bytes = input.destinationScriptBytes ?? 34;
    if (input.claimFeeSat === undefined || input.claimFeeSat <= 0n || ![22, 34].includes(bytes)) return unavailable("Claim mining fee or destination size is unavailable.");
    const rate = Number(input.claimFeeSat) / (121 + bytes), claimTarget = target(rate);
    if (claimTarget === null) return unavailable("The claim fee is below the current fee forecast; inclusion time is unknown.");
    blocks += claimTarget;
    rates += ` Claim: ${input.claimFeeSat.toLocaleString()} sat (${rate.toFixed(2)} sat/vB for the larger script-path fallback).`;
    if (input.destinationScriptBytes === undefined) rates += " Assumes a P2TR destination until final terms bind your address.";
  }
  if (blocks > MAX_BLOCKS) return unavailable("The confirmation wait exceeds the supported forecast.");
  const low = Math.max(1, Math.floor(blockWaitQuantile(blocks, 0.1, market.blockMinutes)));
  const high = Math.max(low + 1, Math.ceil(blockWaitQuantile(blocks, 0.9, market.blockMinutes)));
  return {
    text: `Estimated chain wait: ${low} to ${high} min`,
    detail: `${rates} ${input.profile === "ln-to-btc/v1" ? "Through the first claim confirmation." : "Until the deposit depth allows Lightning payment."} ` +
      `Modeled 10th to 90th percentile block-time range, using recent ${market.blockMinutes.toFixed(1)} min blocks and today's fee queue. ` +
      "Assumes transactions relay and current conditions hold; not a completion guarantee. Excludes your payment/signing time and provider processing." +
      (input.profile === "ln-to-btc/v1" ? " Key-path claims can be faster." : ""),
  };
}
