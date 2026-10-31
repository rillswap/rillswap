/** Advisory recovery clocks only. Never grants claim, refund, or payment authority. */
export type RecoveryProfile = "btc-to-ln/v1" | "ln-to-btc/v1" | "erc20-to-ln/v1" | "ln-to-erc20/v1";

export interface ChainObservation {
  readonly height: number;
  /** Capture before the chain read, not after a potentially slow response. */
  readonly observedAt: number;
}

// Reference provider QuoteSettings, not protocol requirements or client limits.
const FORWARD_REFUND_BLOCKS = 288;
const REVERSE_REFUND_BLOCKS = 144;
const REVERSE_LIGHTNING_BLOCKS = 185;
const MAX_OBSERVATION_AGE_MS = 180_000;
const count = (value: number): boolean => Number.isSafeInteger(value) && value >= 0;
const isEvm = (profile: RecoveryProfile): boolean => profile.includes("erc20");
const isReverse = (profile: RecoveryProfile): boolean => profile.startsWith("ln-to-");

export function expiryDatetime(seconds: number): string {
  const date = new Date(seconds * 1000);
  return Number.isFinite(seconds) && Number.isFinite(date.getTime())
    ? date.toLocaleString(undefined, { timeZoneName: "short" }) : "unavailable";
}

function duration(blocks: number, seconds: number, network: string): string {
  if (network === "regtest") return "mining is on demand; no clock estimate";
  const minutes = Math.ceil(blocks * seconds / 60);
  if (!Number.isSafeInteger(minutes)) return "time estimate unavailable";
  const hours = minutes >= 60 ? ` / ${Number((minutes / 60).toFixed(1)).toLocaleString()} h` : "";
  return `about ${minutes.toLocaleString()} min${hours}`;
}

function heightTiming(height: number, network: string, seconds: number, observation: ChainObservation | undefined, now: number): string {
  if (!observation || !count(observation.height) || !Number.isFinite(observation.observedAt) ||
      !Number.isFinite(now) || now < observation.observedAt || now - observation.observedAt > MAX_OBSERVATION_AGE_MS) {
    return "Time estimate unavailable without a fresh chain observation.";
  }
  const remaining = Math.max(0, height - observation.height);
  if (remaining === 0) return `Observed tip ${observation.height} has reached this height.`;
  const wait = duration(remaining, seconds, network);
  const estimate = observation.observedAt + remaining * seconds * 1000;
  const date = expiryDatetime(estimate / 1000);
  return `${remaining.toLocaleString()} block${remaining === 1 ? "" : "s"} remaining at observed tip ${observation.height} (${wait})` +
    (network !== "regtest" && date !== "unavailable" ? `; estimated ${date}, not guaranteed.` : ".");
}

/** Absolute contract boundary, distinct from the earlier first-disclosure cutoff. */
export function recoveryTiming(input: {
  readonly profile: RecoveryProfile;
  readonly network: string;
  readonly refundLockHeight: number;
  readonly blockSeconds?: number;
  readonly claimMarginBlocks?: number;
  readonly observation?: ChainObservation | undefined;
}, now = Date.now()): string {
  const evm = isEvm(input.profile), reverse = isReverse(input.profile);
  const height = input.refundLockHeight + (evm ? 0 : 1), seconds = evm ? input.blockSeconds : 600;
  if (!count(height) || height === 0 || !seconds || !Number.isFinite(seconds) || seconds <= 0) return "Recovery timing unavailable.";
  const chain = evm ? "EVM" : "Bitcoin";
  let text = `${reverse ? "Provider refund" : "Your refund"} becomes eligible from ${chain} block ${height}. ` +
    heightTiming(height, input.network, seconds, input.observation, now);
  if (reverse) {
    const margin = input.claimMarginBlocks, cutoff = margin === undefined ? NaN : height - margin;
    if (margin !== undefined && count(margin) && margin > 0 && count(cutoff)) {
      text += ` First claim disclosure requires a tip below ${chain} block ${cutoff} (${margin}-block safety margin). ` +
        heightTiming(cutoff, input.network, seconds, input.observation, now);
    } else text += " Claim promptly; safety checks stop first disclosure before refund eligibility.";
    text += " Claims do not expire automatically, but can race refunds.";
  }
  return text;
}

/** Only explicit indicative deltas can be compared with reference defaults. */
export function reverseQuoteRecoveryTiming(input: {
  readonly profile: "ln-to-btc/v1" | "ln-to-erc20/v1";
  readonly network: string;
  readonly refundDelayBlocks: number;
  readonly incomingHtlcExpiryDeltaBlocks: number;
  readonly blockSeconds?: number;
}): { readonly text: string; readonly badges: readonly string[] } {
  const evm = isEvm(input.profile), seconds = evm ? input.blockSeconds : 600;
  const badges: string[] = [];
  let text = "Provider refund delay unavailable.";
  if (count(input.refundDelayBlocks) && input.refundDelayBlocks > 0 && seconds && seconds > 0) {
    text = `Provider refund delay: ${input.refundDelayBlocks.toLocaleString()} ${evm ? "EVM" : "Bitcoin"} blocks (${duration(input.refundDelayBlocks, seconds, input.network)}).`;
    if (evm) badges.push("Provider-set timeout");
    else if (input.refundDelayBlocks !== REVERSE_REFUND_BLOCKS) badges.push("Non-default refund delay");
  }
  if (count(input.incomingHtlcExpiryDeltaBlocks) && input.incomingHtlcExpiryDeltaBlocks > 0) {
    text += ` Lightning hold expiry budget: at least ${input.incomingHtlcExpiryDeltaBlocks.toLocaleString()} Bitcoin blocks (${duration(input.incomingHtlcExpiryDeltaBlocks, 600, input.network)}). Actual wallet release can differ.`;
    if (input.incomingHtlcExpiryDeltaBlocks !== REVERSE_LIGHTNING_BLOCKS) badges.push("Non-default Lightning delta");
  }
  return { text: text + " Final signed heights govern the swap.", badges };
}

export function recoveryDefaults(profile: RecoveryProfile): string {
  const forward = !isReverse(profile);
  const roles = forward ? "The provider claims after paying Lightning; you can refund if it does not pay."
    : "You claim once the provider's funding passes verification; the provider can refund later. Claim promptly, before the earlier safety cutoff.";
  const defaults = isEvm(profile) ? "ERC20 refund delays are provider-set, with no universal default. EVM estimates use the signed seconds per block."
    : forward ? `Reference provider default: your refund after ${FORWARD_REFUND_BLOCKS} Bitcoin blocks, about 2,880 min / 48 h from the quote-time height. The outgoing Lightning budget is 144 blocks, with a 72-block learn-and-claim margin.`
      : `Reference provider default: provider refund after ${REVERSE_REFUND_BLOCKS} Bitcoin blocks, about 1,440 min / 24 h from the quote-time height. The minimum incoming Lightning expiry delta is ${REVERSE_LIGHTNING_BLOCKS} blocks, about 1,850 min / 30 h 50 min, including a 40-block resolution margin.`;
  return `${roles} ${defaults} Providers can configure these values; your client limits are not provider defaults. ` +
    "Block heights govern, clock estimates are approximate. Quote acceptance and invoice payment expiries are separate from recovery timing. Claims can race refunds after refund eligibility.";
}
