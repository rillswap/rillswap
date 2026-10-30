/** Observational UI facts, not another financial lifecycle or a durable journal. */
import { invoiceDescription } from "./bolt11";
export type ActivityName = "terms.verified" | "recovery.saved" | "funding.acknowledged" | "funding.received" |
  "payment.verified" | "cooperation.signing" | "cooperation.verified" | "cooperation.fallback" |
  "lock.submitted" | "lock.confirmed" | "invoice.exposed" | "funding.depth" |
  "claim.submitted" | "claim.unknown" | "claim.confirmed" | "swap.attention";

const FIELDS = new Set([
  "session_id", "profile", "network", "payment_hash", "invoice_hash", "memo", "amount_msat",
  "lightning_principal_sat", "success_fee_sat", "contract_amount_sat", "nominal_payout_sat",
  "claim_fee_reserve_sat", "mining_prepayment_sat", "hold_invoice_sat", "success_fee_token_base",
  "lock_amount_token_base", "payout_token_base", "payout_sat_equivalent", "rate_token_base_per_btc",
  "service_fee_sat", "network_fee_sat", "fee_rate_sat_kvb", "claim_fee_sat", "txid", "stage",
  "confirmations", "required_confirmations", "refund_height", "timelock_block", "reason",
]);
export type ActivityFacts = Readonly<Record<string, string | number | null>>;
export interface SwapActivity { readonly name: ActivityName; readonly facts?: ActivityFacts }
export type ActivityObserver = (event: SwapActivity) => void;

export function logText(value: string, limit = 512): string {
  return value.slice(0, limit).replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`) + (value.length > limit ? "..." : "");
}
export function safeMemo(value: string): string {
  return logText(value.slice(0, 512).replace(/\b(?:[0-9a-f]{64}|(?:lnbc|lntb|lnbcrt|nsec1|age-secret-key-1)[a-z0-9]{20,})\b/gi, "[redacted]"), 80);
}
export function activityFacts(terms: {
  readonly profile_id: string;
  readonly invoice_binding: { readonly payment_hash: string; readonly bolt11_sha256: string; readonly amount_msat: string };
  readonly economics: object;
}, invoice?: string): ActivityFacts {
  let memo: string | null = null;
  try { if (invoice) memo = invoiceDescription(invoice); } catch { /* Optional metadata cannot affect execution. */ }
  try { return { profile: terms.profile_id, payment_hash: terms.invoice_binding.payment_hash,
    invoice_hash: terms.invoice_binding.bolt11_sha256, amount_msat: terms.invoice_binding.amount_msat,
    ...(memo === null ? {} : { memo: safeMemo(memo) }),
    ...Object.fromEntries(Object.entries(terms.economics).filter(([key, value]) => FIELDS.has(key) && typeof value === "string")) };
  } catch { return {}; }
}
export function emitActivity(observer: ActivityObserver | undefined, name: ActivityName, facts: ActivityFacts = {}): void {
  if (!observer) return;
  try {
    observer({ name, facts: Object.fromEntries(Object.entries(facts).filter(([key, value]) => FIELDS.has(key) &&
      (value === null || typeof value === "string" || (typeof value === "number" && Number.isFinite(value))))
      .map(([key, value]) => [key, typeof value === "string" ? key === "memo" ? safeMemo(value) : logText(value) : value])) });
  } catch { /* A diagnostic consumer never changes financial execution. */ }
}

export function activityStatus(event: SwapActivity): { text: string; step: number } {
  switch (event.name) {
    case "terms.verified": return { text: "Signed terms verified", step: 1 };
    case "recovery.saved": return { text: event.facts?.stage === "terms" ? "Recovery saved. Ready to fund" : "Funded recovery saved. Waiting for the provider", step: 2 };
    case "funding.acknowledged": return { text: "Provider acknowledged funding. Waiting for the Lightning payment", step: 3 };
    case "funding.received": return { text: "Provider funding received. Waiting for chain verification", step: 2 };
    case "payment.verified": return { text: "Payment proof verified. Completing the claim", step: 3 };
    case "cooperation.signing": return { text: "Cooperative claim signed. Waiting for the provider", step: 3 };
    case "cooperation.verified": return { text: "Cooperative claim verified (not a chain confirmation)", step: 4 };
    case "cooperation.fallback": return { text: "Payment proof verified. Provider can claim by script path", step: 4 };
    case "lock.submitted": return { text: "Lock submitted. Waiting for confirmations", step: 2 };
    case "lock.confirmed": return { text: "Lock confirmed. Waiting for the next settlement step", step: 3 };
    case "invoice.exposed": return { text: "Pay the invoice once. Waiting for the provider's lock", step: 2 };
    case "funding.depth": return { text: `Funding: ${event.facts?.confirmations} of ${event.facts?.required_confirmations} confirmations`, step: 2 };
    case "claim.submitted": return { text: "Claim submitted. Waiting for confirmation", step: 3 };
    case "claim.unknown": return { text: "Claim submission uncertain. Watching without sending again", step: 3 };
    case "claim.confirmed": return { text: "Claim confirmed", step: 4 };
    case "swap.attention": return { text: "Swap needs attention. Inspect the saved state before any retry", step: -1 };
  }
}

/** Local-memory diagnostic history. Export omits financial and correlation details. */
export class ActivityHistory {
  private readonly entries: { time: string; event: SwapActivity }[] = [];
  append(event: SwapActivity): string | null {
    const prior = this.entries.at(-1)?.event;
    if (prior?.name === event.name && JSON.stringify(prior.facts) === JSON.stringify(event.facts)) return null;
    const time = new Date().toISOString();
    this.entries.push({ time, event });
    if (this.entries.length > 500) this.entries.shift();
    return `${time} | ${event.name} | ${Object.entries(event.facts ?? {}).map(([key, value]) => `${key}=${JSON.stringify(value)}`).join(" ")}`;
  }
  export(build?: string): string {
    return JSON.stringify({ format: "rillswap-diagnostics/v1", build,
      events: this.entries.map(({ time, event }) => ({ time, event: event.name, profile: event.facts?.profile,
        stage: event.facts?.stage, confirmations: event.facts?.confirmations, required_confirmations: event.facts?.required_confirmations })) }, null, 2);
  }
}
