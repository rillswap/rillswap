/** Test-only quote orchestration. Real wallet, invoice validation, and tip client remain in use. */
import { BrowserRecoveryWallet } from "../../src/browserRecoveryWallet";
import { RecoveryFundingUnavailableError } from "../../src/recoveryFunding";
import { forwardRank, rank, type SortMode } from "../../src/swap/ranking";
import type { FeeBreakdown } from "../../src/swap/feePolicy";
declare global {
  interface Window {
    uiFixture: { requests: unknown[]; executed: number; executedProviders: string[]; disposed: number;
      fundingScript?: string; fundingDepth?: number | undefined; fundingSource?: { psbt: string } | { depositTxid: string };
      reverseEvents?: string[]; reverseFunded?: boolean; reverseDepth?: number; reverseClaimConfirmed?: boolean; reverseBroadcastUnknown?: boolean; reverseNodePayment?: boolean; reverseTransientClaimRead?: boolean; reverseClaimFeeRates?: number[];
      /** Each prepared execution's claimConfirmations (null: absent, the signed depth). */
      reverseClaimConfirmations?: (number | null)[];
      fundedRecovery?: number[]; fundingPublished?: boolean;
      wallet: typeof BrowserRecoveryWallet; releaseInfo?: () => void; infoPending: boolean };
    /**
     * Announced base fee for the directory, 0 by default so every fixture quote is above the
     * estimate and shows the review step. Set it with `page.addInitScript` before the page loads.
     */
    uiFixtureAnnouncedFeeSat?: string;
    /** Announced funding depth of the directory entry; unannounced (null) by default. */
    uiFixtureAnnouncedDepth?: number;
    /** Signed funding depths of forward quotes "4" (1,104 sat) and "5" (1,105 sat); 1 each by default. */
    uiFixtureQuoteDepths?: [number, number];
    uiFixtureItemizedFees?: boolean;
    uiFixtureFeeRates?: [number, number];
  }
}
window.uiFixture = { requests: [], executed: 0, executedProviders: [], disposed: 0, wallet: BrowserRecoveryWallet, infoPending: false };
const fixtureFees = (index: number): FeeBreakdown => ({
  offer_event_id: "a".repeat(64), policy: { model: "p2tr-cooperative-1in-2out/v1", base_sat: "200", proportional_millionths: 0,
    max_network_feerate_sat_kvb: "2000", max_routing_fee_ppm: 1000 },
  service_fee_sat: String(100 + index * 100),
  network_fee_sat: String(Math.ceil(154 * (window.uiFixtureFeeRates?.[index] ?? (index === 0 ? 2000 : 500)) / 1000)),
  feerate_sat_kvb: String(window.uiFixtureFeeRates?.[index] ?? (index === 0 ? 2000 : 500)),
  estimated_at: Math.floor(Date.now() / 1000), issued_at: Math.floor(Date.now() / 1000),
});
export const MAX_QUOTE_PROVIDERS = 8;
export const DIRECTORY_PROFILES = ["btc-to-ln/v1", "ln-to-btc/v1", "erc20-to-ln/v1", "ln-to-erc20/v1"];
export const discoverMarketplace = async () => ({ providers: [{ announcement: {} }], warnings: [] });
export const eligibleProviders = (providers: unknown[]) => providers;
export const ineligibilityReason = () => "fixture ineligible";
export const discoverDirectory = async () => ({ warnings: [], entries: [{ identity: "4".repeat(64), slot: "fixture", profiles: ["btc-to-ln/v1", "ln-to-btc/v1"],
  amountBands: [{ minimum_sat: "1000", maximum_sat: "100000000" }], indicativeFeePolicy: { base_sat: window.uiFixtureAnnouncedFeeSat ?? "0", proportional_millionths: 0 },
  relayUrls: ["ws://127.0.0.1:7777/"], expiresAt: Math.floor(Date.now() / 1000) + 3600, fundingConfirmations: window.uiFixtureAnnouncedDepth ?? null }] });
export const indicativeFee = (policy: { base_sat: string; proportional_millionths: number }, amount: bigint) =>
  BigInt(policy.base_sat) + (amount * BigInt(policy.proportional_millionths) + 999_999n) / 1_000_000n;
export const providerLimits = (providers: unknown[]) => providers;
export const unexpired = <T extends { expiresAt: number }>(entries: readonly T[], now = Math.floor(Date.now() / 1000)) =>
  entries.filter((entry) => entry.expiresAt > now);
type FixtureEntry = { identity: string; profiles: string[]; amountBands: { minimum_sat: string; maximum_sat: string }[];
  indicativeFeePolicy: { base_sat: string; proportional_millionths: number }; fundingConfirmations: number | null };
export const estimateFromDirectory = (entries: FixtureEntry[], profile: string, amount: bigint, pinned = "") => {
  const serving = entries.filter((entry) => entry.profiles.includes(profile) && (!pinned || entry.identity === pinned));
  const eligible = serving.filter((entry) => entry.amountBands.some((band) => amount >= BigInt(band.minimum_sat) && amount <= BigInt(band.maximum_sat)));
  if (eligible.length === 0) return { reason: serving.length === 0 ? "No provider announced this swap direction." : "fixture ineligible" };
  return { identity: eligible[0]!.identity, feeSat: indicativeFee(eligible[0]!.indicativeFeePolicy, amount), fundingConfirmations: eligible[0]!.fundingConfirmations };
};
export const quoteProviders = async (_providers: unknown[], request: unknown, _signal?: AbortSignal, mode: SortMode = "time") => {
  window.uiFixture.requests.push(structuredClone(request));
  const depths = window.uiFixtureQuoteDepths ?? [1, 1];
  return { failures: 0, reasons: [], quotes: rank(["4", "5"].map((id, index) => ({ relayUrl: "ws://127.0.0.1:7777/",
    dispose: () => { window.uiFixture.disposed++; },
    prepared: {
      quote: { providerIdentity: id.repeat(64), providerSlot: "fixture",
        ...(window.uiFixtureItemizedFees ? { feeBreakdown: fixtureFees(index) } : {}),
        contractAmountSat: window.uiFixtureItemizedFees ? 1000n + BigInt(fixtureFees(index).service_fee_sat) + BigInt(fixtureFees(index).network_fee_sat) : BigInt(1100 + Number(id)),
        successFeeSat: window.uiFixtureItemizedFees ? BigInt(fixtureFees(index).service_fee_sat) + BigInt(fixtureFees(index).network_fee_sat) : 100n,
        contractHash: "0".repeat(64), refundLockHeight: 300, expiresAt: Math.floor(Date.now() / 1000) + 3600, fundingConfirmations: depths[index]! },
      execute: async (hooks: { saveRecovery: (file: Uint8Array, stage: string) => Promise<void>; fundingSource: (request: unknown) => Promise<unknown> }) => {
        window.uiFixture.executed++; window.uiFixture.executedProviders.push(id.repeat(64));
        await hooks.saveRecovery(new Uint8Array([7, 7, 7]), "terms");
        if (window.uiFixture.fundedRecovery) {
          await hooks.saveRecovery(Uint8Array.from(window.uiFixture.fundedRecovery), "funded");
          window.uiFixture.fundingPublished = true;
          throw new Error("Fixture stopped after funded checkpoint");
        }
        if (window.uiFixture.fundingScript) {
          // Exercise the funding prompt with the test's contract script; record what it resolved with.
          const source = await hooks.fundingSource({ contractScript: window.uiFixture.fundingScript, amountSat: 101_000n, maxFundingFeeSat: 500n,
            refundLockHeight: 300, successFeeSat: 100n, termsExpiry: Math.floor(Date.now() / 1000) + 3600, fundingConfirmations: window.uiFixture.fundingDepth }) as { psbt?: string; deposit?: { transaction: { txid: string } } };
          window.uiFixture.fundingSource = source.psbt !== undefined ? { psbt: source.psbt } : { depositTxid: source.deposit!.transaction.txid };
          throw new Error("Fixture stopped after funding");
        }
        throw new Error("Fixture stopped before funding");
      },
      dispose: () => { window.uiFixture.disposed++; },
    },
  })), forwardRank, mode) };
};
export const quoteReverseProviders = async (_providers: unknown[], request: unknown) => {
  window.uiFixture.requests.push(structuredClone(request));
  return { failures: 0, reasons: [], quotes: ["6", "7"].map((id, index) => ({ relayUrl: "ws://127.0.0.1:7777/",
    dispose: () => { window.uiFixture.disposed++; },
    prepared: {
      quote: { providerIdentity: id.repeat(64), payoutSat: window.uiFixtureItemizedFees ? (request as { payoutSat: bigint }).payoutSat : 50_000n,
        ...(window.uiFixtureItemizedFees ? { feeBreakdown: fixtureFees(index) } : {}),
        holdInvoiceSat: window.uiFixtureItemizedFees ? (request as { payoutSat: bigint }).payoutSat + 143n + BigInt(fixtureFees(index).service_fee_sat) + BigInt(fixtureFees(index).network_fee_sat) : BigInt(51_000 + Number(id)),
        successFeeSat: window.uiFixtureItemizedFees ? BigInt(fixtureFees(index).service_fee_sat) + BigInt(fixtureFees(index).network_fee_sat) : 500n,
        claimFeeReserveSat: window.uiFixtureItemizedFees ? 143n : 500n, fundingConfirmations: 2, refundDelayBlocks: 144, incomingHtlcExpiryDeltaBlocks: 288, expiresAt: Math.floor(Date.now() / 1000) + 3600 },
      // A stand-in execution: enough for the execution UI to accept, show the invoice, and receive fixture funding.
      prepareExecution: async (configuration: { claimFeeRateSatKvb: number; claimConfirmations?: number }) => {
        (window.uiFixture.reverseClaimFeeRates ??= []).push(configuration.claimFeeRateSatKvb);
        (window.uiFixture.reverseClaimConfirmations ??= []).push(configuration.claimConfirmations ?? null);
        window.uiFixture.reverseEvents = [];
        const events = window.uiFixture.reverseEvents;
        const record: { stage: string; claim?: { txid: string }; payment: { state: string; paymentHash: string; bolt11?: string } | null } = { stage: "terms-ready", payment: null };
        const expiresAt = Math.floor(Date.now() / 1000) + 1800;
        // As the real execution: a lower client choice, never above the signed 2.
        let claimDepth = Math.min(configuration.claimConfirmations ?? 2, 2);
        return {
          terms: { economics: { hold_invoice_sat: String(51_000 + Number(id)), nominal_payout_sat: "50000", success_fee_sat: "500", claim_fee_reserve_sat: "500" },
            funding_confirmations: 2, refund_lock_height: 400, max_claim_fee_sat: "800", client_destination_script: "0014" + "11".repeat(20),
            invoice_binding: { expires_at: expiresAt } },
          recoveryFile: new Uint8Array([8, 8, 8]), record,
          get claimDepth() { return claimDepth; },
          lowerClaimDepth: (depth: number) => {
            if (!["funded", "claim-ready"].includes(record.stage) || depth >= claimDepth) throw new Error("fixture refuses");
            events.push(`lower-${depth}`); claimDepth = depth;
          },
          get claimFeeSat() { return record.claim ? "500" : null; },
          get funding() { return record.stage === "terms-ready" || record.stage === "payment-unknown" ? null : { txid: "b".repeat(64), vout: 0 }; },
          fundingDepth: async () => { events.push("depth"); return window.uiFixture.reverseDepth ?? 0; },
          accept: async () => { events.push("accept"); },
          exposeInvoice: async () => {
            events.push("expose"); record.stage = "payment-unknown";
            record.payment = { state: "external-wallet", paymentHash: "c".repeat(64), bolt11: "lnbcrt510010n1fixture" };
            return { bolt11: "lnbcrt510010n1fixture", expiresAt };
          },
          planPayment: async () => {
            events.push("plan"); if (!window.uiFixture.reverseNodePayment) throw new Error("fixture has no node");
            return { feeMsat: "1000", limits: { maxExpiryHeight: 500 }, paymentHash: "c".repeat(64), invoiceBinding: { amount_msat: "51006000" } };
          },
          pay: async () => { events.push("pay"); record.stage = "payment-unknown"; record.payment = { state: "submission-unknown", paymentHash: "c".repeat(64) }; return "IN_FLIGHT"; },
          receiveFunding: async () => {
            events.push("receive");
            if (!window.uiFixture.reverseFunded) { await new Promise((resolve) => setTimeout(resolve, 200)); throw new Error("no funding yet"); }
            record.stage = "funded"; return new Uint8Array([9, 9, 9]);
          },
          prepareClaim: async () => {
            events.push("prepare"); record.stage = "claim-ready"; record.claim = { txid: "a".repeat(64) };
            return { claim: { txid: record.claim.txid, feeSat: "500", outputValueSat: "50000", vsize: 140 }, recoveryFile: new Uint8Array([10, 10, 10]) };
          },
          exposeClaim: async (_api: string, _broadcast: string, action: string) => {
            if (action === "broadcast" && window.uiFixture.reverseTransientClaimRead) {
              window.uiFixture.reverseTransientClaimRead = false; events.push("transient-read"); throw new RecoveryFundingUnavailableError();
            }
            events.push(action);
            if (action === "download") return { outcome: "exported", txid: record.claim!.txid, transactionHex: "00" };
            record.stage = window.uiFixture.reverseBroadcastUnknown ? "claim-unknown" : "accepted";
            return { outcome: window.uiFixture.reverseBroadcastUnknown ? "unknown" : "accepted", txid: record.claim!.txid };
          },
          dispose: () => { events.push("dispose"); },
        };
      },
      dispose: () => { window.uiFixture.disposed++; },
    },
  })) };
};
/** RS-010 is exercised against the real stack (regtest/erc20.spec.ts); page tests never reach a wallet. */
export const selectEvmAsset = () => null;
export const quoteErc20Providers = async () => ({ quotes: [], failures: 0, reasons: ["fixture: no EVM providers"] });
export const quoteLnErc20Providers = async () => ({ quotes: [], failures: 0, reasons: ["fixture: no EVM providers"] });
