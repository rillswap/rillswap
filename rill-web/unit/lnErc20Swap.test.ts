import { describe, expect, test } from "bun:test";
import canonicalize from "canonicalize";
import { evmRecoveryDocument, lockOf, parseEvmRecovery } from "../src/swap/erc20Swap";
import { assertFreshEvmClaim, assertSafeEvmClaim, checkLnErc20QuoteOffer, checkLnErc20TermsOffer, evmClaimMarginBlocks, payoutSatEquivalent, type LnErc20FirmRequest } from "../src/swap/lnErc20Swap";
import { EvmRpc, isErc20SwapCode } from "../src/swap/evmHtlc";
import { hexToBytes } from "@noble/hashes/utils.js";
import { stagingAddress } from "../src/swap/gasSponsor";
import { ASSET, CLIENT, HOLD_INVOICE, NOW, PAYMENT_HASH, PREIMAGE, TERMS, signedReverse, testHoldInvoice } from "./fixtures/lnErc20Cases";
import fixture from "./fixtures/initial-btc-to-ln-v1.json";
import artifact from "../../rill-contracts/artifacts/erc20-swap-v6.json";
import identity from "../src/generated/erc20SwapIdentity.json";

const REQUEST: LnErc20FirmRequest = {
  kind: "ln-to-erc20", mode: "firm", payout_token_base: "51000000", payment_hash: PAYMENT_HASH,
  evm_asset: { chain_id: ASSET.chain_id, token_contract: ASSET.token_contract }, client_evm_address: CLIENT,
  recovery_authorization_xonly_key: TERMS.recovery_authorization_xonly_key,
  limits: { max_success_fee_sat: "200", min_htlc_timelock_block: 1600, max_incoming_htlc_expiry_height: 300 }, extensions: {},
};
const context = (terms = TERMS, request = REQUEST) => ({ request, asset: ASSET, network: TERMS.network_identity,
  identity: TERMS.provider_identity_key, transcript: "77".repeat(32), envelopeContractHash: signedReverse(terms).terms.contract_hash, now: NOW,
  evmTip: TERMS.evm_reference_block });

describe("LN to ERC20 signed offers", () => {
  test("exact invoice, payout and role binding; ceiling exchange math", () => {
    expect(checkLnErc20TermsOffer(signedReverse(), context()).hold_invoice).toBe(HOLD_INVOICE);
    expect(lockOf(TERMS)).toMatchObject({ amount: 51_000_000n, claimAddress: CLIENT, refundAddress: TERMS.provider_evm_address });
    expect(payoutSatEquivalent(1n, 3n)).toBe(33_333_334n);
  });
  test("rejects request changes and a mismatched decoded invoice", () => {
    for (const request of [ { ...REQUEST, payment_hash: "ab".repeat(32) }, { ...REQUEST, payout_token_base: "51000001" },
      { ...REQUEST, client_evm_address: TERMS.provider_evm_address }, { ...REQUEST, recovery_authorization_xonly_key: "ab".repeat(32) },
      { ...REQUEST, limits: { ...REQUEST.limits, max_success_fee_sat: "99" } },
      { ...REQUEST, limits: { ...REQUEST.limits, min_htlc_timelock_block: 2801 } },
      { ...REQUEST, limits: { ...REQUEST.limits, max_incoming_htlc_expiry_height: 299 } } ]) {
      expect(() => checkLnErc20TermsOffer(signedReverse(), context(TERMS, request))).toThrow();
    }
    expect(() => checkLnErc20TermsOffer(signedReverse(TERMS, testHoldInvoice("ab".repeat(32))), context())).toThrow();
  });
  test("rejects changed economics, asset, features, timing and signature", () => {
    for (const terms of [ { ...TERMS, economics: { ...TERMS.economics, rate_token_base_per_btc: "0" } },
      { ...TERMS, economics: { ...TERMS.economics, payout_sat_equivalent: "51001" } },
      { ...TERMS, evm_asset: { ...ASSET, chain_id: 1 } }, { ...TERMS, required_features: ["unknown/v1"] },
      { ...TERMS, htlc_timelock_block: 1001 }, { ...TERMS, timing_policy: { ...TERMS.timing_policy, refund_and_ln_resolution_seconds: 1_000_000 } } ]) {
      expect(() => checkLnErc20TermsOffer(signedReverse(terms), context(terms))).toThrow();
    }
    expect(() => checkLnErc20TermsOffer({ ...signedReverse(), provider_terms_signature: "00".repeat(64) }, context())).toThrow();
    expect(() => checkLnErc20TermsOffer(signedReverse(), { ...context(), now: TERMS.terms_expiry })).toThrow();
  });
  test("the signed EVM reference block must be within ten minutes of blocks of the client's tip", () => {
    const window = Math.ceil(600 / ASSET.block_seconds), reference = TERMS.evm_reference_block;
    for (const tip of [reference - window, reference + window]) {
      expect(checkLnErc20TermsOffer(signedReverse(), { ...context(), evmTip: tip }).hold_invoice).toBe(HOLD_INVOICE);
    }
    // A stale reference (as if block 0) would make every lock scan start far back; a future one shortens the timing math.
    for (const tip of [reference - window - 1, reference + window + 1, reference * 100]) {
      expect(() => checkLnErc20TermsOffer(signedReverse(), { ...context(), evmTip: tip })).toThrow("far from the current tip");
    }
    const future = { ...TERMS, evm_reference_block: reference + 1_000 };
    expect(() => checkLnErc20TermsOffer(signedReverse(future), context(future))).toThrow("far from the current tip");
  });
});

test("indicative shopping validates token economics and timing without an invoice or address", () => {
  const request = { network: fixture.network_identity, payoutTokenBase: 51_000_000n, asset: ASSET,
    limits: { maxSuccessFeeSat: 200n, minTimelockDelayBlocks: 600, maxIncomingHtlcDelayBlocks: 200 } };
  const offer = { kind: "ln-to-erc20", indicative: true, economics: TERMS.economics, evm_asset: ASSET,
    funding_confirmations: 2, settlement_confirmations: 2, evm_reference_block: 1000, timelock_delay_blocks: 1800,
    incoming_htlc_expiry_delta_blocks: 200, expires_at: NOW + 600, extensions: {} };
  expect(checkLnErc20QuoteOffer(offer, request, NOW).economics.hold_invoice_sat).toBe("51100");
  for (const bad of [ { ...offer, expires_at: NOW }, { ...offer, timelock_delay_blocks: 500 },
    { ...offer, incoming_htlc_expiry_delta_blocks: 201 }, { ...offer, economics: { ...TERMS.economics, hold_invoice_sat: "51101" } } ]) {
    expect(() => checkLnErc20QuoteOffer(bad, request, NOW)).toThrow();
  }
});

test("a signed rebate lowers the hold invoice, which must still equal E + S", () => {
  const request = { network: fixture.network_identity, payoutTokenBase: 51_000_000n, asset: ASSET,
    limits: { maxSuccessFeeSat: 0n, minTimelockDelayBlocks: 600, maxIncomingHtlcDelayBlocks: 200 } };
  const offer = (hold: string) => ({ kind: "ln-to-erc20", indicative: true, evm_asset: ASSET,
    economics: { ...TERMS.economics, success_fee_sat: "-100", hold_invoice_sat: hold },
    funding_confirmations: 2, settlement_confirmations: 2, evm_reference_block: 1000, timelock_delay_blocks: 1800,
    incoming_htlc_expiry_delta_blocks: 200, expires_at: NOW + 600, extensions: {} });
  expect(checkLnErc20QuoteOffer(offer("50900"), request, NOW).economics.success_fee_sat).toBe("-100");
  expect(() => checkLnErc20QuoteOffer(offer("51000"), request, NOW)).toThrow();
});

test("reverse recovery persists invoice and preimage; malformed or partial records never authorize a claim", () => {
  const parts = { network: TERMS.network_identity, init: fixture.verification_context.handshake_init as never,
    accept: fixture.verification_context.handshake_accept as never, acceptSignature: "11".repeat(64), offer: signedReverse(),
    acceptanceSignature: "22".repeat(64), clientSessionKey: "33".repeat(32), lockTxHash: null, preimage: PREIMAGE, createdAt: NOW, updatedAt: NOW };
  const file = evmRecoveryDocument(parts), record = parseEvmRecovery(file, TERMS.network_identity, NOW + 1_000_000);
  expect(record.preimage).toBe(PREIMAGE); expect(record.holdInvoice).toBe(HOLD_INVOICE); expect(record.claimTxHash).toBeNull();
  for (const change of [{ preimage: null }, { preimage: "12".repeat(32) }, { claim_tx_hash: "zz" }, { profile_id: "erc20-to-ln/v1" }, { offer: null }]) {
    const bad = { ...JSON.parse(new TextDecoder().decode(file)), ...change };
    expect(() => parseEvmRecovery(new TextEncoder().encode(canonicalize(bad)!), TERMS.network_identity, NOW)).toThrow();
  }
});

function safeRpc(change: Record<string, unknown> = {}): EvmRpc {
  return { chainId: async () => ASSET.chain_id, verifyHtlc: async () => {}, blockNumber: async () => 1500,
    findLockups: async () => [{ lock: lockOf(TERMS), txHash: "01".repeat(32), blockNumber: 1200, logIndex: 0 }],
    lockActive: async () => true, nativeBalance: async () => 1_000_000n, gasPrice: async () => 1n, ...change } as unknown as EvmRpc;
}
test("the advisory margin shares the exact first-disclosure boundary, including the final live check", async () => {
  const margin = evmClaimMarginBlocks(TERMS);
  expect(margin).toBe(Math.max(TERMS.settlement_confirmations + 12, Math.ceil(600 / TERMS.evm_asset.block_seconds)));
  const cutoff = TERMS.htlc_timelock_block - margin;
  await assertSafeEvmClaim(safeRpc({ blockNumber: async () => cutoff - 1 }), TERMS, PREIMAGE);
  await expect(assertSafeEvmClaim(safeRpc({ blockNumber: async () => cutoff }), TERMS, PREIMAGE)).rejects.toThrow("Too close");
  let samples = 0;
  await expect(assertSafeEvmClaim(safeRpc({ blockNumber: async () => ++samples === 1 ? cutoff - 1 : cutoff }), TERMS, PREIMAGE))
    .rejects.toThrow("Claim window or active lock changed");
});

test("claim safety guards refuse wrong chain, contract, lock, depth, active state, margin and gas", async () => {
  await assertSafeEvmClaim(safeRpc(), TERMS, PREIMAGE);
  for (const rpc of [safeRpc({ chainId: async () => 1 }), safeRpc({ verifyHtlc: async () => { throw new Error("wrong code"); } }),
    safeRpc({ findLockups: async () => [{ lock: { ...lockOf(TERMS), amount: 1n }, blockNumber: 1200 }] }),
    safeRpc({ findLockups: async () => [{ lock: lockOf(TERMS), blockNumber: 1500 }] }), safeRpc({ lockActive: async () => false }),
    safeRpc({ blockNumber: async () => 2500 }), safeRpc({ nativeBalance: async () => 0n })]) {
    await expect(assertSafeEvmClaim(rpc, TERMS, PREIMAGE)).rejects.toThrow();
  }
  await expect(assertSafeEvmClaim(safeRpc(), TERMS, "ab".repeat(32))).rejects.toThrow("preimage mismatch");
  // A sponsored claim account never holds gas; every other guard still applies.
  await assertSafeEvmClaim(safeRpc({ nativeBalance: async () => 0n }), TERMS, PREIMAGE, "sponsored");
  await expect(assertSafeEvmClaim(safeRpc({ nativeBalance: async () => 0n, lockActive: async () => false }), TERMS, PREIMAGE, "sponsored")).rejects.toThrow();
});

test("browser-held claim keys travel with the preimage and must control the signed claim address", () => {
  const secret = hexToBytes("11".repeat(32)), staging = stagingAddress(secret);
  const offer = signedReverse({ ...TERMS, client_evm_address: staging });
  const base = { network: TERMS.network_identity, init: fixture.verification_context.handshake_init as never,
    accept: fixture.verification_context.handshake_accept as never, acceptSignature: "11".repeat(64), offer,
    acceptanceSignature: "22".repeat(64), clientSessionKey: "33".repeat(32), lockTxHash: null, preimage: PREIMAGE, createdAt: NOW, updatedAt: NOW };
  const plain = parseEvmRecovery(evmRecoveryDocument(base), TERMS.network_identity, NOW);
  expect(plain.claimKey).toBeNull(); expect(plain.claimDestination).toBeNull();
  const file = evmRecoveryDocument({ ...base, claimKey: "11".repeat(32), claimDestination: CLIENT });
  const record = parseEvmRecovery(file, TERMS.network_identity, NOW);
  expect(record.claimKey).toBe("11".repeat(32)); expect(record.claimDestination).toBe(CLIENT); expect(record.lock.claimAddress).toBe(staging);
  const document = JSON.parse(new TextDecoder().decode(file)) as Record<string, unknown>;
  expect(Object.keys(document)).toContain("claim_destination");
  for (const change of [{ claim_key: "22".repeat(32) }, { claim_key: "zz" }, { claim_destination: "not-an-address" }, { claim_key: null }]) {
    const bad = { ...document, ...change };
    expect(() => parseEvmRecovery(new TextEncoder().encode(canonicalize(bad)!), TERMS.network_identity, NOW)).toThrow();
  }
});

test("bytecode identity masks only compiler immutables, not arbitrary code", () => {
  expect(identity).toEqual({ runtimeHexLength: artifact.runtimeBytecode.length, immutableRanges: artifact.immutableRanges, maskedRuntimeSha256: artifact.maskedRuntimeSha256 });
  expect(isErc20SwapCode(artifact.runtimeBytecode)).toBe(true);
  const { start, length } = artifact.immutableRanges[0]!;
  const changed = artifact.runtimeBytecode.slice(0, 2 + start * 2) + "ff".repeat(length) + artifact.runtimeBytecode.slice(2 + (start + length) * 2);
  expect(isErc20SwapCode(changed)).toBe(true);
  expect(isErc20SwapCode("0x00" + artifact.runtimeBytecode.slice(4))).toBe(false);
  expect(isErc20SwapCode("0x")).toBe(false);
});

test("stalled history or gas reads must recheck the live claim window, not the old tip", async () => {
  for (const stall of ["logs", "gas"]) {
    let tip = 1500;
    const rpc = safeRpc({ blockNumber: async () => tip,
      findLockups: async () => { if (stall === "logs") tip = 2700; return [{ lock: lockOf(TERMS), blockNumber: 1200 }]; },
      nativeBalance: async () => { if (stall === "gas") tip = 2700; return 1_000_000n; } });
    await expect(assertSafeEvmClaim(rpc, TERMS, PREIMAGE)).rejects.toThrow("changed during verification");
  }
  expect(() => assertFreshEvmClaim({ checkedAt: 0 }, 5001)).toThrow("became stale");
});

test("historical lock scans page every block rather than silently dropping old funding", async () => {
  const ranges: { fromBlock: string; toBlock: string }[][] = [];
  const rpc = new EvmRpc("http://localhost", async (_url, init) => {
    const request = JSON.parse(init.body as string); ranges.push(request.params);
    return new Response(JSON.stringify({ result: [] }));
  });
  await rpc.findLockups(ASSET.htlc_contract, PAYMENT_HASH, 1000, 25_001);
  expect(ranges.map((params) => [params[0]!.fromBlock, params[0]!.toBlock])).toEqual([["0x3e8", "0x2af7"], ["0x2af8", "0x5207"], ["0x5208", "0x61a9"]]);
});
