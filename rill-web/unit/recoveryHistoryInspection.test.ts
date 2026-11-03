import { expect, test } from "bun:test";
import canonicalize from "canonicalize";
import { inspectRecoveryHistoryPlaintext, RecoveryInspectionRefusedError } from "../src/recoveryInspection";
import { fixtureRecord } from "./fixtures/recoveryInspectionFixture";
import { reverseRecord } from "./fixtures/reverseRecoveryCases";
import { recoveryInspectionCases } from "./fixtures/recoveryInspectionCases";

const bytes = (record: unknown) => new TextEncoder().encode(canonicalize(record)!);

test("History projects only authenticated public forward amount and invoice date", () => {
  const record = fixtureRecord();
  record.created_at = 1; // The unsigned document date must not become the displayed invoice date.
  const input = bytes(record), before = Uint8Array.from(input);
  const report = inspectRecoveryHistoryPlaintext(input, record.network_identity);
  expect(report).toEqual({ verification: "historical-static", profileId: "btc-to-ln/v1", networkName: record.network_identity.name,
    contractHash: record.contract_hash, amountSat: "100000", invoiceCreatedAt: record.contract_terms.invoice_binding.created_at });
  expect(Object.keys(report).sort()).toEqual(["amountSat", "contractHash", "invoiceCreatedAt", "networkName", "profileId", "verification"]);
  expect(Object.values(report).every((value) => ["string", "number"].includes(typeof value))).toBe(true);
  expect(Object.isFrozen(report)).toBe(true); expect(input).toEqual(before);
  expect(JSON.stringify(report)).not.toContain(record.user_secret.contract_secret_key);
  expect(JSON.stringify(report)).not.toContain("funding_history");
  const termsOnly = structuredClone(record); termsOnly.funding_history = [];
  expect(inspectRecoveryHistoryPlaintext(bytes(termsOnly), record.network_identity)).toEqual(report);
  expect(() => inspectRecoveryHistoryPlaintext(bytes(reverseRecord()), record.network_identity)).toThrow(RecoveryInspectionRefusedError);
  const tampered = structuredClone(record); tampered.contract_terms.invoice_binding.created_at += 1;
  expect(() => inspectRecoveryHistoryPlaintext(bytes(tampered), record.network_identity)).toThrow(RecoveryInspectionRefusedError);
  const wrongNetwork = { ...record.network_identity, genesis_hash: "f".repeat(64) };
  expect(() => inspectRecoveryHistoryPlaintext(input, wrongNetwork)).toThrow(RecoveryInspectionRefusedError);
});

for (const { name, record, accepted, expectedNetwork } of recoveryInspectionCases()) {
  test(`History preserves recovery authentication refusals: ${name}`, () => {
    if (accepted) expect(inspectRecoveryHistoryPlaintext(bytes(record), expectedNetwork).verification).toBe("historical-static");
    else expect(() => inspectRecoveryHistoryPlaintext(bytes(record), expectedNetwork)).toThrow(RecoveryInspectionRefusedError);
  });
}
