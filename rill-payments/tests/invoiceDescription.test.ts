import { expect, test } from "bun:test";
import { decodeBolt11, invoiceBinding, invoiceDescription } from "../src/bolt11";
import { testInvoice } from "./helpers";

test("description is authenticated optional display metadata, not a new binding field", () => {
  const invoice = testInvoice("description");
  expect(invoiceDescription(invoice)).toBe("Public checkout fixture");
  expect(decodeBolt11(invoice)).not.toHaveProperty("description");
  expect(invoiceBinding(invoice, "regtest")).not.toHaveProperty("memo");
});

test("a description hash does not invent a memo", () => {
  const invoice = testInvoice("hashed description", "1000000", 1000, 2000, "bcrt", undefined, "private metadata");
  expect(invoiceDescription(invoice)).toBeNull();
});

test("unauthenticated invoice bytes cannot supply a description", () => {
  const invoice = testInvoice("description");
  expect(() => invoiceDescription(invoice.slice(0, -1) + (invoice.endsWith("q") ? "p" : "q"))).toThrow();
});
