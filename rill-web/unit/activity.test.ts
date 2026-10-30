import { describe, expect, test } from "bun:test";
import { ActivityHistory, activityStatus, emitActivity, logText, safeMemo, type SwapActivity } from "../src/swap/activity";
import { invoiceDescription } from "../src/swap/bolt11";
import { testInvoice } from "../../rill-payments/tests/helpers";
import { notifyActivity } from "../src/swap/notifications";

describe("observational activity", () => {
  test("observer failures and unapproved facts cannot affect execution", () => {
    const events: SwapActivity[] = [];
    emitActivity((event) => events.push(event), "terms.verified", { payment_hash: "ab".repeat(32), amount_msat: "50000000", success_fee_sat: "-1", preimage: "SECRET", invoice: "SECRET" });
    expect(events[0]!.facts).toEqual({ payment_hash: "ab".repeat(32), amount_msat: "50000000", success_fee_sat: "-1" });
    expect(() => emitActivity(() => { throw new Error("gone"); }, "payment.verified")).not.toThrow();
  });
  test("status uses semantic facts, including uncertain broadcasts", () => {
    expect(activityStatus({ name: "funding.acknowledged" }).text).toContain("Waiting for the Lightning payment");
    expect(activityStatus({ name: "claim.unknown" }).text).toContain("without sending again");
    expect(activityStatus({ name: "cooperation.verified" }).text).toContain("not a chain confirmation");
  });
  test("memos are authenticated optional metadata, escaped and bounded", () => {
    expect(typeof invoiceDescription(testInvoice("memo-test"))).toBe("string");
    expect(safeMemo("Coffee\n\u001b[31m " + "c9".repeat(32))).toContain("[redacted]");
    expect(safeMemo("x".repeat(500))).toHaveLength(83);
    expect(logText("text\n\u202etest")).not.toContain("\n");
  });
  test("history deduplicates waits, is bounded, and exports no financial data", () => {
    const history = new ActivityHistory();
    const event: SwapActivity = { name: "funding.depth", facts: { confirmations: 0, required_confirmations: 1, payment_hash: "ab".repeat(32), memo: "private coffee", amount_msat: "50000000", session_id: "cd".repeat(32) } };
    expect(history.append(event)).toContain("payment_hash");
    expect(history.append(event)).toBeNull();
    for (let i = 1; i <= 600; i++) history.append({ ...event, facts: { ...event.facts, confirmations: i } });
    const output = history.export("build-test");
    expect(JSON.parse(output).events).toHaveLength(500);
    for (const privateValue of ["ab".repeat(32), "cd".repeat(32), "private coffee", "50000000"]) expect(output).not.toContain(privateValue);
    expect(JSON.parse(output).events.at(-1).confirmations).toBe(600);
  });
  test("notifications deduplicate per swap and contain no financial facts", () => {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, "Notification");
    const messages: NotificationOptions[] = [];
    class LocalNotification {
      static permission = "granted";
      constructor(_title: string, options: NotificationOptions) { messages.push(options); }
    }
    Object.defineProperty(globalThis, "Notification", { value: LocalNotification, configurable: true });
    try {
      const event: SwapActivity = { name: "payment.verified", facts: { payment_hash: "ab".repeat(32), memo: "private coffee", amount_msat: "50000000" } };
      notifyActivity(event, "a1".repeat(32)); notifyActivity(event, "a1".repeat(32)); notifyActivity(event, "b2".repeat(32));
      expect(messages).toHaveLength(2);
      expect(messages[0]!.tag).not.toBe(messages[1]!.tag);
      expect(JSON.stringify(messages)).not.toContain("private coffee");
      expect(JSON.stringify(messages)).not.toContain("ab".repeat(32));
      expect(JSON.stringify(messages)).not.toContain("50000000");
    } finally {
      if (descriptor) Object.defineProperty(globalThis, "Notification", descriptor); else Reflect.deleteProperty(globalThis, "Notification");
    }
  });
});
