/** Tab-owned notifications. Request permission at swap start, never on page load. No service worker. */
export async function requestSwapNotifications(): Promise<boolean> {
  try {
    if (typeof Notification === "undefined") return false;
    if (Notification.permission === "default") return await Notification.requestPermission() === "granted";
    return Notification.permission === "granted";
  } catch { return false; }
}

/** Call with public status text only, never invoices, addresses, keys, or recovery data. */
const seen = new Set<string>();
export function notifySwap(message: string, reference?: string, milestone = message): void {
  try {
    const tag = reference && /^[0-9a-f]{16,64}$/i.test(reference) ? `rillswap-${reference.slice(0, 16)}` : "rillswap-status";
    const key = `${tag}:${milestone}`;
    if (reference && seen.has(key)) return;
    if (typeof Notification !== "undefined" && Notification.permission === "granted") {
      new Notification("RillSwap", { body: message, tag });
      if (reference) { seen.add(key); if (seen.size > 256) seen.delete(seen.values().next().value!); }
    }
  } catch { /* Notification support must never interrupt a swap. */ }
}

/** Fixed public summaries. Financial facts remain in the local Activity view. */
export function notifyActivity(event: import("./activity").SwapActivity, reference?: string): void {
  const messages: Partial<Record<import("./activity").ActivityName, string>> = {
    "payment.verified": "Payment proof verified. Open your swap for details.",
    "lock.confirmed": "Funds are locked. Open your swap for the next step.",
    "funding.received": "Provider funding received. Waiting for confirmations.",
    "claim.submitted": "Your claim was submitted. Waiting for confirmation.",
    "claim.unknown": "Your claim needs a manual check. Do not submit it again.",
    "claim.confirmed": "Your claim is confirmed.",
    "swap.attention": "Your swap needs attention.",
  };
  if (event.facts?.profile === "ln-to-btc/v1") {
    Object.assign(messages, { "funding.received": "Bitcoin is locked. Waiting for confirmations.",
      "claim.submitted": "Your Bitcoin claim was submitted.", "claim.unknown": "Your Bitcoin claim needs a manual check.",
      "claim.confirmed": "Your Bitcoin claim is confirmed." });
  }
  const message = messages[event.name];
  if (message) notifySwap(message, reference, event.name);
}
