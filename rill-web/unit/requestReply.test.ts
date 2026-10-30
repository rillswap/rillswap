import { expect, test } from "bun:test";
import type { Envelope, PublicationOptions, Session } from "../src/swap/session";
import { requestReply } from "../src/swap/requestReply";

test("a reply wins over a lost relay acknowledgment, and aborts the pending send", async () => {
  let signal: AbortSignal | undefined;
  const request = { message_type: "action_request" } as Envelope, reply = {} as Envelope;
  const session = { providerKey: "provider",
    async send(_request: Envelope, _key: string, check: () => void, options: PublicationOptions) {
      check(); signal = options.signal;
      await new Promise<void>((resolve) => signal!.addEventListener("abort", () => resolve(), { once: true }));
    }, async replyTo() { return reply; },
  } as unknown as Session;
  expect(await requestReply(session, request, "action_result", { remaining: () => 1000 })).toBe(reply);
  expect(signal!.aborted).toBe(true);
});

test("lost application replies retransmit the exact request without rerunning the operation", async () => {
  const request = { message_type: "action_request", message_id: "fixed", sequence: 7, payload: { public_nonce: "fixed nonce" } } as unknown as Envelope;
  const sent: Envelope[] = []; let deliver: (reply: Envelope) => void = () => {};
  const reply = {} as Envelope;
  const session = { providerKey: "provider",
    async send(envelope: Envelope, _key: string, check: () => void) { check(); sent.push(envelope); if (sent.length === 2) deliver(reply); },
    replyTo() { return new Promise<Envelope>((resolve) => { deliver = resolve; }); },
  } as unknown as Session;
  expect(await requestReply(session, request, "action_result", { remaining: () => 1000, retryMs: 1 })).toBe(reply);
  expect(sent).toHaveLength(2); expect(sent.every((item) => item === request)).toBe(true);
});
