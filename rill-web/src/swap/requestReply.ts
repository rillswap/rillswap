/** Retransmit one immutable request, never rerun its application operation. */
import { SwapError, type Envelope, type Session } from "./session";

interface ExchangeOptions {
  readonly remaining: () => number;
  readonly beforePublish?: () => void;
  readonly onAccepted?: () => void;
  readonly retryMs?: number;
  readonly onRetry?: (reason: string) => void;
}

export async function requestReply(session: Session, request: Envelope, expected: string,
  options: ExchangeOptions): Promise<Envelope> {
  const controller = new AbortController(), retryMs = options.retryMs ?? 2000;
  const budget = options.remaining();
  let finished = false;
  const guard = (): void => {
    controller.signal.throwIfAborted();
    options.remaining(); options.beforePublish?.();
  };
  const pause = (ms: number): Promise<void> => new Promise((resolve) => {
    const done = (): void => { clearTimeout(timer); controller.signal.removeEventListener("abort", done); resolve(); };
    const timer = setTimeout(done, ms);
    controller.signal.addEventListener("abort", done, { once: true });
    if (controller.signal.aborted) done();
  });
  const sending = (async (): Promise<never> => {
    while (!finished) {
      controller.signal.throwIfAborted(); options.remaining();
      try {
        // Each send wraps the same signed bytes afresh. Socket-level retries keep that wrapper.
        await session.send(request, session.providerKey!, guard,
          { signal: controller.signal, timeoutMs: Math.min(retryMs, options.remaining()) });
        if (!finished) options.onAccepted?.();
      } catch (error) {
        if (finished) throw error;
        const transportFailure = error instanceof Error &&
          (error.message === `relay did not accept ${request.message_type}` || error.name === "RelayError");
        if (!transportFailure) throw error;
        const reason = error instanceof SwapError ? error.transportReason : undefined;
        options.onRetry?.(["connection closed", "publication rejected", "publication timed out", "subscription closed"].includes(reason ?? "")
          ? reason! : "delivery interrupted");
      }
      if (!finished) await pause(Math.min(retryMs, options.remaining()));
    }
    throw new Error("Request exchange ended");
  })();
  // A caller's clock/guard may throw synchronously while arranging the receive branch.
  void sending.catch(() => {});
  // An authenticated reply proves receipt even if every relay OK was lost.
  try {
    const receiving = session.replyTo(request, expected, budget, controller.signal);
    return await Promise.race([sending, receiving]);
  }
  finally {
    finished = true; controller.abort();
    // Both branches have rejection handlers through Promise.race. Abort fences socket writes.
  }
}
