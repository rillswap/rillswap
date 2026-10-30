/** A live swap's sockets, not its session or financial state. Archive queries stay separate. */
import type { NostrEvent } from "nostr-tools";
import type { RelayConnection } from "./relay";
import type { PublicationOptions, RelayLink } from "./session";

type Connection = Pick<RelayConnection, "publish" | "subscribe" | "next" | "close" | "isClosed" | "query" | "guardedPublication"> & { readonly failureReason?: string | undefined };
type Open = (url: string, signal: AbortSignal) => Promise<Connection>;
const MAX_QUEUE = 1024;
class LiveRelayError extends Error {}

export class LiveRelayLink implements RelayLink {
  readonly guardedPublication = true;
  private readonly stop = new AbortController();
  private readonly connections = new Map<string, Connection>();
  private readonly opening = new Set<string>();
  private readonly queue: string[] = [];
  private readonly waiters = new Set<() => void>();
  private readonly tasks = new Set<Promise<void>>();
  private filter: Record<string, unknown> | undefined;
  private fault: LiveRelayError | undefined;
  private cursor = 0;
  private started = false;
  private seed: readonly [string, Connection] | undefined;
  readonly urls: readonly string[];
  failureReason: string | undefined;

  constructor(readonly url: string, private readonly bootstrap: Connection, alternatives: readonly string[],
    private readonly open: Open,
    private readonly retryMs = 1000) {
    this.urls = [...new Set([url, ...alternatives])];
    this.seed = [url, bootstrap];
  }

  private wake(): void { for (const waiter of [...this.waiters]) waiter(); }

  private wait(ms: number, signal = this.stop.signal, changes = true): Promise<void> {
    signal.throwIfAborted();
    return new Promise((resolve) => {
      const done = (): void => { clearTimeout(timer); this.waiters.delete(done); signal.removeEventListener("abort", done); resolve(); };
      const timer = setTimeout(done, Math.max(0, ms));
      if (changes) this.waiters.add(done);
      signal.addEventListener("abort", done, { once: true });
    });
  }

  private start(): void {
    if (this.started || this.stop.signal.aborted) return;
    this.started = true;
    for (let slot = 0; slot < Math.min(2, this.urls.length); slot++) {
      const task = this.maintain(slot).catch((error: unknown) => {
        if (!this.stop.signal.aborted) { this.fault = error instanceof LiveRelayError ? error : new LiveRelayError("live relay unavailable"); this.wake(); }
      });
      this.tasks.add(task); void task.finally(() => this.tasks.delete(task));
    }
  }

  private async maintain(slot: number): Promise<void> {
    let delay = this.retryMs;
    let retained = slot === 0 ? this.seed : undefined;
    if (slot === 0) this.seed = undefined;
    while (!this.stop.signal.aborted) {
      const available = this.urls.filter((url) => !this.connections.has(url) && !this.opening.has(url));
      const url = retained?.[0] ?? available[this.cursor++ % available.length];
      if (!url) { await this.wait(this.retryMs, this.stop.signal, false); continue; }
      let connection = retained?.[1];
      this.opening.add(url);
      try {
        connection ??= await this.open(url, this.stop.signal);
        this.stop.signal.throwIfAborted();
        while (this.filter) {
          const filter = this.filter;
          await connection.subscribe(filter);
          if (filter === this.filter) break;
        }
        this.connections.set(url, connection); this.opening.delete(url); delay = this.retryMs; this.wake();
        while (!this.stop.signal.aborted && !connection.isClosed) {
          const raw = await connection.next(Date.now() + 30_000, this.stop.signal);
          if (raw === null) continue;
          if (this.queue.length >= MAX_QUEUE) throw new LiveRelayError("live relay inbox overflow");
          this.queue.push(raw); this.wake();
        }
      } catch (error) {
        if (error instanceof LiveRelayError) throw error;
        this.failureReason = "connection closed";
        // Network failures carry no session authority. Reopen using the same filter and keys.
      } finally {
        retained = undefined;
        this.opening.delete(url);
        if (this.connections.get(url) === connection) this.connections.delete(url);
        connection?.close(); this.wake();
      }
      if (!this.stop.signal.aborted) { await this.wait(delay, this.stop.signal, false); delay = Math.min(delay * 2, 30_000); }
    }
  }

  async subscribe(filter: Record<string, unknown>): Promise<void> {
    this.stop.signal.throwIfAborted();
    // Keep the original backdate floor across hours of reconnects, never reconnect-time "now".
    this.filter = structuredClone(filter);
    if (this.started) await Promise.all([...this.connections.values()].map((connection) => connection.subscribe(this.filter!)));
    this.start();
  }

  /** Only nonfinancial preparation uses announcement queries; their original finite bounds remain. */
  query(filter: Record<string, unknown>, limit: number, timeoutMs?: number): ReturnType<RelayConnection["query"]> {
    this.stop.signal.throwIfAborted();
    return this.bootstrap.query(filter, limit, timeoutMs);
  }

  async publish(event: NostrEvent, options: PublicationOptions = {}): Promise<boolean> {
    this.start();
    const deadline = Date.now() + (options.timeoutMs ?? 5000);
    while (!this.stop.signal.aborted && Date.now() < deadline) {
      options.signal?.throwIfAborted();
      if (this.fault) throw this.fault;
      const connections = [...this.connections.values()].filter((connection) => !connection.isClosed);
      if (connections.length) {
        // All writes check the caller's guard after connection establishment, not before it.
        const results = await Promise.all(connections.map((connection) => connection.publish(event,
          { ...options, timeoutMs: Math.max(1, deadline - Date.now()) })));
        for (const [index, accepted] of results.entries()) if (!accepted && !options.signal?.aborted && !this.stop.signal.aborted) {
          this.failureReason = connections[index]!.failureReason ?? "connection closed";
          connections[index]!.close();
        }
        return results.some(Boolean);
      }
      await this.wait(Math.min(100, deadline - Date.now()), options.signal ?? this.stop.signal);
    }
    this.stop.signal.throwIfAborted();
    this.failureReason = "connection closed";
    return false;
  }

  async next(deadline: number, signal?: AbortSignal): Promise<string | null> {
    this.start();
    while (!this.stop.signal.aborted) {
      signal?.throwIfAborted();
      if (this.fault) throw this.fault;
      const raw = this.queue.shift(); if (raw !== undefined) return raw;
      if (Date.now() >= deadline) return null;
      await this.wait(deadline - Date.now(), signal ?? this.stop.signal);
    }
    return null;
  }

  close(): void {
    this.stop.abort();
    this.seed?.[1].close(); this.seed = undefined;
    for (const connection of this.connections.values()) connection.close();
    this.connections.clear(); this.queue.length = 0; this.wake();
  }
}
