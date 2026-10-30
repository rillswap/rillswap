/**
 * Minimal NIP-01 relay client for one swap: publish with OK confirmation,
 * one live subscription, and one bounded one-shot query. Frames over the
 * size cap are dropped; nothing received is trusted before verification.
 */
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";
import type { NostrEvent } from "nostr-tools";

import { isOnionRelay } from "./publicRelays";
import type { PublicationOptions, RelayLink } from "./session";
import { LiveRelayLink } from "./liveRelayLink";

const MAX_FRAME_BYTES = 128 * 1024;
const MAX_QUEUE = 1024;
const PUBLISH_TIMEOUT_MS = 10_000;
const SOCKET_OPEN = 1;
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

export class RelayError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RelayError";
  }
}

/** wss:// anywhere; plain ws:// only to a loopback relay (local regtest) or a v3 onion relay. */
export function checkRelayUrl(text: string): string {
  let url: URL;
  try {
    url = new URL(text.trim());
  } catch {
    throw new RelayError("relay URL is not a URL");
  }
  if (url.protocol === "wss:" || (url.protocol === "ws:" && (LOOPBACK.has(url.hostname) || isOnionRelay(url.href)))) {
    return url.toString();
  }
  throw new RelayError("relay URL must use wss:// (ws:// only for a loopback or onion relay)");
}

type Waiter = () => void;
export type QueryCompletion = "eose" | "timeout" | "closed" | "error" | "limit";
export interface RelayQueryResult {
  readonly events: string[];
  readonly truncated: boolean;
  readonly completion: QueryCompletion;
}

export class RelayConnection implements RelayLink {
  readonly guardedPublication = true;
  private readonly queue: string[] = [];
  private readonly waiters = new Set<Waiter>();
  private readonly acks = new Map<string, (ok: boolean) => void>();
  private readonly queries = new Map<string, { events: string[]; done: (reason: QueryCompletion) => void; limit: number }>();
  private live: string | null = null;
  private closed = false;
  failureReason: string | undefined;

  get isClosed(): boolean { return this.closed; }

  private constructor(private readonly socket: WebSocket) {
    socket.addEventListener("message", (message) => this.onMessage(message.data));
    socket.addEventListener("close", () => {
      this.closed = true;
      this.failureReason ??= "connection closed";
      for (const resolve of this.acks.values()) resolve(false);
      for (const query of this.queries.values()) query.done("closed");
      this.wake();
    });
  }

  static open(url: string, timeoutMs = 10_000, factory = (target: string) => new WebSocket(target), signal?: AbortSignal):
    Promise<RelayConnection> {
    if (signal?.aborted) return Promise.reject(new DOMException("Quote search canceled", "AbortError"));
    const socket = factory(checkRelayUrl(url));
    return new Promise((resolve, reject) => {
      let opened = false;
      const abort = (): void => {
        clearTimeout(timer);
        reject(new DOMException("Quote search canceled", "AbortError"));
        socket.close();
      };
      const timer = setTimeout(() => {
        socket.close();
        reject(new RelayError("relay connection timed out"));
      }, timeoutMs);
      signal?.addEventListener("abort", abort, { once: true });
      socket.addEventListener("close", () => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", abort);
        if (!opened) reject(new RelayError("relay closed before connecting"));
      });
      socket.addEventListener("open", () => {
        clearTimeout(timer);
        if (signal?.aborted) { abort(); return; }
        opened = true;
        resolve(new RelayConnection(socket));
      });
      socket.addEventListener("error", () => {
        clearTimeout(timer);
        socket.close();
        reject(new RelayError("relay connection failed"));
      });
    });
  }

  close(): void {
    this.socket.close();
  }

  resilient(url: string, alternatives: readonly string[]): LiveRelayLink {
    return new LiveRelayLink(checkRelayUrl(url), this, alternatives.map(checkRelayUrl),
      (target, signal) => RelayConnection.open(target, 5000, undefined, signal));
  }

  private wake(): void {
    for (const waiter of [...this.waiters]) waiter();
  }

  private onMessage(data: unknown): void {
    if (typeof data !== "string" || new TextEncoder().encode(data).length > MAX_FRAME_BYTES) return;
    let frame: unknown;
    try {
      frame = JSON.parse(data);
    } catch {
      return;
    }
    if (!Array.isArray(frame)) return;
    const [type, first, second] = frame as unknown[];
    if (type === "OK" && typeof first === "string") {
      if (second !== true) this.failureReason = "publication rejected";
      this.acks.get(first)?.(second === true);
      this.acks.delete(first);
    } else if (type === "EVENT" && typeof first === "string" && second !== null && typeof second === "object") {
      const raw = JSON.stringify(second);
      const query = this.queries.get(first);
      if (query) {
        query.events.push(raw);
        if (query.events.length > query.limit) query.done("limit");
      } else if (first === this.live && this.queue.length < MAX_QUEUE) {
        this.queue.push(raw);
        this.wake();
      }
    } else if ((type === "EOSE" || type === "CLOSED") && typeof first === "string") {
      this.queries.get(first)?.done(type === "EOSE" ? "eose" : "closed");
      // CLOSED is a rejected subscription, not a healthy live mailbox. EOSE is not closure.
      if (type === "CLOSED" && first === this.live) { this.failureReason = "subscription closed"; this.close(); }
    }
  }

  private send(frame: unknown[]): void {
    if (this.closed) throw new RelayError("relay connection closed");
    this.socket.send(JSON.stringify(frame));
  }

  publish(event: NostrEvent, options: PublicationOptions = {}): Promise<boolean> {
    options.signal?.throwIfAborted();
    if (this.closed || (typeof this.socket.readyState === "number" && this.socket.readyState !== SOCKET_OPEN)) {
      this.failureReason = "connection closed"; return Promise.resolve(false);
    }
    options.beforePublish?.();
    return new Promise((resolve) => {
      const finish = (ok: boolean): void => {
        clearTimeout(timer); options.signal?.removeEventListener("abort", abort);
        this.acks.delete(event.id); resolve(ok);
      };
      const abort = (): void => finish(false);
      const timer = setTimeout(() => {
        this.failureReason = "publication timed out";
        finish(false);
      }, options.timeoutMs ?? PUBLISH_TIMEOUT_MS);
      options.signal?.addEventListener("abort", abort, { once: true });
      this.acks.set(event.id, finish);
      try {
        this.send(["EVENT", event]);
      } catch {
        this.failureReason = "connection closed";
        this.acks.get(event.id)?.(false);
      }
    });
  }

  async subscribe(filter: Record<string, unknown>): Promise<void> {
    if (this.live !== null) this.send(["CLOSE", this.live]);
    this.live = bytesToHex(randomBytes(8));
    this.queue.length = 0;
    this.send(["REQ", this.live, filter]);
  }

  async next(deadline: number, signal?: AbortSignal): Promise<string | null> {
    for (;;) {
      signal?.throwIfAborted();
      const item = this.queue.shift();
      if (item !== undefined) return item;
      const remaining = deadline - Date.now();
      if (this.closed || remaining <= 0) return null;
      await new Promise<void>((resolve) => {
        const waiter = (): void => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", waiter);
          this.waiters.delete(waiter);
          resolve();
        };
        const timer = setTimeout(waiter, remaining);
        this.waiters.add(waiter);
        signal?.addEventListener("abort", waiter, { once: true });
      });
    }
  }

  /**
   * Stored events for `filter` until EOSE or the timeout. More than `limit`
   * events ends the query with `truncated` so a caller can refuse a flood.
   */
  async query(filter: Record<string, unknown>, limit: number, timeoutMs = 10_000):
    Promise<{ events: string[]; truncated: boolean }> {
    const { events, truncated } = await this.queryDetailed(filter, limit, timeoutMs);
    return { events, truncated };
  }

  /** Marketplace discovery also needs to distinguish partial and complete responses. */
  queryDetailed(filter: Record<string, unknown>, limit: number, timeoutMs = 10_000):
    Promise<RelayQueryResult> {
    const id = bytesToHex(randomBytes(8));
    return new Promise((resolve) => {
      const events: string[] = [];
      const done = (completion: QueryCompletion): void => {
        clearTimeout(timer);
        if (!this.queries.delete(id)) return;
        try {
          if (!this.closed) this.socket.send(JSON.stringify(["CLOSE", id]));
        } catch { /* Query evidence remains partial if the transport is lost. */ }
        resolve({ events: events.slice(0, limit), truncated: events.length > limit, completion });
      };
      const timer = setTimeout(() => done("timeout"), timeoutMs);
      this.queries.set(id, { events, done, limit });
      try {
        this.send(["REQ", id, filter]);
      } catch {
        done("error");
      }
    });
  }
}
