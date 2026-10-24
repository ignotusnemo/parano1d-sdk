import type { CallOptions, RpcTransport } from "./types.js";

export class RpcError extends Error {
  constructor(public readonly code: number, message: string, public readonly data?: unknown) {
    super(message);
    this.name = "RpcError";
  }
}

export class StateChangedError extends RpcError {
  constructor(message: string, data?: unknown) {
    super(-32041, message, data);
    this.name = "StateChangedError";
  }
}

export class ProtocolError extends Error {
  constructor(message: string) { super(message); this.name = "ProtocolError"; }
}

export interface JsonRpcOptions {
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
  headers?: HeadersInit;
}

export class JsonRpcTransport implements RpcTransport {
  private nextId = 0n;
  private readonly fetcher: typeof globalThis.fetch;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly headers: Headers;
  readonly url: string;

  constructor(url: string | URL, options: JsonRpcOptions = {}) {
    const parsed = new URL(url);
    const loopback = parsed.hostname === "localhost" || parsed.hostname === "[::1]" || /^127\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}$/.test(parsed.hostname);
    if (parsed.username || parsed.password || (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback))) {
      throw new TypeError("Use HTTPS, or loopback HTTP for a local node");
    }
    this.url = parsed.href;
    this.fetcher = (options.fetch ?? globalThis.fetch).bind(globalThis);
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.maxResponseBytes = options.maxResponseBytes ?? 8 * 1024 * 1024;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || !Number.isSafeInteger(this.maxResponseBytes) || this.maxResponseBytes < 1) {
      throw new RangeError("Invalid transport resource limits");
    }
    this.headers = new Headers(options.headers);
    this.headers.set("Content-Type", "application/json");
    this.headers.set("Accept", "application/json");
  }

  async call(method: string, params: readonly unknown[], options: CallOptions = {}): Promise<unknown> {
    if (!/^paranoid_[A-Za-z][A-Za-z0-9]*$/.test(method)) throw new TypeError("Invalid RPC method");
    const id = (++this.nextId).toString();
    const controller = new AbortController();
    const cancel = () => controller.abort(options.signal?.reason);
    if (options.signal?.aborted) cancel();
    else options.signal?.addEventListener("abort", cancel, { once: true });
    const timer = setTimeout(() => controller.abort(new Error("RPC timed out")), this.timeoutMs);
    try {
      const response = await this.fetcher(this.url, {
        method: "POST", headers: this.headers, credentials: "omit", redirect: "error",
        body: JSON.stringify({ jsonrpc: "2.0", id, method, params }), signal: controller.signal,
      });
      if (!response.ok) throw new ProtocolError(`RPC HTTP ${response.status}`);
      if (!response.body) throw new ProtocolError("Empty RPC response");
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let length = 0;
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          length += value.byteLength;
          if (length > this.maxResponseBytes) {
            await reader.cancel();
            throw new ProtocolError("RPC response exceeds its byte limit");
          }
          chunks.push(value);
        }
      } finally { reader.releaseLock(); }
      const bytes = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      let result: unknown;
      try { result = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
      catch { throw new ProtocolError("Invalid JSON RPC response"); }
      if (!result || typeof result !== "object" || Array.isArray(result)) throw new ProtocolError("Invalid RPC envelope");
      const envelope = result as Record<string, unknown>;
      if (envelope.jsonrpc !== "2.0" || envelope.id !== id || (("error" in envelope) === ("result" in envelope))) {
        throw new ProtocolError("RPC envelope does not match its request");
      }
      if ("error" in envelope) {
        const error = envelope.error as Record<string, unknown> | null;
        if (!error || !Number.isSafeInteger(error.code) || typeof error.message !== "string") throw new ProtocolError("Invalid RPC error");
        if (error.code === -32041) throw new StateChangedError(error.message, error.data);
        throw new RpcError(error.code as number, error.message, error.data);
      }
      return envelope.result;
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", cancel);
    }
  }
}
