import dns from "node:dns/promises";
import net from "node:net";
import { Agent as UndiciAgent } from "undici";
import { isPrivateNetworkAddress } from "../../../../../security/network.js";
import type { NetworkCapability } from "../../domain/capability.js";
import { EgressGuard } from "../../guard/egress-guard.js";

export type EgressResponse = Readonly<{
  status: number;
  headers: Readonly<Record<string, string>>;
  body: Uint8Array;
}>;

type ResolvedAddress = Readonly<{ address: string; family: 4 | 6 }>;
type ResolveHost = (hostname: string) => Promise<readonly ResolvedAddress[]>;

type EgressClientOptions = Readonly<{
  resolve?: ResolveHost;
  fetchImpl?: typeof fetch;
  maxResponseBytes?: number;
  timeoutMs?: number;
}>;

const forbiddenRequestHeaders = new Set([
  "connection",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function validateHeaders(headers: Readonly<Record<string, string>> | undefined): void {
  for (const name of Object.keys(headers ?? {})) {
    if (forbiddenRequestHeaders.has(name.toLowerCase())) {
      throw new Error("egress-header-denied");
    }
  }
}

/** Performs public HTTP(S) requests through a policy check and a DNS-pinned socket. */
export class EgressClient {
  private readonly resolve: ResolveHost;
  private readonly fetchImpl: typeof fetch;
  private readonly maxResponseBytes: number;
  private readonly timeoutMs: number;

  constructor(
    private readonly guard = new EgressGuard(),
    options: EgressClientOptions = {},
  ) {
    this.resolve =
      options.resolve ??
      (async (hostname) =>
        (await dns.lookup(hostname, { all: true, verbatim: true })).map((entry) => ({
          address: entry.address,
          family: entry.family === 6 ? 6 : 4,
        })));
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.maxResponseBytes = options.maxResponseBytes ?? 4 * 1024 * 1024;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    if (!Number.isSafeInteger(this.maxResponseBytes) || this.maxResponseBytes <= 0) {
      throw new Error("maxResponseBytes must be a positive integer");
    }
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs <= 0) {
      throw new Error("timeoutMs must be a positive integer");
    }
  }

  async request(
    input: Readonly<{
      url: string;
      policy: NetworkCapability;
      method?: "GET" | "HEAD";
      headers?: Readonly<Record<string, string>>;
      abortSignal?: AbortSignal;
    }>,
  ): Promise<EgressResponse> {
    const authorization = this.guard.authorize(input.policy, input.url);
    validateHeaders(input.headers);
    const addresses = net.isIP(authorization.host)
      ? [{ address: authorization.host, family: net.isIP(authorization.host) as 4 | 6 }]
      : await this.resolve(authorization.host);
    if (!addresses.length) throw new Error("egress-dns-empty");
    if (addresses.some((entry) => isPrivateNetworkAddress(entry.address))) {
      throw new Error("egress-private-address-denied");
    }
    const pinned = addresses[0];
    const dispatcher = new UndiciAgent({
      connect: {
        lookup: (_hostname, _options, callback) => {
          callback(null, pinned.address, pinned.family);
        },
      },
    });
    const timeoutSignal = AbortSignal.timeout(this.timeoutMs);
    const signal = input.abortSignal
      ? AbortSignal.any([input.abortSignal, timeoutSignal])
      : timeoutSignal;
    try {
      const response = await this.fetchImpl(authorization.url, {
        method: input.method ?? "GET",
        headers: input.headers,
        redirect: "manual",
        signal,
        dispatcher,
      } as RequestInit & { dispatcher: UndiciAgent });
      const body = await this.readBody(response);
      return Object.freeze({
        status: response.status,
        headers: Object.freeze(Object.fromEntries(response.headers.entries())),
        body,
      });
    } finally {
      await dispatcher.close();
    }
  }

  private async readBody(response: Response): Promise<Uint8Array> {
    if (!response.body) return new Uint8Array();
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > this.maxResponseBytes) {
          await reader.cancel("egress-response-too-large");
          throw new Error("egress-response-too-large");
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const body = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return body;
  }
}
