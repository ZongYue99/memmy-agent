import type { NetworkCapability } from "../domain/capability.js";
import { normalizeNetworkHost } from "../../../../security/network.js";

export type EgressAuthorization = Readonly<{
  url: URL;
  host: string;
  protocol: "http" | "https";
  port: number;
}>;

function defaultPort(protocol: "http" | "https"): number {
  return protocol === "https" ? 443 : 80;
}

/** Applies the effective network profile before DNS resolution or socket creation. */
export class EgressGuard {
  authorize(policy: NetworkCapability, rawUrl: string): EgressAuthorization {
    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch {
      throw new Error("egress-invalid-url");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("egress-protocol-denied");
    }
    if (url.username || url.password) throw new Error("egress-credentials-denied");
    const protocol = url.protocol.slice(0, -1) as "http" | "https";
    const host = normalizeNetworkHost(url.hostname);
    const port = url.port ? Number(url.port) : defaultPort(protocol);
    if (!host || !Number.isSafeInteger(port) || port < 1 || port > 65_535) {
      throw new Error("egress-target-invalid");
    }
    if (policy.mode === "denied") throw new Error("egress-policy-denied");
    if (policy.mode === "allowlist") {
      const allowed = policy.targets.some(
        (target) =>
          normalizeNetworkHost(target.host) === host &&
          target.protocols.includes(protocol) &&
          target.ports.includes(port),
      );
      if (!allowed) throw new Error("egress-target-not-allowlisted");
    }
    return Object.freeze({ url, host, protocol, port });
  }
}
