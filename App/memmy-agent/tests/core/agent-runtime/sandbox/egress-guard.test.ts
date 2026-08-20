import { describe, expect, it } from "vitest";
import { EgressGuard } from "../../../../src/core/agent-runtime/sandbox/guard/egress-guard.js";

const allowlist = {
  mode: "allowlist" as const,
  targets: [{ host: "Example.COM", protocols: ["https" as const], ports: [443] }],
};

describe("EgressGuard", () => {
  it("denies all targets when network access is disabled", () => {
    expect(() =>
      new EgressGuard().authorize({ mode: "denied" }, "https://example.com/data"),
    ).toThrow("egress-policy-denied");
  });

  it("requires an exact allowlisted host, protocol, and port", () => {
    expect(new EgressGuard().authorize(allowlist, "https://example.com/data")).toMatchObject({
      host: "example.com",
      protocol: "https",
      port: 443,
    });
    expect(() => new EgressGuard().authorize(allowlist, "https://api.example.com/data")).toThrow(
      "egress-target-not-allowlisted",
    );
    expect(() => new EgressGuard().authorize(allowlist, "https://example.com:8443/data")).toThrow(
      "egress-target-not-allowlisted",
    );
  });

  it("rejects embedded credentials and non-HTTP protocols", () => {
    const guard = new EgressGuard();
    expect(() =>
      guard.authorize({ mode: "unrestricted" }, "https://user:secret@example.com"),
    ).toThrow("egress-credentials-denied");
    expect(() => guard.authorize({ mode: "unrestricted" }, "file:///etc/passwd")).toThrow(
      "egress-protocol-denied",
    );
  });
});
