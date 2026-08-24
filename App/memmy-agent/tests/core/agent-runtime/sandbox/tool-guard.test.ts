import { describe, expect, it } from "vitest";
import type { CapabilitySet } from "../../../../src/core/agent-runtime/sandbox/domain/capability.js";
import { decideToolAccess } from "../../../../src/core/agent-runtime/sandbox/guard/tool-guard.js";
import { resolvePolicy } from "../../../../src/core/agent-runtime/sandbox/policy/policy-resolver.js";

function capabilities(overrides: Partial<CapabilitySet> = {}): CapabilitySet {
  return {
    filesystem: overrides.filesystem ?? { read: ["/workspace"], write: ["/workspace"], deny: [] },
    network: overrides.network ?? { mode: "denied" },
    process:
      overrides.process ??
      ({
        spawn: "non-interactive",
        maxProcesses: 8,
        maxRuntimeMs: 60_000,
        maxOutputBytes: 1_000_000,
      } as const),
    environment: overrides.environment ?? { inherit: ["PATH"], set: {}, remove: [] },
    externalEffects: overrides.externalEffects ?? { maximum: "none" },
  };
}

function authorization(
  requestedCapabilities: Parameters<typeof resolvePolicy>[0]["requestedCapabilities"],
  overrides: Readonly<{
    policyCap?: CapabilitySet;
    baseGrant?: CapabilitySet;
    approvalChannel?: "desktop" | "none";
  }> = {},
) {
  return resolvePolicy({
    caps: [overrides.policyCap ?? capabilities()],
    baseGrants: [overrides.baseGrant ?? capabilities()],
    requestedCapabilities,
    entrypoint: {
      class: overrides.approvalChannel === "none" ? "background" : "interactive",
      projectId: "project-1",
      approvalChannel: overrides.approvalChannel ?? "desktop",
      executorId: "local",
    },
    workspaceProfile:
      overrides.approvalChannel === "none" ? "workspace-confidential" : "workspace-compatible",
    approvalMode: "on-request",
  });
}

describe("ToolGuard", () => {
  it("allows capabilities already covered by the base grant", () => {
    const auth = authorization([
      { kind: "filesystem", access: "write", path: "/workspace/src/index.ts" },
      { kind: "process", interactive: false, command: "npm test" },
    ]);

    expect(decideToolAccess(auth)).toEqual({ kind: "execute", authorization: auth });
  });

  it("asks only when the capability is inside policyCap", () => {
    const network = {
      mode: "allowlist" as const,
      targets: [{ host: "api.example.com", protocols: ["https" as const], ports: [443] }],
    };
    const auth = authorization(
      [{ kind: "network", host: "api.example.com", protocol: "https", port: 443 }],
      { policyCap: capabilities({ network }), baseGrant: capabilities() },
    );
    expect(decideToolAccess(auth)).toEqual({
      kind: "requires-approval",
      reason: "approval-required",
      authorization: auth,
      missingCapabilities: [
        { kind: "network", host: "api.example.com", protocol: "https", port: 443 },
      ],
    });
  });

  it("denies capabilities outside policyCap", () => {
    expect(
      decideToolAccess(
        authorization([{ kind: "filesystem", access: "read", path: "/etc/passwd" }]),
      ),
    ).toEqual({
      kind: "deny",
      reason: "exceeds-policy-cap",
      deniedCapabilities: [{ kind: "filesystem", access: "read", path: "/etc/passwd" }],
    });
  });

  it("turns Ask into Deny when the entrypoint has no trusted approval channel", () => {
    const network = {
      mode: "allowlist" as const,
      targets: [{ host: "api.example.com", protocols: ["https" as const], ports: [443] }],
    };
    expect(
      decideToolAccess(
        authorization(
          [{ kind: "network", host: "api.example.com", protocol: "https", port: 443 }],
          {
            policyCap: capabilities({ network }),
            baseGrant: capabilities(),
            approvalChannel: "none",
          },
        ),
      ),
    ).toEqual({
      kind: "deny",
      reason: "approval-not-allowed",
      deniedCapabilities: [
        { kind: "network", host: "api.example.com", protocol: "https", port: 443 },
      ],
    });
  });

  it("fails closed for unknown capabilities", () => {
    expect(
      decideToolAccess(authorization([{ kind: "unknown", name: "unregistered-tool" }])),
    ).toEqual({
      kind: "deny",
      reason: "unknown-capability",
      deniedCapabilities: [{ kind: "unknown", name: "unregistered-tool" }],
    });
  });
});
