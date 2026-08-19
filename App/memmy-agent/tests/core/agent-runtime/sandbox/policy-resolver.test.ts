import path from "node:path";
import { describe, expect, it } from "vitest";
import type { CapabilitySet } from "../../../../src/core/agent-runtime/sandbox/domain/capability.js";
import { stablePolicyHash } from "../../../../src/core/agent-runtime/sandbox/policy/policy-hash.js";
import { resolvePolicy } from "../../../../src/core/agent-runtime/sandbox/policy/policy-resolver.js";

function capabilities(overrides: Partial<CapabilitySet> = {}): CapabilitySet {
  return {
    filesystem: overrides.filesystem ?? { read: ["/"], write: ["/"], deny: [] },
    network: overrides.network ?? { mode: "unrestricted" },
    process:
      overrides.process ??
      ({
        spawn: "interactive",
        maxProcesses: 32,
        maxRuntimeMs: 60_000,
        maxOutputBytes: 1_000_000,
      } as const),
    environment: overrides.environment ?? { inherit: ["PATH", "LANG"], set: {}, remove: [] },
    resources: overrides.resources ?? [
      "browser",
      "stdio-mcp",
      "http-mcp",
      "plugin-worker",
      "memory-writer",
      "exec-session",
      "goal",
      "cron",
    ],
    externalEffects: overrides.externalEffects ?? { maximum: "irreversible" },
  };
}

const entrypoint = {
  class: "interactive",
  projectId: "project-1",
  approvalChannel: "desktop",
  executorId: "local",
} as const;

describe("PolicyResolver", () => {
  it("intersects caps, constrains the base grant, and compiles a hashed profile", () => {
    const workspace = path.resolve("/workspace/project");
    const result = resolvePolicy({
      caps: [
        capabilities(),
        capabilities({
          filesystem: { read: ["/workspace"], write: [workspace], deny: ["/workspace/.env"] },
          network: {
            mode: "allowlist",
            targets: [
              { host: "api.example.com", protocols: ["https"], ports: [443] },
              { host: "docs.example.com", protocols: ["https"], ports: [443] },
            ],
          },
          resources: ["browser", "stdio-mcp"],
        }),
      ],
      baseGrants: [
        capabilities({
          filesystem: { read: [workspace], write: ["/"], deny: [] },
          network: {
            mode: "allowlist",
            targets: [{ host: "api.example.com", protocols: ["https"], ports: [443] }],
          },
          resources: ["browser", "memory-writer"],
        }),
      ],
      entrypoint,
      workspaceProfile: "workspace-compatible",
      approvalMode: "on-request",
    });

    expect(result.policyCap.filesystem).toEqual({
      read: [path.resolve("/workspace")],
      write: [workspace],
      deny: [path.resolve("/workspace/.env")],
    });
    expect(result.baseGrant.filesystem).toEqual({
      read: [workspace],
      write: [workspace],
      deny: [path.resolve("/workspace/.env")],
    });
    expect(result.permissionProfile).toMatchObject({
      version: 1,
      type: "managed",
      filesystem: { kind: "restricted" },
    });
    expect(result.compiledPolicyHash).toBe(result.permissionProfile.policyHash);
    const { policyHash, ...unhashedProfile } = result.permissionProfile;
    expect(policyHash).toBe(stablePolicyHash(unhashedProfile));
  });

  it("rejects an empty cap chain", () => {
    expect(() =>
      resolvePolicy({
        caps: [],
        baseGrants: [capabilities()],
        entrypoint,
        workspaceProfile: "workspace-compatible",
        approvalMode: "never",
      }),
    ).toThrow("caps must contain at least one capability set");
  });
});
