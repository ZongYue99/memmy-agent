import { describe, expect, it } from "vitest";
import { attachApprovalGrantHash } from "../../../../src/core/agent-runtime/sandbox/approval/approval-grant.js";
import type { SandboxExecutionRecord } from "../../../../src/core/agent-runtime/sandbox/domain/sandbox-attempt.js";
import { RetryController } from "../../../../src/core/agent-runtime/sandbox/manager/retry-controller.js";
import { capabilitySetAllows } from "../../../../src/core/agent-runtime/sandbox/policy/policy-cap.js";
import {
  applyApproval,
  resolvePolicy,
} from "../../../../src/core/agent-runtime/sandbox/policy/policy-resolver.js";
import { createWorkspacePreset } from "../../../../src/core/agent-runtime/sandbox/policy/presets.js";

function authorization(approvalMode: "never" | "on-request" = "on-request") {
  const cap = createWorkspacePreset({
    workspaceRoot: "/workspace",
    profile: "workspace-confidential",
    homeDirectory: "/Users/tester",
  });
  const baseGrant = createWorkspacePreset({
    workspaceRoot: "/workspace/project",
    profile: "workspace-confidential",
    homeDirectory: "/Users/tester",
  });
  return resolvePolicy({
    caps: [cap],
    baseGrants: [baseGrant],
    entrypoint: {
      class: "interactive",
      projectId: "project-1",
      approvalChannel: "desktop",
      executorId: "local",
    },
    workspaceProfile: "workspace-confidential",
    approvalMode,
  });
}

function grant(path: string) {
  const initial = authorization();
  return attachApprovalGrantHash({
    grantId: "grant-1",
    runtimeCallId: "call-1",
    argsHash: "args-hash",
    initialPolicyHash: initial.initialPolicyHash,
    parentAttemptId: "attempt-1",
    additionalPermission: [{ kind: "filesystem", access: "read", path }],
    subjectId: "user-1",
    nonceHash: "nonce-hash",
    issuedAt: 1_000,
    expiresAt: 2_000,
    usage: "single-use",
  });
}

function deniedRecord(
  path: string,
  options: Readonly<{ parentAttemptId?: string; minimallySupplementable?: boolean }> = {},
): SandboxExecutionRecord {
  const resolved = authorization();
  return {
    attempt: {
      attemptId: "attempt-1",
      ...(options.parentAttemptId ? { parentAttemptId: options.parentAttemptId } : {}),
      runtimeCallId: "call-1",
      argsHash: "args-hash",
      permissionProfile: resolved.permissionProfile,
      compiledPolicyHash: resolved.compiledPolicyHash,
      sandboxType: "macos-seatbelt",
      sandboxCwd: "/workspace/project",
      workspaceRoots: ["/workspace/project"],
      networkContextId: "network-1",
      createdAt: 900,
    },
    stateHistory: [
      {
        attemptId: "attempt-1",
        observedAt: 1_000,
        state: {
          kind: "denied",
          evidence: {
            source: "os-sandbox",
            operation: "file-read",
            requiredCapability: { kind: "filesystem", access: "read", path },
            summary: "sandbox denied a read",
            minimallySupplementable: options.minimallySupplementable ?? true,
          },
        },
      },
    ],
  };
}

describe("approval policy", () => {
  it("adds only the approved filesystem access and recompiles the profile", () => {
    const initial = authorization();
    const approved = applyApproval(initial, grant("/workspace/shared.txt"));

    expect(
      capabilitySetAllows(approved.baseGrant, {
        kind: "filesystem",
        access: "read",
        path: "/workspace/shared.txt",
      }),
    ).toBe(true);
    expect(approved.initialPolicyHash).toBe(initial.initialPolicyHash);
    expect(approved.compiledPolicyHash).not.toBe(initial.compiledPolicyHash);
    expect(initial.baseGrant.filesystem.read).not.toContain("/workspace/shared.txt");
  });

  it("rejects grants outside policyCap or after approval policy changes", () => {
    expect(() => applyApproval(authorization(), grant("/outside/secret"))).toThrow(
      "approval grant exceeds the current policy cap",
    );
    expect(authorization("never").initialPolicyHash).not.toBe(authorization().initialPolicyHash);
    expect(() => applyApproval(authorization("never"), grant("/workspace/shared.txt"))).toThrow(
      "approval grant does not match the current policy",
    );
  });

  it("allows one minimal retry but rejects an Attempt #3 or capability outside policyCap", () => {
    const controller = new RetryController();

    expect(controller.evaluate(deniedRecord("/workspace/shared.txt"), authorization())).toEqual({
      kind: "eligible",
      additionalPermission: [{ kind: "filesystem", access: "read", path: "/workspace/shared.txt" }],
    });
    expect(
      controller.evaluate(
        deniedRecord("/workspace/shared.txt", { parentAttemptId: "attempt-0" }),
        authorization(),
      ),
    ).toEqual({ kind: "not-eligible", reason: "already-retried" });
    expect(controller.evaluate(deniedRecord("/outside/secret"), authorization())).toEqual({
      kind: "not-eligible",
      reason: "exceeds-policy-cap",
    });
    const mismatched = deniedRecord("/workspace/shared.txt");
    expect(
      controller.evaluate(
        {
          ...mismatched,
          attempt: { ...mismatched.attempt, compiledPolicyHash: "different-policy" },
        },
        authorization(),
      ),
    ).toEqual({ kind: "not-eligible", reason: "authorization-mismatch" });
  });
});
