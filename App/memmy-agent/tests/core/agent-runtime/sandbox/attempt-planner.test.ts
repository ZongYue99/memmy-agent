import { describe, expect, it } from "vitest";
import { attachApprovalGrantHash } from "../../../../src/core/agent-runtime/sandbox/approval/approval-grant.js";
import { AttemptPlanner } from "../../../../src/core/agent-runtime/sandbox/manager/attempt-planner.js";
import {
  applyApproval,
  resolvePolicy,
} from "../../../../src/core/agent-runtime/sandbox/policy/policy-resolver.js";
import { createWorkspacePreset } from "../../../../src/core/agent-runtime/sandbox/policy/presets.js";
import { stablePolicyHash } from "../../../../src/core/agent-runtime/sandbox/policy/policy-hash.js";

function authorization() {
  const preset = createWorkspacePreset({
    workspaceRoot: "/workspace/project",
    profile: "workspace-confidential",
    homeDirectory: "/Users/tester",
  });
  return resolvePolicy({
    caps: [preset],
    baseGrants: [preset],
    entrypoint: {
      class: "background",
      projectId: "project-1",
      approvalChannel: "none",
      executorId: "local",
    },
    workspaceProfile: "workspace-confidential",
    approvalMode: "never",
  });
}

function planner() {
  return new AttemptPlanner({ nextId: () => "attempt-1" }, { now: () => 1_800_000_000_000 });
}

function approvalAuthorization() {
  const preset = createWorkspacePreset({
    workspaceRoot: "/workspace/project",
    profile: "workspace-confidential",
    homeDirectory: "/Users/tester",
  });
  return resolvePolicy({
    caps: [preset],
    baseGrants: [preset],
    entrypoint: {
      class: "interactive",
      projectId: "project-1",
      approvalChannel: "desktop",
      executorId: "local",
    },
    workspaceProfile: "workspace-confidential",
    approvalMode: "on-request",
  });
}

function input(overrides: Record<string, unknown> = {}) {
  return {
    runtimeCallId: "call-1",
    call: { toolName: "exec", arguments: { command: "pwd" } },
    authorization: authorization(),
    sandboxType: "macos-seatbelt" as const,
    sandboxCwd: "/workspace/project",
    workspaceRoots: ["/workspace/project"],
    networkContextId: "network-1",
    ...overrides,
  };
}

describe("AttemptPlanner", () => {
  it("creates an immutable initial attempt bound to call and policy hashes", () => {
    const planned = planner().planInitial(input());

    expect(planned.attempt).toMatchObject({
      attemptId: "attempt-1",
      runtimeCallId: "call-1",
      argsHash: stablePolicyHash(planned.call),
      sandboxType: "macos-seatbelt",
      sandboxCwd: "/workspace/project",
      workspaceRoots: ["/workspace/project"],
      networkContextId: "network-1",
      createdAt: 1_800_000_000_000,
    });
    expect(planned.attempt).not.toHaveProperty("parentAttemptId");
    expect(planned.attempt.compiledPolicyHash).toBe(planned.attempt.permissionProfile.policyHash);
    expect(Object.isFrozen(planned)).toBe(true);
    expect(Object.isFrozen(planned.call.arguments)).toBe(true);
    expect(Object.isFrozen(planned.attempt)).toBe(true);
    expect(Object.isFrozen(planned.attempt.permissionProfile.filesystem)).toBe(true);
  });

  it("rejects mismatched or tampered permission profile hashes", () => {
    const resolved = authorization();
    expect(() =>
      planner().planInitial(
        input({
          authorization: { ...resolved, compiledPolicyHash: "wrong" },
        }),
      ),
    ).toThrow("compiled policy hash does not match permission profile");

    const clonedProfile = structuredClone(resolved.permissionProfile);
    const profile = {
      ...clonedProfile,
      process: {
        ...clonedProfile.process,
        maxProcesses: clonedProfile.process.maxProcesses + 1,
      },
    };
    expect(() =>
      planner().planInitial(
        input({
          authorization: { ...resolved, permissionProfile: profile },
        }),
      ),
    ).toThrow("permission profile hash verification failed");
  });

  it("rejects incompatible targets and working directories outside the workspace", () => {
    expect(() => planner().planInitial(input({ sandboxType: "disabled" }))).toThrow(
      "managed permission profile requires a managed sandbox type",
    );
    expect(() => planner().planInitial(input({ sandboxCwd: "/tmp/outside" }))).toThrow(
      "sandboxCwd must be inside a workspace root",
    );
  });

  it("binds Attempt #2 to its parent and prevents another retry", () => {
    let attempt = 0;
    const retryPlanner = new AttemptPlanner(
      { nextId: () => `attempt-${++attempt}` },
      { now: () => 1_800_000_000_000 + attempt },
    );
    const initialAuthorization = approvalAuthorization();
    const call = { toolName: "exec", arguments: { command: "pwd" } };
    const initial = retryPlanner.planInitial({
      runtimeCallId: "call-1",
      call,
      authorization: initialAuthorization,
      sandboxType: "macos-seatbelt",
      sandboxCwd: "/workspace/project",
      workspaceRoots: ["/workspace/project"],
      networkContextId: "network-1",
    });
    const grant = attachApprovalGrantHash({
      grantId: "grant-1",
      runtimeCallId: "call-1",
      argsHash: initial.attempt.argsHash,
      initialPolicyHash: initialAuthorization.initialPolicyHash,
      parentAttemptId: initial.attempt.attemptId,
      additionalPermission: [
        { kind: "filesystem", access: "read", path: "/workspace/project/shared.txt" },
      ],
      subjectId: "user-1",
      nonceHash: "nonce-hash",
      issuedAt: 1_000,
      expiresAt: 2_000,
      usage: "single-use",
    });
    const retryAuthorization = applyApproval(initialAuthorization, grant);
    const retry = retryPlanner.planRetry({
      parentAttempt: initial.attempt,
      call,
      authorization: retryAuthorization,
      approvalGrant: grant,
      sandboxType: "macos-seatbelt",
      networkContextId: "network-2",
    });

    expect(retry.attempt).toMatchObject({
      attemptId: "attempt-2",
      parentAttemptId: "attempt-1",
      approvalGrantHash: grant.approvalGrantHash,
      sandboxCwd: initial.attempt.sandboxCwd,
      workspaceRoots: initial.attempt.workspaceRoots,
    });
    expect(() =>
      retryPlanner.planRetry({
        parentAttempt: retry.attempt,
        call,
        authorization: retryAuthorization,
        approvalGrant: grant,
        sandboxType: "macos-seatbelt",
        networkContextId: "network-3",
      }),
    ).toThrow("a retry attempt cannot create another retry");
  });
});
