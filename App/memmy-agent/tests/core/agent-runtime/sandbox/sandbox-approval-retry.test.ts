import { describe, expect, it, vi } from "vitest";
import { InMemoryApprovalGrantStore } from "../../../../src/core/agent-runtime/sandbox/adapters/approval/in-memory-approval-grant-store.js";
import { ApprovalBroker } from "../../../../src/core/agent-runtime/sandbox/approval/approval-broker.js";
import type { ApprovalRequest } from "../../../../src/core/agent-runtime/sandbox/approval/approval-grant.js";
import type { SandboxAuditEventDraft } from "../../../../src/core/agent-runtime/sandbox/domain/audit-event.js";
import type { NormalizedToolCall } from "../../../../src/core/agent-runtime/sandbox/domain/sandbox-attempt.js";
import type { SandboxExecutionOutcome } from "../../../../src/core/agent-runtime/sandbox/domain/sandbox-result.js";
import { AttemptPlanner } from "../../../../src/core/agent-runtime/sandbox/manager/attempt-planner.js";
import { SandboxManager } from "../../../../src/core/agent-runtime/sandbox/manager/sandbox-manager.js";
import { resolvePolicy } from "../../../../src/core/agent-runtime/sandbox/policy/policy-resolver.js";
import { createWorkspacePreset } from "../../../../src/core/agent-runtime/sandbox/policy/presets.js";
import type { SandboxExecutorPort } from "../../../../src/core/agent-runtime/sandbox/ports/sandbox-executor-port.js";

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

function deniedOutcome(): SandboxExecutionOutcome {
  return {
    kind: "denied",
    evidence: {
      source: "os-sandbox",
      operation: "file-read",
      requiredCapability: {
        kind: "filesystem",
        access: "read",
        path: "/workspace/shared.txt",
      },
      systemCode: "SEATBELT_DENY",
      summary: "macOS sandbox rejected a filesystem read",
      minimallySupplementable: true,
    },
  };
}

function completedOutcome(): SandboxExecutionOutcome {
  return {
    kind: "completed",
    result: {
      exitCode: 0,
      signal: null,
      stdoutSummary: "ok",
      stderrSummary: "",
      outputTruncated: false,
      startedAt: 100,
      completedAt: 200,
    },
  };
}

function executor(outcomes: readonly SandboxExecutionOutcome[]) {
  let index = 0;
  const observedCalls: NormalizedToolCall[] = [];
  return {
    observedCalls,
    selectTarget: vi.fn(() => ({
      sandboxType: "macos-seatbelt" as const,
    })),
    start: vi.fn((input: Parameters<SandboxExecutorPort["start"]>[0]) => {
      observedCalls.push(input.call);
      const outcome = outcomes[index++];
      if (!outcome) throw new Error("unexpected sandbox execution");
      return {
        processHandle: `process-${index}`,
        completion: Promise.resolve(outcome),
        cancel: async () => {},
      };
    }),
  };
}

function harness(
  sandboxExecutor: SandboxExecutorPort,
  onApproval?: (request: ApprovalRequest) => void,
) {
  let now = 1_800_000_000_000;
  let attempt = 0;
  const clock = { now: () => now++ };
  const ids = {
    nextId: (kind: "attempt" | "approval-request" | "approval-grant" | "audit") =>
      kind === "attempt" ? `attempt-${++attempt}` : `${kind}-1`,
  };
  const audit = {
    record: vi.fn(async (draft: SandboxAuditEventDraft) => {
      void draft;
    }),
  };
  const channel = {
    requestApproval: vi.fn(async (request: ApprovalRequest) => {
      onApproval?.(request);
      return {
        kind: "approved" as const,
        requestId: request.requestId,
        subjectId: request.subjectId,
        nonce: request.nonce,
      };
    }),
  };
  const store = new InMemoryApprovalGrantStore();
  const broker = new ApprovalBroker({
    audit,
    channel,
    store,
    ids,
    clock,
    nonce: () => "nonce-1",
  });
  return {
    manager: new SandboxManager(new AttemptPlanner(ids, clock), sandboxExecutor, clock, {
      audit,
      approvalRetry: { broker },
    }),
    audit,
    channel,
    store,
  };
}

function runInput(
  call: NormalizedToolCall,
  overrides: Readonly<{
    resolveCurrentAuthorization?: () => ReturnType<typeof authorization>;
    abortSignal?: AbortSignal;
  }> = {},
) {
  const initialAuthorization = authorization();
  return {
    runtimeCallId: "call-1",
    call,
    authorization: initialAuthorization,
    resolveCurrentAuthorization:
      overrides.resolveCurrentAuthorization ?? (() => initialAuthorization),
    approvalSubjectId: "user-1",
    sandboxCwd: "/workspace/project",
    workspaceRoots: ["/workspace/project"],
    ...(overrides.abortSignal ? { abortSignal: overrides.abortSignal } : {}),
  };
}

describe("SandboxManager approval retry", () => {
  it("creates one approval-bound Attempt #2 with unchanged arguments", async () => {
    const sandboxExecutor = executor([deniedOutcome(), completedOutcome()]);
    const { manager, audit, channel, store } = harness(sandboxExecutor);
    const consume = vi.spyOn(store, "consume");
    const call = { toolName: "exec", arguments: { command: "cat /workspace/shared.txt" } };

    const chain = await manager.runWithApprovalRetry(runInput(call));

    expect(chain.retry).toEqual({ kind: "retry-attempted" });
    expect(channel.requestApproval).toHaveBeenCalledOnce();
    expect(consume).toHaveBeenCalledOnce();
    expect(sandboxExecutor.start).toHaveBeenCalledTimes(2);
    expect(chain.attempts.map(({ attempt }) => attempt.attemptId)).toEqual([
      "attempt-1",
      "attempt-2",
    ]);
    expect(chain.attempts[1].attempt).toMatchObject({
      parentAttemptId: "attempt-1",
      argsHash: chain.attempts[0].attempt.argsHash,
    });
    expect(chain.attempts[1].attempt.approvalGrantHash).toBeTruthy();
    expect(sandboxExecutor.observedCalls[1]).toEqual(sandboxExecutor.observedCalls[0]);
    expect(chain.attempts[1].attempt.permissionProfile.filesystem).toMatchObject({
      kind: "restricted",
      entries: expect.arrayContaining([
        expect.objectContaining({ path: "/workspace/shared.txt", access: "read" }),
      ]),
    });
    expect(audit.record.mock.calls.map(([draft]) => draft.detail.kind)).toEqual([
      "attempt-finished",
      "approval-requested",
      "approval-decided",
      "approval-grant-issued",
      "retry-planned",
      "approval-grant-consumed",
      "attempt-finished",
    ]);
  });

  it("never creates Attempt #3 when Attempt #2 is also denied", async () => {
    const sandboxExecutor = executor([deniedOutcome(), deniedOutcome()]);
    const { manager } = harness(sandboxExecutor);

    const chain = await manager.runWithApprovalRetry(
      runInput({ toolName: "exec", arguments: { command: "cat /workspace/shared.txt" } }),
    );

    expect(chain.retry).toEqual({ kind: "retry-attempted" });
    expect(chain.attempts).toHaveLength(2);
    expect(chain.attempts[1].stateHistory.at(-1)?.state.kind).toBe("denied");
    expect(sandboxExecutor.start).toHaveBeenCalledTimes(2);
  });

  it("rejects the retry when policy changes while approval is pending", async () => {
    const sandboxExecutor = executor([deniedOutcome()]);
    const { manager, store } = harness(sandboxExecutor);
    const revoke = vi.spyOn(store, "revoke");

    const chain = await manager.runWithApprovalRetry(
      runInput(
        { toolName: "exec", arguments: { command: "cat /workspace/shared.txt" } },
        { resolveCurrentAuthorization: () => authorization("never") },
      ),
    );

    expect(chain.retry).toEqual({ kind: "not-retried", reason: "policy-changed" });
    expect(revoke).toHaveBeenCalledOnce();
    expect(sandboxExecutor.start).toHaveBeenCalledOnce();
  });

  it("does not start Attempt #2 when atomic grant consumption fails", async () => {
    const sandboxExecutor = executor([deniedOutcome()]);
    const { manager, store } = harness(sandboxExecutor);
    vi.spyOn(store, "consume").mockResolvedValue(null);

    const chain = await manager.runWithApprovalRetry(
      runInput({ toolName: "exec", arguments: { command: "cat /workspace/shared.txt" } }),
    );

    expect(chain.retry).toEqual({
      kind: "not-retried",
      reason: "grant-consumption-failed",
    });
    expect(chain.attempts).toHaveLength(1);
    expect(sandboxExecutor.start).toHaveBeenCalledOnce();
  });

  it("revokes the grant when cancellation wins before consumption", async () => {
    const controller = new AbortController();
    const sandboxExecutor = executor([deniedOutcome()]);
    sandboxExecutor.selectTarget.mockImplementationOnce(() => ({
      sandboxType: "macos-seatbelt",
    }));
    sandboxExecutor.selectTarget.mockImplementationOnce(() => {
      controller.abort();
      return { sandboxType: "macos-seatbelt" };
    });
    const { manager, store } = harness(sandboxExecutor);
    const consume = vi.spyOn(store, "consume");
    const revoke = vi.spyOn(store, "revoke");

    const chain = await manager.runWithApprovalRetry(
      runInput(
        { toolName: "exec", arguments: { command: "cat /workspace/shared.txt" } },
        { abortSignal: controller.signal },
      ),
    );

    expect(chain.retry).toEqual({ kind: "not-retried", reason: "approval-cancelled" });
    expect(revoke).toHaveBeenCalledOnce();
    expect(consume).not.toHaveBeenCalled();
    expect(sandboxExecutor.start).toHaveBeenCalledOnce();
  });

  it("rejects retry when the original call arguments change after Attempt #1", async () => {
    const sandboxExecutor = executor([deniedOutcome()]);
    const call = { toolName: "exec", arguments: { command: "cat /workspace/shared.txt" } };
    const { manager, store } = harness(sandboxExecutor, () => {
      call.arguments.command = "cat /outside/secret";
    });
    const revoke = vi.spyOn(store, "revoke");

    const chain = await manager.runWithApprovalRetry(runInput(call));

    expect(chain.retry).toEqual({ kind: "not-retried", reason: "retry-plan-invalid" });
    expect(revoke).toHaveBeenCalledOnce();
    expect(sandboxExecutor.start).toHaveBeenCalledOnce();
  });

  it("does not consume the grant when the retry plan cannot be audited", async () => {
    const sandboxExecutor = executor([deniedOutcome()]);
    const { manager, audit, store } = harness(sandboxExecutor);
    audit.record.mockImplementation(async (draft) => {
      if (draft.detail.kind === "retry-planned") throw new Error("audit unavailable");
    });
    const consume = vi.spyOn(store, "consume");
    const revoke = vi.spyOn(store, "revoke");

    const chain = await manager.runWithApprovalRetry(
      runInput({ toolName: "exec", arguments: { command: "cat /workspace/shared.txt" } }),
    );

    expect(chain.retry).toEqual({ kind: "not-retried", reason: "audit-unavailable" });
    expect(revoke).toHaveBeenCalledOnce();
    expect(consume).not.toHaveBeenCalled();
    expect(sandboxExecutor.start).toHaveBeenCalledOnce();
  });

  it("does not start Attempt #2 when grant consumption cannot be audited", async () => {
    const sandboxExecutor = executor([deniedOutcome()]);
    const { manager, audit, store } = harness(sandboxExecutor);
    audit.record.mockImplementation(async (draft) => {
      if (draft.detail.kind === "approval-grant-consumed") {
        throw new Error("audit unavailable");
      }
    });
    const consume = vi.spyOn(store, "consume");

    const chain = await manager.runWithApprovalRetry(
      runInput({ toolName: "exec", arguments: { command: "cat /workspace/shared.txt" } }),
    );

    expect(chain.retry).toEqual({ kind: "not-retried", reason: "audit-unavailable" });
    expect(consume).toHaveBeenCalledOnce();
    expect(sandboxExecutor.start).toHaveBeenCalledOnce();
  });
});
