import { describe, expect, it, vi } from "vitest";
import type { SandboxExecutionOutcome } from "../../../../src/core/agent-runtime/sandbox/domain/sandbox-result.js";
import { AttemptPlanner } from "../../../../src/core/agent-runtime/sandbox/manager/attempt-planner.js";
import {
  SandboxManager,
  SandboxManagerError,
} from "../../../../src/core/agent-runtime/sandbox/manager/sandbox-manager.js";
import { resolvePolicy } from "../../../../src/core/agent-runtime/sandbox/policy/policy-resolver.js";
import { createWorkspacePreset } from "../../../../src/core/agent-runtime/sandbox/policy/presets.js";
import type {
  SandboxExecutionHandle,
  SandboxExecutorPort,
} from "../../../../src/core/agent-runtime/sandbox/ports/sandbox-executor-port.js";

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
      evidenceRefs: [],
    },
  };
}

function executor(handle: SandboxExecutionHandle): SandboxExecutorPort & {
  selectTarget: ReturnType<typeof vi.fn>;
  start: ReturnType<typeof vi.fn>;
} {
  return {
    selectTarget: vi.fn(() => ({
      sandboxType: "macos-seatbelt" as const,
      networkContextId: "network-1",
    })),
    start: vi.fn(() => handle),
  };
}

function manager(sandboxExecutor: SandboxExecutorPort) {
  let now = 1_800_000_000_000;
  const clock = { now: () => now++ };
  return new SandboxManager(
    new AttemptPlanner({ nextId: () => "attempt-1" }, clock),
    sandboxExecutor,
    clock,
  );
}

function runInput(abortSignal?: AbortSignal) {
  return {
    runtimeCallId: "call-1",
    call: { toolName: "exec", arguments: { command: "pwd" } },
    authorization: authorization(),
    sandboxCwd: "/workspace/project",
    workspaceRoots: ["/workspace/project"],
    ...(abortSignal ? { abortSignal } : {}),
  };
}

describe("SandboxManager", () => {
  it("runs Attempt #1 once and records created, running, and completed", async () => {
    const cancel = vi.fn(async () => {});
    const sandboxExecutor = executor({
      processHandle: "process-1",
      completion: Promise.resolve(completedOutcome()),
      cancel,
    });

    const record = await manager(sandboxExecutor).runInitialAttempt(runInput());

    expect(sandboxExecutor.selectTarget).toHaveBeenCalledOnce();
    expect(sandboxExecutor.start).toHaveBeenCalledOnce();
    expect(sandboxExecutor.start.mock.calls[0][0]).toMatchObject({
      attempt: { attemptId: "attempt-1", sandboxType: "macos-seatbelt" },
      call: { toolName: "exec", arguments: { command: "pwd" } },
    });
    expect(record.stateHistory.map(({ state }) => state.kind)).toEqual([
      "created",
      "running",
      "completed",
    ]);
    expect(record.stateHistory.map(({ observedAt }) => observedAt)).toEqual([
      1_800_000_000_001, 1_800_000_000_002, 1_800_000_000_003,
    ]);
    expect(cancel).not.toHaveBeenCalled();
    expect(Object.isFrozen(record.stateHistory[2].state)).toBe(true);
  });

  it("records a start failure without claiming the attempt ran", async () => {
    const sandboxExecutor = executor({
      processHandle: "unused",
      completion: Promise.resolve(completedOutcome()),
      cancel: async () => {},
    });
    sandboxExecutor.start.mockRejectedValue(new Error("secret backend detail"));

    const record = await manager(sandboxExecutor).runInitialAttempt(runInput());

    expect(record.stateHistory.map(({ state }) => state)).toEqual([
      { kind: "created" },
      { kind: "runtime-failed", reason: "executor-start-failed" },
    ]);
  });

  it("normalizes target-selection failures without creating an attempt", async () => {
    const sandboxExecutor = executor({
      processHandle: "unused",
      completion: Promise.resolve(completedOutcome()),
      cancel: async () => {},
    });
    sandboxExecutor.selectTarget.mockRejectedValue(new Error("secret platform detail"));

    await expect(manager(sandboxExecutor).runInitialAttempt(runInput())).rejects.toEqual(
      new SandboxManagerError("executor-target-unavailable"),
    );
    expect(sandboxExecutor.start).not.toHaveBeenCalled();
  });

  it("records a structured denial without retrying", async () => {
    const denial: SandboxExecutionOutcome = {
      kind: "denied",
      evidence: {
        source: "os-sandbox",
        operation: "file-read",
        systemCode: "EPERM",
        summary: "sandbox rejected file read",
        minimallySupplementable: true,
      },
    };
    const sandboxExecutor = executor({
      processHandle: "process-1",
      completion: Promise.resolve(denial),
      cancel: async () => {},
    });

    const record = await manager(sandboxExecutor).runInitialAttempt(runInput());

    expect(record.stateHistory.at(-1)?.state).toEqual({
      kind: "denied",
      evidence: denial.evidence,
    });
    expect(sandboxExecutor.start).toHaveBeenCalledOnce();
    expect(record.attempt).not.toHaveProperty("parentAttemptId");
  });

  it("cancels a running attempt and lets cancellation win the completion race", async () => {
    let complete!: (outcome: SandboxExecutionOutcome) => void;
    const completion = new Promise<SandboxExecutionOutcome>((resolve) => {
      complete = resolve;
    });
    const cancel = vi.fn(async () => {
      complete(completedOutcome());
    });
    const sandboxExecutor = executor({ processHandle: "process-1", completion, cancel });
    const controller = new AbortController();
    const running = manager(sandboxExecutor).runInitialAttempt(runInput(controller.signal));
    await vi.waitFor(() => expect(sandboxExecutor.start).toHaveBeenCalledOnce());

    controller.abort();
    const record = await running;

    expect(cancel).toHaveBeenCalledWith("caller-aborted");
    expect(record.stateHistory.at(-1)?.state).toEqual({
      kind: "cancelled",
      reason: "caller-aborted",
    });
  });
});
