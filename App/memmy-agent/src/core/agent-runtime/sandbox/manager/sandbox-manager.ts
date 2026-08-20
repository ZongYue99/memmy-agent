import type {
  AttemptState,
  AttemptStateRecord,
  NormalizedToolCall,
  SandboxExecutionRecord,
} from "../domain/sandbox-attempt.js";
import { transitionAttemptState } from "../domain/sandbox-attempt.js";
import { immutableSnapshot } from "../domain/immutable.js";
import type { SandboxExecutionOutcome } from "../domain/sandbox-result.js";
import type { EffectiveAuthorization } from "../policy/policy-resolver.js";
import type { ClockPort } from "../ports/clock-port.js";
import type {
  SandboxExecutionHandle,
  SandboxExecutionTarget,
  SandboxExecutorPort,
} from "../ports/sandbox-executor-port.js";
import {
  assertValidAuthorization,
  AttemptPlanner,
  normalizeWorkspaceContext,
} from "./attempt-planner.js";

export class SandboxManagerError extends Error {
  constructor(readonly code: "executor-target-unavailable") {
    super(code);
    this.name = "SandboxManagerError";
  }
}

function normalizedReason(reason: string, fallback: string): string {
  return /^[a-z0-9][a-z0-9._-]{0,127}$/i.test(reason) ? reason : fallback;
}

function terminalState(outcome: SandboxExecutionOutcome): AttemptState {
  switch (outcome.kind) {
    case "completed":
      return { kind: "completed", result: outcome.result };
    case "denied":
      return { kind: "denied", evidence: outcome.evidence };
    case "cancelled":
      return { kind: "cancelled", reason: normalizedReason(outcome.reason, "executor-cancelled") };
    case "runtime-failed":
      return {
        kind: "runtime-failed",
        reason: normalizedReason(outcome.reason, "executor-runtime-failed"),
      };
  }
}

async function waitForCompletion(
  handle: SandboxExecutionHandle,
  abortSignal?: AbortSignal,
): Promise<SandboxExecutionOutcome> {
  if (!abortSignal) {
    return handle.completion.catch(() => ({
      kind: "runtime-failed",
      reason: "executor-completion-failed",
    }));
  }
  if (abortSignal.aborted) {
    try {
      await handle.cancel("caller-aborted");
      return { kind: "cancelled", reason: "caller-aborted" };
    } catch {
      return { kind: "runtime-failed", reason: "executor-cancel-failed" };
    }
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = (outcome: SandboxExecutionOutcome) => {
      if (settled) return;
      settled = true;
      abortSignal.removeEventListener("abort", onAbort);
      resolve(outcome);
    };
    const onAbort = () => {
      if (settled) return;
      settled = true;
      abortSignal.removeEventListener("abort", onAbort);
      handle.cancel("caller-aborted").then(
        () => resolve({ kind: "cancelled", reason: "caller-aborted" }),
        () => resolve({ kind: "runtime-failed", reason: "executor-cancel-failed" }),
      );
    };
    abortSignal.addEventListener("abort", onAbort, { once: true });
    if (abortSignal.aborted) onAbort();
    handle.completion.then(finish, () =>
      finish({
        kind: "runtime-failed",
        reason: "executor-completion-failed",
      }),
    );
  });
}

export class SandboxManager {
  constructor(
    private readonly planner: AttemptPlanner,
    private readonly executor: SandboxExecutorPort,
    private readonly clock: ClockPort,
  ) {}

  async runInitialAttempt(
    input: Readonly<{
      runtimeCallId: string;
      call: NormalizedToolCall;
      authorization: EffectiveAuthorization;
      sandboxCwd: string;
      workspaceRoots: readonly string[];
      abortSignal?: AbortSignal;
    }>,
  ): Promise<SandboxExecutionRecord> {
    assertValidAuthorization(input.authorization);
    const workspaceContext = normalizeWorkspaceContext(input.sandboxCwd, input.workspaceRoots);
    let target: SandboxExecutionTarget;
    try {
      target = await this.executor.selectTarget({
        permissionProfile: immutableSnapshot(input.authorization.permissionProfile),
        sandboxCwd: workspaceContext.sandboxCwd,
        workspaceRoots: workspaceContext.workspaceRoots,
      });
    } catch {
      throw new SandboxManagerError("executor-target-unavailable");
    }
    const planned = this.planner.planInitial({
      runtimeCallId: input.runtimeCallId,
      call: input.call,
      authorization: input.authorization,
      sandboxType: target.sandboxType,
      sandboxCwd: workspaceContext.sandboxCwd,
      workspaceRoots: workspaceContext.workspaceRoots,
      networkContextId: target.networkContextId,
    });
    const history: AttemptStateRecord[] = [];
    let state: AttemptState = { kind: "created" };
    history.push(this.record(planned.attempt.attemptId, state));
    if (input.abortSignal?.aborted) {
      state = transitionAttemptState(state, { kind: "cancelled", reason: "caller-aborted" });
      history.push(this.record(planned.attempt.attemptId, state));
      return Object.freeze({ attempt: planned.attempt, stateHistory: Object.freeze(history) });
    }
    let handle: SandboxExecutionHandle;
    try {
      handle = await this.executor.start({
        attempt: planned.attempt,
        call: planned.call,
        abortSignal: input.abortSignal,
      });
      if (!handle.processHandle || handle.processHandle !== handle.processHandle.trim()) {
        throw new Error("invalid process handle");
      }
    } catch {
      state = transitionAttemptState(state, {
        kind: "runtime-failed",
        reason: "executor-start-failed",
      });
      history.push(this.record(planned.attempt.attemptId, state));
      return Object.freeze({ attempt: planned.attempt, stateHistory: Object.freeze(history) });
    }
    state = transitionAttemptState(state, {
      kind: "running",
      processHandle: handle.processHandle,
    });
    history.push(this.record(planned.attempt.attemptId, state));
    state = transitionAttemptState(
      state,
      terminalState(await waitForCompletion(handle, input.abortSignal)),
    );
    history.push(this.record(planned.attempt.attemptId, state));
    return Object.freeze({ attempt: planned.attempt, stateHistory: Object.freeze(history) });
  }

  private record(attemptId: string, state: AttemptState): AttemptStateRecord {
    const observedAt = this.clock.now();
    if (!Number.isSafeInteger(observedAt) || observedAt < 0) {
      throw new Error("observedAt must be a non-negative Unix millisecond timestamp");
    }
    return Object.freeze({
      attemptId,
      state: immutableSnapshot(state),
      observedAt,
    });
  }
}
