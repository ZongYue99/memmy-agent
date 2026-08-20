import type { ApprovalGrant } from "../approval/approval-grant.js";
import type { ApprovalBroker } from "../approval/approval-broker.js";
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
import { applyApproval } from "../policy/policy-resolver.js";
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
  type NormalizedWorkspaceContext,
  type PlannedSandboxAttempt,
} from "./attempt-planner.js";
import { RetryController, type RetryIneligibilityReason } from "./retry-controller.js";

export class SandboxManagerError extends Error {
  constructor(readonly code: "executor-target-unavailable") {
    super(code);
    this.name = "SandboxManagerError";
  }
}

export type ApprovalRetryDependencies = Readonly<{
  broker: ApprovalBroker;
  controller?: RetryController;
}>;

export type RetryDisposition =
  | Readonly<{ kind: "retry-attempted" }>
  | Readonly<{
      kind: "not-retried";
      reason:
        | RetryIneligibilityReason
        | "approval-unavailable"
        | "approval-denied"
        | "approval-cancelled"
        | "approval-expired"
        | "approval-invalid"
        | "policy-unavailable"
        | "policy-changed"
        | "retry-target-unavailable"
        | "retry-plan-invalid"
        | "grant-consumption-failed";
    }>;

export type SandboxExecutionChain = Readonly<{
  attempts: readonly SandboxExecutionRecord[];
  retry: RetryDisposition;
}>;

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
  private readonly retryController: RetryController;

  constructor(
    private readonly planner: AttemptPlanner,
    private readonly executor: SandboxExecutorPort,
    private readonly clock: ClockPort,
    private readonly approvalRetry?: ApprovalRetryDependencies,
  ) {
    this.retryController = approvalRetry?.controller ?? new RetryController();
  }

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
    const target = await this.selectTarget(input.authorization, workspaceContext);
    const planned = this.planner.planInitial({
      runtimeCallId: input.runtimeCallId,
      call: input.call,
      authorization: input.authorization,
      sandboxType: target.sandboxType,
      sandboxCwd: workspaceContext.sandboxCwd,
      workspaceRoots: workspaceContext.workspaceRoots,
      networkContextId: target.networkContextId,
    });
    return this.execute(planned, input.abortSignal);
  }

  async runWithApprovalRetry(
    input: Readonly<{
      runtimeCallId: string;
      call: NormalizedToolCall;
      authorization: EffectiveAuthorization;
      resolveCurrentAuthorization: () => EffectiveAuthorization | Promise<EffectiveAuthorization>;
      approvalSubjectId: string;
      sandboxCwd: string;
      workspaceRoots: readonly string[];
      abortSignal?: AbortSignal;
    }>,
  ): Promise<SandboxExecutionChain> {
    const initial = await this.runInitialAttempt(input);
    const retryDecision = this.retryController.evaluate(initial, input.authorization);
    if (retryDecision.kind === "not-eligible") {
      return this.chain([initial], { kind: "not-retried", reason: retryDecision.reason });
    }
    const broker = this.approvalRetry?.broker;
    if (!broker) {
      return this.chain([initial], { kind: "not-retried", reason: "approval-unavailable" });
    }
    let approval;
    try {
      approval = await broker.requestApproval({
        runtimeCallId: initial.attempt.runtimeCallId,
        argsHash: initial.attempt.argsHash,
        initialPolicyHash: input.authorization.initialPolicyHash,
        parentAttemptId: initial.attempt.attemptId,
        additionalPermission: retryDecision.additionalPermission,
        subjectId: input.approvalSubjectId,
        abortSignal: input.abortSignal,
      });
    } catch {
      return this.chain([initial], { kind: "not-retried", reason: "approval-invalid" });
    }
    if (approval.kind !== "approved") {
      const reason =
        approval.kind === "invalid-response"
          ? "approval-invalid"
          : (`approval-${approval.kind}` as const);
      return this.chain([initial], { kind: "not-retried", reason });
    }
    const { grant } = approval;
    if (input.abortSignal?.aborted) {
      await this.revokeGrant(grant.grantId);
      return this.chain([initial], { kind: "not-retried", reason: "approval-cancelled" });
    }
    let currentAuthorization: EffectiveAuthorization;
    try {
      currentAuthorization = await input.resolveCurrentAuthorization();
      assertValidAuthorization(currentAuthorization);
    } catch {
      await this.revokeGrant(grant.grantId);
      return this.chain([initial], { kind: "not-retried", reason: "policy-unavailable" });
    }
    if (currentAuthorization.initialPolicyHash !== grant.initialPolicyHash) {
      await this.revokeGrant(grant.grantId);
      return this.chain([initial], { kind: "not-retried", reason: "policy-changed" });
    }
    let retryAuthorization: EffectiveAuthorization;
    try {
      retryAuthorization = applyApproval(currentAuthorization, grant);
    } catch {
      await this.revokeGrant(grant.grantId);
      return this.chain([initial], { kind: "not-retried", reason: "policy-changed" });
    }
    let target: SandboxExecutionTarget;
    try {
      target = await this.selectTarget(retryAuthorization, {
        sandboxCwd: initial.attempt.sandboxCwd,
        workspaceRoots: initial.attempt.workspaceRoots,
      });
    } catch {
      await this.revokeGrant(grant.grantId);
      return this.chain([initial], {
        kind: "not-retried",
        reason: "retry-target-unavailable",
      });
    }
    let retry: PlannedSandboxAttempt;
    try {
      retry = this.planner.planRetry({
        parentAttempt: initial.attempt,
        call: input.call,
        authorization: retryAuthorization,
        approvalGrant: grant,
        sandboxType: target.sandboxType,
        networkContextId: target.networkContextId,
      });
    } catch {
      await this.revokeGrant(grant.grantId);
      return this.chain([initial], { kind: "not-retried", reason: "retry-plan-invalid" });
    }
    if (input.abortSignal?.aborted) {
      await this.revokeGrant(grant.grantId);
      return this.chain([initial], { kind: "not-retried", reason: "approval-cancelled" });
    }
    let consumed: ApprovalGrant | null;
    try {
      consumed = await broker.consume(grant.grantId, {
        runtimeCallId: initial.attempt.runtimeCallId,
        argsHash: initial.attempt.argsHash,
        initialPolicyHash: grant.initialPolicyHash,
        parentAttemptId: initial.attempt.attemptId,
        subjectId: input.approvalSubjectId,
        approvalGrantHash: grant.approvalGrantHash,
      });
    } catch {
      consumed = null;
    }
    if (consumed?.approvalGrantHash !== grant.approvalGrantHash) {
      return this.chain([initial], {
        kind: "not-retried",
        reason: "grant-consumption-failed",
      });
    }
    const retried = await this.execute(retry, input.abortSignal);
    return this.chain([initial, retried], { kind: "retry-attempted" });
  }

  private async selectTarget(
    authorization: EffectiveAuthorization,
    workspace: NormalizedWorkspaceContext,
  ): Promise<SandboxExecutionTarget> {
    try {
      return await this.executor.selectTarget({
        permissionProfile: immutableSnapshot(authorization.permissionProfile),
        sandboxCwd: workspace.sandboxCwd,
        workspaceRoots: workspace.workspaceRoots,
      });
    } catch {
      throw new SandboxManagerError("executor-target-unavailable");
    }
  }

  private async execute(
    planned: PlannedSandboxAttempt,
    abortSignal?: AbortSignal,
  ): Promise<SandboxExecutionRecord> {
    const history: AttemptStateRecord[] = [];
    let state: AttemptState = { kind: "created" };
    history.push(this.record(planned.attempt.attemptId, state));
    if (abortSignal?.aborted) {
      state = transitionAttemptState(state, { kind: "cancelled", reason: "caller-aborted" });
      history.push(this.record(planned.attempt.attemptId, state));
      return Object.freeze({ attempt: planned.attempt, stateHistory: Object.freeze(history) });
    }
    let handle: SandboxExecutionHandle;
    try {
      handle = await this.executor.start({
        attempt: planned.attempt,
        call: planned.call,
        abortSignal,
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
      terminalState(await waitForCompletion(handle, abortSignal)),
    );
    history.push(this.record(planned.attempt.attemptId, state));
    return Object.freeze({ attempt: planned.attempt, stateHistory: Object.freeze(history) });
  }

  private async revokeGrant(grantId: string): Promise<void> {
    try {
      await this.approvalRetry?.broker.revoke(grantId);
    } catch {
      // This manager still refuses the retry; the call-bound grant expires independently.
    }
  }

  private chain(
    attempts: readonly SandboxExecutionRecord[],
    retry: RetryDisposition,
  ): SandboxExecutionChain {
    return Object.freeze({ attempts: Object.freeze([...attempts]), retry: Object.freeze(retry) });
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
