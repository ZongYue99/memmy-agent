import type { ApprovalPromptHandler } from "../adapters/approval/callback-approval-channel.js";
import type { ApprovalAuditDecision } from "../domain/audit-event.js";
import { immutableSnapshot } from "../domain/immutable.js";
import type { EffectiveAuthorization } from "../policy/policy-resolver.js";
import { applyPreflightApproval } from "../policy/policy-resolver.js";
import { stablePolicyHash } from "../policy/policy-hash.js";
import type { AuditPort } from "../ports/audit-port.js";
import type { ClockPort } from "../ports/clock-port.js";
import type { IdGeneratorPort } from "../ports/id-generator-port.js";
import type { ToolCallGuardDecision, ToolCallGuardRequest } from "../ports/tool-call-guard-port.js";

const DEFAULT_APPROVAL_TTL_MS = 60_000;

type AskDecision = Extract<ToolCallGuardDecision, { type: "ask" }>;

export type PreflightApprovalOutcome =
  | Readonly<{ kind: "approved"; authorization: EffectiveAuthorization }>
  | Readonly<{ kind: "denied" | "cancelled" | "expired" | "invalid-response" }>;

type BoundedPromptResult =
  | Awaited<ReturnType<ApprovalPromptHandler>>
  | "expired"
  | "invalid-response";

/** Owns bounded execution-before-start approval without creating a synthetic SandboxAttempt. */
export class PreflightApprovalBroker {
  private readonly ttlMs: number;

  constructor(
    private readonly options: Readonly<{
      prompt: ApprovalPromptHandler;
      ids: IdGeneratorPort;
      clock: ClockPort;
      audit: AuditPort;
      ttlMs?: number;
    }>,
  ) {
    this.ttlMs = options.ttlMs ?? DEFAULT_APPROVAL_TTL_MS;
    if (!Number.isSafeInteger(this.ttlMs) || this.ttlMs <= 0) {
      throw new Error("ttlMs must be a positive integer");
    }
  }

  async requestApproval(
    input: Readonly<{
      request: ToolCallGuardRequest;
      decision: AskDecision;
      subjectId: string;
      resolveCurrentDecision: () => ToolCallGuardDecision | Promise<ToolCallGuardDecision>;
      abortSignal?: AbortSignal;
    }>,
  ): Promise<PreflightApprovalOutcome> {
    if (input.abortSignal?.aborted) return { kind: "cancelled" };
    const runtimeCallId = input.request.callId ?? this.options.ids.nextId("runtime-call");
    const requestId = this.options.ids.nextId("approval-request");
    const argsHash = stablePolicyHash({
      toolName: input.request.toolName,
      arguments: input.request.arguments,
    });
    const requestedAt = this.options.clock.now();
    const expiresAt = requestedAt + this.ttlMs;
    if (
      !runtimeCallId.trim() ||
      !requestId.trim() ||
      !input.subjectId.trim() ||
      !Number.isSafeInteger(requestedAt) ||
      requestedAt < 0 ||
      !Number.isSafeInteger(expiresAt)
    ) {
      return { kind: "invalid-response" };
    }
    if (
      !(await this.recordAudit({
        runtimeCallId,
        detail: {
          kind: "preflight-approval-requested",
          requestId,
          argsHash,
          initialPolicyHash: input.decision.authorization.initialPolicyHash,
          subjectId: input.subjectId,
          expiresAt,
        },
      }))
    ) {
      return { kind: "invalid-response" };
    }
    const recordDecision = (decision: ApprovalAuditDecision) =>
      this.recordAudit({
        runtimeCallId,
        detail: { kind: "preflight-approval-decided", requestId, decision },
      });
    const result = await this.requestBoundedPrompt(
      immutableSnapshot({
        requestId,
        runtimeCallId,
        additionalPermission: input.decision.missingCapabilities,
        expiresAt,
      }),
      input.abortSignal,
    );
    if (result === "expired" || result === "invalid-response") {
      await recordDecision(result === "expired" ? "expired" : "invalid");
      return { kind: result };
    }
    if (result !== "approved") {
      if (!(await recordDecision(result))) return { kind: "invalid-response" };
      return { kind: result };
    }
    if (input.abortSignal?.aborted) {
      await recordDecision("cancelled");
      return { kind: "cancelled" };
    }
    const decidedAt = this.options.clock.now();
    if (!Number.isSafeInteger(decidedAt) || decidedAt < requestedAt) {
      await recordDecision("invalid");
      return { kind: "invalid-response" };
    }
    if (decidedAt > expiresAt) {
      await recordDecision("expired");
      return { kind: "expired" };
    }
    let current: ToolCallGuardDecision;
    try {
      current = await input.resolveCurrentDecision();
    } catch {
      await recordDecision("invalid");
      return { kind: "invalid-response" };
    }
    if (
      current.type !== "ask" ||
      current.authorization.initialPolicyHash !== input.decision.authorization.initialPolicyHash ||
      stablePolicyHash(current.missingCapabilities) !==
        stablePolicyHash(input.decision.missingCapabilities)
    ) {
      await recordDecision("invalid");
      return { kind: "invalid-response" };
    }
    let authorization: EffectiveAuthorization;
    try {
      authorization = applyPreflightApproval(current.authorization, current.missingCapabilities);
    } catch {
      await recordDecision("invalid");
      return { kind: "invalid-response" };
    }
    if (!(await recordDecision("approved"))) return { kind: "invalid-response" };
    return immutableSnapshot({ kind: "approved", authorization });
  }

  private async recordAudit(draft: Parameters<AuditPort["record"]>[0]): Promise<boolean> {
    try {
      await this.options.audit.record(draft);
      return true;
    } catch {
      return false;
    }
  }

  private requestBoundedPrompt(
    prompt: Parameters<ApprovalPromptHandler>[0],
    abortSignal?: AbortSignal,
  ): Promise<BoundedPromptResult> {
    if (abortSignal?.aborted) return Promise.resolve("cancelled");
    return new Promise((resolve) => {
      let settled = false;
      const finish = (result: BoundedPromptResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        abortSignal?.removeEventListener("abort", onAbort);
        resolve(result);
      };
      const onAbort = () => finish("cancelled");
      const delay = Math.max(1, prompt.expiresAt - this.options.clock.now());
      const timer = setTimeout(() => finish("expired"), delay);
      timer.unref?.();
      abortSignal?.addEventListener("abort", onAbort, { once: true });
      void Promise.resolve()
        .then(() => this.options.prompt(prompt, abortSignal))
        .then((result) =>
          finish(
            result === "approved" || result === "denied" || result === "cancelled"
              ? result
              : "invalid-response",
          ),
        )
        .catch(() => finish(abortSignal?.aborted ? "cancelled" : "invalid-response"));
    });
  }
}
