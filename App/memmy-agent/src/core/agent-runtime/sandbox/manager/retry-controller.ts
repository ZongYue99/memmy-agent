import type { ResolvedAccessSet } from "../domain/capability.js";
import { immutableSnapshot } from "../domain/immutable.js";
import type { SandboxExecutionRecord } from "../domain/sandbox-attempt.js";
import { capabilitySetAllows } from "../policy/policy-cap.js";
import type { EffectiveAuthorization } from "../policy/policy-resolver.js";

export type RetryIneligibilityReason =
  | "not-denied"
  | "already-retried"
  | "authorization-mismatch"
  | "approval-not-allowed"
  | "not-minimally-supplementable"
  | "missing-required-capability"
  | "unsupported-capability"
  | "already-authorized"
  | "exceeds-policy-cap";

export type RetryDecision =
  | Readonly<{ kind: "eligible"; additionalPermission: ResolvedAccessSet }>
  | Readonly<{
      kind: "not-eligible";
      reason: RetryIneligibilityReason;
    }>;

/** Decides whether a completed Attempt may form one approval-bound retry. */
export class RetryController {
  evaluate(record: SandboxExecutionRecord, authorization: EffectiveAuthorization): RetryDecision {
    const terminal = record.stateHistory.at(-1)?.state;
    if (terminal?.kind !== "denied") return { kind: "not-eligible", reason: "not-denied" };
    if (record.attempt.parentAttemptId || record.attempt.approvalGrantHash) {
      return { kind: "not-eligible", reason: "already-retried" };
    }
    if (
      record.attempt.compiledPolicyHash !== authorization.compiledPolicyHash ||
      record.attempt.permissionProfile.policyHash !== authorization.compiledPolicyHash
    ) {
      return { kind: "not-eligible", reason: "authorization-mismatch" };
    }
    if (
      authorization.approvalMode !== "on-request" ||
      authorization.entrypoint.approvalChannel === "none"
    ) {
      return { kind: "not-eligible", reason: "approval-not-allowed" };
    }
    if (!terminal.evidence.minimallySupplementable) {
      return { kind: "not-eligible", reason: "not-minimally-supplementable" };
    }
    const required = terminal.evidence.requiredCapability;
    if (!required) return { kind: "not-eligible", reason: "missing-required-capability" };
    if (required.kind !== "filesystem") {
      return { kind: "not-eligible", reason: "unsupported-capability" };
    }
    if (capabilitySetAllows(authorization.baseGrant, required)) {
      return { kind: "not-eligible", reason: "already-authorized" };
    }
    if (!capabilitySetAllows(authorization.policyCap, required)) {
      return { kind: "not-eligible", reason: "exceeds-policy-cap" };
    }
    return immutableSnapshot({ kind: "eligible", additionalPermission: [required] });
  }
}
