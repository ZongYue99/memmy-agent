import type { ResolvedAccess } from "../domain/capability.js";
import { capabilitySetAllows } from "../policy/policy-cap.js";
import type { EffectiveAuthorization } from "../policy/policy-resolver.js";

export type ToolDecision =
  | Readonly<{ kind: "execute"; authorization: EffectiveAuthorization }>
  | Readonly<{
      kind: "requires-approval";
      reason: "approval-required";
      authorization: EffectiveAuthorization;
      missingCapabilities: readonly ResolvedAccess[];
    }>
  | Readonly<{
      kind: "deny";
      reason: "unknown-capability" | "exceeds-policy-cap" | "approval-not-allowed";
      deniedCapabilities: readonly ResolvedAccess[];
    }>;

export function decideToolAccess(authorization: EffectiveAuthorization): ToolDecision {
  const requested = authorization.requestedCapabilities;
  const unknown = requested.filter((capability) => capability.kind === "unknown");
  if (unknown.length) {
    return { kind: "deny", reason: "unknown-capability", deniedCapabilities: unknown };
  }

  const outsideCap = requested.filter(
    (capability) => !capabilitySetAllows(authorization.policyCap, capability),
  );
  if (outsideCap.length) {
    return { kind: "deny", reason: "exceeds-policy-cap", deniedCapabilities: outsideCap };
  }

  const missing = requested.filter(
    (capability) => !capabilitySetAllows(authorization.baseGrant, capability),
  );
  if (!missing.length) return { kind: "execute", authorization };
  if (
    authorization.approvalMode === "never" ||
    authorization.entrypoint.approvalChannel === "none"
  ) {
    return {
      kind: "deny",
      reason: "approval-not-allowed",
      deniedCapabilities: missing,
    };
  }
  return {
    kind: "requires-approval",
    reason: "approval-required",
    authorization,
    missingCapabilities: missing,
  };
}
