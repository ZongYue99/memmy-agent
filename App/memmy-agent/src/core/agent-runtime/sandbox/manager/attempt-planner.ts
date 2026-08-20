import path from "node:path";
import type { CanonicalPath } from "../domain/capability.js";
import type { NormalizedToolCall, SandboxAttempt, SandboxType } from "../domain/sandbox-attempt.js";
import { deepFreeze, immutableSnapshot } from "../domain/immutable.js";
import type { PermissionProfile } from "../domain/permission-profile.js";
import type { EffectiveAuthorization } from "../policy/policy-resolver.js";
import { stablePolicyHash } from "../policy/policy-hash.js";
import type { ClockPort } from "../ports/clock-port.js";
import type { IdGeneratorPort } from "../ports/id-generator-port.js";

export type PlannedSandboxAttempt = Readonly<{
  attempt: SandboxAttempt;
  call: NormalizedToolCall;
}>;

export type NormalizedWorkspaceContext = Readonly<{
  sandboxCwd: CanonicalPath;
  workspaceRoots: readonly CanonicalPath[];
}>;

function pathIsInside(target: string, root: string): boolean {
  const relative = path.relative(root, target);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function requireStableIdentifier(label: string, value: string): void {
  if (!value || value !== value.trim()) throw new Error(`${label} must be a stable identifier`);
}

export function normalizeWorkspaceContext(
  sandboxCwd: CanonicalPath,
  roots: readonly CanonicalPath[],
): NormalizedWorkspaceContext {
  const workspaceRoots = [...new Set(roots.map((root) => path.resolve(root)))].sort();
  if (!workspaceRoots.length) throw new Error("workspaceRoots must not be empty");
  const normalizedCwd = path.resolve(sandboxCwd);
  if (!workspaceRoots.some((root) => pathIsInside(normalizedCwd, root))) {
    throw new Error("sandboxCwd must be inside a workspace root");
  }
  return deepFreeze({ sandboxCwd: normalizedCwd, workspaceRoots });
}

export function assertValidAuthorization(authorization: EffectiveAuthorization): void {
  const profile = authorization.permissionProfile;
  const { policyHash, ...unhashed } = profile;
  if (authorization.compiledPolicyHash !== policyHash) {
    throw new Error("compiled policy hash does not match permission profile");
  }
  if (stablePolicyHash(unhashed) !== policyHash) {
    throw new Error("permission profile hash verification failed");
  }
}

export class AttemptPlanner {
  constructor(
    private readonly ids: IdGeneratorPort,
    private readonly clock: ClockPort,
  ) {}

  planInitial(
    input: Readonly<{
      runtimeCallId: string;
      call: NormalizedToolCall;
      authorization: EffectiveAuthorization;
      sandboxType: SandboxType;
      sandboxCwd: CanonicalPath;
      workspaceRoots: readonly CanonicalPath[];
      networkContextId: string;
    }>,
  ): PlannedSandboxAttempt {
    requireStableIdentifier("runtimeCallId", input.runtimeCallId);
    requireStableIdentifier("toolName", input.call.toolName);
    requireStableIdentifier("networkContextId", input.networkContextId);
    assertValidAuthorization(input.authorization);
    const { sandboxCwd, workspaceRoots } = normalizeWorkspaceContext(
      input.sandboxCwd,
      input.workspaceRoots,
    );
    if (input.sandboxType === "external" || input.sandboxType === "disabled") {
      throw new Error("managed permission profile requires a managed sandbox type");
    }
    const call = immutableSnapshot(input.call);
    const argsHash = stablePolicyHash(call);
    const attemptId = this.ids.nextId("attempt");
    requireStableIdentifier("attemptId", attemptId);
    const createdAt = this.clock.now();
    if (!Number.isSafeInteger(createdAt) || createdAt < 0) {
      throw new Error("createdAt must be a non-negative Unix millisecond timestamp");
    }
    const permissionProfile = immutableSnapshot<PermissionProfile>(
      input.authorization.permissionProfile,
    );
    const attempt = deepFreeze<SandboxAttempt>({
      attemptId,
      runtimeCallId: input.runtimeCallId,
      argsHash,
      permissionProfile,
      compiledPolicyHash: permissionProfile.policyHash,
      sandboxType: input.sandboxType,
      sandboxCwd,
      workspaceRoots,
      networkContextId: input.networkContextId,
      createdAt,
    });
    return deepFreeze({ attempt, call });
  }
}
