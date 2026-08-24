import type { CanonicalPath } from "../domain/capability.js";
import type { NormalizedToolCall, SandboxAttempt, SandboxType } from "../domain/sandbox-attempt.js";
import type { PermissionProfile } from "../domain/permission-profile.js";
import type { SandboxExecutionOutcome } from "../domain/sandbox-result.js";

export type SandboxExecutionTarget = Readonly<{
  sandboxType: SandboxType;
}>;

export type SandboxExecutionHandle = Readonly<{
  processHandle: string;
  completion: Promise<SandboxExecutionOutcome>;
  cancel(reason: string): Promise<void>;
}>;

/**
 * Executes an immutable SandboxAttempt. Implementations may run locally or remotely, but must
 * enforce the supplied PermissionProfile. Cancellation must be idempotent and resolve only after
 * the complete process tree has stopped.
 */
export interface SandboxExecutorPort {
  selectTarget(
    input: Readonly<{
      permissionProfile: PermissionProfile;
      sandboxCwd: CanonicalPath;
      workspaceRoots: readonly CanonicalPath[];
    }>,
  ): SandboxExecutionTarget | Promise<SandboxExecutionTarget>;

  start(
    input: Readonly<{
      attempt: SandboxAttempt;
      call: NormalizedToolCall;
      abortSignal?: AbortSignal;
    }>,
  ): SandboxExecutionHandle | Promise<SandboxExecutionHandle>;
}
