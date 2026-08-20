import type {
  NormalizedToolCall,
  SandboxAttempt,
  SandboxType,
} from "../../domain/sandbox-attempt.js";
import type { PermissionProfile } from "../../domain/permission-profile.js";
import type {
  SandboxExecutionHandle,
  SandboxExecutionTarget,
} from "../../ports/sandbox-executor-port.js";

export type LocalSandboxType = Exclude<SandboxType, "external" | "disabled">;

export type SandboxBackendSupport =
  | Readonly<{ supported: true; target: SandboxExecutionTarget }>
  | Readonly<{
      supported: false;
      reason:
        | "platform-mismatch"
        | "backend-unavailable"
        | "backend-attestation-invalid"
        | "filesystem-mode-unsupported"
        | "network-mode-unsupported"
        | "process-mode-unsupported"
        | "process-limit-unsupported"
        | "invalid-policy";
    }>;

export type SandboxBackendSelectionInput = Readonly<{
  permissionProfile: PermissionProfile;
  sandboxCwd: string;
  workspaceRoots: readonly string[];
}>;

/**
 * Implements one local operating-system sandbox. A backend must reject a profile unless every
 * capability it accepts can be enforced by that backend; partial or best-effort enforcement is
 * not a supported success mode.
 */
export interface SandboxBackend {
  readonly sandboxType: LocalSandboxType;

  inspectSupport(input: SandboxBackendSelectionInput): SandboxBackendSupport;

  start(
    input: Readonly<{
      attempt: SandboxAttempt;
      call: NormalizedToolCall;
      abortSignal?: AbortSignal;
    }>,
  ): Promise<SandboxExecutionHandle>;
}
