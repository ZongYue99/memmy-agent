import type {
  NormalizedToolCall,
  SandboxAttempt,
  SandboxType,
} from "../../domain/sandbox-attempt.js";
import type { PermissionProfile } from "../../domain/permission-profile.js";
import { stablePolicyHash } from "../../policy/policy-hash.js";
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

export function commandFromExecCall(call: NormalizedToolCall): string | null {
  const command = call.arguments.command;
  return call.toolName === "exec" &&
    typeof command === "string" &&
    command.trim() &&
    !command.includes("\0")
    ? command
    : null;
}

export function attemptMatchesCall(attempt: SandboxAttempt, call: NormalizedToolCall): boolean {
  try {
    const { policyHash, ...unhashed } = attempt.permissionProfile;
    return (
      attempt.compiledPolicyHash === policyHash &&
      stablePolicyHash(unhashed) === policyHash &&
      stablePolicyHash(call) === attempt.argsHash
    );
  } catch {
    return false;
  }
}

export function profileSupportsRestrictedExec(profile: PermissionProfile): boolean {
  return (
    profile.filesystem.kind === "restricted" &&
    profile.network.mode === "denied" &&
    profile.process.spawn === "non-interactive"
  );
}

export function createBoundedOutputCapture(maxBytes: number) {
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  let capturedBytes = 0;
  let truncated = false;
  return {
    append(stream: "stdout" | "stderr", chunk: Buffer): void {
      const remaining = maxBytes - capturedBytes;
      if (remaining <= 0) {
        truncated = true;
        return;
      }
      const captured = chunk.byteLength > remaining ? chunk.subarray(0, remaining) : chunk;
      (stream === "stdout" ? stdout : stderr).push(captured);
      capturedBytes += captured.byteLength;
      if (captured.byteLength !== chunk.byteLength) truncated = true;
    },
    result() {
      return {
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        truncated,
      };
    },
  };
}

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
