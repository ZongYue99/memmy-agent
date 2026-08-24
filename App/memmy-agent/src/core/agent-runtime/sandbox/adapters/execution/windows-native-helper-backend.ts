import type { ChildProcess, SpawnOptions } from "node:child_process";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { NormalizedToolCall, SandboxAttempt } from "../../domain/sandbox-attempt.js";
import type { SandboxExecutionHandle } from "../../ports/sandbox-executor-port.js";
import {
  attemptMatchesCall,
  commandFromExecCall,
  createBoundedOutputCapture,
  profileSupportsRestrictedExec,
  type SandboxBackend,
  type SandboxBackendSelectionInput,
  type SandboxBackendSupport,
} from "./sandbox-backend.js";

const PROTOCOL_VERSION = 1;
const TERMINATE_GRACE_MS = 1_000;

type SpawnProcess = (
  command: string,
  args: readonly string[],
  options: SpawnOptions,
) => ChildProcess;

type WindowsNativeHelperBackendOptions = Readonly<{
  platform?: NodeJS.Platform;
  helperExecutable?: string;
  expectedSha256?: string;
  spawnProcess?: SpawnProcess;
  now?: () => number;
}>;

export class WindowsNativeHelperBackendError extends Error {
  constructor(
    readonly code:
      | "unsupported-profile"
      | "unsupported-call"
      | "helper-attestation-failed"
      | "spawn-failed",
  ) {
    super(code);
    this.name = "WindowsNativeHelperBackendError";
  }
}

function sha256File(filename: string): string {
  return createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
}

function canonicalCwd(sandboxCwd: string, workspaceRoots: readonly string[]): string {
  const cwd = fs.realpathSync.native(sandboxCwd);
  const insideWorkspace = workspaceRoots.some((root) => {
    const relative = path.relative(fs.realpathSync.native(root), cwd);
    return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
  });
  if (!insideWorkspace) throw new Error("sandbox cwd is outside the workspace");
  return cwd;
}

function terminate(child: ChildProcess, signal: NodeJS.Signals): void {
  try {
    child.kill(signal);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
  }
}

/**
 * Adapts the versioned Windows Restricted Token + Job Object native helper protocol. The helper
 * binary is used only when its SHA-256 matches the trusted product manifest value.
 */
export class WindowsNativeHelperBackend implements SandboxBackend {
  readonly sandboxType = "windows-restricted-token" as const;
  private readonly platform: NodeJS.Platform;
  private readonly helperExecutable: string;
  private readonly expectedSha256: string;
  private readonly spawnProcess: SpawnProcess;
  private readonly now: () => number;

  constructor(options: WindowsNativeHelperBackendOptions = {}) {
    this.platform = options.platform ?? process.platform;
    this.helperExecutable =
      options.helperExecutable ?? process.env.MEMMY_WINDOWS_SANDBOX_HELPER ?? "";
    this.expectedSha256 = (
      options.expectedSha256 ??
      process.env.MEMMY_WINDOWS_SANDBOX_HELPER_SHA256 ??
      ""
    ).toLowerCase();
    this.spawnProcess = options.spawnProcess ?? spawn;
    this.now = options.now ?? Date.now;
  }

  private helperIsAttested(): boolean {
    if (!this.helperExecutable || !this.expectedSha256) return false;
    try {
      const status = fs.lstatSync(this.helperExecutable);
      return (
        status.isFile() &&
        !status.isSymbolicLink() &&
        sha256File(this.helperExecutable) === this.expectedSha256
      );
    } catch {
      return false;
    }
  }

  inspectSupport(input: SandboxBackendSelectionInput): SandboxBackendSupport {
    if (this.platform !== "win32") return { supported: false, reason: "platform-mismatch" };
    if (!this.helperExecutable || !this.expectedSha256) {
      return { supported: false, reason: "backend-unavailable" };
    }
    try {
      fs.accessSync(this.helperExecutable, fs.constants.R_OK);
    } catch {
      return { supported: false, reason: "backend-unavailable" };
    }
    if (!this.helperIsAttested()) {
      return { supported: false, reason: "backend-attestation-invalid" };
    }
    if (input.permissionProfile.filesystem.kind !== "restricted") {
      return { supported: false, reason: "filesystem-mode-unsupported" };
    }
    if (input.permissionProfile.network.mode !== "denied") {
      return { supported: false, reason: "network-mode-unsupported" };
    }
    if (input.permissionProfile.process.spawn !== "non-interactive") {
      return { supported: false, reason: "process-mode-unsupported" };
    }
    if (input.permissionProfile.process.maxProcesses < 1) {
      return { supported: false, reason: "process-limit-unsupported" };
    }
    try {
      canonicalCwd(input.sandboxCwd, input.workspaceRoots);
    } catch {
      return { supported: false, reason: "invalid-policy" };
    }
    return {
      supported: true,
      target: {
        sandboxType: this.sandboxType,
        networkContextId: "windows-restricted-network-token",
      },
    };
  }

  async start(
    input: Readonly<{
      attempt: SandboxAttempt;
      call: NormalizedToolCall;
      abortSignal?: AbortSignal;
    }>,
  ): Promise<SandboxExecutionHandle> {
    const profile = input.attempt.permissionProfile;
    if (
      this.platform !== "win32" ||
      input.attempt.sandboxType !== this.sandboxType ||
      !profileSupportsRestrictedExec(profile) ||
      profile.process.maxProcesses < 1 ||
      !attemptMatchesCall(input.attempt, input.call)
    ) {
      throw new WindowsNativeHelperBackendError("unsupported-profile");
    }
    if (!this.helperIsAttested()) {
      throw new WindowsNativeHelperBackendError("helper-attestation-failed");
    }
    const cwd = canonicalCwd(input.attempt.sandboxCwd, input.attempt.workspaceRoots);
    const command = commandFromExecCall(input.call);
    if (!command) throw new WindowsNativeHelperBackendError("unsupported-call");
    const request = `${JSON.stringify({
      protocolVersion: PROTOCOL_VERSION,
      attemptId: input.attempt.attemptId,
      argsHash: input.attempt.argsHash,
      compiledPolicyHash: input.attempt.compiledPolicyHash,
      command,
      cwd,
      permissionProfile: profile,
    })}\n`;
    const output = createBoundedOutputCapture(profile.process.maxOutputBytes);
    const startedAt = this.now();
    let child: ChildProcess;
    try {
      child = this.spawnProcess(
        this.helperExecutable,
        ["--protocol-version", String(PROTOCOL_VERSION)],
        {
          cwd,
          env: {},
          detached: false,
          shell: false,
          windowsHide: true,
          stdio: ["pipe", "pipe", "pipe"],
        },
      );
    } catch {
      throw new WindowsNativeHelperBackendError("spawn-failed");
    }
    if (!child.stdin) {
      terminate(child, "SIGKILL");
      throw new WindowsNativeHelperBackendError("spawn-failed");
    }
    child.stdout?.on("data", (chunk: Buffer) => output.append("stdout", chunk));
    child.stderr?.on("data", (chunk: Buffer) => output.append("stderr", chunk));

    let cancellationReason: string | null = null;
    let terminateTimer: NodeJS.Timeout | undefined;
    let resolveClosed!: () => void;
    const closed = new Promise<void>((resolve) => {
      resolveClosed = resolve;
    });
    let resolveCompletion!: (value: Awaited<SandboxExecutionHandle["completion"]>) => void;
    const completion = new Promise<Awaited<SandboxExecutionHandle["completion"]>>((resolve) => {
      resolveCompletion = resolve;
    });
    let settled = false;
    const finish = (outcome: Awaited<SandboxExecutionHandle["completion"]>) => {
      if (settled) return;
      settled = true;
      if (terminateTimer) clearTimeout(terminateTimer);
      clearTimeout(runtimeTimer);
      input.abortSignal?.removeEventListener("abort", onAbort);
      resolveCompletion(outcome);
      resolveClosed();
    };
    child.once("error", () => finish({ kind: "runtime-failed", reason: "executor-spawn-failed" }));
    child.stdin.once("error", () =>
      finish({ kind: "runtime-failed", reason: "executor-input-failed" }),
    );
    child.once("close", (exitCode, signal) => {
      if (cancellationReason) {
        finish({ kind: "cancelled", reason: cancellationReason });
        return;
      }
      const captured = output.result();
      finish({
        kind: "completed",
        result: {
          exitCode,
          signal,
          stdoutSummary: captured.stdout,
          stderrSummary: captured.stderr,
          outputTruncated: captured.truncated,
          startedAt,
          completedAt: this.now(),
          evidenceRefs: [],
        },
      });
    });
    let cancelPromise: Promise<void> | undefined;
    const cancel = (reason: string): Promise<void> => {
      if (cancelPromise) return cancelPromise;
      cancellationReason = reason;
      cancelPromise = (async () => {
        terminate(child, "SIGTERM");
        terminateTimer = setTimeout(() => terminate(child, "SIGKILL"), TERMINATE_GRACE_MS);
        terminateTimer.unref?.();
        await closed;
      })();
      return cancelPromise;
    };
    const onAbort = () => void cancel("caller-aborted");
    input.abortSignal?.addEventListener("abort", onAbort, { once: true });
    const runtimeTimer = setTimeout(
      () => void cancel("max-runtime-exceeded"),
      profile.process.maxRuntimeMs,
    );
    runtimeTimer.unref?.();
    await new Promise<void>((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", () => reject(new WindowsNativeHelperBackendError("spawn-failed")));
    });
    child.stdin.end(request);
    if (input.abortSignal?.aborted) await cancel("caller-aborted");
    return Object.freeze({ processHandle: `local:${child.pid}`, completion, cancel });
  }
}
