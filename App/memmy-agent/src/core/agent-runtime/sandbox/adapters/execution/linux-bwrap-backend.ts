import type { ChildProcess, SpawnOptions } from "node:child_process";
import { spawn } from "node:child_process";
import fs from "node:fs";
import type { NormalizedToolCall, SandboxAttempt } from "../../domain/sandbox-attempt.js";
import type { PermissionProfile } from "../../domain/permission-profile.js";
import type { SandboxExecutionHandle } from "../../ports/sandbox-executor-port.js";
import { stablePolicyHash } from "../../policy/policy-hash.js";
import type {
  SandboxBackend,
  SandboxBackendSelectionInput,
  SandboxBackendSupport,
} from "./sandbox-backend.js";
import { compileLinuxBwrapPolicy } from "./linux-bwrap-policy.js";

const DEFAULT_BWRAP_EXECUTABLE = "/usr/bin/bwrap";
const TERMINATE_GRACE_MS = 1_000;

type SpawnProcess = (
  command: string,
  args: readonly string[],
  options: SpawnOptions,
) => ChildProcess;

type LinuxBwrapBackendOptions = Readonly<{
  platform?: NodeJS.Platform;
  executable?: string;
  spawnProcess?: SpawnProcess;
  now?: () => number;
}>;

export class LinuxBwrapBackendError extends Error {
  constructor(readonly code: "unsupported-profile" | "unsupported-call" | "spawn-failed") {
    super(code);
    this.name = "LinuxBwrapBackendError";
  }
}

function commandFromCall(call: NormalizedToolCall): string {
  if (call.toolName !== "exec") throw new LinuxBwrapBackendError("unsupported-call");
  const command = call.arguments.command;
  if (typeof command !== "string" || !command.trim() || command.includes("\0")) {
    throw new LinuxBwrapBackendError("unsupported-call");
  }
  return command;
}

function profileIsSupported(profile: PermissionProfile): boolean {
  return (
    profile.filesystem.kind === "restricted" &&
    profile.network.mode === "denied" &&
    profile.process.spawn === "non-interactive" &&
    (profile.process.maxProcesses === 1 || profile.process.maxProcesses === Number.MAX_SAFE_INTEGER)
  );
}

function attemptIsBound(attempt: SandboxAttempt, call: NormalizedToolCall): boolean {
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

function signalProcessTree(child: ChildProcess, signal: NodeJS.Signals): void {
  if (!child.pid) return;
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") child.kill(signal);
  }
}

/** Executes a command in a Bubblewrap namespace with an empty mount root and no network namespace. */
export class LinuxBwrapBackend implements SandboxBackend {
  readonly sandboxType = "linux-bwrap" as const;
  private readonly platform: NodeJS.Platform;
  private readonly executable: string;
  private readonly spawnProcess: SpawnProcess;
  private readonly now: () => number;

  constructor(options: LinuxBwrapBackendOptions = {}) {
    this.platform = options.platform ?? process.platform;
    this.executable = options.executable ?? DEFAULT_BWRAP_EXECUTABLE;
    this.spawnProcess = options.spawnProcess ?? spawn;
    this.now = options.now ?? Date.now;
  }

  inspectSupport(input: SandboxBackendSelectionInput): SandboxBackendSupport {
    if (this.platform !== "linux") return { supported: false, reason: "platform-mismatch" };
    try {
      fs.accessSync(this.executable, fs.constants.X_OK);
    } catch {
      return { supported: false, reason: "backend-unavailable" };
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
    if (
      input.permissionProfile.process.maxProcesses !== 1 &&
      input.permissionProfile.process.maxProcesses !== Number.MAX_SAFE_INTEGER
    ) {
      return { supported: false, reason: "process-limit-unsupported" };
    }
    try {
      compileLinuxBwrapPolicy(input.permissionProfile, input.sandboxCwd, input.workspaceRoots);
    } catch {
      return { supported: false, reason: "invalid-policy" };
    }
    return {
      supported: true,
      target: { sandboxType: this.sandboxType, networkContextId: "linux-network-namespace" },
    };
  }

  async start(
    input: Readonly<{
      attempt: SandboxAttempt;
      call: NormalizedToolCall;
      abortSignal?: AbortSignal;
    }>,
  ): Promise<SandboxExecutionHandle> {
    if (
      this.platform !== "linux" ||
      input.attempt.sandboxType !== this.sandboxType ||
      !profileIsSupported(input.attempt.permissionProfile) ||
      !attemptIsBound(input.attempt, input.call)
    ) {
      throw new LinuxBwrapBackendError("unsupported-profile");
    }
    const command = commandFromCall(input.call);
    const compiled = compileLinuxBwrapPolicy(
      input.attempt.permissionProfile,
      input.attempt.sandboxCwd,
      input.attempt.workspaceRoots,
    );
    let capturedBytes = 0;
    let outputTruncated = false;
    const append = (chunk: Buffer) => {
      const remaining = input.attempt.permissionProfile.process.maxOutputBytes - capturedBytes;
      if (remaining <= 0) {
        outputTruncated = true;
        return Buffer.alloc(0);
      }
      const captured = chunk.byteLength > remaining ? chunk.subarray(0, remaining) : chunk;
      capturedBytes += captured.byteLength;
      if (captured.byteLength !== chunk.byteLength) outputTruncated = true;
      return captured;
    };
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    const startedAt = this.now();
    let child: ChildProcess;
    try {
      child = this.spawnProcess(
        this.executable,
        [...compiled.args, "--", "/bin/sh", "-c", command],
        {
          cwd: compiled.cwd,
          env: {},
          detached: true,
          shell: false,
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
    } catch {
      throw new LinuxBwrapBackendError("spawn-failed");
    }
    child.stdout?.on("data", (chunk: Buffer) => {
      const captured = append(chunk);
      if (captured.length) stdout.push(captured);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      const captured = append(chunk);
      if (captured.length) stderr.push(captured);
    });
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
    child.once("close", (exitCode, signal) => {
      if (cancellationReason) {
        finish({ kind: "cancelled", reason: cancellationReason });
        return;
      }
      finish({
        kind: "completed",
        result: {
          exitCode,
          signal,
          stdoutSummary: Buffer.concat(stdout).toString("utf8"),
          stderrSummary: Buffer.concat(stderr).toString("utf8"),
          outputTruncated,
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
        signalProcessTree(child, "SIGTERM");
        terminateTimer = setTimeout(() => signalProcessTree(child, "SIGKILL"), TERMINATE_GRACE_MS);
        terminateTimer.unref?.();
        await closed;
      })();
      return cancelPromise;
    };
    const onAbort = () => void cancel("caller-aborted");
    input.abortSignal?.addEventListener("abort", onAbort, { once: true });
    const runtimeTimer = setTimeout(
      () => void cancel("max-runtime-exceeded"),
      input.attempt.permissionProfile.process.maxRuntimeMs,
    );
    runtimeTimer.unref?.();
    await new Promise<void>((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", () => reject(new LinuxBwrapBackendError("spawn-failed")));
    });
    if (input.abortSignal?.aborted) await cancel("caller-aborted");
    return Object.freeze({ processHandle: `local:${child.pid}`, completion, cancel });
  }
}
