import type { ChildProcess } from "node:child_process";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { NormalizedToolCall, SandboxAttempt } from "../../domain/sandbox-attempt.js";
import type { PermissionProfile } from "../../domain/permission-profile.js";
import type { SandboxExecutionOutcome } from "../../domain/sandbox-result.js";
import { classifyDenial } from "../../guard/denial-classifier.js";
import type { SandboxExecutionHandle } from "../../ports/sandbox-executor-port.js";
import {
  attemptMatchesCall,
  commandFromExecCall,
  createBoundedOutputCapture,
  restrictedExecUnsupportedReason,
  type SandboxBackend,
  type SandboxBackendSelectionInput,
  type SandboxBackendSupport,
  type SpawnProcess,
} from "./sandbox-backend.js";
import {
  compileMacosSeatbeltPolicy,
  type CompiledSeatbeltPolicy,
} from "./macos-seatbelt-policy.js";
import {
  MacosSeatbeltDenialMonitor,
  type SeatbeltDenialMonitor,
} from "./macos-seatbelt-denial-monitor.js";

const DEFAULT_SEATBELT_EXECUTABLE = "/usr/bin/sandbox-exec";
const TERMINATE_GRACE_MS = 1_000;

type MacosSeatbeltBackendOptions = Readonly<{
  platform?: NodeJS.Platform;
  seatbeltExecutable?: string;
  spawnProcess?: SpawnProcess;
  now?: () => number;
  denialMonitor?: SeatbeltDenialMonitor;
}>;

function buildEnvironment(profile: PermissionProfile): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  const removed = new Set(profile.environment.remove);
  for (const name of profile.environment.inherit) {
    if (!name || name.includes("=") || name.includes("\0")) {
      throw new Error("unsupported-profile");
    }
    if (removed.has(name)) continue;
    const value = process.env[name];
    if (value !== undefined) environment[name] = value;
  }
  for (const [name, value] of Object.entries(profile.environment.set)) {
    if (!name || name.includes("=") || name.includes("\0") || value.includes("\0")) {
      throw new Error("unsupported-profile");
    }
    if (!removed.has(name)) environment[name] = value;
  }
  return environment;
}

function processTreeSignal(child: ChildProcess, signal: NodeJS.Signals): void {
  const pid = child.pid;
  if (typeof pid !== "number" || pid <= 0) return;
  try {
    process.kill(-pid, signal);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return;
    child.kill(signal);
  }
}

function pathIsInside(target: string, root: string): boolean {
  const relative = path.relative(root, target);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function canonicalSandboxCwd(
  sandboxCwd: string,
  workspaceRoots: readonly string[],
  compiled: CompiledSeatbeltPolicy,
): string {
  try {
    const cwd = fs.realpathSync.native(sandboxCwd);
    const roots = workspaceRoots.map((root) => fs.realpathSync.native(root));
    if (!roots.some((root) => pathIsInside(cwd, root))) throw new Error("cwd outside workspace");
    if (!compiled.readableRoots.some((root) => pathIsInside(cwd, root))) {
      throw new Error("cwd is not readable");
    }
    if (compiled.deniedRoots.some((root) => pathIsInside(cwd, root))) {
      throw new Error("cwd is denied");
    }
    return cwd;
  } catch {
    throw new Error("unsupported-profile");
  }
}

export class MacosSeatbeltBackend implements SandboxBackend {
  readonly sandboxType = "macos-seatbelt" as const;
  private readonly platform: NodeJS.Platform;
  private readonly seatbeltExecutable: string;
  private readonly spawnProcess: SpawnProcess;
  private readonly now: () => number;
  private readonly denialMonitor: SeatbeltDenialMonitor;

  constructor(options: MacosSeatbeltBackendOptions = {}) {
    this.platform = options.platform ?? process.platform;
    this.seatbeltExecutable = options.seatbeltExecutable ?? DEFAULT_SEATBELT_EXECUTABLE;
    this.spawnProcess = options.spawnProcess ?? spawn;
    this.now = options.now ?? Date.now;
    this.denialMonitor = options.denialMonitor ?? new MacosSeatbeltDenialMonitor();
  }

  inspectSupport(input: SandboxBackendSelectionInput): SandboxBackendSupport {
    if (this.platform !== "darwin") return { supported: false, reason: "platform-mismatch" };
    try {
      fs.accessSync(this.seatbeltExecutable, fs.constants.X_OK);
    } catch {
      return { supported: false, reason: "backend-unavailable" };
    }
    const { permissionProfile } = input;
    const unsupportedReason = restrictedExecUnsupportedReason(permissionProfile);
    if (unsupportedReason) return { supported: false, reason: unsupportedReason };
    if (
      permissionProfile.process.maxProcesses !== 1 &&
      permissionProfile.process.maxProcesses !== Number.MAX_SAFE_INTEGER
    ) {
      return { supported: false, reason: "process-limit-unsupported" };
    }
    try {
      const compiled = compileMacosSeatbeltPolicy(permissionProfile);
      canonicalSandboxCwd(input.sandboxCwd, input.workspaceRoots, compiled);
    } catch {
      return { supported: false, reason: "invalid-policy" };
    }
    return {
      supported: true,
      target: { sandboxType: this.sandboxType },
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
      this.platform !== "darwin" ||
      input.attempt.sandboxType !== this.sandboxType ||
      restrictedExecUnsupportedReason(profile) !== null ||
      (profile.process.maxProcesses !== 1 &&
        profile.process.maxProcesses !== Number.MAX_SAFE_INTEGER) ||
      !attemptMatchesCall(input.attempt, input.call)
    ) {
      throw new Error("unsupported-profile");
    }
    const command = commandFromExecCall(input.call);
    if (!command) throw new Error("unsupported-call");
    const compiled = compileMacosSeatbeltPolicy(profile);
    const sandboxCwd = canonicalSandboxCwd(
      input.attempt.sandboxCwd,
      input.attempt.workspaceRoots,
      compiled,
    );
    const environment = buildEnvironment(profile);
    const denialCapture = await this.denialMonitor
      .start(profile.process.maxRuntimeMs)
      .catch(() => null);
    const startedAt = this.now();
    const output = createBoundedOutputCapture(profile.process.maxOutputBytes);
    const args = ["-p", compiled.policy, ...compiled.parameters, "--", "/bin/sh", "-c", command];
    let child: ChildProcess;
    try {
      child = this.spawnProcess(this.seatbeltExecutable, args, {
        cwd: sandboxCwd,
        env: environment,
        detached: true,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch {
      await denialCapture?.finish();
      throw new Error("spawn-failed");
    }
    if (child.pid) denialCapture?.bindProcess(child.pid);
    child.stdout?.on("data", (chunk: Buffer) => output.append("stdout", chunk));
    child.stderr?.on("data", (chunk: Buffer) => output.append("stderr", chunk));

    let cancellationReason: string | null = null;
    let terminateTimer: NodeJS.Timeout | undefined;
    let resolveClosed!: () => void;
    const closed = new Promise<void>((resolve) => {
      resolveClosed = resolve;
    });
    let resolveCompletion!: (outcome: Awaited<SandboxExecutionHandle["completion"]>) => void;
    const completion = new Promise<Awaited<SandboxExecutionHandle["completion"]>>((resolve) => {
      resolveCompletion = resolve;
    });
    let settling = false;
    const finish = async (outcome: SandboxExecutionOutcome): Promise<void> => {
      if (settling) return;
      settling = true;
      if (terminateTimer) clearTimeout(terminateTimer);
      clearTimeout(runtimeTimer);
      input.abortSignal?.removeEventListener("abort", onAbort);
      const waitForObservation =
        outcome.kind === "completed" &&
        outcome.result.exitCode !== null &&
        outcome.result.exitCode !== 0;
      const observations =
        (await denialCapture?.finish({ waitForObservation }).catch(() => [])) ?? [];
      const finalOutcome =
        outcome.kind === "completed"
          ? (() => {
              const evidence = classifyDenial({
                attempt: input.attempt,
                result: outcome.result,
                observations,
                filesystem: compiled,
              });
              return evidence ? { kind: "denied" as const, evidence } : outcome;
            })()
          : outcome;
      resolveCompletion(finalOutcome);
      resolveClosed();
    };
    child.once("error", () => {
      void finish({ kind: "runtime-failed", reason: "executor-spawn-failed" });
    });
    child.once("close", (exitCode, signal) => {
      if (cancellationReason) {
        void finish({ kind: "cancelled", reason: cancellationReason });
        return;
      }
      const captured = output.result();
      void finish({
        kind: "completed",
        result: {
          exitCode,
          signal,
          stdoutSummary: captured.stdout,
          stderrSummary: captured.stderr,
          outputTruncated: captured.truncated,
          startedAt,
          completedAt: this.now(),
        },
      });
    });

    let cancelPromise: Promise<void> | undefined;
    const cancel = (reason: string): Promise<void> => {
      if (cancelPromise) return cancelPromise;
      cancellationReason = reason;
      cancelPromise = (async () => {
        processTreeSignal(child, "SIGTERM");
        terminateTimer = setTimeout(() => processTreeSignal(child, "SIGKILL"), TERMINATE_GRACE_MS);
        terminateTimer.unref?.();
        await closed;
      })();
      return cancelPromise;
    };
    const onAbort = () => {
      void cancel("caller-aborted");
    };
    input.abortSignal?.addEventListener("abort", onAbort, { once: true });
    const runtimeTimer = setTimeout(
      () => void cancel("max-runtime-exceeded"),
      profile.process.maxRuntimeMs,
    );
    runtimeTimer.unref?.();

    await new Promise<void>((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", () => reject(new Error("spawn-failed")));
    });
    if (child.pid) denialCapture?.bindProcess(child.pid);
    if (cancellationReason) {
      processTreeSignal(child, "SIGTERM");
      await cancelPromise;
    } else if (input.abortSignal?.aborted) {
      await cancel("caller-aborted");
    }
    return Object.freeze({
      processHandle: `local:${child.pid}`,
      completion,
      cancel,
    });
  }
}
