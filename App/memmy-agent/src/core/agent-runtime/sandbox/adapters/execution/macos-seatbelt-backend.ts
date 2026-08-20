import type { ChildProcess, SpawnOptions } from "node:child_process";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { NormalizedToolCall, SandboxAttempt } from "../../domain/sandbox-attempt.js";
import type { PermissionProfile } from "../../domain/permission-profile.js";
import type { SandboxExecutionOutcome } from "../../domain/sandbox-result.js";
import { DenialClassifier } from "../../guard/denial-classifier.js";
import { stablePolicyHash } from "../../policy/policy-hash.js";
import type { SandboxExecutionHandle } from "../../ports/sandbox-executor-port.js";
import type {
  SandboxBackend,
  SandboxBackendSelectionInput,
  SandboxBackendSupport,
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

type SpawnProcess = (
  command: string,
  args: readonly string[],
  options: SpawnOptions,
) => ChildProcess;

type MacosSeatbeltBackendOptions = Readonly<{
  platform?: NodeJS.Platform;
  seatbeltExecutable?: string;
  spawnProcess?: SpawnProcess;
  now?: () => number;
  denialMonitor?: SeatbeltDenialMonitor;
  denialClassifier?: DenialClassifier;
}>;

type OutputCapture = Readonly<{
  append(stream: "stdout" | "stderr", chunk: Buffer): void;
  result(): Readonly<{ stdout: string; stderr: string; truncated: boolean }>;
}>;

export class MacosSeatbeltBackendError extends Error {
  constructor(readonly code: "unsupported-profile" | "unsupported-call" | "spawn-failed") {
    super(code);
    this.name = "MacosSeatbeltBackendError";
  }
}

function createOutputCapture(maxBytes: number): OutputCapture {
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  let capturedBytes = 0;
  let truncated = false;
  return {
    append(stream, chunk) {
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

function commandFromCall(call: NormalizedToolCall): string {
  if (call.toolName !== "exec") throw new MacosSeatbeltBackendError("unsupported-call");
  const command = call.arguments.command;
  if (typeof command !== "string" || !command.trim() || command.includes("\0")) {
    throw new MacosSeatbeltBackendError("unsupported-call");
  }
  return command;
}

function buildEnvironment(profile: PermissionProfile): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  const removed = new Set(profile.environment.remove);
  for (const name of profile.environment.inherit) {
    if (!name || name.includes("=") || name.includes("\0")) {
      throw new MacosSeatbeltBackendError("unsupported-profile");
    }
    if (removed.has(name)) continue;
    const value = process.env[name];
    if (value !== undefined) environment[name] = value;
  }
  for (const [name, value] of Object.entries(profile.environment.set)) {
    if (!name || name.includes("=") || name.includes("\0") || value.includes("\0")) {
      throw new MacosSeatbeltBackendError("unsupported-profile");
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
    throw new MacosSeatbeltBackendError("unsupported-profile");
  }
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

function profileIsSupported(profile: PermissionProfile): boolean {
  return (
    profile.filesystem.kind === "restricted" &&
    profile.network.mode === "denied" &&
    profile.process.spawn === "non-interactive" &&
    (profile.process.maxProcesses === 1 || profile.process.maxProcesses === Number.MAX_SAFE_INTEGER)
  );
}

export class MacosSeatbeltBackend implements SandboxBackend {
  readonly sandboxType = "macos-seatbelt" as const;
  private readonly platform: NodeJS.Platform;
  private readonly seatbeltExecutable: string;
  private readonly spawnProcess: SpawnProcess;
  private readonly now: () => number;
  private readonly denialMonitor: SeatbeltDenialMonitor;
  private readonly denialClassifier: DenialClassifier;

  constructor(options: MacosSeatbeltBackendOptions = {}) {
    this.platform = options.platform ?? process.platform;
    this.seatbeltExecutable = options.seatbeltExecutable ?? DEFAULT_SEATBELT_EXECUTABLE;
    this.spawnProcess = options.spawnProcess ?? spawn;
    this.now = options.now ?? Date.now;
    this.denialMonitor = options.denialMonitor ?? new MacosSeatbeltDenialMonitor();
    this.denialClassifier = options.denialClassifier ?? new DenialClassifier();
  }

  inspectSupport(input: SandboxBackendSelectionInput): SandboxBackendSupport {
    if (this.platform !== "darwin") return { supported: false, reason: "platform-mismatch" };
    try {
      fs.accessSync(this.seatbeltExecutable, fs.constants.X_OK);
    } catch {
      return { supported: false, reason: "backend-unavailable" };
    }
    const { permissionProfile } = input;
    if (permissionProfile.filesystem.kind !== "restricted") {
      return { supported: false, reason: "filesystem-mode-unsupported" };
    }
    if (permissionProfile.network.mode !== "denied") {
      return { supported: false, reason: "network-mode-unsupported" };
    }
    if (permissionProfile.process.spawn !== "non-interactive") {
      return { supported: false, reason: "process-mode-unsupported" };
    }
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
      target: { sandboxType: this.sandboxType, networkContextId: "local-network-denied" },
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
      this.platform !== "darwin" ||
      input.attempt.sandboxType !== this.sandboxType ||
      !profileIsSupported(input.attempt.permissionProfile) ||
      !attemptIsBound(input.attempt, input.call)
    ) {
      throw new MacosSeatbeltBackendError("unsupported-profile");
    }
    const command = commandFromCall(input.call);
    const compiled = compileMacosSeatbeltPolicy(input.attempt.permissionProfile);
    const sandboxCwd = canonicalSandboxCwd(
      input.attempt.sandboxCwd,
      input.attempt.workspaceRoots,
      compiled,
    );
    const environment = buildEnvironment(input.attempt.permissionProfile);
    const denialCapture = await this.denialMonitor
      .start(input.attempt.permissionProfile.process.maxRuntimeMs)
      .catch(() => null);
    const startedAt = this.now();
    const output = createOutputCapture(input.attempt.permissionProfile.process.maxOutputBytes);
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
      throw new MacosSeatbeltBackendError("spawn-failed");
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
              const evidence = this.denialClassifier.classify({
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
          evidenceRefs: [],
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
      input.attempt.permissionProfile.process.maxRuntimeMs,
    );
    runtimeTimer.unref?.();

    await new Promise<void>((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", () => reject(new MacosSeatbeltBackendError("spawn-failed")));
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
