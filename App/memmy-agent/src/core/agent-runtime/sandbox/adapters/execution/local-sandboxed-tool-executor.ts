import { randomUUID } from "node:crypto";
import path from "node:path";
import type { SandboxExecutionRecord } from "../../domain/sandbox-attempt.js";
import { SandboxManager } from "../../manager/sandbox-manager.js";
import type {
  SandboxedToolExecutionRequest,
  SandboxedToolExecutorPort,
} from "../../ports/sandboxed-tool-executor-port.js";

type ApprovalRetryOptions = Readonly<{
  subjectId: string;
  resolveCurrentAuthorization: (
    request: SandboxedToolExecutionRequest,
  ) => Promise<SandboxedToolExecutionRequest["authorization"]>;
}>;

function firstString(...values: unknown[]): string | null {
  return (
    values.find((value): value is string => typeof value === "string" && value.trim().length > 0) ??
    null
  );
}

function outputLimit(arguments_: Readonly<Record<string, unknown>>): number {
  const value =
    arguments_.max_output_chars ??
    arguments_.maxOutputChars ??
    arguments_.max_output_tokens ??
    arguments_.maxOutputTokens;
  return typeof value === "number" && Number.isSafeInteger(value)
    ? Math.min(Math.max(value, 1_000), 100_000)
    : 10_000;
}

function timeoutSeconds(arguments_: Readonly<Record<string, unknown>>): number | null {
  const value = arguments_.timeout ?? arguments_.timeout_s ?? arguments_.timeoutS;
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0
    ? Math.min(value, 600)
    : null;
}

function formatRecord(record: SandboxExecutionRecord, maxChars: number): string {
  const terminal = record.stateHistory.at(-1)?.state;
  if (!terminal) return "Error: sandbox_runtime_failed: missing terminal state";
  switch (terminal.kind) {
    case "completed": {
      const parts: string[] = [];
      if (terminal.result.stdoutSummary) parts.push(terminal.result.stdoutSummary);
      if (terminal.result.stderrSummary) {
        parts.push(`STDERR:\n${terminal.result.stderrSummary}`);
      }
      parts.push(`Exit code: ${terminal.result.exitCode}`);
      const output = parts.join("\n").slice(0, maxChars);
      return terminal.result.exitCode === 0
        ? output
        : `Error: command exited with ${terminal.result.exitCode}\n${output}`;
    }
    case "denied":
      return `Error: sandbox_denied: ${terminal.evidence.summary}`;
    case "cancelled":
      return `Error: sandbox_cancelled: ${terminal.reason}`;
    case "runtime-failed":
      return `Error: sandbox_runtime_failed: ${terminal.reason}`;
    case "created":
    case "running":
      return "Error: sandbox_runtime_failed: non-terminal execution record";
  }
}

/** Routes non-interactive exec calls through SandboxManager and the selected OS backend. */
export class LocalSandboxedToolExecutor implements SandboxedToolExecutorPort {
  constructor(
    private readonly manager: SandboxManager,
    private readonly approvalRetry?: ApprovalRetryOptions,
  ) {}

  handles(toolName: string): boolean {
    return toolName === "exec";
  }

  async execute(request: SandboxedToolExecutionRequest): Promise<unknown> {
    if (!this.handles(request.toolName)) {
      return `Error: sandbox_executor_unsupported_tool: ${request.toolName}`;
    }
    const command = firstString(request.arguments.command, request.arguments.cmd);
    if (!command) return "Error: Missing command. Provide command or cmd.";
    const relativeCwd = firstString(
      request.arguments.cwd,
      request.arguments.working_dir,
      request.arguments.workingDir,
      request.arguments.workdir,
    );
    const sandboxCwd = path.resolve(request.workspaceRoot, relativeCwd ?? ".");
    const timeout = timeoutSeconds(request.arguments);
    const timeoutSignal = timeout === null ? null : AbortSignal.timeout(timeout * 1_000);
    const abortSignal =
      request.abortSignal && timeoutSignal
        ? AbortSignal.any([request.abortSignal, timeoutSignal])
        : (request.abortSignal ?? timeoutSignal ?? undefined);
    const runtimeCallId = request.runtimeCallId?.trim() || `runtime-call-${randomUUID()}`;
    const call = { toolName: "exec", arguments: { command, sandboxCwd } };
    const executionInput = {
      runtimeCallId,
      call,
      authorization: request.authorization,
      sandboxCwd,
      workspaceRoots: [request.workspaceRoot],
      ...(abortSignal ? { abortSignal } : {}),
    };
    const approvalRetry = this.approvalRetry;
    const record = approvalRetry
      ? (
          await this.manager.runWithApprovalRetry({
            ...executionInput,
            resolveCurrentAuthorization: () => approvalRetry.resolveCurrentAuthorization(request),
            approvalSubjectId: approvalRetry.subjectId,
          })
        ).attempts.at(-1)!
      : await this.manager.runInitialAttempt(executionInput);
    if (timeoutSignal?.aborted && !request.abortSignal?.aborted) {
      return `Error: Command timed out after ${timeout} seconds`;
    }
    return formatRecord(record, outputLimit(request.arguments));
  }
}
