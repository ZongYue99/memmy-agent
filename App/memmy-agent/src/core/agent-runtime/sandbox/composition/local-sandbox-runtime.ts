import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { InMemoryApprovalGrantStore } from "../adapters/approval/in-memory-approval-grant-store.js";
import {
  CallbackApprovalChannel,
  type ApprovalPromptHandler,
} from "../adapters/approval/callback-approval-channel.js";
import { AuditRecorder } from "../adapters/audit/audit-recorder.js";
import { JsonlAuditOutbox } from "../adapters/audit/jsonl-audit-outbox.js";
import { BackendRegistry } from "../adapters/execution/backend-registry.js";
import { LocalSandboxExecutor } from "../adapters/execution/local-sandbox-executor.js";
import { LocalSandboxedToolExecutor } from "../adapters/execution/local-sandboxed-tool-executor.js";
import { LinuxBwrapBackend } from "../adapters/execution/linux-bwrap-backend.js";
import { MacosSeatbeltBackend } from "../adapters/execution/macos-seatbelt-backend.js";
import { ApprovalBroker } from "../approval/approval-broker.js";
import { AttemptPlanner } from "../manager/attempt-planner.js";
import { SandboxManager } from "../manager/sandbox-manager.js";
import type { EntrypointSource, WorkspaceProfile } from "../policy/entrypoint-classifier.js";
import type { SandboxedToolExecutorPort } from "../ports/sandboxed-tool-executor-port.js";
import type { ToolCallGuardPort } from "../ports/tool-call-guard-port.js";
import { createLocalToolCallGuard } from "./local-tool-call-guard.js";

export type LocalSandboxRuntime = Readonly<{
  guard: ToolCallGuardPort;
  executor: SandboxedToolExecutorPort;
}>;

function ensurePrivateAuditDirectory(workspaceRoot: string): string {
  const canonicalWorkspace = fs.realpathSync.native(workspaceRoot);
  let current = canonicalWorkspace;
  for (const segment of [".memmy", "sandbox"] as const) {
    current = path.join(current, segment);
    if (!fs.existsSync(current)) fs.mkdirSync(current, { mode: 0o700 });
    const status = fs.lstatSync(current);
    if (!status.isDirectory() || status.isSymbolicLink()) {
      throw new Error("sandbox audit directory must be a real directory");
    }
    if (process.platform !== "win32") fs.chmodSync(current, 0o700);
  }
  return current;
}

export function createLocalSandboxRuntime(
  input: Readonly<{
    workspaceRoot: string;
    interactiveProfile: WorkspaceProfile;
    backgroundProfile: WorkspaceProfile;
    source: EntrypointSource;
    projectId: string;
    executorId?: string;
    approvalPrompt?: ApprovalPromptHandler;
    approvalSubjectId?: string;
  }>,
): LocalSandboxRuntime {
  const workspaceRoot = fs.realpathSync.native(path.resolve(input.workspaceRoot));
  const clock = { now: Date.now };
  const ids = { nextId: (kind: string) => `${kind}-${randomUUID()}` };
  const auditDirectory = ensurePrivateAuditDirectory(workspaceRoot);
  const audit = new AuditRecorder(
    new JsonlAuditOutbox(path.join(auditDirectory, "audit.jsonl")),
    ids,
    clock,
  );
  const platformExecutor = new LocalSandboxExecutor(
    new BackendRegistry([new MacosSeatbeltBackend(), new LinuxBwrapBackend()]),
  );
  const approvalMode =
    input.approvalPrompt && ["desktop", "cli", "tui"].includes(input.source)
      ? "on-request"
      : "never";
  const guard = createLocalToolCallGuard({ ...input, workspaceRoot, approvalMode });
  const approvalBroker =
    approvalMode === "on-request" && input.approvalPrompt
      ? new ApprovalBroker({
          channel: new CallbackApprovalChannel(input.approvalPrompt),
          store: new InMemoryApprovalGrantStore(),
          ids,
          clock,
          audit,
        })
      : null;
  const manager = new SandboxManager(new AttemptPlanner(ids, clock), platformExecutor, clock, {
    audit,
    ...(approvalBroker ? { approvalRetry: { broker: approvalBroker } } : {}),
  });
  return {
    guard,
    executor: new LocalSandboxedToolExecutor(
      manager,
      approvalBroker
        ? {
            subjectId: input.approvalSubjectId ?? "local-user",
            resolveCurrentAuthorization: async (request) => {
              const decision = await guard.authorize({
                callId: request.runtimeCallId,
                toolName: request.toolName,
                arguments: request.arguments,
              });
              if (decision.type !== "allow" || !decision.authorization) {
                throw new Error("sandbox authorization is no longer available");
              }
              return decision.authorization;
            },
          }
        : undefined,
    ),
  };
}
