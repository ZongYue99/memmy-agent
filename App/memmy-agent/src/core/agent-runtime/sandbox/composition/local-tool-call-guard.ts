import path from "node:path";
import type { AgentInternalTurnContext } from "../../runner.js";
import type { EntrypointSource, WorkspaceProfile } from "../policy/entrypoint-classifier.js";
import { classifyEntrypoint } from "../policy/entrypoint-classifier.js";
import { resolvePolicy } from "../policy/policy-resolver.js";
import type { ApprovalMode } from "../policy/policy-resolver.js";
import { createWorkspacePreset } from "../policy/presets.js";
import { CapabilityRegistry } from "../guard/capability-registry.js";
import { registerCoreFileCapabilities } from "../guard/core-file-capabilities.js";
import { registerExecCapabilities } from "../guard/exec-capabilities.js";
import { PolicyToolCallGuard } from "../guard/policy-tool-call-guard.js";

export function runtimeEntrypointSource(
  channel: string | null | undefined,
  internalTurnContext: AgentInternalTurnContext | null | undefined,
  turnSource?: unknown,
): EntrypointSource {
  if (internalTurnContext?.kind === "goal_continuation") return "goal";
  const sourceKind =
    turnSource && typeof turnSource === "object" && "kind" in turnSource
      ? (turnSource as { kind?: unknown }).kind
      : null;
  if (sourceKind === "tui") return "tui";
  if (sourceKind === "gui") return "desktop";
  if (channel === "cli") return "cli";
  if (channel === "tui") return "tui";
  return "channel";
}

export function createLocalToolCallGuard(
  input: Readonly<{
    workspaceRoot: string;
    interactiveProfile: WorkspaceProfile;
    backgroundProfile: WorkspaceProfile;
    source: EntrypointSource;
    projectId: string;
    executorId?: string;
    approvalMode?: ApprovalMode;
  }>,
): PolicyToolCallGuard {
  const workspaceRoot = path.resolve(input.workspaceRoot);
  const entrypoint = classifyEntrypoint({
    source: input.source,
    projectId: input.projectId,
    executorId: input.executorId ?? "local",
  });
  const workspaceProfile =
    entrypoint.context.class === "interactive" ? input.interactiveProfile : input.backgroundProfile;
  const basePreset = createWorkspacePreset({
    workspaceRoot,
    profile: workspaceProfile,
  });
  const approvalMode = input.approvalMode ?? "never";
  const capPreset = createWorkspacePreset({
    workspaceRoot,
    profile:
      approvalMode === "on-request" && entrypoint.context.class === "interactive"
        ? "workspace-compatible"
        : workspaceProfile,
  });
  const capabilities = new CapabilityRegistry();
  registerCoreFileCapabilities(capabilities);
  registerExecCapabilities(capabilities);
  return new PolicyToolCallGuard(
    capabilities,
    { cwd: workspaceRoot, workspaceRoots: [workspaceRoot] },
    (requestedCapabilities) =>
      resolvePolicy({
        caps: [capPreset],
        baseGrants: [basePreset],
        requestedCapabilities,
        entrypoint: entrypoint.context,
        workspaceProfile,
        approvalMode,
      }),
  );
}
