export type WorkspaceProfile = "workspace-compatible" | "workspace-confidential";
export type EntrypointClass = "interactive" | "background" | "external";
export type ApprovalChannel = "desktop" | "cli" | "tui" | "none";

export type EntrypointContext = Readonly<{
  class: EntrypointClass;
  projectId: string;
  parentAuthorizationHash?: string;
  approvalChannel: ApprovalChannel;
  executorId: string;
}>;

export type EntrypointSource =
  | "desktop"
  | "cli"
  | "tui"
  | "goal"
  | "cron"
  | "channel"
  | "subagent"
  | "external-executor";

export type ClassifiedEntrypoint = Readonly<{
  context: EntrypointContext;
  workspaceProfile: WorkspaceProfile;
}>;

export function classifyEntrypoint(
  input: Readonly<{
    source: EntrypointSource;
    projectId: string;
    executorId: string;
    parentAuthorizationHash?: string;
  }>,
): ClassifiedEntrypoint {
  const common = {
    projectId: input.projectId,
    executorId: input.executorId,
    ...(input.parentAuthorizationHash
      ? { parentAuthorizationHash: input.parentAuthorizationHash }
      : {}),
  };
  switch (input.source) {
    case "desktop":
    case "cli":
    case "tui":
      return {
        context: { ...common, class: "interactive", approvalChannel: input.source },
        workspaceProfile: "workspace-compatible",
      };
    case "goal":
    case "cron":
    case "channel":
      return {
        context: { ...common, class: "background", approvalChannel: "none" },
        workspaceProfile: "workspace-confidential",
      };
    case "subagent":
    case "external-executor":
      return {
        context: { ...common, class: "external", approvalChannel: "none" },
        workspaceProfile: "workspace-confidential",
      };
  }
}
