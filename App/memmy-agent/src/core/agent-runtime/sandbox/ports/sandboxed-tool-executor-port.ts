import type { EffectiveAuthorization } from "../policy/policy-resolver.js";

export type SandboxedToolExecutionRequest = Readonly<{
  runtimeCallId: string | null;
  toolName: string;
  arguments: Readonly<Record<string, unknown>>;
  authorization: EffectiveAuthorization;
  workspaceRoot: string;
  abortSignal?: AbortSignal;
}>;

/** Executes supported Tool calls through SandboxManager instead of the Tool's in-process path. */
export interface SandboxedToolExecutorPort {
  handles(toolName: string): boolean;
  execute(request: SandboxedToolExecutionRequest): Promise<unknown>;
}
