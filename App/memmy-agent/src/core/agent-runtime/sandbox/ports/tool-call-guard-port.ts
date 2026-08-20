import type { EffectiveAuthorization } from "../policy/policy-resolver.js";

export type ToolCallGuardRequest = Readonly<{
  callId: string | null;
  toolName: string;
  arguments: Readonly<Record<string, unknown>>;
}>;

export type ToolCallGuardDecision =
  | Readonly<{ type: "allow"; authorization?: EffectiveAuthorization }>
  | Readonly<{ type: "ask"; reason: string }>
  | Readonly<{ type: "deny"; reason: string }>;

export interface ToolCallGuardPort {
  authorize(request: ToolCallGuardRequest): ToolCallGuardDecision | Promise<ToolCallGuardDecision>;
}
