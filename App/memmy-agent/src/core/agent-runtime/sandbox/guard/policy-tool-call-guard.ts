import type { ResolvedAccessSet, ToolCapabilityContext } from "../domain/capability.js";
import type { EffectiveAuthorization } from "../policy/policy-resolver.js";
import type {
  ToolCallGuardDecision,
  ToolCallGuardPort,
  ToolCallGuardRequest,
} from "../ports/tool-call-guard-port.js";
import { CapabilityRegistry } from "./capability-registry.js";
import { decideToolAccess } from "./tool-guard.js";

export type AuthorizationResolver = (
  requestedCapabilities: ResolvedAccessSet,
) => EffectiveAuthorization | Promise<EffectiveAuthorization>;

export class PolicyToolCallGuard implements ToolCallGuardPort {
  constructor(
    private readonly capabilities: CapabilityRegistry,
    private readonly capabilityContext: ToolCapabilityContext,
    private readonly resolveAuthorization: AuthorizationResolver,
  ) {}

  async authorize(request: ToolCallGuardRequest): Promise<ToolCallGuardDecision> {
    const requestedCapabilities = this.capabilities.resolve(
      request.toolName,
      request.arguments,
      this.capabilityContext,
    );
    const decision = decideToolAccess(await this.resolveAuthorization(requestedCapabilities));
    switch (decision.kind) {
      case "execute":
        return { type: "allow", authorization: decision.authorization };
      case "requires-approval":
        return { type: "ask", reason: decision.reason };
      case "deny":
        return { type: "deny", reason: decision.reason };
    }
  }
}
