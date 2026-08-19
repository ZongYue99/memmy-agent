import type {
  ResolvedAccessSet,
  ToolAccessResolver,
  ToolCapabilityContext,
} from "../domain/capability.js";

export class CapabilityRegistry {
  private readonly resolvers = new Map<string, ToolAccessResolver>();

  register(toolName: string, resolver: ToolAccessResolver): void {
    if (!toolName.trim()) throw new Error("toolName must not be empty");
    this.resolvers.set(toolName, resolver);
  }

  resolve(
    toolName: string,
    params: Readonly<Record<string, unknown>>,
    context: ToolCapabilityContext,
  ): ResolvedAccessSet {
    const resolver = this.resolvers.get(toolName);
    if (!resolver) return [{ kind: "unknown", name: toolName }];
    return resolver(params, context);
  }
}
