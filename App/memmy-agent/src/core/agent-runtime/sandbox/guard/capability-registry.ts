import type {
  ResolvedAccessSet,
  ToolCapabilities,
  ToolCapabilityContext,
} from "../domain/capability.js";

export class CapabilityRegistry {
  private readonly definitions = new Map<string, ToolCapabilities>();

  register(toolName: string, definition: ToolCapabilities): void {
    if (!toolName.trim()) throw new Error("toolName must not be empty");
    this.definitions.set(toolName, definition);
  }

  resolve(
    toolName: string,
    params: Readonly<Record<string, unknown>>,
    context: ToolCapabilityContext,
  ): ResolvedAccessSet {
    const definition = this.definitions.get(toolName);
    if (!definition) return Object.freeze([{ kind: "unknown", name: toolName }]);
    return Object.freeze([...definition.resolveAccess(params, context)]);
  }

  get(toolName: string): ToolCapabilities | undefined {
    return this.definitions.get(toolName);
  }
}
