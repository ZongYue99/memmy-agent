import { describe, expect, it } from "vitest";
import { CapabilityRegistry } from "../../../../src/core/agent-runtime/sandbox/guard/capability-registry.js";

const context = { cwd: "/workspace", workspaceRoots: ["/workspace"] };

describe("CapabilityRegistry", () => {
  it("resolves access from normalized tool parameters", () => {
    const registry = new CapabilityRegistry();
    registry.register("write_file", (params) => [
      { kind: "filesystem", access: "write", path: String(params.path) },
    ]);

    expect(registry.resolve("write_file", { path: "/workspace/index.ts" }, context)).toEqual([
      { kind: "filesystem", access: "write", path: "/workspace/index.ts" },
    ]);
  });

  it("fails closed when a tool has no capability definition", () => {
    expect(new CapabilityRegistry().resolve("third_party_tool", {}, context)).toEqual([
      { kind: "unknown", name: "third_party_tool" },
    ]);
  });
});
