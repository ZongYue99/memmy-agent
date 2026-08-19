import { describe, expect, it, vi } from "vitest";
import { AgentRunner, AgentRunSpec } from "../../../../src/core/agent-runtime/runner.js";
import { Tool } from "../../../../src/core/agent-runtime/tools/base.js";
import { ToolRegistry } from "../../../../src/core/agent-runtime/tools/registry.js";
import { CapabilityRegistry } from "../../../../src/core/agent-runtime/sandbox/guard/capability-registry.js";
import { PolicyToolCallGuard } from "../../../../src/core/agent-runtime/sandbox/guard/policy-tool-call-guard.js";
import { resolvePolicy } from "../../../../src/core/agent-runtime/sandbox/policy/policy-resolver.js";
import { createWorkspacePreset } from "../../../../src/core/agent-runtime/sandbox/policy/presets.js";
import { ToolCallRequest } from "../../../../src/providers/base.js";

class TestWriteTool extends Tool {
  readonly executions: Record<string, unknown>[] = [];

  get name(): string {
    return "write_file";
  }

  get description(): string {
    return "test write";
  }

  get parameters(): Record<string, unknown> {
    return {
      type: "object",
      properties: { path: { type: "string" }, count: { type: "integer" } },
      required: ["path", "count"],
    };
  }

  execute(params: Record<string, unknown>): string {
    this.executions.push(params);
    return `count:${params.count}`;
  }
}

function createGuard(capabilities: CapabilityRegistry): PolicyToolCallGuard {
  const grant = createWorkspacePreset({
    workspaceRoot: "/workspace",
    profile: "workspace-confidential",
    homeDirectory: "/Users/tester",
  });
  return new PolicyToolCallGuard(
    capabilities,
    { cwd: "/workspace", workspaceRoots: ["/workspace"] },
    (requestedCapabilities) =>
      resolvePolicy({
        caps: [grant],
        baseGrants: [grant],
        requestedCapabilities,
        entrypoint: {
          class: "interactive",
          projectId: "project-1",
          approvalChannel: "desktop",
          executorId: "local",
        },
        workspaceProfile: "workspace-confidential",
        approvalMode: "on-request",
      }),
  );
}

describe("PolicyToolCallGuard", () => {
  it("connects prepared parameters to capability resolution and tool execution", async () => {
    const tool = new TestWriteTool();
    const tools = new ToolRegistry();
    tools.register(tool);
    const capabilities = new CapabilityRegistry();
    const resolveAccess = vi.fn((params: Readonly<Record<string, unknown>>) => [
      { kind: "filesystem" as const, access: "write" as const, path: String(params.path) },
    ]);
    capabilities.register("write_file", resolveAccess);

    const [result] = await new AgentRunner().executeTools(
      new AgentRunSpec({ tools, toolCallGuard: createGuard(capabilities) }),
      [
        new ToolCallRequest({
          id: "call-1",
          name: "write_file",
          arguments: { path: "/workspace/file.txt", count: "2" },
        }),
      ],
    );

    expect(resolveAccess).toHaveBeenCalledWith(
      { path: "/workspace/file.txt", count: 2 },
      { cwd: "/workspace", workspaceRoots: ["/workspace"] },
    );
    expect(tool.executions).toEqual([{ path: "/workspace/file.txt", count: 2 }]);
    expect(result).toMatchObject({ result: "count:2", event: { status: "ok" } });
  });

  it("fails closed before execution when the tool has no capability resolver", async () => {
    const tool = new TestWriteTool();
    const tools = new ToolRegistry();
    tools.register(tool);

    const [result] = await new AgentRunner().executeTools(
      new AgentRunSpec({ tools, toolCallGuard: createGuard(new CapabilityRegistry()) }),
      [
        new ToolCallRequest({
          id: "call-2",
          name: "write_file",
          arguments: { path: "/workspace/file.txt", count: 2 },
        }),
      ],
    );

    expect(tool.executions).toEqual([]);
    expect(result.result).toBe("Error: sandbox_denied: unknown-capability");
  });
});
