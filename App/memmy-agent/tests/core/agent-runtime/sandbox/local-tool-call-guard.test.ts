import { describe, expect, it } from "vitest";
import {
  createLocalToolCallGuard,
  runtimeEntrypointSource,
} from "../../../../src/core/agent-runtime/sandbox/composition/local-tool-call-guard.js";

describe("local tool-call guard composition", () => {
  it("allows workspace file access and denies unsupported or outside access", async () => {
    const guard = createLocalToolCallGuard({
      workspaceRoot: "/workspace/project",
      interactiveProfile: "workspace-confidential",
      backgroundProfile: "workspace-confidential",
      source: "cli",
      projectId: "project-1",
    });

    await expect(
      guard.authorize({
        callId: "read-1",
        toolName: "read_file",
        arguments: { path: "README.md" },
      }),
    ).resolves.toMatchObject({ type: "allow", authorization: { approvalMode: "never" } });
    await expect(
      guard.authorize({
        callId: "read-2",
        toolName: "read_file",
        arguments: { path: "/etc/passwd" },
      }),
    ).resolves.toEqual({ type: "deny", reason: "exceeds-policy-cap" });
    await expect(
      guard.authorize({
        callId: "exec-1",
        toolName: "exec",
        arguments: { command: "pwd" },
      }),
    ).resolves.toMatchObject({ type: "allow", authorization: { approvalMode: "never" } });
    await expect(
      guard.authorize({
        callId: "exec-session-1",
        toolName: "exec",
        arguments: { command: "pwd", yield_time_ms: 1_000 },
      }),
    ).resolves.toEqual({ type: "deny", reason: "unknown-capability" });
  });

  it("classifies goal continuations before their transport channel", () => {
    expect(
      runtimeEntrypointSource("cli", {
        kind: "goal_continuation",
        goalId: "goal-1",
        objective: "continue",
      }),
    ).toBe("goal");
    expect(runtimeEntrypointSource("cli", null)).toBe("cli");
    expect(runtimeEntrypointSource("websocket", null)).toBe("channel");
  });
});
