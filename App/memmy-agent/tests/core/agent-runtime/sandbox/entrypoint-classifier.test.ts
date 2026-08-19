import { describe, expect, it } from "vitest";
import { classifyEntrypoint } from "../../../../src/core/agent-runtime/sandbox/policy/entrypoint-classifier.js";

describe("EntrypointClassifier", () => {
  it("keeps Desktop, CLI, and TUI interactive with a trusted approval channel", () => {
    expect(
      ["desktop", "cli", "tui"].map((source) =>
        classifyEntrypoint({
          source: source as "desktop" | "cli" | "tui",
          projectId: "project-1",
          executorId: "local",
        }),
      ),
    ).toEqual([
      {
        context: {
          class: "interactive",
          projectId: "project-1",
          approvalChannel: "desktop",
          executorId: "local",
        },
        workspaceProfile: "workspace-compatible",
      },
      {
        context: {
          class: "interactive",
          projectId: "project-1",
          approvalChannel: "cli",
          executorId: "local",
        },
        workspaceProfile: "workspace-compatible",
      },
      {
        context: {
          class: "interactive",
          projectId: "project-1",
          approvalChannel: "tui",
          executorId: "local",
        },
        workspaceProfile: "workspace-compatible",
      },
    ]);
  });

  it("classifies unattended entrypoints as confidential and non-interactive", () => {
    expect(
      classifyEntrypoint({
        source: "cron",
        projectId: "project-1",
        executorId: "local",
      }),
    ).toEqual({
      context: {
        class: "background",
        projectId: "project-1",
        approvalChannel: "none",
        executorId: "local",
      },
      workspaceProfile: "workspace-confidential",
    });
  });
});
