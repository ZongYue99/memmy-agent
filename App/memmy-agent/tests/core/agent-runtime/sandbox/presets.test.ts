import path from "node:path";
import { describe, expect, it } from "vitest";
import { createWorkspacePreset } from "../../../../src/core/agent-runtime/sandbox/policy/presets.js";

describe("createWorkspacePreset", () => {
  it("gives interactive workspaces host read compatibility with sensitive denies", () => {
    const preset = createWorkspacePreset({
      workspaceRoot: "/workspace/project",
      profile: "workspace-compatible",
      homeDirectory: "/Users/tester",
    });

    expect(preset.filesystem).toEqual({
      read: [path.parse(path.resolve("/workspace/project")).root],
      write: [path.resolve("/workspace/project")],
      deny: [
        path.resolve("/Users/tester/.aws"),
        path.resolve("/Users/tester/.config/gcloud"),
        path.resolve("/Users/tester/.ssh"),
        path.resolve("/Users/tester/Library/Application Support/Google/Chrome"),
        path.resolve("/workspace/project/.env"),
      ].sort(),
    });
    expect(preset.network).toEqual({ mode: "denied" });
  });

  it("limits confidential workspaces to the declared workspace root", () => {
    const preset = createWorkspacePreset({
      workspaceRoot: "/workspace/project",
      profile: "workspace-confidential",
      homeDirectory: "/Users/tester",
    });

    expect(preset.filesystem.read).toEqual([path.resolve("/workspace/project")]);
    expect(preset.filesystem.write).toEqual([path.resolve("/workspace/project")]);
  });
});
