import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { CapabilityRegistry } from "../../../../src/core/agent-runtime/sandbox/guard/capability-registry.js";
import { registerCoreFileCapabilities } from "../../../../src/core/agent-runtime/sandbox/guard/core-file-capabilities.js";

const context = { cwd: "/workspace/project", workspaceRoots: ["/workspace/project"] };
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe("core file capabilities", () => {
  it.each([
    ["read_file", "read"],
    ["list_dir", "read"],
    ["write_file", "write"],
    ["edit_file", "write"],
  ] as const)("resolves %s to canonical %s access", (toolName, access) => {
    const registry = new CapabilityRegistry();
    registerCoreFileCapabilities(registry);

    expect(registry.resolve(toolName, { path: "src/index.ts" }, context)).toEqual([
      {
        kind: "filesystem",
        access,
        path: path.resolve(context.cwd, "src/index.ts"),
      },
    ]);
  });

  it("fails closed when a file path is missing", () => {
    const registry = new CapabilityRegistry();
    registerCoreFileCapabilities(registry);

    expect(registry.resolve("list_dir", {}, context)).toEqual([
      { kind: "unknown", name: "list_dir.path" },
    ]);
  });

  it("resolves symlinks before policy evaluation", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "memmy-capability-path-"));
    roots.push(root);
    const workspace = path.join(root, "workspace");
    const outside = path.join(root, "outside");
    fs.mkdirSync(workspace);
    fs.mkdirSync(outside);
    fs.symlinkSync(outside, path.join(workspace, "linked"));
    const registry = new CapabilityRegistry();
    registerCoreFileCapabilities(registry);

    expect(registry.resolve(
      "write_file",
      { path: "linked/new-file.txt" },
      { cwd: workspace, workspaceRoots: [workspace] },
    )).toEqual([{
      kind: "filesystem",
      access: "write",
      path: path.join(fs.realpathSync(outside), "new-file.txt"),
    }]);
  });

  it("fails closed for a broken symlink", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "memmy-capability-broken-link-"));
    roots.push(root);
    fs.symlinkSync(path.join(root, "missing-target"), path.join(root, "broken"));
    const registry = new CapabilityRegistry();
    registerCoreFileCapabilities(registry);

    expect(registry.resolve(
      "write_file",
      { path: path.join(root, "broken") },
      { cwd: root, workspaceRoots: [root] },
    )).toEqual([{ kind: "unknown", name: "write_file.path" }]);
  });
});
