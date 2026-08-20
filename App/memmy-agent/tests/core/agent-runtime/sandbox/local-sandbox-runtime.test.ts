import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createLocalSandboxRuntime } from "../../../../src/core/agent-runtime/sandbox/composition/local-sandbox-runtime.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "memmy-local-sandbox-runtime-"));
  roots.push(root);
  const workspace = path.join(root, "workspace");
  fs.mkdirSync(workspace);
  return { root, workspace };
}

async function authorizeExec(
  runtime: ReturnType<typeof createLocalSandboxRuntime>,
  arguments_: Readonly<Record<string, unknown>>,
) {
  const decision = await runtime.guard.authorize({
    callId: "exec-1",
    toolName: "exec",
    arguments: arguments_,
  });
  if (decision.type !== "allow" || !decision.authorization) {
    throw new Error(`exec was not authorized: ${decision.type}`);
  }
  return decision.authorization;
}

describe.skipIf(process.platform !== "darwin")("local sandbox runtime", () => {
  it("routes exec through Seatbelt and appends its terminal audit evidence", async () => {
    const { workspace } = fixture();
    const runtime = createLocalSandboxRuntime({
      workspaceRoot: workspace,
      interactiveProfile: "workspace-confidential",
      backgroundProfile: "workspace-confidential",
      source: "cli",
      projectId: "project-1",
    });
    const arguments_ = { command: "printf sandboxed" };
    const authorization = await authorizeExec(runtime, arguments_);

    await expect(
      runtime.executor.execute({
        runtimeCallId: "exec-1",
        toolName: "exec",
        arguments: arguments_,
        authorization,
        workspaceRoot: workspace,
      }),
    ).resolves.toBe("sandboxed\nExit code: 0");

    const auditEvents = fs
      .readFileSync(path.join(workspace, ".memmy", "sandbox", "audit.jsonl"), "utf8")
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(auditEvents).toHaveLength(1);
    expect(auditEvents[0]).toMatchObject({
      runtimeCallId: "exec-1",
      detail: { kind: "attempt-finished", sandboxType: "macos-seatbelt", state: "completed" },
    });
  });

  it("does not expose content from outside the confidential workspace", async () => {
    const { root, workspace } = fixture();
    const protectedPath = path.join(root, "protected.txt");
    fs.writeFileSync(protectedPath, "outside-secret", "utf8");
    const runtime = createLocalSandboxRuntime({
      workspaceRoot: workspace,
      interactiveProfile: "workspace-confidential",
      backgroundProfile: "workspace-confidential",
      source: "cli",
      projectId: "project-1",
    });
    const arguments_ = { command: `cat ${JSON.stringify(protectedPath)}` };
    const authorization = await authorizeExec(runtime, arguments_);

    const output = await runtime.executor.execute({
      runtimeCallId: "exec-2",
      toolName: "exec",
      arguments: arguments_,
      authorization,
      workspaceRoot: workspace,
    });

    expect(String(output)).toContain("Error:");
    expect(String(output)).not.toContain("outside-secret");
  });

  it("applies a shorter per-call timeout without weakening the profile limit", async () => {
    const { workspace } = fixture();
    const runtime = createLocalSandboxRuntime({
      workspaceRoot: workspace,
      interactiveProfile: "workspace-confidential",
      backgroundProfile: "workspace-confidential",
      source: "cli",
      projectId: "project-1",
    });
    const arguments_ = { command: "sleep 5", timeout: 1 };
    const authorization = await authorizeExec(runtime, arguments_);

    await expect(
      runtime.executor.execute({
        runtimeCallId: "exec-timeout",
        toolName: "exec",
        arguments: arguments_,
        authorization,
        workspaceRoot: workspace,
      }),
    ).resolves.toBe("Error: Command timed out after 1 seconds");
  });
});
