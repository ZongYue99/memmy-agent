import { describe, expect, it, vi } from "vitest";
import { PreflightApprovalBroker } from "../../../../src/core/agent-runtime/sandbox/approval/preflight-approval-broker.js";
import { createLocalToolCallGuard } from "../../../../src/core/agent-runtime/sandbox/composition/local-tool-call-guard.js";

const request = {
  callId: "read-external",
  toolName: "read_file",
  arguments: { path: "/opt/shared.txt" },
};

async function askDecision() {
  const guard = createLocalToolCallGuard({
    workspaceRoot: "/workspace/project",
    interactiveProfile: "workspace-confidential",
    backgroundProfile: "workspace-confidential",
    source: "cli",
    projectId: "project-1",
    approvalMode: "on-request",
  });
  const decision = await guard.authorize(request);
  if (decision.type !== "ask") throw new Error(`expected ask, received ${decision.type}`);
  return { guard, decision };
}

describe("PreflightApprovalBroker", () => {
  it("rechecks current policy before applying an approved capability", async () => {
    const { decision } = await askDecision();
    const events: unknown[] = [];
    const broker = new PreflightApprovalBroker({
      prompt: async () => "approved",
      ids: { nextId: (kind) => `${kind}-1` },
      clock: { now: () => 1_000 },
      audit: { record: async (event) => void events.push(event) },
    });

    await expect(
      broker.requestApproval({
        request,
        decision,
        subjectId: "user-1",
        resolveCurrentDecision: async () => ({ type: "deny", reason: "policy-changed" }),
      }),
    ).resolves.toEqual({ kind: "invalid-response" });
    expect(events).toHaveLength(2);
  });

  it("expires a prompt that never resolves", async () => {
    const { guard, decision } = await askDecision();
    const prompt = vi.fn(() => new Promise<"approved">(() => undefined));
    const broker = new PreflightApprovalBroker({
      prompt,
      ids: { nextId: (kind) => `${kind}-1` },
      clock: { now: Date.now },
      audit: { record: async () => undefined },
      ttlMs: 5,
    });

    await expect(
      broker.requestApproval({
        request,
        decision,
        subjectId: "user-1",
        resolveCurrentDecision: () => guard.authorize(request),
      }),
    ).resolves.toEqual({ kind: "expired" });
    expect(prompt).toHaveBeenCalledOnce();
  });
});
