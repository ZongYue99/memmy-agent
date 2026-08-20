import { describe, expect, it, vi } from "vitest";
import { CallbackApprovalChannel } from "../../../../src/core/agent-runtime/sandbox/adapters/approval/callback-approval-channel.js";
import type { ApprovalPrompt } from "../../../../src/core/agent-runtime/sandbox/adapters/approval/callback-approval-channel.js";
import type { ApprovalRequest } from "../../../../src/core/agent-runtime/sandbox/approval/approval-grant.js";

const request: ApprovalRequest = {
  requestId: "request-1",
  runtimeCallId: "call-1",
  argsHash: "a".repeat(64),
  initialPolicyHash: "b".repeat(64),
  parentAttemptId: "attempt-1",
  additionalPermission: [{ kind: "filesystem", access: "read", path: "/shared/file.txt" }],
  subjectId: "user-1",
  nonce: "secret-nonce",
  requestedAt: 1_000,
  expiresAt: 2_000,
};

describe("CallbackApprovalChannel", () => {
  it("keeps the challenge nonce out of the UI prompt and binds an approval internally", async () => {
    const handler = vi.fn(async (prompt: ApprovalPrompt) => {
      void prompt;
      return "approved" as const;
    });
    const channel = new CallbackApprovalChannel(handler);

    await expect(channel.requestApproval(request)).resolves.toEqual({
      kind: "approved",
      requestId: "request-1",
      subjectId: "user-1",
      nonce: "secret-nonce",
    });
    expect(handler).toHaveBeenCalledWith(
      {
        requestId: "request-1",
        runtimeCallId: "call-1",
        parentAttemptId: "attempt-1",
        additionalPermission: request.additionalPermission,
        expiresAt: 2_000,
      },
      undefined,
    );
    expect(JSON.stringify(handler.mock.calls[0][0])).not.toContain("secret-nonce");
  });

  it("does not invoke the UI after cancellation", async () => {
    const handler = vi.fn(async (prompt: ApprovalPrompt) => {
      void prompt;
      return "approved" as const;
    });
    const channel = new CallbackApprovalChannel(handler);
    const controller = new AbortController();
    controller.abort();

    await expect(channel.requestApproval(request, controller.signal)).resolves.toEqual({
      kind: "cancelled",
      requestId: "request-1",
    });
    expect(handler).not.toHaveBeenCalled();
  });
});
