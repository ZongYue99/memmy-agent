import { describe, expect, it, vi } from "vitest";
import { InMemoryApprovalGrantStore } from "../../../../src/core/agent-runtime/sandbox/adapters/approval/in-memory-approval-grant-store.js";
import { ApprovalBroker } from "../../../../src/core/agent-runtime/sandbox/approval/approval-broker.js";
import type { ApprovalRequest } from "../../../../src/core/agent-runtime/sandbox/approval/approval-grant.js";

function broker(
  decide: (request: ApprovalRequest) => Promise<{
    kind: "approved";
    requestId: string;
    subjectId: string;
    nonce: string;
  }>,
  nowValues = [1_000, 1_001, 1_002, 1_003],
) {
  const ids = {
    nextId: vi.fn((kind: "attempt" | "approval-request" | "approval-grant") => `${kind}-1`),
  };
  const channel = { requestApproval: vi.fn(decide) };
  const store = new InMemoryApprovalGrantStore();
  let index = 0;
  return {
    broker: new ApprovalBroker({
      channel,
      store,
      ids,
      clock: { now: () => nowValues[index++] ?? nowValues.at(-1)! },
      nonce: () => "nonce-1",
      ttlMs: 100,
    }),
    channel,
  };
}

const requestInput = {
  runtimeCallId: "call-1",
  argsHash: "args-hash",
  initialPolicyHash: "policy-hash",
  parentAttemptId: "attempt-1",
  additionalPermission: [
    { kind: "filesystem" as const, access: "read" as const, path: "/workspace/shared.txt" },
  ],
  subjectId: "user-1",
};

describe("ApprovalBroker", () => {
  it("issues a call-bound grant that can be consumed exactly once", async () => {
    const { broker: approvalBroker, channel } = broker(async (request) => ({
      kind: "approved",
      requestId: request.requestId,
      subjectId: request.subjectId,
      nonce: request.nonce,
    }));

    const outcome = await approvalBroker.requestApproval(requestInput);

    expect(outcome.kind).toBe("approved");
    expect(Object.isFrozen(requestInput.additionalPermission)).toBe(false);
    if (outcome.kind !== "approved") return;
    expect(channel.requestApproval).toHaveBeenCalledWith(
      expect.objectContaining({
        requestId: "approval-request-1",
        parentAttemptId: "attempt-1",
        nonce: "nonce-1",
        expiresAt: 1_100,
      }),
      undefined,
    );
    const binding = {
      runtimeCallId: "call-1",
      argsHash: "args-hash",
      initialPolicyHash: "policy-hash",
      parentAttemptId: "attempt-1",
      subjectId: "user-1",
      approvalGrantHash: outcome.grant.approvalGrantHash,
    };
    expect(await approvalBroker.consume(outcome.grant.grantId, binding)).toEqual(outcome.grant);
    expect(await approvalBroker.consume(outcome.grant.grantId, binding)).toBeNull();
  });

  it("fails closed for an invalid subject or nonce", async () => {
    const { broker: wrongSubject } = broker(async (request) => ({
      kind: "approved",
      requestId: request.requestId,
      subjectId: "other-user",
      nonce: request.nonce,
    }));
    const { broker: wrongNonce } = broker(async (request) => ({
      kind: "approved",
      requestId: request.requestId,
      subjectId: request.subjectId,
      nonce: "wrong",
    }));

    expect(await wrongSubject.requestApproval(requestInput)).toEqual({
      kind: "invalid-response",
    });
    expect(await wrongNonce.requestApproval(requestInput)).toEqual({ kind: "invalid-response" });
  });

  it("does not issue a grant after the challenge expires", async () => {
    const { broker: approvalBroker } = broker(
      async (request) => ({
        kind: "approved",
        requestId: request.requestId,
        subjectId: request.subjectId,
        nonce: request.nonce,
      }),
      [1_000, 1_101],
    );

    expect(await approvalBroker.requestApproval(requestInput)).toEqual({ kind: "expired" });
  });

  it("does not open an approval channel for an already aborted call", async () => {
    const { broker: approvalBroker, channel } = broker(async (request) => ({
      kind: "approved",
      requestId: request.requestId,
      subjectId: request.subjectId,
      nonce: request.nonce,
    }));
    const controller = new AbortController();
    controller.abort();

    expect(
      await approvalBroker.requestApproval({ ...requestInput, abortSignal: controller.signal }),
    ).toEqual({ kind: "cancelled" });
    expect(channel.requestApproval).not.toHaveBeenCalled();
  });
});
