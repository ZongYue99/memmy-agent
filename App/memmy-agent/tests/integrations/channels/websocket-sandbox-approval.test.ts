import { describe, expect, it, vi } from "vitest";
import { WebSocketSandboxApprovalCoordinator } from "../../../src/integrations/channels/websocket-sandbox-approval.js";

const prompt = {
  requestId: "request-1",
  runtimeCallId: "call-1",
  parentAttemptId: "attempt-1",
  additionalPermission: [
    { kind: "filesystem" as const, access: "read" as const, path: "/shared/file.txt" },
  ],
  expiresAt: 2_000,
};

describe("WebSocketSandboxApprovalCoordinator", () => {
  it("accepts one decision only from a connection that received the prompt", async () => {
    const coordinator = new WebSocketSandboxApprovalCoordinator(() => 1_000);
    const trusted = {};
    const other = {};
    const send = vi.fn(async () => undefined);
    const result = coordinator.request({
      chatId: "chat-1",
      prompt,
      connections: [trusted],
      send,
    });

    expect(coordinator.decide(other, "request-1", "approved")).toBe("not-authorized");
    expect(coordinator.decide(trusted, "request-1", "approved")).toBe("accepted");
    expect(coordinator.decide(trusted, "request-1", "approved")).toBe("not-pending");
    await expect(result).resolves.toBe("approved");
    expect(send).toHaveBeenCalledWith(trusted, {
      event: "sandbox_approval_request",
      chat_id: "chat-1",
      request_id: "request-1",
      additional_permission: prompt.additionalPermission,
      expires_at: 2_000,
    });
    expect(JSON.stringify(send.mock.calls)).not.toContain("nonce");
  });

  it("cancels when every eligible client disconnects", async () => {
    const coordinator = new WebSocketSandboxApprovalCoordinator(() => 1_000);
    const connection = {};
    const result = coordinator.request({
      chatId: "chat-1",
      prompt,
      connections: [connection],
      send: async () => undefined,
    });

    coordinator.disconnect(connection);

    await expect(result).resolves.toBe("cancelled");
  });

  it("fails closed for missing clients, expired prompts, aborts, and invalid decisions", async () => {
    const coordinator = new WebSocketSandboxApprovalCoordinator(() => 2_000);
    await expect(
      coordinator.request({
        chatId: "chat-1",
        prompt,
        connections: [],
        send: async () => undefined,
      }),
    ).resolves.toBe("cancelled");

    const active = new WebSocketSandboxApprovalCoordinator(() => 1_000);
    const connection = {};
    const controller = new AbortController();
    const result = active.request({
      chatId: "chat-1",
      prompt,
      connections: [connection],
      send: async () => undefined,
      abortSignal: controller.signal,
    });
    expect(active.decide(connection, "request-1", "always")).toBe("invalid-decision");
    controller.abort();
    await expect(result).resolves.toBe("cancelled");
  });
});
