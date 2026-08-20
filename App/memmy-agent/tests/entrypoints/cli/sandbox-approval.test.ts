import { describe, expect, it, vi } from "vitest";
import {
  createCliSandboxApprovalPrompt,
  createCliSandboxApprovalPromptFactory,
  formatCliSandboxApproval,
} from "../../../src/entrypoints/cli/sandbox-approval.js";

const prompt = {
  requestId: "request-1",
  runtimeCallId: "call-1",
  parentAttemptId: "attempt-1",
  additionalPermission: [
    { kind: "filesystem" as const, access: "read" as const, path: "/shared/report.txt" },
  ],
  expiresAt: 2_000,
};

describe("CLI sandbox approval", () => {
  it("renders only the minimum requested capability", () => {
    expect(formatCliSandboxApproval(prompt)).toBe(
      "Sandbox blocked this operation. Allow once?\n  - Read /shared/report.txt",
    );
    expect(JSON.stringify(formatCliSandboxApproval(prompt))).not.toContain("attempt-1");
  });

  it("returns a bounded decision only for an active TTY prompt", async () => {
    const confirm = vi.fn(async () => true);
    const handler = createCliSandboxApprovalPrompt({
      confirm,
      isInteractive: () => true,
      now: () => 1_500,
    });

    await expect(handler(prompt)).resolves.toBe("approved");
    expect(confirm).toHaveBeenCalledWith(formatCliSandboxApproval(prompt));
  });

  it("fails closed without a TTY, after expiry, or when the prompt throws", async () => {
    const confirm = vi.fn(async () => true);
    await expect(
      createCliSandboxApprovalPrompt({ confirm, isInteractive: () => false })(prompt),
    ).resolves.toBe("cancelled");
    await expect(
      createCliSandboxApprovalPrompt({
        confirm,
        isInteractive: () => true,
        now: () => prompt.expiresAt,
      })(prompt),
    ).resolves.toBe("cancelled");
    await expect(
      createCliSandboxApprovalPrompt({
        confirm: async () => {
          throw new Error("terminal closed");
        },
        isInteractive: () => true,
        now: () => 1_500,
      })(prompt),
    ).resolves.toBe("cancelled");
  });

  it("does not expose CLI approval to background or remote channel sources", () => {
    const factory = createCliSandboxApprovalPromptFactory();

    expect(factory({ source: "cli" })).toBeTypeOf("function");
    expect(factory({ source: "goal" })).toBeNull();
    expect(factory({ source: "channel" })).toBeNull();
    expect(factory({ source: "desktop" })).toBeNull();
    expect(factory({ source: "tui" })).toBeNull();
  });
});
