import type { ApprovalRequest } from "../../approval/approval-grant.js";
import type { ResolvedAccessSet } from "../../domain/capability.js";
import { immutableSnapshot } from "../../domain/immutable.js";
import type { ApprovalChannelPort } from "../../ports/approval-channel-port.js";

export type ApprovalPrompt = Readonly<{
  requestId: string;
  additionalPermission: ResolvedAccessSet;
  expiresAt: number;
}>;

export type ApprovalPromptResult = "approved" | "denied" | "cancelled";

export type ApprovalPromptHandler = (
  prompt: ApprovalPrompt,
  abortSignal?: AbortSignal,
) => Promise<ApprovalPromptResult>;

/** Keeps the nonce inside the trusted adapter while a UI decides a bounded approval prompt. */
export class CallbackApprovalChannel implements ApprovalChannelPort {
  constructor(private readonly handler: ApprovalPromptHandler) {}

  async requestApproval(request: ApprovalRequest, abortSignal?: AbortSignal) {
    if (abortSignal?.aborted) return { kind: "cancelled" as const, requestId: request.requestId };
    const result = await this.handler(
      immutableSnapshot({
        requestId: request.requestId,
        additionalPermission: request.additionalPermission,
        expiresAt: request.expiresAt,
      }),
      abortSignal,
    );
    if (result !== "approved") return { kind: result, requestId: request.requestId };
    return {
      kind: "approved" as const,
      requestId: request.requestId,
      subjectId: request.subjectId,
      nonce: request.nonce,
    };
  }
}
