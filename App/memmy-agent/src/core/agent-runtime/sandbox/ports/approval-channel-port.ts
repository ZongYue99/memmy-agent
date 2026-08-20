import type { ApprovalDecision, ApprovalRequest } from "../approval/approval-grant.js";

/** Presents a bound challenge through a trusted Desktop, CLI, or TUI approval surface. */
export interface ApprovalChannelPort {
  requestApproval(request: ApprovalRequest, abortSignal?: AbortSignal): Promise<ApprovalDecision>;
}
