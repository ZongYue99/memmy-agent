import type { ApprovalGrant, ApprovalGrantBinding } from "../approval/approval-grant.js";

/** Stores grants and atomically removes one only when all consumption bindings match. */
export interface ApprovalGrantStorePort {
  save(grant: ApprovalGrant): Promise<boolean>;
  consume(
    grantId: string,
    binding: ApprovalGrantBinding,
    consumedAt: number,
  ): Promise<ApprovalGrant | null>;
  revoke(grantId: string): Promise<void>;
}
