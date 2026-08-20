import type { ApprovalGrant, ApprovalGrantBinding } from "../../approval/approval-grant.js";
import { approvalGrantIsValid } from "../../approval/approval-grant.js";
import { immutableSnapshot } from "../../domain/immutable.js";
import type { ApprovalGrantStorePort } from "../../ports/approval-grant-store-port.js";

function matchesBinding(grant: ApprovalGrant, binding: ApprovalGrantBinding): boolean {
  return (
    grant.runtimeCallId === binding.runtimeCallId &&
    grant.argsHash === binding.argsHash &&
    grant.initialPolicyHash === binding.initialPolicyHash &&
    grant.parentAttemptId === binding.parentAttemptId &&
    grant.subjectId === binding.subjectId &&
    grant.approvalGrantHash === binding.approvalGrantHash
  );
}

/** Process-local single-use grant storage for local runtimes and tests. */
export class InMemoryApprovalGrantStore implements ApprovalGrantStorePort {
  private readonly grants = new Map<string, ApprovalGrant>();

  async save(grant: ApprovalGrant): Promise<boolean> {
    if (!approvalGrantIsValid(grant) || this.grants.has(grant.grantId)) return false;
    this.grants.set(grant.grantId, immutableSnapshot(grant));
    return true;
  }

  async consume(
    grantId: string,
    binding: ApprovalGrantBinding,
    consumedAt: number,
  ): Promise<ApprovalGrant | null> {
    const grant = this.grants.get(grantId);
    if (!grant) return null;
    if (
      !Number.isSafeInteger(consumedAt) ||
      consumedAt < grant.issuedAt ||
      !matchesBinding(grant, binding)
    ) {
      return null;
    }
    this.grants.delete(grantId);
    if (consumedAt > grant.expiresAt || !approvalGrantIsValid(grant)) return null;
    return immutableSnapshot(grant);
  }

  async revoke(grantId: string): Promise<void> {
    this.grants.delete(grantId);
  }
}
