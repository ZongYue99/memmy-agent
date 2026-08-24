import type { ResolvedAccessSet } from "../domain/capability.js";
import { immutableSnapshot } from "../domain/immutable.js";
import { stablePolicyHash } from "../policy/policy-hash.js";

export type ApprovalRequest = Readonly<{
  requestId: string;
  runtimeCallId: string;
  argsHash: string;
  initialPolicyHash: string;
  parentAttemptId: string;
  additionalPermission: ResolvedAccessSet;
  subjectId: string;
  nonce: string;
  requestedAt: number;
  expiresAt: number;
}>;

export type ApprovalDecision =
  | Readonly<{
      kind: "approved";
      requestId: string;
      subjectId: string;
      nonce: string;
    }>
  | Readonly<{ kind: "denied" | "cancelled"; requestId: string }>;

export type UnhashedApprovalGrant = Readonly<{
  grantId: string;
  runtimeCallId: string;
  argsHash: string;
  initialPolicyHash: string;
  parentAttemptId: string;
  additionalPermission: ResolvedAccessSet;
  subjectId: string;
  issuedAt: number;
  expiresAt: number;
}>;

export type ApprovalGrant = UnhashedApprovalGrant &
  Readonly<{
    approvalGrantHash: string;
  }>;

export type ApprovalGrantBinding = Readonly<{
  runtimeCallId: string;
  argsHash: string;
  initialPolicyHash: string;
  parentAttemptId: string;
  subjectId: string;
  approvalGrantHash: string;
}>;

export function attachApprovalGrantHash(grant: UnhashedApprovalGrant): ApprovalGrant {
  return immutableSnapshot({ ...grant, approvalGrantHash: stablePolicyHash(grant) });
}

export function approvalGrantIsValid(grant: ApprovalGrant): boolean {
  const { approvalGrantHash, ...unhashed } = grant;
  return stablePolicyHash(unhashed) === approvalGrantHash;
}
