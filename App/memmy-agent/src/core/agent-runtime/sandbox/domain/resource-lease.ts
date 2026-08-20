import type { ResourceKind } from "./capability.js";
import { immutableSnapshot } from "./immutable.js";
import type { WorkspaceProfile } from "../policy/entrypoint-classifier.js";

export type ResourceLeaseState = "starting" | "active" | "revoking" | "terminated" | "failed";

export type ResourceLease = Readonly<{
  leaseId: string;
  resourceId: string;
  resourceType: ResourceKind;
  ownerId: string;
  projectId: string;
  workspaceProfile: WorkspaceProfile;
  policyCapHash: string;
  compiledPolicyHash: string;
  backendCapabilityHash: string;
  state: ResourceLeaseState;
  expiresAt: number;
}>;

const TRANSITIONS: Readonly<Record<ResourceLeaseState, readonly ResourceLeaseState[]>> = {
  starting: ["active", "revoking", "failed"],
  active: ["revoking", "failed"],
  revoking: ["terminated", "failed"],
  terminated: [],
  failed: ["revoking", "terminated"],
};

export function transitionResourceLease(
  lease: ResourceLease,
  state: ResourceLeaseState,
): ResourceLease {
  if (!TRANSITIONS[lease.state].includes(state)) {
    throw new Error(`invalid resource lease transition: ${lease.state} -> ${state}`);
  }
  return immutableSnapshot({ ...lease, state });
}
