import type { CapabilitySet, ResolvedAccessSet } from "../domain/capability.js";
import type { ApprovalGrant } from "../approval/approval-grant.js";
import { approvalGrantIsValid } from "../approval/approval-grant.js";
import type { FileSystemEntry, PermissionProfile } from "../domain/permission-profile.js";
import type { EntrypointContext, WorkspaceProfile } from "./entrypoint-classifier.js";
import {
  capabilitySetAllows,
  intersectCapabilitySets,
  normalizeCapabilitySet,
} from "./policy-cap.js";
import { attachPolicyHash, stablePolicyHash } from "./policy-hash.js";

export type ApprovalMode = "never" | "on-request";

export type EffectiveAuthorization = Readonly<{
  entrypoint: EntrypointContext;
  workspaceProfile: WorkspaceProfile;
  policyCap: CapabilitySet;
  baseGrant: CapabilitySet;
  permissionProfile: PermissionProfile;
  requestedCapabilities: ResolvedAccessSet;
  approvalMode: ApprovalMode;
  initialPolicyHash: string;
  compiledPolicyHash: string;
}>;

export type ResolvePolicyInput = Readonly<{
  caps: readonly CapabilitySet[];
  baseGrants: readonly CapabilitySet[];
  requestedCapabilities?: ResolvedAccessSet;
  entrypoint: EntrypointContext;
  workspaceProfile: WorkspaceProfile;
  approvalMode: ApprovalMode;
}>;

function intersectAll(profiles: readonly CapabilitySet[], label: string): CapabilitySet {
  if (!profiles.length) throw new Error(`${label} must contain at least one capability set`);
  return profiles.slice(1).reduce(intersectCapabilitySets, normalizeCapabilitySet(profiles[0]));
}

function fileSystemEntries(capability: CapabilitySet): FileSystemEntry[] {
  const entries: FileSystemEntry[] = [
    ...capability.filesystem.read.map((path) => ({
      path,
      access: "read" as const,
      missingPathBehavior: "skip" as const,
    })),
    ...capability.filesystem.write.map((path) => ({
      path,
      access: "write" as const,
      missingPathBehavior: "deny" as const,
    })),
    ...capability.filesystem.deny.map((path) => ({
      path,
      access: "deny" as const,
      missingPathBehavior: "skip" as const,
    })),
  ];
  return entries.sort((left, right) => {
    if (left.path.length !== right.path.length) return right.path.length - left.path.length;
    if (left.access === right.access) return left.path.localeCompare(right.path);
    if (left.access === "deny") return -1;
    if (right.access === "deny") return 1;
    return left.access.localeCompare(right.access);
  });
}

function compileManagedProfile(capability: CapabilitySet): PermissionProfile {
  return attachPolicyHash({
    version: 1,
    type: "managed",
    filesystem: { kind: "restricted", entries: fileSystemEntries(capability) },
    network: capability.network,
    process: capability.process,
    environment: capability.environment,
  });
}

function addApprovedFilesystemAccess(
  capability: CapabilitySet,
  additionalPermission: ResolvedAccessSet,
): CapabilitySet {
  const filesystem = {
    read: [...capability.filesystem.read],
    write: [...capability.filesystem.write],
    deny: [...capability.filesystem.deny],
  };
  for (const access of additionalPermission) {
    if (access.kind !== "filesystem") {
      throw new Error("approval contains an unsupported capability");
    }
    filesystem[access.access].push(access.path);
  }
  return normalizeCapabilitySet({ ...capability, filesystem });
}

export function applyPreflightApproval(
  authorization: EffectiveAuthorization,
  additionalPermission: ResolvedAccessSet,
): EffectiveAuthorization {
  if (
    authorization.approvalMode !== "on-request" ||
    authorization.entrypoint.approvalChannel === "none"
  ) {
    throw new Error("the current policy does not allow approval");
  }
  if (!additionalPermission.length) throw new Error("approval must add a permission");
  if (
    additionalPermission.some((access) => !capabilitySetAllows(authorization.policyCap, access))
  ) {
    throw new Error("approval exceeds the current policy cap");
  }
  const baseGrant = addApprovedFilesystemAccess(authorization.baseGrant, additionalPermission);
  const permissionProfile = compileManagedProfile(baseGrant);
  return {
    ...authorization,
    baseGrant,
    permissionProfile,
    compiledPolicyHash: permissionProfile.policyHash,
  };
}

export function resolvePolicy(input: ResolvePolicyInput): EffectiveAuthorization {
  const policyCap = intersectAll(input.caps, "caps");
  const requestedBaseGrant = intersectAll(input.baseGrants, "baseGrants");
  const baseGrant = intersectCapabilitySets(policyCap, requestedBaseGrant);
  const permissionProfile = compileManagedProfile(baseGrant);
  const initialPolicyHash = stablePolicyHash({
    entrypoint: input.entrypoint,
    workspaceProfile: input.workspaceProfile,
    policyCap,
    baseGrant,
    approvalMode: input.approvalMode,
  });
  return {
    entrypoint: input.entrypoint,
    workspaceProfile: input.workspaceProfile,
    policyCap,
    baseGrant,
    permissionProfile,
    requestedCapabilities: input.requestedCapabilities ?? [],
    approvalMode: input.approvalMode,
    initialPolicyHash,
    compiledPolicyHash: permissionProfile.policyHash,
  };
}

export function applyApproval(
  authorization: EffectiveAuthorization,
  grant: ApprovalGrant,
): EffectiveAuthorization {
  if (!approvalGrantIsValid(grant)) throw new Error("approval grant hash verification failed");
  if (grant.initialPolicyHash !== authorization.initialPolicyHash) {
    throw new Error("approval grant does not match the current policy");
  }
  if (
    authorization.approvalMode !== "on-request" ||
    authorization.entrypoint.approvalChannel === "none"
  ) {
    throw new Error("the current policy does not allow approval");
  }
  if (!grant.additionalPermission.length) {
    throw new Error("approval grant must add a permission");
  }
  if (
    grant.additionalPermission.some(
      (access) => !capabilitySetAllows(authorization.policyCap, access),
    )
  ) {
    throw new Error("approval grant exceeds the current policy cap");
  }
  return applyPreflightApproval(authorization, grant.additionalPermission);
}
