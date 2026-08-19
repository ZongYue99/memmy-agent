import type { CapabilitySet, ResolvedAccessSet } from "../domain/capability.js";
import type {
  FileSystemEntry,
  ManagedPermissionProfile,
  PermissionProfile,
} from "../domain/permission-profile.js";
import type { EntrypointContext, WorkspaceProfile } from "./entrypoint-classifier.js";
import { intersectCapabilitySets, normalizeCapabilitySet } from "./policy-cap.js";
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

function compileManagedProfile(capability: CapabilitySet): ManagedPermissionProfile {
  return attachPolicyHash({
    version: 1,
    type: "managed",
    filesystem: { kind: "restricted", entries: fileSystemEntries(capability) },
    network: capability.network,
    process: capability.process,
    environment: capability.environment,
  }) as ManagedPermissionProfile;
}

export class PolicyResolver {
  resolve(input: ResolvePolicyInput): EffectiveAuthorization {
    const policyCap = intersectAll(input.caps, "caps");
    const requestedBaseGrant = intersectAll(input.baseGrants, "baseGrants");
    const baseGrant = intersectCapabilitySets(policyCap, requestedBaseGrant);
    const permissionProfile = compileManagedProfile(baseGrant);
    const initialPolicyHash = stablePolicyHash({
      entrypoint: input.entrypoint,
      workspaceProfile: input.workspaceProfile,
      policyCap,
      baseGrant,
    });
    return Object.freeze({
      entrypoint: input.entrypoint,
      workspaceProfile: input.workspaceProfile,
      policyCap,
      baseGrant,
      permissionProfile,
      requestedCapabilities: Object.freeze([...(input.requestedCapabilities ?? [])]),
      approvalMode: input.approvalMode,
      initialPolicyHash,
      compiledPolicyHash: permissionProfile.policyHash,
    });
  }
}
