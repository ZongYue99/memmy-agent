import type {
  CanonicalPath,
  EnvironmentCapability,
  NetworkCapability,
  ProcessCapability,
} from "./capability.js";

export type FileSystemEntry = Readonly<{
  path: CanonicalPath;
  access: "read" | "write" | "deny";
  missingPathBehavior: "deny" | "skip";
}>;

type ProfileMetadata = Readonly<{
  version: 1;
  policyHash: string;
}>;

export type ManagedPermissionProfile = ProfileMetadata &
  Readonly<{
    type: "managed";
    filesystem:
      | Readonly<{ kind: "restricted"; entries: readonly FileSystemEntry[] }>
      | Readonly<{ kind: "unrestricted"; entries: readonly [] }>;
    network: NetworkCapability;
    process: ProcessCapability;
    environment: EnvironmentCapability;
  }>;

export type ExternalPermissionProfile = ProfileMetadata &
  Readonly<{
    type: "external";
    executorId: string;
    requiredAttestation: Readonly<{
      protocolVersion: number;
      capabilityHash: string;
    }>;
    network: NetworkCapability;
  }>;

export type DisabledPermissionProfile = ProfileMetadata &
  Readonly<{
    type: "disabled";
    reason: "user-selected-danger-full-access";
  }>;

export type PermissionProfile =
  | ManagedPermissionProfile
  | ExternalPermissionProfile
  | DisabledPermissionProfile;

export type UnhashedPermissionProfile =
  | Omit<ManagedPermissionProfile, "policyHash">
  | Omit<ExternalPermissionProfile, "policyHash">
  | Omit<DisabledPermissionProfile, "policyHash">;
