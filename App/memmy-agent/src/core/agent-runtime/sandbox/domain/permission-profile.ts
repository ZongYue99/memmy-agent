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

export type PermissionProfile = ProfileMetadata &
  Readonly<{
    type: "managed";
    filesystem:
      | Readonly<{ kind: "restricted"; entries: readonly FileSystemEntry[] }>
      | Readonly<{ kind: "unrestricted"; entries: readonly [] }>;
    network: NetworkCapability;
    process: ProcessCapability;
    environment: EnvironmentCapability;
  }>;

export type UnhashedPermissionProfile = Omit<PermissionProfile, "policyHash">;
