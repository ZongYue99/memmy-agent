export type CanonicalPath = string;

export const RESOURCE_KINDS = [
  "browser",
  "stdio-mcp",
  "http-mcp",
  "plugin-worker",
  "memory-writer",
  "exec-session",
  "goal",
  "cron",
] as const;

export type ResourceKind = (typeof RESOURCE_KINDS)[number];

export type FileSystemCapability = Readonly<{
  read: readonly CanonicalPath[];
  write: readonly CanonicalPath[];
  deny: readonly CanonicalPath[];
}>;

export type NetworkTarget = Readonly<{
  host: string;
  protocols: readonly ("http" | "https" | "tcp")[];
  ports: readonly number[];
}>;

export type NetworkCapability =
  | Readonly<{ mode: "denied" }>
  | Readonly<{ mode: "allowlist"; targets: readonly NetworkTarget[] }>
  | Readonly<{ mode: "unrestricted" }>;

export type ProcessCapability = Readonly<{
  spawn: "denied" | "non-interactive" | "interactive";
  maxProcesses: number;
  maxRuntimeMs: number;
  maxOutputBytes: number;
}>;

export type EnvironmentCapability = Readonly<{
  inherit: readonly string[];
  set: Readonly<Record<string, string>>;
  remove: readonly string[];
}>;

export type ExternalEffectLevel = "none" | "reversible" | "irreversible";

export type CapabilitySet = Readonly<{
  filesystem: FileSystemCapability;
  network: NetworkCapability;
  process: ProcessCapability;
  environment: EnvironmentCapability;
  resources: readonly ResourceKind[];
  externalEffects: Readonly<{ maximum: ExternalEffectLevel }>;
}>;

export type ResolvedAccess =
  | Readonly<{ kind: "filesystem"; access: "read" | "write"; path: CanonicalPath }>
  | Readonly<{
      kind: "network";
      host: string;
      protocol: "http" | "https" | "tcp";
      port: number;
    }>
  | Readonly<{ kind: "process"; interactive: boolean; command?: string }>
  | Readonly<{ kind: "environment"; name: string; operation: "inherit" | "set" }>
  | Readonly<{ kind: "resource"; resource: ResourceKind }>
  | Readonly<{ kind: "external-effect"; level: ExternalEffectLevel }>
  | Readonly<{ kind: "unknown"; name: string }>;

export type ResolvedAccessSet = readonly ResolvedAccess[];

export type ToolCapabilityContext = Readonly<{
  cwd: CanonicalPath;
  workspaceRoots: readonly CanonicalPath[];
}>;

export type ToolCapabilities = Readonly<{
  filesystem: "none" | "read" | "write";
  process: "none" | "spawn" | "interactive";
  network: "none" | "http" | "browser" | "arbitrary";
  externalSideEffect: ExternalEffectLevel;
  persistence: "none" | "session" | "cross-turn";
  sensitiveData: "none" | "memory" | "agent-source" | "credentials";
  resolveAccess: (
    params: Readonly<Record<string, unknown>>,
    context: ToolCapabilityContext,
  ) => ResolvedAccessSet;
}>;

export type RequestedCapability = ResolvedAccess;
export type RequestedCapabilities = ResolvedAccessSet;
