import type { CanonicalPath } from "./capability.js";
import type { DenialEvidence } from "./denial-evidence.js";
import type { PermissionProfile } from "./permission-profile.js";
import type { SandboxedResult } from "./sandbox-result.js";

export type SandboxType =
  | "macos-seatbelt"
  | "linux-bwrap"
  | "linux-landlock"
  | "windows-restricted-token"
  | "external"
  | "disabled";

export type NormalizedToolCall = Readonly<{
  toolName: string;
  arguments: Readonly<Record<string, unknown>>;
}>;

export type SandboxAttempt = Readonly<{
  attemptId: string;
  parentAttemptId?: string;
  runtimeCallId: string;
  argsHash: string;
  permissionProfile: PermissionProfile;
  compiledPolicyHash: string;
  sandboxType: SandboxType;
  sandboxCwd: CanonicalPath;
  workspaceRoots: readonly CanonicalPath[];
  approvalGrantHash?: string;
  createdAt: number;
}>;

export type AttemptState =
  | Readonly<{ kind: "created" }>
  | Readonly<{ kind: "running"; processHandle: string }>
  | Readonly<{ kind: "completed"; result: SandboxedResult }>
  | Readonly<{ kind: "denied"; evidence: DenialEvidence }>
  | Readonly<{ kind: "cancelled"; reason: string }>
  | Readonly<{ kind: "runtime-failed"; reason: string }>;

export type AttemptStateRecord = Readonly<{
  attemptId: string;
  state: AttemptState;
  observedAt: number;
}>;

export type SandboxExecutionRecord = Readonly<{
  attempt: SandboxAttempt;
  stateHistory: readonly AttemptStateRecord[];
}>;

const ALLOWED_TRANSITIONS: Readonly<Record<AttemptState["kind"], readonly AttemptState["kind"][]>> =
  {
    created: ["running", "cancelled", "runtime-failed"],
    running: ["completed", "denied", "cancelled", "runtime-failed"],
    completed: [],
    denied: [],
    cancelled: [],
    "runtime-failed": [],
  };

export function transitionAttemptState(current: AttemptState, next: AttemptState): AttemptState {
  if (!ALLOWED_TRANSITIONS[current.kind].includes(next.kind)) {
    throw new Error(`invalid sandbox attempt transition: ${current.kind} -> ${next.kind}`);
  }
  return next;
}
