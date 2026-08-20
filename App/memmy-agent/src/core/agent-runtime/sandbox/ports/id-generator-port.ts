export type SandboxIdKind =
  | "attempt"
  | "runtime-call"
  | "approval-request"
  | "approval-grant"
  | "resource-lease"
  | "audit";

export interface IdGeneratorPort {
  nextId(kind: SandboxIdKind): string;
}
