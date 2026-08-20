export type SandboxIdKind =
  | "attempt"
  | "approval-request"
  | "approval-grant"
  | "resource-lease"
  | "audit";

export interface IdGeneratorPort {
  nextId(kind: SandboxIdKind): string;
}
