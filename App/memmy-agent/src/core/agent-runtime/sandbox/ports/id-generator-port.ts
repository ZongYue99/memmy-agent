export type SandboxIdKind = "attempt" | "approval-request" | "approval-grant";

export interface IdGeneratorPort {
  nextId(kind: SandboxIdKind): string;
}
