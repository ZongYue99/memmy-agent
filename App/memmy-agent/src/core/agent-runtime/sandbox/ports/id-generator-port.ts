export type SandboxIdKind = "attempt" | "approval-request" | "approval-grant" | "audit";

export interface IdGeneratorPort {
  nextId(kind: SandboxIdKind): string;
}
