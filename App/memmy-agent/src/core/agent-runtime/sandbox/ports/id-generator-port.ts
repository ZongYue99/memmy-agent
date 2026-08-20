export type SandboxIdKind = "attempt";

export interface IdGeneratorPort {
  nextId(kind: SandboxIdKind): string;
}
