import type { DenialEvidence } from "./denial-evidence.js";

export type SandboxedResult = Readonly<{
  exitCode: number | null;
  signal: string | null;
  stdoutSummary: string;
  stderrSummary: string;
  outputTruncated: boolean;
  startedAt: number;
  completedAt: number;
  evidenceRefs: readonly string[];
}>;

export type SandboxExecutionOutcome =
  | Readonly<{ kind: "completed"; result: SandboxedResult }>
  | Readonly<{ kind: "denied"; evidence: DenialEvidence }>
  | Readonly<{ kind: "cancelled"; reason: string }>
  | Readonly<{ kind: "runtime-failed"; reason: string }>;
