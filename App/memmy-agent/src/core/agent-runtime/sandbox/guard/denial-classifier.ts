import path from "node:path";
import type { ResolvedAccess } from "../domain/capability.js";
import type { DenialEvidence, DenialObservation } from "../domain/denial-evidence.js";
import type { SandboxAttempt } from "../domain/sandbox-attempt.js";
import type { SandboxedResult } from "../domain/sandbox-result.js";
import { stablePolicyHash } from "../policy/policy-hash.js";

const IGNORED_PLATFORM_TARGETS = ["/dev", "/System", "/usr", "/bin", "/sbin", "/Library"];
const IGNORED_PLATFORM_EXACT_TARGETS = new Set([
  "/",
  "/tmp",
  "/var",
  "/private",
  "/private/tmp",
  "/private/var",
]);

export type EnforcedFileSystemSnapshot = Readonly<{
  readableRoots: readonly string[];
  writableRoots: readonly string[];
  deniedRoots: readonly string[];
}>;

type ClassifiedObservation = Readonly<{
  evidence: DenialEvidence;
  priority: number;
  observedAt: number;
}>;

function pathIsInside(target: string, root: string): boolean {
  const relative = path.relative(root, target);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function fileAccess(operation: string): "read" | "write" | null {
  if (operation.startsWith("file-read")) return "read";
  if (operation.startsWith("file-write")) return "write";
  return null;
}

function fileObservation(
  attempt: SandboxAttempt,
  filesystem: EnforcedFileSystemSnapshot,
  observation: DenialObservation,
): ClassifiedObservation | null {
  const access = fileAccess(observation.operation);
  if (!access || !path.isAbsolute(observation.target)) return null;
  const target = path.resolve(observation.target);
  if (IGNORED_PLATFORM_EXACT_TARGETS.has(target)) return null;
  if (IGNORED_PLATFORM_TARGETS.some((root) => pathIsInside(target, root))) return null;
  const explicitlyDenied = filesystem.deniedRoots.some((root) => pathIsInside(target, root));
  const allowedRoots = access === "read" ? filesystem.readableRoots : filesystem.writableRoots;
  const allowed = allowedRoots.some((root) => pathIsInside(target, root));
  if (allowed && !explicitlyDenied) return null;
  const requiredCapability: ResolvedAccess = { kind: "filesystem", access, path: target };
  return {
    priority: explicitlyDenied ? 120 : 110,
    observedAt: observation.observedAt,
    evidence: {
      source: "os-sandbox",
      operation: `file-${access}`,
      requiredCapability,
      systemCode: "SEATBELT_DENY",
      summary: `macOS sandbox rejected a filesystem ${access}`,
      minimallySupplementable: true,
      evidenceRef: stablePolicyHash({ attemptId: attempt.attemptId, observation }),
    },
  };
}

function nonFileObservation(
  attempt: SandboxAttempt,
  observation: DenialObservation,
): ClassifiedObservation | null {
  let operation: string;
  let priority: number;
  let requiredCapability: ResolvedAccess | undefined;
  if (observation.operation.startsWith("network-")) {
    if (attempt.permissionProfile.network.mode !== "denied") return null;
    operation = "network";
    priority = 130;
  } else if (observation.operation === "process-fork") {
    operation = "process-spawn";
    priority = 125;
    requiredCapability = { kind: "process", interactive: false };
  } else {
    return null;
  }
  return {
    priority,
    observedAt: observation.observedAt,
    evidence: {
      source: "os-sandbox",
      operation,
      ...(requiredCapability ? { requiredCapability } : {}),
      systemCode: "SEATBELT_DENY",
      summary: `macOS sandbox rejected a ${operation} operation`,
      minimallySupplementable: false,
      evidenceRef: stablePolicyHash({ attemptId: attempt.attemptId, observation }),
    },
  };
}

/** Converts trusted platform observations into denial evidence without consulting process output. */
export class DenialClassifier {
  classify(
    input: Readonly<{
      attempt: SandboxAttempt;
      result: SandboxedResult;
      observations: readonly DenialObservation[];
      filesystem: EnforcedFileSystemSnapshot;
    }>,
  ): DenialEvidence | null {
    if (input.result.exitCode === 0 || input.result.exitCode === null) return null;
    const candidates = input.observations
      .filter(
        (observation) =>
          observation.provenance === "macos-kernel-sandbox-log" &&
          observation.observedAt >= input.result.startedAt - 100 &&
          observation.observedAt <= input.result.completedAt + 10,
      )
      .map(
        (observation) =>
          fileObservation(input.attempt, input.filesystem, observation) ??
          nonFileObservation(input.attempt, observation),
      )
      .filter((candidate): candidate is ClassifiedObservation => candidate !== null)
      .sort((left, right) => right.priority - left.priority || right.observedAt - left.observedAt);
    return candidates[0]?.evidence ?? null;
  }
}
