import os from "node:os";
import path from "node:path";
import type { CapabilitySet } from "../domain/capability.js";
import type { WorkspaceProfile } from "./entrypoint-classifier.js";
import { normalizeCapabilitySet } from "./policy-cap.js";

const DEFAULT_PROCESS_LIMITS = {
  spawn: "non-interactive" as const,
  maxProcesses: 1,
  maxRuntimeMs: 30 * 60 * 1_000,
  maxOutputBytes: 10 * 1_024 * 1_024,
};

function sensitivePaths(workspaceRoot: string, homeDirectory: string): string[] {
  return [
    path.join(workspaceRoot, ".env"),
    path.join(homeDirectory, ".ssh"),
    path.join(homeDirectory, ".aws"),
    path.join(homeDirectory, ".config", "gcloud"),
    path.join(homeDirectory, "Library", "Application Support", "Google", "Chrome"),
  ];
}

export function createWorkspacePreset(
  input: Readonly<{
    workspaceRoot: string;
    profile: WorkspaceProfile;
    homeDirectory?: string;
  }>,
): CapabilitySet {
  const workspaceRoot = path.resolve(input.workspaceRoot);
  const homeDirectory = path.resolve(input.homeDirectory ?? os.homedir());
  const compatible = input.profile === "workspace-compatible";
  return normalizeCapabilitySet({
    filesystem: {
      read: compatible ? [path.parse(workspaceRoot).root] : [workspaceRoot],
      write: [workspaceRoot],
      deny: sensitivePaths(workspaceRoot, homeDirectory),
    },
    network: { mode: "denied" },
    process: DEFAULT_PROCESS_LIMITS,
    environment: {
      inherit: ["HOME", "LANG", "PATH", "SHELL", "TERM", "TMPDIR"],
      set: {},
      remove: [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "OPENAI_API_KEY",
      ],
    },
    resources: [],
    externalEffects: { maximum: "none" },
  });
}
