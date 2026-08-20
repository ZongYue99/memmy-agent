import type {
  ApprovalPrompt,
  ApprovalPromptHandler,
  EntrypointSource,
} from "../../core/agent-runtime/sandbox/index.js";
import { getQuestionary } from "./onboard.js";

type CliSandboxApprovalOptions = Readonly<{
  confirm?: (message: string) => Promise<boolean>;
  isInteractive?: () => boolean;
  now?: () => number;
  beforePrompt?: () => void;
}>;

function capabilityLabel(capability: ApprovalPrompt["additionalPermission"][number]): string {
  switch (capability.kind) {
    case "filesystem":
      return `${capability.access === "read" ? "Read" : "Write"} ${capability.path}`;
    case "network":
      return `Connect to ${capability.protocol}://${capability.host}:${capability.port}`;
    case "process":
      return capability.interactive ? "Start an interactive process" : "Start a process";
    case "environment":
      return `${capability.operation === "set" ? "Set" : "Inherit"} environment variable ${capability.name}`;
    case "resource":
      return `Use ${capability.resource}`;
    case "external-effect":
      return `Perform a ${capability.level} external effect`;
    case "unknown":
      return `Unknown capability ${capability.name}`;
  }
}

export function formatCliSandboxApproval(prompt: ApprovalPrompt): string {
  const capabilities = prompt.additionalPermission
    .map((capability) => `  - ${capabilityLabel(capability)}`)
    .join("\n");
  return `Sandbox blocked this operation. Allow once?\n${capabilities}`;
}

export function createCliSandboxApprovalPrompt(
  options: CliSandboxApprovalOptions = {},
): ApprovalPromptHandler {
  const confirm =
    options.confirm ??
    ((message: string) => getQuestionary().confirm(message, { default: false }).ask());
  const isInteractive =
    options.isInteractive ?? (() => Boolean(process.stdin.isTTY && process.stdout.isTTY));
  const now = options.now ?? Date.now;
  return async (prompt, abortSignal) => {
    if (abortSignal?.aborted || !isInteractive()) return "cancelled";
    if (now() >= prompt.expiresAt) return "cancelled";
    options.beforePrompt?.();
    let approved: boolean;
    try {
      approved = (await confirm(formatCliSandboxApproval(prompt))) === true;
    } catch {
      return "cancelled";
    }
    if (abortSignal?.aborted || now() >= prompt.expiresAt) return "cancelled";
    return approved ? "approved" : "denied";
  };
}

export function createCliSandboxApprovalPromptFactory(
  options: CliSandboxApprovalOptions = {},
): (context: { source: EntrypointSource }) => ApprovalPromptHandler | null {
  const prompt = createCliSandboxApprovalPrompt(options);
  return ({ source }) => (source === "cli" ? prompt : null);
}
