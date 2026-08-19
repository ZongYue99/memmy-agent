import fs from "node:fs";
import path from "node:path";
import type {
  ResolvedAccessSet,
  ToolAccessResolver,
  ToolCapabilityContext,
} from "../domain/capability.js";
import { CapabilityRegistry } from "./capability-registry.js";

type FileAccess = "read" | "write";

const CORE_FILE_TOOLS: Readonly<Record<string, FileAccess>> = {
  read_file: "read",
  write_file: "write",
  edit_file: "write",
  list_dir: "read",
};

function fileAccessResolver(toolName: string, access: FileAccess): ToolAccessResolver {
  return (
    params: Readonly<Record<string, unknown>>,
    context: ToolCapabilityContext,
  ): ResolvedAccessSet => {
    const requestedPath = params.path;
    if (typeof requestedPath !== "string" || !requestedPath.trim()) {
      return [{ kind: "unknown", name: `${toolName}.path` }];
    }
    const canonicalPath = canonicalizeForPolicy(path.resolve(context.cwd, requestedPath));
    if (!canonicalPath) return [{ kind: "unknown", name: `${toolName}.path` }];
    return [
      {
        kind: "filesystem",
        access,
        path: canonicalPath,
      },
    ];
  };
}

function canonicalizeForPolicy(target: string): string | null {
  const missingSegments: string[] = [];
  let candidate = target;
  for (;;) {
    try {
      fs.lstatSync(candidate);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") return null;
      const parent = path.dirname(candidate);
      if (parent === candidate) return null;
      missingSegments.unshift(path.basename(candidate));
      candidate = parent;
      continue;
    }
    try {
      return path.join(fs.realpathSync(candidate), ...missingSegments);
    } catch {
      return null;
    }
  }
}

export function registerCoreFileCapabilities(registry: CapabilityRegistry): void {
  for (const [toolName, access] of Object.entries(CORE_FILE_TOOLS)) {
    registry.register(toolName, fileAccessResolver(toolName, access));
  }
}
