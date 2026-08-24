import path from "node:path";
import type { ResolvedAccessSet } from "../domain/capability.js";
import { CapabilityRegistry } from "./capability-registry.js";

function firstString(...values: unknown[]): string | null {
  return (
    values.find((value): value is string => typeof value === "string" && value.trim().length > 0) ??
    null
  );
}

export function registerExecCapabilities(registry: CapabilityRegistry): void {
  registry.register("exec", (params, context): ResolvedAccessSet => {
    if (!firstString(params.command, params.cmd)) {
      return [{ kind: "unknown", name: "exec-command" }];
    }
    if (
      params.yield_time_ms !== undefined ||
      params.yieldTimeMs !== undefined ||
      params.shell !== undefined ||
      params.login === false
    ) {
      return [{ kind: "unknown", name: "exec-session-or-shell-option" }];
    }
    const requestedCwd = firstString(
      params.cwd,
      params.working_dir,
      params.workingDir,
      params.workdir,
    );
    const cwd = path.resolve(context.cwd, requestedCwd ?? ".");
    return [
      { kind: "filesystem", access: "read", path: cwd },
      { kind: "process", interactive: false },
    ];
  });
}
