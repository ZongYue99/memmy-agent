import fs from "node:fs";
import path from "node:path";
import type { PermissionProfile } from "../../domain/permission-profile.js";

const SYSTEM_READ_ROOTS = [
  "/bin",
  "/sbin",
  "/usr",
  "/lib",
  "/lib64",
  "/etc/ld.so.cache",
  "/etc/ld.so.preload",
  "/etc/ssl/certs",
] as const;

export type CompiledBwrapPolicy = Readonly<{
  args: readonly string[];
  cwd: string;
  readableRoots: readonly string[];
  writableRoots: readonly string[];
  deniedRoots: readonly string[];
}>;

function pathIsInside(target: string, root: string): boolean {
  const relative = path.relative(root, target);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function canonicalEntry(entry: PermissionProfile["filesystem"]["entries"][number]): string | null {
  try {
    return fs.realpathSync.native(entry.path);
  } catch {
    if (entry.missingPathBehavior === "skip") return null;
    throw new Error(`sandbox path is unavailable: ${entry.path}`);
  }
}

function uniqueDeepestFirst(values: readonly string[]): string[] {
  return [...new Set(values)].sort(
    (left, right) => right.length - left.length || left.localeCompare(right),
  );
}

/** Compiles a restricted, network-denied profile into an empty-root Bubblewrap mount plan. */
export function compileLinuxBwrapPolicy(
  profile: PermissionProfile,
  sandboxCwd: string,
  workspaceRoots: readonly string[],
): CompiledBwrapPolicy {
  if (
    profile.filesystem.kind !== "restricted" ||
    profile.network.mode !== "denied" ||
    profile.process.spawn !== "non-interactive" ||
    (profile.process.maxProcesses !== 1 && profile.process.maxProcesses !== Number.MAX_SAFE_INTEGER)
  ) {
    throw new Error("unsupported Bubblewrap permission profile");
  }
  const entries = profile.filesystem.entries
    .map((entry) => ({ entry, canonical: canonicalEntry(entry) }))
    .filter((value): value is { entry: typeof value.entry; canonical: string } =>
      Boolean(value.canonical),
    );
  const readableRoots = uniqueDeepestFirst(
    entries.filter(({ entry }) => entry.access === "read").map(({ canonical }) => canonical),
  );
  const writableRoots = uniqueDeepestFirst(
    entries.filter(({ entry }) => entry.access === "write").map(({ canonical }) => canonical),
  );
  const deniedRoots = uniqueDeepestFirst(
    entries.filter(({ entry }) => entry.access === "deny").map(({ canonical }) => canonical),
  );
  const cwd = fs.realpathSync.native(sandboxCwd);
  const roots = workspaceRoots.map((root) => fs.realpathSync.native(root));
  if (!roots.some((root) => pathIsInside(cwd, root))) {
    throw new Error("sandbox cwd is outside the workspace");
  }
  if (
    ![...readableRoots, ...writableRoots].some((root) => pathIsInside(cwd, root)) ||
    deniedRoots.some((root) => pathIsInside(cwd, root))
  ) {
    throw new Error("sandbox cwd is not visible");
  }

  const args: string[] = [
    "--die-with-parent",
    "--new-session",
    "--unshare-user",
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-net",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/tmp",
  ];
  for (const root of SYSTEM_READ_ROOTS) {
    if (fs.existsSync(root)) args.push("--ro-bind", root, root);
  }
  for (const root of readableRoots) args.push("--ro-bind", root, root);
  for (const root of writableRoots) args.push("--bind", root, root);
  for (const root of deniedRoots) {
    const status = fs.statSync(root);
    if (status.isDirectory()) args.push("--tmpfs", root);
    else args.push("--ro-bind", "/dev/null", root);
  }
  args.push("--chdir", cwd, "--clearenv");
  const removed = new Set(profile.environment.remove);
  for (const name of profile.environment.inherit) {
    if (!name || name.includes("=") || name.includes("\0")) {
      throw new Error("invalid inherited environment name");
    }
    if (removed.has(name)) continue;
    const value = process.env[name];
    if (value !== undefined) args.push("--setenv", name, value);
  }
  for (const [name, value] of Object.entries(profile.environment.set)) {
    if (!name || name.includes("=") || name.includes("\0") || value.includes("\0")) {
      throw new Error("invalid sandbox environment entry");
    }
    if (!removed.has(name)) args.push("--setenv", name, value);
  }
  return Object.freeze({ args, cwd, readableRoots, writableRoots, deniedRoots });
}
