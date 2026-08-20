import fs from "node:fs";
import path from "node:path";
import type { FileSystemEntry, PermissionProfile } from "../../domain/permission-profile.js";

const PLATFORM_POLICY = `(version 1)
(deny default)
(allow process-exec)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow sysctl-read)
(allow iokit-open (iokit-registry-entry-class "RootDomainUserClient"))
(allow mach-lookup
  (global-name "com.apple.system.opendirectoryd.libinfo") (global-name "com.apple.PowerManagement.control")
  (global-name "com.apple.cfprefsd.daemon") (global-name "com.apple.cfprefsd.agent")
  (local-name "com.apple.cfprefsd.agent"))
(allow file-read* file-test-existence
  (literal "/")
  (subpath "/bin") (subpath "/sbin")
  (subpath "/usr/bin") (subpath "/usr/sbin")
  (subpath "/usr/lib") (subpath "/usr/libexec") (subpath "/usr/share")
  (subpath "/System/Library") (subpath "/Library/Apple")
  (subpath "/Library/Preferences") (subpath "/private/var/db/timezone")
  (literal "/private/var/select/sh"))
(allow file-map-executable
  (subpath "/usr/lib") (subpath "/System/Library") (subpath "/Library/Apple"))
(allow file-read* file-write-data file-test-existence
  (literal "/dev/null")
  (literal "/dev/zero"))
(allow file-read* file-write* (subpath "/dev/fd"))
(allow file-read-metadata
  (literal "/dev")
  (regex #"^/dev/.*$"))
(allow file-read-metadata file-test-existence
  (literal "/etc")
  (literal "/tmp")
  (literal "/var"))`;

export type CompiledSeatbeltPolicy = Readonly<{
  policy: string;
  parameters: readonly string[];
  readableRoots: readonly string[];
  writableRoots: readonly string[];
  deniedRoots: readonly string[];
}>;

export class SeatbeltPolicyError extends Error {
  constructor(
    readonly code:
      | "unsupported-filesystem"
      | "unsupported-network"
      | "unsupported-process"
      | "invalid-path"
      | "missing-path",
  ) {
    super(code);
    this.name = "SeatbeltPolicyError";
  }
}

function canonicalizeEntry(entry: FileSystemEntry): string | null {
  if (!path.isAbsolute(entry.path)) throw new SeatbeltPolicyError("invalid-path");
  try {
    return fs.realpathSync.native(entry.path);
  } catch (error) {
    if (
      (error as NodeJS.ErrnoException).code === "ENOENT" &&
      entry.missingPathBehavior === "skip"
    ) {
      return null;
    }
    throw new SeatbeltPolicyError("missing-path");
  }
}

function parameterRule(
  operation: "file-read* file-test-existence" | "file-write*" | "file-read* file-write*",
  kind: "READABLE_ROOT" | "WRITABLE_ROOT" | "DENIED_ROOT",
  roots: readonly string[],
): { policy: string; parameters: string[] } {
  const parameters = roots.map((root, index) => `-D${kind}_${index}=${root}`);
  const predicates = roots
    .map(
      (_, index) =>
        `(require-any\n    (literal (param "${kind}_${index}"))\n    (subpath (param "${kind}_${index}")))`,
    )
    .join("\n  ");
  if (!predicates) return { policy: "", parameters };
  return {
    policy: `(${kind === "DENIED_ROOT" ? "deny" : "allow"} ${operation}\n  ${predicates})`,
    parameters,
  };
}

function ancestorRules(roots: readonly string[]): string {
  const predicates = roots
    .map((_, index) => `(path-ancestors (param "READABLE_ROOT_${index}"))`)
    .join("\n  ");
  return predicates ? `(allow file-read-metadata file-test-existence\n  ${predicates})` : "";
}

export function compileMacosSeatbeltPolicy(profile: PermissionProfile): CompiledSeatbeltPolicy {
  if (profile.filesystem.kind !== "restricted") {
    throw new SeatbeltPolicyError("unsupported-filesystem");
  }
  if (profile.network.mode !== "denied") {
    throw new SeatbeltPolicyError("unsupported-network");
  }
  if (
    profile.process.spawn !== "non-interactive" ||
    (profile.process.maxProcesses !== 1 && profile.process.maxProcesses !== Number.MAX_SAFE_INTEGER)
  ) {
    throw new SeatbeltPolicyError("unsupported-process");
  }
  const roots = {
    read: new Set<string>(),
    write: new Set<string>(),
    deny: new Set<string>(),
  };
  for (const entry of profile.filesystem.entries) {
    const canonical = canonicalizeEntry(entry);
    if (canonical) roots[entry.access].add(canonical);
  }
  const readableRoots = [...roots.read].sort();
  const writableRoots = [...roots.write].sort();
  const deniedRoots = [...roots.deny].sort();
  const read = parameterRule("file-read* file-test-existence", "READABLE_ROOT", readableRoots);
  const write = parameterRule("file-write*", "WRITABLE_ROOT", writableRoots);
  const deny = parameterRule("file-read* file-write*", "DENIED_ROOT", deniedRoots);
  const processPolicy = profile.process.maxProcesses === 1 ? "" : "(allow process-fork)";
  const policy = [
    PLATFORM_POLICY,
    processPolicy,
    ancestorRules(readableRoots),
    read.policy,
    write.policy,
    deny.policy,
  ]
    .filter(Boolean)
    .join("\n\n");
  return Object.freeze({
    policy,
    parameters: Object.freeze([...read.parameters, ...write.parameters, ...deny.parameters]),
    readableRoots: Object.freeze(readableRoots),
    writableRoots: Object.freeze(writableRoots),
    deniedRoots: Object.freeze(deniedRoots),
  });
}
