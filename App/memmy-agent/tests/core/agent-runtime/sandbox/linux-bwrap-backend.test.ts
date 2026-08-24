import type { ChildProcess, SpawnOptions } from "node:child_process";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LinuxBwrapBackend } from "../../../../src/core/agent-runtime/sandbox/adapters/execution/linux-bwrap-backend.js";
import { compileLinuxBwrapPolicy } from "../../../../src/core/agent-runtime/sandbox/adapters/execution/linux-bwrap-policy.js";
import type {
  PermissionProfile,
  UnhashedPermissionProfile,
} from "../../../../src/core/agent-runtime/sandbox/domain/permission-profile.js";
import type { SandboxAttempt } from "../../../../src/core/agent-runtime/sandbox/domain/sandbox-attempt.js";
import {
  attachPolicyHash,
  stablePolicyHash,
} from "../../../../src/core/agent-runtime/sandbox/policy/policy-hash.js";

const temporaryRoots: string[] = [];

function fixture(maxOutputBytes = 64): Readonly<{
  root: string;
  workspace: string;
  denied: string;
  profile: PermissionProfile;
}> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "memmy-bwrap-"));
  temporaryRoots.push(root);
  const workspace = path.join(root, "workspace");
  const denied = path.join(workspace, ".env");
  fs.mkdirSync(workspace);
  fs.writeFileSync(denied, "secret");
  const unhashed: UnhashedPermissionProfile = {
    type: "managed",
    version: 1,
    filesystem: {
      kind: "restricted",
      entries: [
        { path: root, access: "read", missingPathBehavior: "deny" },
        { path: workspace, access: "write", missingPathBehavior: "deny" },
        { path: denied, access: "deny", missingPathBehavior: "deny" },
      ],
    },
    network: { mode: "denied" },
    process: {
      spawn: "non-interactive",
      maxProcesses: 1,
      maxRuntimeMs: 5_000,
      maxOutputBytes,
    },
    environment: { inherit: [], set: { PATH: "/usr/bin:/bin" }, remove: [] },
  };
  return { root, workspace, denied, profile: attachPolicyHash(unhashed) };
}

function attempt(
  workspace: string,
  profile: PermissionProfile,
  call: Readonly<{ toolName: string; arguments: Readonly<Record<string, unknown>> }>,
): SandboxAttempt {
  return {
    attemptId: "attempt-linux",
    runtimeCallId: "call-linux",
    argsHash: stablePolicyHash(call),
    permissionProfile: profile,
    compiledPolicyHash: profile.policyHash,
    sandboxType: "linux-bwrap",
    sandboxCwd: workspace,
    workspaceRoots: [workspace],
    createdAt: 1,
  };
}

function fakeChild(): ChildProcess {
  const child = new EventEmitter() as ChildProcess;
  Object.defineProperty(child, "pid", { value: 42_424 });
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = null;
  child.kill = vi.fn(() => true);
  return child;
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe("Linux Bubblewrap backend", () => {
  it("compiles an empty-root, network-isolated mount plan with deny masks last", () => {
    const { workspace, denied, profile } = fixture();
    const compiled = compileLinuxBwrapPolicy(profile, workspace, [workspace]);
    const canonicalWorkspace = fs.realpathSync.native(workspace);
    const canonicalDenied = fs.realpathSync.native(denied);

    expect(compiled.args).toContain("--unshare-net");
    expect(compiled.args.join("\0")).not.toContain("--ro-bind\0/\0/");
    const writeMount = compiled.args.findIndex(
      (value, index) =>
        value === "--bind" &&
        compiled.args[index + 1] === canonicalWorkspace &&
        compiled.args[index + 2] === canonicalWorkspace,
    );
    const denyMount = compiled.args.findIndex(
      (value, index) =>
        value === "--ro-bind" &&
        compiled.args[index + 1] === "/dev/null" &&
        compiled.args[index + 2] === canonicalDenied,
    );
    expect(writeMount).toBeGreaterThanOrEqual(0);
    expect(denyMount).toBeGreaterThan(writeMount);
    expect(compiled.args.slice(-6)).toEqual([
      "--chdir",
      canonicalWorkspace,
      "--clearenv",
      "--setenv",
      "PATH",
      "/usr/bin:/bin",
    ]);
  });

  it("selects only enforceable Linux profiles with an executable backend", () => {
    const { workspace, profile } = fixture();
    const backend = new LinuxBwrapBackend({ platform: "linux", executable: "/bin/sh" });
    expect(
      backend.inspectSupport({
        permissionProfile: profile,
        sandboxCwd: workspace,
        workspaceRoots: [workspace],
      }),
    ).toEqual({
      supported: true,
      target: { sandboxType: "linux-bwrap" },
    });
    expect(
      new LinuxBwrapBackend({ platform: "darwin", executable: "/bin/sh" }).inspectSupport({
        permissionProfile: profile,
        sandboxCwd: workspace,
        workspaceRoots: [workspace],
      }),
    ).toEqual({ supported: false, reason: "platform-mismatch" });
  });

  it("binds the attempt hash, bounds output, and launches without a shell wrapper", async () => {
    const { workspace, profile } = fixture(4);
    const child = fakeChild();
    const spawnProcess = vi.fn<
      (command: string, args: readonly string[], options: SpawnOptions) => ChildProcess
    >(() => {
      queueMicrotask(() => child.emit("spawn"));
      return child;
    });
    const backend = new LinuxBwrapBackend({
      platform: "linux",
      executable: "/bin/sh",
      spawnProcess,
      now: () => 10,
    });
    const call = { toolName: "exec", arguments: { command: "printf hello" } };
    const handle = await backend.start({ attempt: attempt(workspace, profile, call), call });
    child.stdout?.emit("data", Buffer.from("hello"));
    child.emit("close", 0, null);

    await expect(handle.completion).resolves.toMatchObject({
      kind: "completed",
      result: { stdoutSummary: "hell", outputTruncated: true },
    });
    expect(spawnProcess).toHaveBeenCalledOnce();
    expect(spawnProcess.mock.calls[0]?.[2]).toMatchObject({
      shell: false,
      detached: true,
      env: {},
    });
    expect(spawnProcess.mock.calls[0]?.[1]).toEqual(
      expect.arrayContaining(["--unshare-net", "--", "/bin/sh", "-c", "printf hello"]),
    );

    await expect(
      backend.start({
        attempt: { ...attempt(workspace, profile, call), argsHash: "tampered" },
        call,
      }),
    ).rejects.toThrow("unsupported-profile");
    expect(spawnProcess).toHaveBeenCalledOnce();
  });
});
