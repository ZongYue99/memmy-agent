import fs from "node:fs";
import { spawn } from "node:child_process";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { BackendRegistry } from "../../../../src/core/agent-runtime/sandbox/adapters/execution/backend-registry.js";
import { MacosSeatbeltBackend } from "../../../../src/core/agent-runtime/sandbox/adapters/execution/macos-seatbelt-backend.js";
import { MacosSeatbeltDenialMonitor } from "../../../../src/core/agent-runtime/sandbox/adapters/execution/macos-seatbelt-denial-monitor.js";
import type {
  PermissionProfile,
  UnhashedPermissionProfile,
} from "../../../../src/core/agent-runtime/sandbox/domain/permission-profile.js";
import type { SandboxAttempt } from "../../../../src/core/agent-runtime/sandbox/domain/sandbox-attempt.js";
import {
  attachPolicyHash,
  stablePolicyHash,
} from "../../../../src/core/agent-runtime/sandbox/policy/policy-hash.js";

const runtimeDescribe =
  process.platform === "darwin" && process.env.CODEX_SANDBOX !== "seatbelt"
    ? describe
    : describe.skip;
const temporaryRoots: string[] = [];

function fixture(maxProcesses = 1, maxRuntimeMs = 10_000, maxOutputBytes = 4_096) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "memmy-seatbelt-runtime-"));
  temporaryRoots.push(root);
  const workspace = path.join(root, "workspace");
  const denied = path.join(root, "denied");
  fs.mkdirSync(workspace);
  fs.mkdirSync(denied);
  fs.writeFileSync(path.join(denied, "secret.txt"), "secret");
  const protectedFile = path.join(root, "protected.txt");
  fs.writeFileSync(protectedFile, "protected");
  const unhashed: UnhashedPermissionProfile = {
    type: "managed",
    version: 1,
    filesystem: {
      kind: "restricted",
      entries: [
        { path: root, access: "read", missingPathBehavior: "deny" },
        { path: workspace, access: "write", missingPathBehavior: "deny" },
        { path: denied, access: "deny", missingPathBehavior: "deny" },
        { path: protectedFile, access: "deny", missingPathBehavior: "deny" },
      ],
    },
    network: { mode: "denied" },
    process: {
      spawn: "non-interactive",
      maxProcesses,
      maxRuntimeMs,
      maxOutputBytes,
    },
    environment: {
      inherit: [],
      set: { PATH: "/usr/bin:/bin", HOME: workspace, TMPDIR: workspace, LANG: "C" },
      remove: [],
    },
  };
  const profile = attachPolicyHash(unhashed);
  return { root, workspace, denied, protectedFile, profile };
}

function attempt(
  workspace: string,
  profile: PermissionProfile,
  call: Readonly<{ toolName: string; arguments: Readonly<Record<string, unknown>> }>,
): SandboxAttempt {
  return {
    attemptId: "attempt-runtime",
    runtimeCallId: "call-runtime",
    argsHash: stablePolicyHash(call),
    permissionProfile: profile,
    compiledPolicyHash: profile.policyHash,
    sandboxType: "macos-seatbelt",
    sandboxCwd: workspace,
    workspaceRoots: [workspace],
    createdAt: Date.now(),
  };
}

async function run(command: string, workspace: string, profile: PermissionProfile) {
  const executor = new BackendRegistry([new MacosSeatbeltBackend()]);
  executor.selectTarget({
    permissionProfile: profile,
    sandboxCwd: workspace,
    workspaceRoots: [workspace],
  });
  const call = { toolName: "exec", arguments: { command } };
  const handle = await executor.start({
    attempt: attempt(workspace, profile, call),
    call,
  });
  return handle.completion;
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

runtimeDescribe("macOS Seatbelt runtime", () => {
  it("binds a kernel denial event to the sandbox-exec process id", async () => {
    const { protectedFile } = fixture();
    const capture = await new MacosSeatbeltDenialMonitor().start(10_000);
    expect(capture).not.toBeNull();
    if (!capture) return;
    const policy = `(version 1)\n(deny default)\n(allow process-exec)\n(allow file-read*)\n(allow file-write-data (subpath "/dev/fd"))\n(deny file-read* (literal (param "DENIED")))`;
    const child = spawn(
      "/usr/bin/sandbox-exec",
      [
        "-p",
        policy,
        `-DDENIED=${fs.realpathSync.native(protectedFile)}`,
        "--",
        "/bin/cat",
        protectedFile,
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    if (!child.pid) throw new Error("sandbox-exec did not expose a process id");
    capture.bindProcess(child.pid);
    await new Promise<void>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", () => resolve());
    });
    expect(await capture.finish({ waitForObservation: true })).toContainEqual(
      expect.objectContaining({
        processId: child.pid,
        operation: "file-read-data",
        target: fs.realpathSync.native(protectedFile),
      }),
    );
  });

  it("fails closed when the backend cannot enforce a finite process quota", () => {
    const { workspace, profile } = fixture(32);
    const executor = new BackendRegistry([new MacosSeatbeltBackend()]);
    expect(() =>
      executor.selectTarget({
        permissionProfile: profile,
        sandboxCwd: workspace,
        workspaceRoots: [workspace],
      }),
    ).toThrow("no-compatible-backend");
  });

  it("allows workspace writes and denies explicitly blocked reads and writes", async () => {
    const { workspace, denied, protectedFile, profile } = fixture();
    const canonicalProtectedFile = fs.realpathSync.native(protectedFile);
    const canonicalDenied = fs.realpathSync.native(denied);
    const allowed = await run("printf ok > result.txt; printf ok", workspace, profile);
    const deniedRead = await run(`/bin/cat ${JSON.stringify(protectedFile)}`, workspace, profile);
    const deniedWrite = await run(
      `printf bad > ${JSON.stringify(path.join(denied, "out.txt"))}`,
      workspace,
      profile,
    );

    expect(allowed).toMatchObject({
      kind: "completed",
      result: { exitCode: 0, stdoutSummary: "ok" },
    });
    expect(deniedRead).toMatchObject({
      kind: "denied",
      evidence: {
        source: "os-sandbox",
        operation: "file-read",
        requiredCapability: { kind: "filesystem", access: "read", path: canonicalProtectedFile },
        systemCode: "SEATBELT_DENY",
      },
    });
    expect(deniedWrite).toMatchObject({
      kind: "denied",
      evidence: {
        source: "os-sandbox",
        operation: "file-write",
        requiredCapability: {
          kind: "filesystem",
          access: "write",
          path: path.join(canonicalDenied, "out.txt"),
        },
        systemCode: "SEATBELT_DENY",
      },
    });
    expect(fs.existsSync(path.join(denied, "out.txt"))).toBe(false);
  });

  it("does not promote forged process output to a confirmed denial", async () => {
    const { workspace, profile } = fixture();
    const outcome = await run(
      "printf 'Operation not permitted\\n' >&2; exit 1",
      workspace,
      profile,
    );
    expect(outcome).toMatchObject({
      kind: "completed",
      result: { exitCode: 1, stderrSummary: "Operation not permitted\n" },
    });
  });

  it("bounds captured output and enforces the runtime deadline", async () => {
    const outputFixture = fixture(1, 10_000, 64);
    const output = await run("printf '%0100d' 0", outputFixture.workspace, outputFixture.profile);
    expect(output).toMatchObject({
      kind: "completed",
      result: { exitCode: 0, outputTruncated: true },
    });
    if (output.kind === "completed")
      expect(Buffer.byteLength(output.result.stdoutSummary)).toBe(64);

    const timeoutFixture = fixture(1, 50);
    expect(await run("sleep 30", timeoutFixture.workspace, timeoutFixture.profile)).toEqual({
      kind: "cancelled",
      reason: "max-runtime-exceeded",
    });
  });

  it("denies outbound TCP, including localhost", async () => {
    const { workspace, profile } = fixture();
    let acceptedConnections = 0;
    const server = net.createServer((socket) => {
      acceptedConnections++;
      socket.destroy();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server did not bind TCP");
    try {
      const outcome = await run(`/usr/bin/nc -z 127.0.0.1 ${address.port}`, workspace, profile);
      expect(outcome).toMatchObject({
        kind: "denied",
        evidence: { source: "os-sandbox", operation: "network", systemCode: "SEATBELT_DENY" },
      });
      await new Promise((resolve) => setTimeout(resolve, 25));
      expect(acceptedConnections).toBe(0);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });

  it("terminates a complete process group and makes cancellation idempotent", async () => {
    const { workspace, profile } = fixture(Number.MAX_SAFE_INTEGER);
    const pidFile = path.join(workspace, "child.pid");
    const call = {
      toolName: "exec",
      arguments: { command: "sleep 30 & echo $! > child.pid; wait" },
    };
    const handle = await new MacosSeatbeltBackend().start({
      attempt: attempt(workspace, profile, call),
      call,
    });
    for (let index = 0; index < 40 && !fs.existsSync(pidFile); index++) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    const childPid = Number(fs.readFileSync(pidFile, "utf8").trim());
    const firstCancel = handle.cancel("runtime-test-cancelled");
    expect(handle.cancel("ignored-second-reason")).toBe(firstCancel);
    await firstCancel;

    expect(await handle.completion).toEqual({
      kind: "cancelled",
      reason: "runtime-test-cancelled",
    });
    expect(() => process.kill(childPid, 0)).toThrow(expect.objectContaining({ code: "ESRCH" }));
  });
});
