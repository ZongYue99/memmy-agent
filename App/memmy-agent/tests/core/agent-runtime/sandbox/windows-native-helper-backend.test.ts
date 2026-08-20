import type { ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WindowsNativeHelperBackend } from "../../../../src/core/agent-runtime/sandbox/adapters/execution/windows-native-helper-backend.js";
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

function fixture(): Readonly<{
  root: string;
  helper: string;
  helperHash: string;
  profile: PermissionProfile;
}> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "memmy-windows-helper-"));
  temporaryRoots.push(root);
  const helper = path.join(root, "sandbox-helper.exe");
  fs.writeFileSync(helper, "trusted helper fixture");
  const helperHash = createHash("sha256").update(fs.readFileSync(helper)).digest("hex");
  const unhashed: UnhashedPermissionProfile = {
    type: "managed",
    version: 1,
    filesystem: {
      kind: "restricted",
      entries: [{ path: root, access: "write", missingPathBehavior: "deny" }],
    },
    network: { mode: "denied" },
    process: {
      spawn: "non-interactive",
      maxProcesses: 1,
      maxRuntimeMs: 5_000,
      maxOutputBytes: 64,
    },
    environment: { inherit: [], set: {}, remove: [] },
  };
  return { root, helper, helperHash, profile: attachPolicyHash(unhashed) };
}

function attempt(
  root: string,
  profile: PermissionProfile,
  call: Readonly<{ toolName: string; arguments: Readonly<Record<string, unknown>> }>,
): SandboxAttempt {
  return {
    attemptId: "attempt-windows",
    runtimeCallId: "call-windows",
    argsHash: stablePolicyHash(call),
    permissionProfile: profile,
    compiledPolicyHash: profile.policyHash,
    sandboxType: "windows-restricted-token",
    sandboxCwd: root,
    workspaceRoots: [root],
    networkContextId: "windows-restricted-network-token",
    createdAt: 1,
  };
}

function fakeChild(): Readonly<{ child: ChildProcess; request: Promise<string> }> {
  const child = new EventEmitter() as ChildProcess;
  child.pid = 31_337;
  const stdin = new PassThrough();
  child.stdin = stdin;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = vi.fn(() => true);
  const chunks: Buffer[] = [];
  stdin.on("data", (chunk: Buffer) => chunks.push(chunk));
  const request = new Promise<string>((resolve) => {
    stdin.on("finish", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
  return { child, request };
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe("Windows native sandbox helper backend", () => {
  it("fails closed when the helper or trusted manifest hash is absent or mismatched", () => {
    const { root, helper, profile } = fixture();
    const input = { permissionProfile: profile, sandboxCwd: root, workspaceRoots: [root] };

    expect(new WindowsNativeHelperBackend({ platform: "win32" }).inspectSupport(input)).toEqual({
      supported: false,
      reason: "backend-unavailable",
    });
    expect(
      new WindowsNativeHelperBackend({
        platform: "win32",
        helperExecutable: helper,
        expectedSha256: "0".repeat(64),
      }).inspectSupport(input),
    ).toEqual({ supported: false, reason: "backend-attestation-invalid" });
  });

  it("selects an attested helper for a supported restricted profile", () => {
    const { root, helper, helperHash, profile } = fixture();
    expect(
      new WindowsNativeHelperBackend({
        platform: "win32",
        helperExecutable: helper,
        expectedSha256: helperHash,
      }).inspectSupport({ permissionProfile: profile, sandboxCwd: root, workspaceRoots: [root] }),
    ).toEqual({
      supported: true,
      target: {
        sandboxType: "windows-restricted-token",
        networkContextId: "windows-restricted-network-token",
      },
    });
  });

  it("sends a hash-bound v1 request over stdin and never invokes a shell wrapper", async () => {
    const { root, helper, helperHash, profile } = fixture();
    const { child, request } = fakeChild();
    const spawnProcess = vi.fn(() => {
      queueMicrotask(() => child.emit("spawn"));
      return child;
    });
    const backend = new WindowsNativeHelperBackend({
      platform: "win32",
      helperExecutable: helper,
      expectedSha256: helperHash,
      spawnProcess,
      now: () => 10,
    });
    const call = { toolName: "exec", arguments: { command: "echo hello" } };
    const boundAttempt = attempt(root, profile, call);
    const handle = await backend.start({ attempt: boundAttempt, call });
    const payload = JSON.parse(await request);
    child.stdout?.emit("data", Buffer.from("ok"));
    child.emit("close", 0, null);

    expect(payload).toMatchObject({
      protocolVersion: 1,
      attemptId: boundAttempt.attemptId,
      argsHash: boundAttempt.argsHash,
      compiledPolicyHash: boundAttempt.compiledPolicyHash,
      command: "echo hello",
    });
    expect(spawnProcess.mock.calls[0]?.[1]).toEqual(["--protocol-version", "1"]);
    expect(spawnProcess.mock.calls[0]?.[2]).toMatchObject({ shell: false, windowsHide: true });
    await expect(handle.completion).resolves.toMatchObject({
      kind: "completed",
      result: { exitCode: 0, stdoutSummary: "ok" },
    });
  });
});
