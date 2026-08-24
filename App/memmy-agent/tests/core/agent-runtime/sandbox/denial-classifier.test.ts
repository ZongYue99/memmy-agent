import { describe, expect, it } from "vitest";
import { parseSeatbeltDenialEvent } from "../../../../src/core/agent-runtime/sandbox/adapters/execution/macos-seatbelt-denial-monitor.js";
import type { DenialObservation } from "../../../../src/core/agent-runtime/sandbox/domain/denial-evidence.js";
import type {
  PermissionProfile,
  UnhashedPermissionProfile,
} from "../../../../src/core/agent-runtime/sandbox/domain/permission-profile.js";
import type { SandboxAttempt } from "../../../../src/core/agent-runtime/sandbox/domain/sandbox-attempt.js";
import type { SandboxedResult } from "../../../../src/core/agent-runtime/sandbox/domain/sandbox-result.js";
import { classifyDenial } from "../../../../src/core/agent-runtime/sandbox/guard/denial-classifier.js";
import {
  attachPolicyHash,
  stablePolicyHash,
} from "../../../../src/core/agent-runtime/sandbox/policy/policy-hash.js";

function profile(): PermissionProfile {
  const unhashed: UnhashedPermissionProfile = {
    type: "managed",
    version: 1,
    filesystem: {
      kind: "restricted",
      entries: [
        { path: "/workspace", access: "read", missingPathBehavior: "deny" },
        { path: "/workspace", access: "write", missingPathBehavior: "deny" },
        { path: "/workspace/.env", access: "deny", missingPathBehavior: "deny" },
      ],
    },
    network: { mode: "denied" },
    process: {
      spawn: "non-interactive",
      maxProcesses: 1,
      maxRuntimeMs: 1_000,
      maxOutputBytes: 1_000,
    },
    environment: { inherit: [], set: {}, remove: [] },
  };
  return attachPolicyHash(unhashed);
}

function attempt(): SandboxAttempt {
  const permissionProfile = profile();
  const call = { toolName: "exec", arguments: { command: "cat .env" } };
  return {
    attemptId: "attempt-1",
    runtimeCallId: "call-1",
    argsHash: stablePolicyHash(call),
    permissionProfile,
    compiledPolicyHash: permissionProfile.policyHash,
    sandboxType: "macos-seatbelt",
    sandboxCwd: "/workspace",
    workspaceRoots: ["/workspace"],
    createdAt: 50,
  };
}

function result(exitCode = 1, stderrSummary = ""): SandboxedResult {
  return {
    exitCode,
    signal: null,
    stdoutSummary: "",
    stderrSummary,
    outputTruncated: false,
    startedAt: 100,
    completedAt: 200,
  };
}

function observation(overrides: Partial<DenialObservation> = {}): DenialObservation {
  return {
    provenance: "macos-kernel-sandbox-log",
    processId: 123,
    processName: "cat",
    operation: "file-read-data",
    target: "/workspace/.env",
    observedAt: 150,
    ...overrides,
  };
}

const filesystem = {
  readableRoots: ["/workspace"],
  writableRoots: ["/workspace"],
  deniedRoots: ["/workspace/.env"],
};

describe("classifyDenial", () => {
  it("creates confirmed evidence from a matching kernel filesystem denial", () => {
    expect(
      classifyDenial({
        attempt: attempt(),
        result: result(),
        observations: [observation()],
        filesystem,
      }),
    ).toMatchObject({
      source: "os-sandbox",
      operation: "file-read",
      requiredCapability: { kind: "filesystem", access: "read", path: "/workspace/.env" },
      systemCode: "SEATBELT_DENY",
      minimallySupplementable: true,
    });
  });

  it("does not trust stderr keywords or benign platform observations", () => {
    expect(
      classifyDenial({
        attempt: attempt(),
        result: result(1, "Operation not permitted"),
        observations: [],
        filesystem,
      }),
    ).toBeNull();
    expect(
      classifyDenial({
        attempt: attempt(),
        result: result(),
        observations: [
          observation({ operation: "sysctl-read", target: "kern.bootargs" }),
          observation({ operation: "file-write-data", target: "/dev/dtracehelper" }),
        ],
        filesystem,
      }),
    ).toBeNull();
  });

  it("requires a non-zero result and an observation inside its execution window", () => {
    expect(
      classifyDenial({
        attempt: attempt(),
        result: result(0),
        observations: [observation()],
        filesystem,
      }),
    ).toBeNull();
    expect(
      classifyDenial({
        attempt: attempt(),
        result: result(),
        observations: [observation({ observedAt: 10_000 })],
        filesystem,
      }),
    ).toBeNull();
  });
});

describe("parseSeatbeltDenialEvent", () => {
  it("parses only kernel Sandbox.kext denial events", () => {
    const event = {
      senderImagePath: "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox",
      timestamp: "2026-08-20 11:30:59.619174+0800",
      eventMessage: "Sandbox: cat(81103) deny(1) file-read-data /workspace/.env",
    };
    expect(parseSeatbeltDenialEvent(JSON.stringify(event))).toMatchObject({
      provenance: "macos-kernel-sandbox-log",
      processId: 81103,
      processName: "cat",
      operation: "file-read-data",
      target: "/workspace/.env",
    });
    expect(
      parseSeatbeltDenialEvent(
        JSON.stringify({
          ...event,
          senderImagePath: "/tmp/fake",
          eventMessage: event.eventMessage,
        }),
      ),
    ).toBeNull();
  });
});
