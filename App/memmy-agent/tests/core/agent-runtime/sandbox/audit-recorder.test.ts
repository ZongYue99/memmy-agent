import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AuditRecorder } from "../../../../src/core/agent-runtime/sandbox/adapters/audit/audit-recorder.js";
import { JsonlAuditOutbox } from "../../../../src/core/agent-runtime/sandbox/adapters/audit/jsonl-audit-outbox.js";
import type { SandboxAuditEventDraft } from "../../../../src/core/agent-runtime/sandbox/domain/audit-event.js";

const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "memmy-sandbox-audit-"));
  temporaryRoots.push(root);
  return { root, outboxPath: path.join(root, "sandbox-audit.jsonl") };
}

function draft(runtimeCallId = "call-1"): SandboxAuditEventDraft {
  return {
    runtimeCallId,
    detail: {
      kind: "approval-requested",
      requestId: "approval-request-1",
      parentAttemptId: "attempt-1",
      argsHash: "a".repeat(64),
      initialPolicyHash: "b".repeat(64),
      subjectId: "user-1",
      expiresAt: 2_000,
    },
  };
}

describe("sandbox audit recorder", () => {
  it("writes a bounded allowlisted event to a private append-only JSONL file", async () => {
    const { outboxPath } = fixture();
    const recorder = new AuditRecorder(
      new JsonlAuditOutbox(outboxPath),
      { nextId: () => "audit-1" },
      { now: () => 1_000 },
    );

    await recorder.record(draft());

    const lines = fs.readFileSync(outboxPath, "utf8").trimEnd().split("\n");
    expect(lines.map((line) => JSON.parse(line))).toEqual([
      {
        version: 1,
        auditId: "audit-1",
        recordedAt: 1_000,
        ...draft(),
      },
    ]);
    if (process.platform !== "win32") {
      expect(fs.statSync(outboxPath).mode & 0o077).toBe(0);
    }
    expect(lines[0]).not.toContain("nonce");
    expect(lines[0]).not.toContain("command");
  });

  it("serializes concurrent appends as complete JSONL records", async () => {
    const { outboxPath } = fixture();
    let sequence = 0;
    const recorder = new AuditRecorder(
      new JsonlAuditOutbox(outboxPath),
      { nextId: () => `audit-${++sequence}` },
      { now: () => 1_000 + sequence },
    );

    await Promise.all([recorder.record(draft("call-1")), recorder.record(draft("call-2"))]);

    const events = fs
      .readFileSync(outboxPath, "utf8")
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(events.map(({ runtimeCallId }) => runtimeCallId)).toEqual(["call-1", "call-2"]);
  });

  it("rejects non-allowlisted identifier content before creating the outbox", async () => {
    const { outboxPath } = fixture();
    const recorder = new AuditRecorder(
      new JsonlAuditOutbox(outboxPath),
      { nextId: () => "audit-1" },
      { now: () => 1_000 },
    );

    await expect(recorder.record(draft("call-1\nsecret"))).rejects.toThrow(
      "runtimeCallId must be a bounded audit identifier",
    );
    await expect(
      recorder.record({
        runtimeCallId: "call-1",
        detail: { kind: "raw-payload", payload: "secret" },
      } as unknown as SandboxAuditEventDraft),
    ).rejects.toThrow("unsupported sandbox audit event kind");
    expect(fs.existsSync(outboxPath)).toBe(false);
  });

  it("fails closed when the outbox capacity is exhausted", async () => {
    const { outboxPath } = fixture();
    const recorder = new AuditRecorder(
      new JsonlAuditOutbox(outboxPath, 1),
      { nextId: () => "audit-1" },
      { now: () => 1_000 },
    );

    await expect(recorder.record(draft())).rejects.toThrow("audit outbox exceeds size limit");
    expect(fs.readFileSync(outboxPath, "utf8")).toBe("");
  });
});
