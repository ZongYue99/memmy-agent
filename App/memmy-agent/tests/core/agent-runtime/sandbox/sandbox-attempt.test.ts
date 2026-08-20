import { describe, expect, it } from "vitest";
import {
  transitionAttemptState,
  type AttemptState,
} from "../../../../src/core/agent-runtime/sandbox/domain/sandbox-attempt.js";

describe("sandbox attempt state", () => {
  it("allows only created to running to terminal transitions", () => {
    const created: AttemptState = { kind: "created" };
    const running = transitionAttemptState(created, {
      kind: "running",
      processHandle: "process-1",
    });
    const completed = transitionAttemptState(running, {
      kind: "completed",
      result: {
        exitCode: 0,
        signal: null,
        stdoutSummary: "ok",
        stderrSummary: "",
        outputTruncated: false,
        startedAt: 100,
        completedAt: 200,
        evidenceRefs: [],
      },
    });

    expect(completed.kind).toBe("completed");
    expect(() => transitionAttemptState(created, completed)).toThrow(
      "invalid sandbox attempt transition: created -> completed",
    );
    expect(() => transitionAttemptState(completed, { kind: "cancelled", reason: "late" })).toThrow(
      "invalid sandbox attempt transition: completed -> cancelled",
    );
  });
});
