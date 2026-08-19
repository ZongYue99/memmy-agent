import { describe, expect, it } from "vitest";
import type { CapabilitySet } from "../../../../src/core/agent-runtime/sandbox/domain/capability.js";
import { normalizeCapabilitySet } from "../../../../src/core/agent-runtime/sandbox/policy/policy-cap.js";

describe("normalizeCapabilitySet", () => {
  it("canonicalizes and deduplicates network targets for stable policy hashing", () => {
    const capability: CapabilitySet = {
      filesystem: { read: [], write: [], deny: [] },
      network: {
        mode: "allowlist",
        targets: [
          { host: "API.EXAMPLE.COM.", protocols: ["https", "http"], ports: [443, 80, 443] },
          { host: "api.example.com", protocols: ["http", "https"], ports: [80, 443] },
        ],
      },
      process: {
        spawn: "denied",
        maxProcesses: 0,
        maxRuntimeMs: 0,
        maxOutputBytes: 0,
      },
      environment: { inherit: [], set: {}, remove: [] },
      resources: [],
      externalEffects: { maximum: "none" },
    };

    expect(normalizeCapabilitySet(capability).network).toEqual({
      mode: "allowlist",
      targets: [{ host: "api.example.com", protocols: ["http", "https"], ports: [80, 443] }],
    });
  });
});
