import { describe, expect, it, vi } from "vitest";
import { RuntimeResourceGuard } from "../../../../src/core/agent-runtime/sandbox/guard/runtime-resource-guard.js";
import { normalizeCapabilitySet } from "../../../../src/core/agent-runtime/sandbox/policy/policy-cap.js";
import { resolvePolicy } from "../../../../src/core/agent-runtime/sandbox/policy/policy-resolver.js";
import { createWorkspacePreset } from "../../../../src/core/agent-runtime/sandbox/policy/presets.js";

function authorization(compiledVariant = "base") {
  const preset = createWorkspacePreset({
    workspaceRoot: "/workspace/project",
    profile: "workspace-confidential",
    homeDirectory: "/home/user",
  });
  const granted = normalizeCapabilitySet({ ...preset, resources: ["browser"] });
  const resolved = resolvePolicy({
    caps: [granted],
    baseGrants: [granted],
    entrypoint: {
      class: "interactive",
      approvalChannel: "desktop",
      projectId: "project-1",
      executorId: "local",
    },
    workspaceProfile: "workspace-confidential",
    approvalMode: "on-request",
  });
  return compiledVariant === "base"
    ? resolved
    : { ...resolved, compiledPolicyHash: "c".repeat(64) };
}

function fixture(now = 1_000) {
  const events: any[] = [];
  const terminate = vi.fn(async () => undefined);
  let current = now;
  const guard = new RuntimeResourceGuard({
    ids: { nextId: () => "lease-1" },
    clock: { now: () => current },
    audit: { record: async (event) => void events.push(event) },
    runtime: { terminate },
  });
  return { guard, events, terminate, setNow: (value: number) => void (current = value) };
}

const beginInput = {
  runtimeCallId: "browser-create-1",
  resourceId: "browser-1",
  resourceType: "browser" as const,
  ownerId: "user-1",
  projectId: "project-1",
  authorization: authorization(),
  backendCapabilityHash: "b".repeat(64),
  ttlMs: 60_000,
};

describe("RuntimeResourceGuard", () => {
  it("creates, activates, and revalidates a lease against current authority", async () => {
    const { guard, events, terminate } = fixture();
    const starting = await guard.begin(beginInput);
    const active = await guard.activate("browser-active-1", starting.leaseId);

    await expect(
      guard.authorizeReuse({
        runtimeCallId: "browser-use-1",
        leaseId: active.leaseId,
        ownerId: "user-1",
        projectId: "project-1",
        authorization: authorization(),
        backendCapabilityHash: "b".repeat(64),
      }),
    ).resolves.toEqual({ kind: "allow", lease: active });
    expect(events.map((event) => event.detail.state)).toEqual(["starting", "active"]);
    expect(terminate).not.toHaveBeenCalled();
  });

  it("does not let a mismatched owner or project use or revoke another lease", async () => {
    const { guard, terminate } = fixture();
    const lease = await guard.activate("active", (await guard.begin(beginInput)).leaseId);

    await expect(
      guard.authorizeReuse({
        runtimeCallId: "use",
        leaseId: lease.leaseId,
        ownerId: "other-user",
        projectId: "project-1",
        authorization: authorization(),
        backendCapabilityHash: "b".repeat(64),
      }),
    ).resolves.toEqual({ kind: "deny", reason: "owner-mismatch" });
    expect(terminate).not.toHaveBeenCalled();
    expect(guard.snapshot(lease.leaseId)?.state).toBe("active");
  });

  it("revokes before denying reuse after expiry or policy/backend changes", async () => {
    const { guard, events, terminate, setNow } = fixture();
    const lease = await guard.activate("active", (await guard.begin(beginInput)).leaseId);
    setNow(61_000);

    await expect(
      guard.authorizeReuse({
        runtimeCallId: "expired-use",
        leaseId: lease.leaseId,
        ownerId: "user-1",
        projectId: "project-1",
        authorization: authorization("changed"),
        backendCapabilityHash: "d".repeat(64),
      }),
    ).resolves.toEqual({ kind: "deny", reason: "lease-expired" });
    expect(terminate).toHaveBeenCalledWith("browser-1", "lease-expired");
    expect(guard.snapshot(lease.leaseId)?.state).toBe("terminated");
    expect(events.map((event) => event.detail.state)).toEqual([
      "starting",
      "active",
      "revoking",
      "terminated",
    ]);
  });

  it("fails closed when the resource type is absent from the base grant", async () => {
    const { guard } = fixture();
    const deniedAuthorization = resolvePolicy({
      caps: [
        createWorkspacePreset({
          workspaceRoot: "/workspace/project",
          profile: "workspace-confidential",
        }),
      ],
      baseGrants: [
        createWorkspacePreset({
          workspaceRoot: "/workspace/project",
          profile: "workspace-confidential",
        }),
      ],
      entrypoint: {
        class: "interactive",
        approvalChannel: "desktop",
        projectId: "project-1",
        executorId: "local",
      },
      workspaceProfile: "workspace-confidential",
      approvalMode: "never",
    });

    await expect(
      guard.begin({ ...beginInput, authorization: deniedAuthorization }),
    ).rejects.toThrow("resource capability is not granted");
  });

  it("terminates a resource even when revocation audit persistence fails", async () => {
    const terminate = vi.fn(async () => undefined);
    let records = 0;
    const guard = new RuntimeResourceGuard({
      ids: { nextId: () => "lease-1" },
      clock: { now: () => 1_000 },
      audit: {
        record: async () => {
          records += 1;
          if (records >= 3) throw new Error("audit unavailable");
        },
      },
      runtime: { terminate },
    });
    const lease = await guard.activate("active", (await guard.begin(beginInput)).leaseId);

    await expect(guard.revoke("revoke", lease.leaseId, "policy-changed")).rejects.toThrow(
      "audit unavailable",
    );
    expect(terminate).toHaveBeenCalledWith("browser-1", "policy-changed");
    expect(guard.snapshot(lease.leaseId)?.state).toBe("terminated");
  });
});
