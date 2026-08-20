import type { ResourceKind } from "../domain/capability.js";
import type { ResourceLease } from "../domain/resource-lease.js";
import { transitionResourceLease } from "../domain/resource-lease.js";
import { immutableSnapshot } from "../domain/immutable.js";
import type { EffectiveAuthorization } from "../policy/policy-resolver.js";
import { stablePolicyHash } from "../policy/policy-hash.js";
import type { AuditPort } from "../ports/audit-port.js";
import type { ClockPort } from "../ports/clock-port.js";
import type { IdGeneratorPort } from "../ports/id-generator-port.js";
import type { ResourceRuntimePort } from "../ports/resource-runtime-port.js";

export type ResourceReuseDecision =
  | Readonly<{ kind: "allow"; lease: ResourceLease }>
  | Readonly<{
      kind: "deny";
      reason:
        | "lease-not-found"
        | "lease-not-active"
        | "owner-mismatch"
        | "project-mismatch"
        | "lease-expired"
        | "policy-changed"
        | "backend-capability-changed";
    }>;

type RuntimeResourceGuardDependencies = Readonly<{
  ids: IdGeneratorPort;
  clock: ClockPort;
  audit: AuditPort;
  runtime: ResourceRuntimePort;
}>;

function stableIdentifier(value: string, label: string): void {
  if (!value || value !== value.trim() || value.length > 256) {
    throw new Error(`${label} must be a bounded stable identifier`);
  }
}

function sha256Hash(value: string, label: string): void {
  if (!/^[a-f0-9]{64}$/.test(value)) throw new Error(`${label} must be a SHA-256 hash`);
}

/** Enforces owner, project, policy, backend, expiry, and revocation on long-lived resources. */
export class RuntimeResourceGuard {
  private readonly leases = new Map<string, ResourceLease>();

  constructor(private readonly dependencies: RuntimeResourceGuardDependencies) {}

  async begin(
    input: Readonly<{
      runtimeCallId: string;
      resourceId: string;
      resourceType: ResourceKind;
      ownerId: string;
      projectId: string;
      authorization: EffectiveAuthorization;
      backendCapabilityHash: string;
      ttlMs: number;
    }>,
  ): Promise<ResourceLease> {
    for (const [label, value] of [
      ["runtimeCallId", input.runtimeCallId],
      ["resourceId", input.resourceId],
      ["ownerId", input.ownerId],
      ["projectId", input.projectId],
      ["backendCapabilityHash", input.backendCapabilityHash],
    ] as const)
      stableIdentifier(value, label);
    sha256Hash(input.backendCapabilityHash, "backendCapabilityHash");
    if (!input.authorization.baseGrant.resources.includes(input.resourceType)) {
      throw new Error("resource capability is not granted");
    }
    if (!Number.isSafeInteger(input.ttlMs) || input.ttlMs <= 0) {
      throw new Error("ttlMs must be a positive integer");
    }
    const leaseId = this.dependencies.ids.nextId("resource-lease");
    stableIdentifier(leaseId, "leaseId");
    const issuedAt = this.dependencies.clock.now();
    if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) {
      throw new Error("resource lease clock must return a non-negative timestamp");
    }
    const expiresAt = issuedAt + input.ttlMs;
    if (!Number.isSafeInteger(expiresAt)) throw new Error("resource lease expiry is out of range");
    const lease = immutableSnapshot({
      leaseId,
      resourceId: input.resourceId,
      resourceType: input.resourceType,
      ownerId: input.ownerId,
      projectId: input.projectId,
      workspaceProfile: input.authorization.workspaceProfile,
      policyCapHash: stablePolicyHash(input.authorization.policyCap),
      compiledPolicyHash: input.authorization.compiledPolicyHash,
      backendCapabilityHash: input.backendCapabilityHash,
      state: "starting" as const,
      expiresAt,
    });
    await this.record(input.runtimeCallId, lease);
    this.leases.set(leaseId, lease);
    return lease;
  }

  async activate(runtimeCallId: string, leaseId: string): Promise<ResourceLease> {
    const lease = this.requiredLease(leaseId);
    const active = transitionResourceLease(lease, "active");
    try {
      await this.record(runtimeCallId, active);
      this.leases.set(leaseId, active);
      return active;
    } catch (error) {
      await this.dependencies.runtime.terminate(lease.resourceId, "activation-audit-failed");
      this.leases.set(leaseId, transitionResourceLease(lease, "failed"));
      throw error;
    }
  }

  async authorizeReuse(
    input: Readonly<{
      runtimeCallId: string;
      leaseId: string;
      ownerId: string;
      projectId: string;
      authorization: EffectiveAuthorization;
      backendCapabilityHash: string;
    }>,
  ): Promise<ResourceReuseDecision> {
    const lease = this.leases.get(input.leaseId);
    if (!lease) return { kind: "deny", reason: "lease-not-found" };
    if (lease.state !== "active") return { kind: "deny", reason: "lease-not-active" };
    if (lease.ownerId !== input.ownerId) return { kind: "deny", reason: "owner-mismatch" };
    if (lease.projectId !== input.projectId) return { kind: "deny", reason: "project-mismatch" };
    if (this.dependencies.clock.now() >= lease.expiresAt) {
      await this.revoke(input.runtimeCallId, lease.leaseId, "lease-expired").catch(() => undefined);
      return { kind: "deny", reason: "lease-expired" };
    }
    if (
      lease.policyCapHash !== stablePolicyHash(input.authorization.policyCap) ||
      lease.compiledPolicyHash !== input.authorization.compiledPolicyHash
    ) {
      await this.revoke(input.runtimeCallId, lease.leaseId, "policy-changed").catch(
        () => undefined,
      );
      return { kind: "deny", reason: "policy-changed" };
    }
    if (lease.backendCapabilityHash !== input.backendCapabilityHash) {
      await this.revoke(input.runtimeCallId, lease.leaseId, "backend-capability-changed").catch(
        () => undefined,
      );
      return { kind: "deny", reason: "backend-capability-changed" };
    }
    return immutableSnapshot({ kind: "allow", lease });
  }

  async revoke(runtimeCallId: string, leaseId: string, reason: string): Promise<ResourceLease> {
    stableIdentifier(reason, "reason");
    const current = this.requiredLease(leaseId);
    if (current.state === "terminated") return current;
    const revoking = transitionResourceLease(current, "revoking");
    this.leases.set(leaseId, revoking);
    let auditError: unknown = null;
    try {
      await this.record(runtimeCallId, revoking, reason);
    } catch (error) {
      auditError = error;
    }
    let terminal: ResourceLease;
    try {
      await this.dependencies.runtime.terminate(current.resourceId, reason);
      terminal = transitionResourceLease(revoking, "terminated");
    } catch {
      terminal = transitionResourceLease(revoking, "failed");
    }
    this.leases.set(leaseId, terminal);
    try {
      await this.record(runtimeCallId, terminal, reason);
    } catch (error) {
      auditError ??= error;
    }
    if (auditError) throw auditError;
    return terminal;
  }

  snapshot(leaseId: string): ResourceLease | null {
    const lease = this.leases.get(leaseId);
    return lease ? immutableSnapshot(lease) : null;
  }

  private requiredLease(leaseId: string): ResourceLease {
    const lease = this.leases.get(leaseId);
    if (!lease) throw new Error("resource lease not found");
    return lease;
  }

  private record(runtimeCallId: string, lease: ResourceLease, reasonCode?: string): Promise<void> {
    return this.dependencies.audit.record({
      runtimeCallId,
      detail: {
        kind: "resource-lease-state",
        leaseId: lease.leaseId,
        resourceId: lease.resourceId,
        resourceType: lease.resourceType,
        state: lease.state,
        compiledPolicyHash: lease.compiledPolicyHash,
        backendCapabilityHash: lease.backendCapabilityHash,
        expiresAt: lease.expiresAt,
        ...(reasonCode ? { reasonCode } : {}),
      },
    });
  }
}
