import { createHash } from "node:crypto";
import type { PermissionProfile, UnhashedPermissionProfile } from "../domain/permission-profile.js";

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => [key, stableValue(nested)]),
  );
}

export function stablePolicyHash(value: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(stableValue(value)))
    .digest("hex");
}

export function attachPolicyHash(profile: UnhashedPermissionProfile): PermissionProfile {
  return Object.freeze({
    ...profile,
    policyHash: stablePolicyHash(profile),
  }) as PermissionProfile;
}

export function verifyPolicyHash(profile: PermissionProfile): boolean {
  const { policyHash, ...unhashed } = profile;
  return policyHash === stablePolicyHash(unhashed);
}
