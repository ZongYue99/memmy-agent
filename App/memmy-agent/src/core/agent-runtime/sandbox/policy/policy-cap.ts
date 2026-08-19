import path from "node:path";
import type {
  CapabilitySet,
  ExternalEffectLevel,
  NetworkCapability,
  NetworkTarget,
  ProcessCapability,
  ResolvedAccess,
  ResourceKind,
} from "../domain/capability.js";

const SPAWN_RANK: Record<ProcessCapability["spawn"], number> = {
  denied: 0,
  "non-interactive": 1,
  interactive: 2,
};

const EFFECT_RANK: Record<ExternalEffectLevel, number> = {
  none: 0,
  reversible: 1,
  irreversible: 2,
};

function canonicalPath(value: string): string {
  return path.resolve(value);
}

function pathIsInside(target: string, root: string): boolean {
  const relative = path.relative(canonicalPath(root), canonicalPath(target));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function intersectRoots(left: readonly string[], right: readonly string[]): string[] {
  const intersection: string[] = [];
  for (const leftRoot of left) {
    for (const rightRoot of right) {
      if (pathIsInside(leftRoot, rightRoot)) intersection.push(canonicalPath(leftRoot));
      else if (pathIsInside(rightRoot, leftRoot)) intersection.push(canonicalPath(rightRoot));
    }
  }
  return uniqueSorted(intersection);
}

function normalizeHost(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, "");
}

function targetKey(target: NetworkTarget): string {
  return normalizeHost(target.host);
}

function intersectNetworkTarget(left: NetworkTarget, right: NetworkTarget): NetworkTarget | null {
  if (targetKey(left) !== targetKey(right)) return null;
  const rightProtocols = new Set(right.protocols);
  const rightPorts = new Set(right.ports);
  const protocols = left.protocols.filter((protocol) => rightProtocols.has(protocol)).sort();
  const ports = left.ports.filter((port) => rightPorts.has(port)).sort((a, b) => a - b);
  if (!protocols.length || !ports.length) return null;
  return { host: targetKey(left), protocols, ports };
}

function intersectNetwork(left: NetworkCapability, right: NetworkCapability): NetworkCapability {
  if (left.mode === "denied" || right.mode === "denied") return { mode: "denied" };
  if (left.mode === "unrestricted") return right;
  if (right.mode === "unrestricted") return left;
  const targets = left.targets.flatMap((leftTarget) =>
    right.targets.flatMap((rightTarget) => {
      const intersection = intersectNetworkTarget(leftTarget, rightTarget);
      return intersection ? [intersection] : [];
    }),
  );
  return { mode: "allowlist", targets };
}

function intersectNamedValues(left: readonly string[], right: readonly string[]): string[] {
  const allowed = new Set(right);
  return uniqueSorted(left.filter((value) => allowed.has(value)));
}

function lowerSpawn(
  left: ProcessCapability["spawn"],
  right: ProcessCapability["spawn"],
): ProcessCapability["spawn"] {
  return SPAWN_RANK[left] <= SPAWN_RANK[right] ? left : right;
}

function lowerEffect(left: ExternalEffectLevel, right: ExternalEffectLevel): ExternalEffectLevel {
  return EFFECT_RANK[left] <= EFFECT_RANK[right] ? left : right;
}

export function normalizeCapabilitySet(capability: CapabilitySet): CapabilitySet {
  const network =
    capability.network.mode === "allowlist"
      ? {
          mode: "allowlist" as const,
          targets: [
            ...new Map(
              capability.network.targets.map((target) => {
                const normalized = {
                  host: normalizeHost(target.host),
                  protocols: [...new Set(target.protocols)].sort(),
                  ports: [...new Set(target.ports)].sort((a, b) => a - b),
                };
                const key = `${normalized.host}|${normalized.protocols.join(",")}|${normalized.ports.join(",")}`;
                return [key, normalized] as const;
              }),
            ).values(),
          ].sort((left, right) => {
            const byHost = left.host.localeCompare(right.host);
            if (byHost !== 0) return byHost;
            const byProtocol = left.protocols.join(",").localeCompare(right.protocols.join(","));
            if (byProtocol !== 0) return byProtocol;
            return left.ports.join(",").localeCompare(right.ports.join(","));
          }),
        }
      : capability.network;
  return {
    filesystem: {
      read: uniqueSorted(capability.filesystem.read.map(canonicalPath)),
      write: uniqueSorted(capability.filesystem.write.map(canonicalPath)),
      deny: uniqueSorted(capability.filesystem.deny.map(canonicalPath)),
    },
    network,
    process: { ...capability.process },
    environment: {
      inherit: uniqueSorted(capability.environment.inherit),
      set: Object.fromEntries(
        Object.entries(capability.environment.set).sort(([a], [b]) => a.localeCompare(b)),
      ),
      remove: uniqueSorted(capability.environment.remove),
    },
    resources: [...new Set(capability.resources)].sort(),
    externalEffects: { ...capability.externalEffects },
  };
}

export function intersectCapabilitySets(left: CapabilitySet, right: CapabilitySet): CapabilitySet {
  const leftSetKeys = new Set(Object.keys(left.environment.set));
  const rightSet = Object.entries(right.environment.set);
  return normalizeCapabilitySet({
    filesystem: {
      read: intersectRoots(left.filesystem.read, right.filesystem.read),
      write: intersectRoots(left.filesystem.write, right.filesystem.write),
      deny: uniqueSorted([...left.filesystem.deny, ...right.filesystem.deny].map(canonicalPath)),
    },
    network: intersectNetwork(left.network, right.network),
    process: {
      spawn: lowerSpawn(left.process.spawn, right.process.spawn),
      maxProcesses: Math.min(left.process.maxProcesses, right.process.maxProcesses),
      maxRuntimeMs: Math.min(left.process.maxRuntimeMs, right.process.maxRuntimeMs),
      maxOutputBytes: Math.min(left.process.maxOutputBytes, right.process.maxOutputBytes),
    },
    environment: {
      inherit: intersectNamedValues(left.environment.inherit, right.environment.inherit),
      set: Object.fromEntries(
        rightSet.filter(
          ([key, value]) => leftSetKeys.has(key) && left.environment.set[key] === value,
        ),
      ),
      remove: uniqueSorted([...left.environment.remove, ...right.environment.remove]),
    },
    resources: intersectNamedValues(left.resources, right.resources) as ResourceKind[],
    externalEffects: {
      maximum: lowerEffect(left.externalEffects.maximum, right.externalEffects.maximum),
    },
  });
}

function pathAllowed(
  capability: CapabilitySet["filesystem"],
  access: "read" | "write",
  target: string,
): boolean {
  if (capability.deny.some((root) => pathIsInside(target, root))) return false;
  const roots = access === "write" ? capability.write : capability.read;
  return roots.some((root) => pathIsInside(target, root));
}

function networkAllowed(
  capability: NetworkCapability,
  access: Extract<ResolvedAccess, { kind: "network" }>,
): boolean {
  if (capability.mode === "unrestricted") return true;
  if (capability.mode === "denied") return false;
  return capability.targets.some(
    (target) =>
      normalizeHost(target.host) === normalizeHost(access.host) &&
      target.protocols.includes(access.protocol) &&
      target.ports.includes(access.port),
  );
}

export function capabilitySetAllows(capability: CapabilitySet, access: ResolvedAccess): boolean {
  switch (access.kind) {
    case "filesystem":
      return pathAllowed(capability.filesystem, access.access, access.path);
    case "network":
      return networkAllowed(capability.network, access);
    case "process":
      return access.interactive
        ? capability.process.spawn === "interactive"
        : capability.process.spawn !== "denied";
    case "environment":
      return access.operation === "inherit"
        ? capability.environment.inherit.includes(access.name)
        : Object.hasOwn(capability.environment.set, access.name);
    case "resource":
      return capability.resources.includes(access.resource);
    case "external-effect":
      return EFFECT_RANK[access.level] <= EFFECT_RANK[capability.externalEffects.maximum];
    case "unknown":
      return false;
  }
}
