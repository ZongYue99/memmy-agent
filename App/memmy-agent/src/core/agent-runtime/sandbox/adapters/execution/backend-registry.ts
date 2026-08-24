import type {
  SandboxExecutionHandle,
  SandboxExecutionTarget,
  SandboxExecutorPort,
} from "../../ports/sandbox-executor-port.js";
import type {
  LocalSandboxType,
  SandboxBackend,
  SandboxBackendSelectionInput,
} from "./sandbox-backend.js";

export class BackendRegistryError extends Error {
  constructor(
    readonly code: "duplicate-backend" | "no-compatible-backend" | "backend-not-registered",
  ) {
    super(code);
    this.name = "BackendRegistryError";
  }
}

export class BackendRegistry implements SandboxExecutorPort {
  private readonly backends: ReadonlyMap<LocalSandboxType, SandboxBackend>;

  constructor(backends: readonly SandboxBackend[]) {
    const indexed = new Map<LocalSandboxType, SandboxBackend>();
    for (const backend of backends) {
      if (indexed.has(backend.sandboxType)) {
        throw new BackendRegistryError("duplicate-backend");
      }
      indexed.set(backend.sandboxType, backend);
    }
    this.backends = indexed;
  }

  selectTarget(input: SandboxBackendSelectionInput): SandboxExecutionTarget {
    for (const backend of this.backends.values()) {
      const support = backend.inspectSupport(input);
      if (support.supported) return support.target;
    }
    throw new BackendRegistryError("no-compatible-backend");
  }

  start(input: Parameters<SandboxExecutorPort["start"]>[0]): Promise<SandboxExecutionHandle> {
    const sandboxType = input.attempt.sandboxType;
    if (sandboxType === "external" || sandboxType === "disabled") {
      throw new BackendRegistryError("backend-not-registered");
    }
    const backend = this.backends.get(sandboxType);
    if (!backend) throw new BackendRegistryError("backend-not-registered");
    return backend.start(input);
  }
}
