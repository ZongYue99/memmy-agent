import type { SandboxExecutorPort } from "../../ports/sandbox-executor-port.js";
import { BackendRegistry } from "./backend-registry.js";

export class LocalSandboxExecutor implements SandboxExecutorPort {
  constructor(private readonly backends: BackendRegistry) {}

  selectTarget(input: Parameters<SandboxExecutorPort["selectTarget"]>[0]) {
    return this.backends.selectTarget(input);
  }

  start(input: Parameters<SandboxExecutorPort["start"]>[0]) {
    return this.backends.start(input.attempt.sandboxType, input);
  }
}
