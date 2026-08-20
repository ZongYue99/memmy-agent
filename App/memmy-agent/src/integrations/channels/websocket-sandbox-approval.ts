import type {
  ApprovalPrompt,
  ApprovalPromptResult,
} from "../../core/agent-runtime/sandbox/index.js";

type PendingApproval = {
  targets: Set<object>;
  resolve: (result: ApprovalPromptResult) => void;
  timer: NodeJS.Timeout;
  abortSignal?: AbortSignal;
  onAbort?: () => void;
};

export type SandboxApprovalDecisionResult =
  | "accepted"
  | "not-pending"
  | "not-authorized"
  | "invalid-decision";

/** Owns single-use WebSocket approval prompts without exposing broker challenge material. */
export class WebSocketSandboxApprovalCoordinator {
  private readonly pending = new Map<string, PendingApproval>();

  constructor(private readonly now: () => number = Date.now) {}

  request(
    input: Readonly<{
      chatId: string;
      prompt: ApprovalPrompt;
      connections: readonly object[];
      send: (connection: object, payload: Record<string, unknown>) => Promise<void>;
      abortSignal?: AbortSignal;
    }>,
  ): Promise<ApprovalPromptResult> {
    if (
      input.abortSignal?.aborted ||
      input.prompt.expiresAt <= this.now() ||
      !input.connections.length ||
      this.pending.has(input.prompt.requestId)
    ) {
      return Promise.resolve("cancelled");
    }
    return new Promise((resolve) => {
      const finish = (result: ApprovalPromptResult) => {
        const pending = this.pending.get(input.prompt.requestId);
        if (!pending) return;
        this.pending.delete(input.prompt.requestId);
        clearTimeout(pending.timer);
        if (pending.abortSignal && pending.onAbort) {
          pending.abortSignal.removeEventListener("abort", pending.onAbort);
        }
        resolve(result);
      };
      const delay = Math.max(1, input.prompt.expiresAt - this.now());
      const timer = setTimeout(() => finish("cancelled"), delay);
      timer.unref?.();
      const pending: PendingApproval = {
        targets: new Set(input.connections),
        resolve,
        timer,
        ...(input.abortSignal ? { abortSignal: input.abortSignal } : {}),
      };
      if (input.abortSignal) {
        pending.onAbort = () => finish("cancelled");
        input.abortSignal.addEventListener("abort", pending.onAbort, { once: true });
      }
      this.pending.set(input.prompt.requestId, pending);
      const payload = {
        event: "sandbox_approval_request",
        chat_id: input.chatId,
        request_id: input.prompt.requestId,
        additional_permission: input.prompt.additionalPermission,
        expires_at: input.prompt.expiresAt,
      };
      void Promise.all(input.connections.map((connection) => input.send(connection, payload)));
    });
  }

  decide(connection: object, requestId: string, decision: unknown): SandboxApprovalDecisionResult {
    const pending = this.pending.get(requestId);
    if (!pending) return "not-pending";
    if (!pending.targets.has(connection)) return "not-authorized";
    if (decision !== "approved" && decision !== "denied") return "invalid-decision";
    this.finish(requestId, decision);
    return "accepted";
  }

  disconnect(connection: object): void {
    for (const [requestId, pending] of this.pending) {
      pending.targets.delete(connection);
      if (!pending.targets.size) this.finish(requestId, "cancelled");
    }
  }

  close(): void {
    for (const requestId of [...this.pending.keys()]) this.finish(requestId, "cancelled");
  }

  private finish(requestId: string, result: ApprovalPromptResult): void {
    const pending = this.pending.get(requestId);
    if (!pending) return;
    this.pending.delete(requestId);
    clearTimeout(pending.timer);
    if (pending.abortSignal && pending.onAbort) {
      pending.abortSignal.removeEventListener("abort", pending.onAbort);
    }
    pending.resolve(result);
  }
}
