import { PreflightApprovalBroker } from "../approval/preflight-approval-broker.js";
import type {
  ToolCallGuardDecision,
  ToolCallGuardPort,
  ToolCallGuardRequest,
} from "../ports/tool-call-guard-port.js";

/** Adds trusted pre-execution approval to a pure policy guard. */
export class ApprovingToolCallGuard implements ToolCallGuardPort {
  constructor(
    private readonly guard: ToolCallGuardPort,
    private readonly broker: PreflightApprovalBroker,
    private readonly subjectId: string,
  ) {}

  async authorize(request: ToolCallGuardRequest): Promise<ToolCallGuardDecision> {
    const decision = await this.guard.authorize(request);
    if (decision.type !== "ask") return decision;
    const outcome = await this.broker.requestApproval({
      request,
      decision,
      subjectId: this.subjectId,
      resolveCurrentDecision: () => this.guard.authorize(request),
      ...(request.abortSignal ? { abortSignal: request.abortSignal } : {}),
    });
    if (outcome.kind === "approved") {
      return { type: "allow", authorization: outcome.authorization };
    }
    return { type: "deny", reason: `approval-${outcome.kind}` };
  }
}
