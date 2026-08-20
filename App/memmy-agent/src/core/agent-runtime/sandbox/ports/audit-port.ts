import type { SandboxAuditEventDraft } from "../domain/audit-event.js";

/** Records a bounded audit draft without accepting arbitrary or sensitive payload fields. */
export interface AuditPort {
  record(draft: SandboxAuditEventDraft): Promise<void>;
}
