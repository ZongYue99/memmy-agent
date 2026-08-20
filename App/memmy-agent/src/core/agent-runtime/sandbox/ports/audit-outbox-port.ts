import type { SandboxAuditEvent } from "../domain/audit-event.js";

/** Durably appends audit events; delivery workers may use auditId for downstream deduplication. */
export interface AuditOutboxPort {
  append(event: SandboxAuditEvent): Promise<void>;
}
