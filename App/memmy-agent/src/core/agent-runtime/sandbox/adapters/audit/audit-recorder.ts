import type { SandboxAuditEventDraft } from "../../domain/audit-event.js";
import type { AuditOutboxPort } from "../../ports/audit-outbox-port.js";
import type { AuditPort } from "../../ports/audit-port.js";
import type { ClockPort } from "../../ports/clock-port.js";
import type { IdGeneratorPort } from "../../ports/id-generator-port.js";
import { containsControlCharacter, redactAuditDraft } from "./audit-redaction.js";

function requireIdentifier(value: string): void {
  if (!value || value.length > 256 || value !== value.trim() || containsControlCharacter(value)) {
    throw new Error("invalid audit id");
  }
}

/** Validates, snapshots, envelopes, and durably appends sandbox audit events. */
export class AuditRecorder implements AuditPort {
  constructor(
    private readonly outbox: AuditOutboxPort,
    private readonly ids: IdGeneratorPort,
    private readonly clock: ClockPort,
  ) {}

  async record(draft: SandboxAuditEventDraft): Promise<void> {
    const sanitized = redactAuditDraft(draft);
    const auditId = this.ids.nextId("audit");
    requireIdentifier(auditId);
    const recordedAt = this.clock.now();
    if (!Number.isSafeInteger(recordedAt) || recordedAt < 0) {
      throw new Error("recordedAt must be a non-negative Unix millisecond timestamp");
    }
    await this.outbox.append({ version: 1, auditId, recordedAt, ...sanitized });
  }
}
