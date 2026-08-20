import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import type { SandboxAuditEvent } from "../../domain/audit-event.js";
import type { AuditOutboxPort } from "../../ports/audit-outbox-port.js";

const MAX_EVENT_BYTES = 16 * 1_024;
const DEFAULT_MAX_OUTBOX_BYTES = 16 * 1_024 * 1_024;

/** Append-only, fsync-backed local outbox with bounded event and file sizes. */
export class JsonlAuditOutbox implements AuditOutboxPort {
  private pending: Promise<void> = Promise.resolve();
  private readonly filePath: string;

  constructor(
    filePath: string,
    private readonly maxOutboxBytes = DEFAULT_MAX_OUTBOX_BYTES,
  ) {
    if (!path.isAbsolute(filePath)) throw new Error("audit outbox path must be absolute");
    if (!Number.isSafeInteger(maxOutboxBytes) || maxOutboxBytes <= 0) {
      throw new Error("maxOutboxBytes must be a positive integer");
    }
    this.filePath = path.resolve(filePath);
  }

  append(event: SandboxAuditEvent): Promise<void> {
    const operation = this.pending.then(() => this.appendOne(event));
    this.pending = operation.catch(() => {});
    return operation;
  }

  private async appendOne(event: SandboxAuditEvent): Promise<void> {
    const line = `${JSON.stringify(event)}\n`;
    const eventBytes = Buffer.byteLength(line);
    if (eventBytes > MAX_EVENT_BYTES) throw new Error("audit event exceeds size limit");
    const parent = await realpath(path.dirname(this.filePath));
    const target = path.join(parent, path.basename(this.filePath));
    try {
      const existing = await lstat(target);
      if (!existing.isFile() || existing.isSymbolicLink()) {
        throw new Error("audit outbox must be a regular file");
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const flags =
      constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY | constants.O_NOFOLLOW;
    const handle = await open(target, flags, 0o600);
    try {
      const status = await handle.stat();
      if (!status.isFile()) throw new Error("audit outbox must be a regular file");
      if (process.platform !== "win32" && (status.mode & 0o077) !== 0) {
        throw new Error("audit outbox permissions are too broad");
      }
      if (status.size + eventBytes > this.maxOutboxBytes) {
        throw new Error("audit outbox exceeds size limit");
      }
      await handle.appendFile(line, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
  }
}
