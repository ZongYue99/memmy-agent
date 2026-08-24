import type { ChildProcess } from "node:child_process";
import { spawn } from "node:child_process";
import type { DenialObservation } from "../../domain/denial-evidence.js";
import type { SpawnProcess } from "./sandbox-backend.js";

const LOG_EXECUTABLE = "/usr/bin/log";
const MAX_LINE_CHARS = 16_384;
const MAX_OBSERVATIONS = 256;
const READY_TIMEOUT_MS = 1_000;
const DELIVERY_GRACE_MS = 150;
const DENIAL_DELIVERY_TIMEOUT_MS = 1_500;
const STOP_TIMEOUT_MS = 500;

export interface SeatbeltDenialCapture {
  bindProcess(processId: number): void;
  finish(
    options?: Readonly<{ waitForObservation?: boolean }>,
  ): Promise<readonly DenialObservation[]>;
}

export interface SeatbeltDenialMonitor {
  start(maxRuntimeMs: number): Promise<SeatbeltDenialCapture | null>;
}

type UnifiedLogEvent = Readonly<{
  senderImagePath?: unknown;
  timestamp?: unknown;
  eventMessage?: unknown;
}>;

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function stopProcess(process: ChildProcess, signal: NodeJS.Signals): void {
  try {
    process.kill(signal);
  } catch {
    // The monitor is best-effort evidence collection and may already have exited.
  }
}

export function parseSeatbeltDenialEvent(line: string): DenialObservation | null {
  let event: UnifiedLogEvent;
  try {
    event = JSON.parse(line) as UnifiedLogEvent;
  } catch {
    return null;
  }
  if (
    typeof event.senderImagePath !== "string" ||
    !event.senderImagePath.includes("/Sandbox.kext/") ||
    typeof event.eventMessage !== "string"
  ) {
    return null;
  }
  const match = /^Sandbox: (.+?)\((\d+)\) deny\(\d+\) ([^\s]+)(?:\s+(.*))?$/.exec(
    event.eventMessage,
  );
  if (!match) return null;
  const processId = Number(match[2]);
  if (!Number.isSafeInteger(processId) || processId <= 0) return null;
  const parsedTimestamp = typeof event.timestamp === "string" ? Date.parse(event.timestamp) : NaN;
  return Object.freeze({
    provenance: "macos-kernel-sandbox-log",
    processId,
    processName: match[1],
    operation: match[3],
    target: match[4] ?? "",
    observedAt: Number.isFinite(parsedTimestamp) ? parsedTimestamp : Date.now(),
  });
}

export class MacosSeatbeltDenialMonitor implements SeatbeltDenialMonitor {
  constructor(private readonly spawnProcess: SpawnProcess = spawn) {}

  async start(maxRuntimeMs: number): Promise<SeatbeltDenialCapture | null> {
    if (!Number.isSafeInteger(maxRuntimeMs) || maxRuntimeMs < 0) return null;
    const monitorTimeoutSeconds = Math.max(1, Math.ceil(maxRuntimeMs / 1_000) + 2);
    let process: ChildProcess;
    try {
      process = this.spawnProcess(
        LOG_EXECUTABLE,
        [
          "stream",
          "--style",
          "ndjson",
          "--level",
          "debug",
          "--timeout",
          String(monitorTimeoutSeconds),
          "--predicate",
          'senderImagePath CONTAINS "Sandbox.kext" AND eventMessage CONTAINS "deny("',
        ],
        {
          env: { PATH: "/usr/bin:/bin", LANG: "C" },
          shell: false,
          stdio: ["ignore", "pipe", "ignore"],
        },
      );
    } catch {
      return null;
    }

    let targetProcessId: number | null = null;
    let pending = "";
    let observations: DenialObservation[] = [];
    let sawOutput = false;
    let exited = false;
    let resolveReady!: () => void;
    const ready = new Promise<void>((resolve) => {
      resolveReady = resolve;
    });
    let resolveClosed!: () => void;
    const closed = new Promise<void>((resolve) => {
      resolveClosed = resolve;
    });
    let resolveTargetObservation!: () => void;
    const targetObservation = new Promise<void>((resolve) => {
      resolveTargetObservation = resolve;
    });
    const onData = (chunk: Buffer) => {
      if (!sawOutput) {
        sawOutput = true;
        resolveReady();
      }
      pending += chunk.toString("utf8");
      if (pending.length > MAX_LINE_CHARS * 2) pending = pending.slice(-MAX_LINE_CHARS);
      const lines = pending.split("\n");
      pending = lines.pop() ?? "";
      for (const line of lines) {
        if (line.length > MAX_LINE_CHARS) continue;
        const observation = parseSeatbeltDenialEvent(line);
        if (
          !observation ||
          (targetProcessId !== null && observation.processId !== targetProcessId)
        ) {
          continue;
        }
        if (observations.length < MAX_OBSERVATIONS) observations.push(observation);
        if (targetProcessId !== null) resolveTargetObservation();
      }
    };
    process.stdout?.on("data", onData);
    const onExit = () => {
      if (exited) return;
      exited = true;
      resolveReady();
      resolveClosed();
    };
    process.once("error", onExit);
    process.once("close", onExit);
    await Promise.race([ready, delay(READY_TIMEOUT_MS)]);
    if (exited || !sawOutput) {
      if (!exited) stopProcess(process, "SIGTERM");
      await Promise.race([closed, delay(STOP_TIMEOUT_MS)]);
      if (!exited) {
        stopProcess(process, "SIGKILL");
        await Promise.race([closed, delay(STOP_TIMEOUT_MS)]);
      }
      return null;
    }

    let finishPromise: Promise<readonly DenialObservation[]> | undefined;
    return {
      bindProcess(processId) {
        if (!Number.isSafeInteger(processId) || processId <= 0 || targetProcessId !== null) return;
        targetProcessId = processId;
        observations = observations.filter((observation) => observation.processId === processId);
        if (observations.length) resolveTargetObservation();
      },
      finish(options) {
        if (finishPromise) return finishPromise;
        finishPromise = (async () => {
          if (options?.waitForObservation && !observations.length) {
            await Promise.race([targetObservation, delay(DENIAL_DELIVERY_TIMEOUT_MS)]);
          } else {
            await delay(DELIVERY_GRACE_MS);
          }
          if (!exited) stopProcess(process, "SIGTERM");
          await Promise.race([closed, delay(STOP_TIMEOUT_MS)]);
          if (!exited) {
            stopProcess(process, "SIGKILL");
            await Promise.race([closed, delay(STOP_TIMEOUT_MS)]);
          }
          process.stdout?.removeListener("data", onData);
          return Object.freeze(targetProcessId === null ? [] : [...observations]);
        })();
        return finishPromise;
      },
    };
  }
}
