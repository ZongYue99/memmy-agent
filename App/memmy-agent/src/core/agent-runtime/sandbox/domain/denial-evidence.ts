import type { ResolvedAccess } from "./capability.js";

export type DenialSource = "os-sandbox" | "network-egress" | "executor";

export type DenialObservation = Readonly<{
  provenance: "macos-kernel-sandbox-log";
  processId: number;
  processName: string;
  operation: string;
  target: string;
  observedAt: number;
}>;

export type DenialEvidence = Readonly<{
  source: DenialSource;
  operation: string;
  requiredCapability?: ResolvedAccess;
  systemCode?: string;
  summary: string;
  minimallySupplementable: boolean;
  evidenceRef?: string;
}>;
