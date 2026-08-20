import type { ResolvedAccess } from "./capability.js";

export type DenialSource = "os-sandbox" | "network-egress" | "executor";

export type DenialEvidence = Readonly<{
  source: DenialSource;
  operation: string;
  requiredCapability?: ResolvedAccess;
  systemCode?: string;
  summary: string;
  minimallySupplementable: boolean;
  evidenceRef?: string;
}>;
