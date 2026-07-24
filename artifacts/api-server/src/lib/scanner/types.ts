/**
 * Shared scanner contracts.
 *
 * The legacy scanner remains the compatibility implementation while phase
 * modules are migrated behind these stable types.
 */

export interface RealFinding {
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  verification?: "verified" | "version_match" | "suspected" | "informational";
  confidence?: number;
  evidenceQuality?: "weak" | "standard" | "strong";
  verificationMethod?: string;
  reproducibility?: "reproducible" | "intermittent" | "not_reproducible" | "not_tested";
  affectedEndpoint?: string;
  affectedParameter?: string;
  negativeTests?: string;
  limitations?: string;
  toolInfo?: string;
  description: string;
  cvss: number;
  cve: string | null;
  evidence: string;
  remediation: string;
  compliance?: { owasp?: string[]; pci?: string[]; nist?: string[] };
}

export interface ScanResult {
  findings: RealFinding[];
  wafBlocked: boolean;
}

export interface Target {
  url: string;
  hostname: string;
  port: number;
  isHttps: boolean;
  assetType: string;
}

export type ScanType = "recon" | "enumeration" | "vulnerability" | "full";
export type LogFn = (message: string) => Promise<void> | void;
export type ScanProfile = "passive" | "safe_active" | "deep_authorized" | "authenticated" | "lab";

export interface ScanPolicy {
  profile: ScanProfile;
  requestBudget: number;
  timeoutMs: number;
  maxConcurrency: number;
  allowDeepChecks: boolean;
  allowExternalCallbacks: boolean;
  allowToolAdapters: boolean;
}

export interface ScanContext {
  remaining: number;
  exhaustedNotified: boolean;
  authHeaders?: Record<string, string>;
  wafChallengeDetected: boolean;
  wafChallengeLogEmitted: boolean;
  activeProbeDepth: number;
  onWafChallenge?: () => void | Promise<void>;
  capturedSession?: string;
}

export interface PhaseContext {
  target: Target;
  policy: ScanPolicy;
  log: LogFn;
  addFindings: (findings: RealFinding[]) => void;
}