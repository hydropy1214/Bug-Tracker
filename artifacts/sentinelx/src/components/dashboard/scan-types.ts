export interface Finding {
  id: number;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvss: number;
  cve: string | null;
  description: string;
  evidence: string;
  remediation: string;
  status: string;
  verification?: "verified" | "version_match" | "suspected" | "informational";
  confidence?: number;
  evidenceQuality?: "weak" | "standard" | "strong";
  verificationMethod?: string | null;
  reproducibility?: "reproducible" | "intermittent" | "not_reproducible" | "not_tested";
  affectedEndpoint?: string | null;
  affectedParameter?: string | null;
  negativeTests?: string | null;
  limitations?: string | null;
  toolInfo?: string | null;
}

export interface Scan {
  id: number;
  status: "pending" | "running" | "completed" | "failed" | "canceled";
  progress: number;
  logs: string | null;
  findingsCount: number;
  wafBlocked: boolean;
  startedAt: string | null;
  completedAt: string | null;
  type: string;
  profile?: string;
}

export interface ScanStatus {
  scan: Scan;
  findings: Finding[];
}

export interface PersistedScan {
  scanId: number;
  target: string;
}

export const SEV: Record<string, { label: string; color: string; bg: string; border: string; dot: string }> = {
  critical: { label: "CRITICAL", color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", dot: "bg-red-400" },
  high: { label: "HIGH", color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", dot: "bg-orange-400" },
  medium: { label: "MEDIUM", color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", dot: "bg-yellow-400" },
  low: { label: "LOW", color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30", dot: "bg-blue-400" },
  info: { label: "INFO", color: "text-muted-foreground", bg: "bg-accent", border: "border-border", dot: "bg-muted-foreground" },
};

export const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

export function sevCount(findings: Finding[], severity: string): number {
  return findings.filter((finding) => finding.severity === severity).length;
}

export function verificationLabel(value?: Finding["verification"]): string {
  return value === "suspected"
    ? "SUSPECTED"
    : value === "version_match"
      ? "VERSION MATCH"
      : value === "informational"
        ? "INFORMATIONAL"
        : "VERIFIED";
}