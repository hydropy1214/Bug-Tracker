import { useState, useEffect, useRef, useCallback } from "react";
import {
  Shield, Search, Zap, Terminal, AlertTriangle, CheckCircle2,
  ChevronDown, ChevronRight, ExternalLink, RefreshCw, Play,
  Clock, Activity, Lock, Globe, Server, Radar, Bug, KeyRound,
  Fingerprint, Eye, Cpu
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import { FindingCard as DashboardFindingCard, SeveritySummary as DashboardSeveritySummary } from "@/components/dashboard/FindingCard";
import { useScanPolling } from "@/hooks/useScanPolling";

// ─── Types ────────────────────────────────────────────────────────────────────

type Phase = "idle" | "scanning" | "complete" | "error";

interface Scan {
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

interface Finding {
  id: number;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvss: number;
  cve: string | null;
  description: string;
  evidence: string;
  remediation: string;
  status: string;
  verified?: boolean;
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

interface ScanStatus {
  scan: Scan;
  findings: Finding[];
}

interface PersistedScan {
  scanId: number;
  target: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SEV: Record<string, { label: string; color: string; bg: string; border: string; dot: string }> = {
  critical: { label: "CRITICAL", color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",    dot: "bg-red-400" },
  high:     { label: "HIGH",     color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", dot: "bg-orange-400" },
  medium:   { label: "MEDIUM",   color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", dot: "bg-yellow-400" },
  low:      { label: "LOW",      color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30",   dot: "bg-blue-400" },
  info:     { label: "INFO",     color: "text-muted-foreground", bg: "bg-accent",   border: "border-border",       dot: "bg-muted-foreground" },
};

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function sevCount(findings: Finding[], sev: string) {
  return findings.filter(f => f.severity === sev).length;
}

function verificationLabel(value?: Finding["verification"]) {
  return value === "suspected" ? "SUSPECTED" : value === "version_match" ? "VERSION MATCH" : value === "informational" ? "INFORMATIONAL" : "VERIFIED";
}

// ─── Finding Card ─────────────────────────────────────────────────────────────

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const s = SEV[finding.severity] ?? SEV.info!;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn("rounded-md border overflow-hidden transition-all", s.border, s.bg)}
    >
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:brightness-110 transition-all"
      >
        <div className={cn("w-2 h-2 rounded-full flex-shrink-0 mt-1.5", s.dot)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={cn("text-[10px] font-mono font-bold tracking-widest", s.color)}>{s.label}</span>
            <span className={cn(
              "text-[10px] font-mono px-1.5 py-0.5 rounded border",
              finding.verification === "suspected"
                ? "text-yellow-300 border-yellow-500/30 bg-yellow-500/10"
                : finding.verification === "version_match"
                ? "text-cyan-300 border-cyan-500/30 bg-cyan-500/10"
                : finding.verification === "informational"
                ? "text-muted-foreground border-border bg-accent"
                : "text-emerald-300 border-emerald-500/30 bg-emerald-500/10",
            )}>
              {verificationLabel(finding.verification)}
              {finding.confidence != null ? ` · ${finding.confidence}%` : ""}
            </span>
            {finding.verified && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border text-primary border-primary/30 bg-primary/10">
                CANARY VERIFIED
              </span>
            )}
            {finding.cvss > 0 && (
              <span className={cn("text-[10px] font-mono px-1.5 py-0.5 rounded border", s.color, s.border)}>
                CVSS {finding.cvss.toFixed(1)}
              </span>
            )}
            {finding.cve && (
              <a
                href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`}
                target="_blank"
                rel="noopener noreferrer"
                onClick={e => e.stopPropagation()}
                className="text-[10px] font-mono text-primary hover:underline flex items-center gap-0.5"
              >
                {finding.cve} <ExternalLink className="w-2.5 h-2.5" />
              </a>
            )}
          </div>
          <div className="font-medium text-sm text-foreground mt-0.5 leading-snug">{finding.title}</div>
        </div>
        <div className="flex-shrink-0 mt-1">
          {open ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />}
        </div>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 space-y-4 border-t border-white/5">
              <div className="pt-3">
                <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1.5">Description</div>
                <p className="text-sm text-foreground/80 leading-relaxed">{finding.description}</p>
              </div>

              {finding.verification === "suspected" && (
                <div className="rounded border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-[11px] font-mono text-yellow-200">
                  ⚠ This is a signal requiring analyst validation — not a confirmed exploit.
                </div>
              )}

              <div>
                <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                  <Terminal className="w-3 h-3" /> Evidence / Proof
                </div>
                <pre className="text-[11px] font-mono bg-black/40 border border-white/10 rounded p-3 overflow-x-auto text-primary/90 whitespace-pre-wrap leading-relaxed max-h-64 overflow-y-auto">
                  {finding.evidence}
                </pre>
              </div>

              <div>
                <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" /> Remediation
                </div>
                <pre className="text-[11px] font-mono text-foreground/70 whitespace-pre-wrap leading-relaxed">{finding.remediation}</pre>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[10px] font-mono">
                <div className="rounded border border-border/60 bg-black/20 px-2 py-1.5">
                  <span className="text-muted-foreground block uppercase">Evidence</span>
                  <span className="text-foreground">{finding.evidenceQuality ?? "standard"}</span>
                </div>
                <div className="rounded border border-border/60 bg-black/20 px-2 py-1.5">
                  <span className="text-muted-foreground block uppercase">Repeatability</span>
                  <span className="text-foreground">{finding.reproducibility?.replaceAll("_", " ") ?? "not tested"}</span>
                </div>
                {finding.affectedParameter && (
                  <div className="rounded border border-border/60 bg-black/20 px-2 py-1.5">
                    <span className="text-muted-foreground block uppercase">Parameter</span>
                    <span className="text-foreground break-all">{finding.affectedParameter}</span>
                  </div>
                )}
                {finding.verificationMethod && (
                  <div className="rounded border border-border/60 bg-black/20 px-2 py-1.5">
                    <span className="text-muted-foreground block uppercase">Method</span>
                    <span className="text-foreground">{finding.verificationMethod}</span>
                  </div>
                )}
              </div>

              {finding.negativeTests && (
                <div>
                  <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1.5">Negative Controls</div>
                  <p className="text-[11px] font-mono text-foreground/70 whitespace-pre-wrap">{finding.negativeTests}</p>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ─── Severity Summary ─────────────────────────────────────────────────────────

function SeveritySummary({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null;
  return (
    <div className="flex items-center gap-2 flex-wrap">
      {SEV_ORDER.map(sev => {
        const count = sevCount(findings, sev);
        if (count === 0) return null;
        const s = SEV[sev]!;
        return (
          <div key={sev} className={cn("flex items-center gap-1.5 px-2.5 py-1 rounded border text-[11px] font-mono font-bold", s.color, s.bg, s.border)}>
            <span className={cn("w-1.5 h-1.5 rounded-full", s.dot)} />
            {count} {s.label}
          </div>
        );
      })}
    </div>
  );
}

// ─── Scan Engine Capabilities ─────────────────────────────────────────────────

const CAPABILITIES = [
  { icon: <Globe className="w-4 h-4 text-primary" />,       title: "DNS · WHOIS · Subdomain Discovery",     desc: "dig-based DNS enumeration, crt.sh cert transparency, DNS brute-force, zone transfer, subdomain takeover detection" },
  { icon: <Radar className="w-4 h-4 text-cyan-400" />,      title: "WAF/CDN Detection",                    desc: "Detects Cloudflare, AWS WAF, Akamai, Imperva and more; suspends active probes when a challenge is detected" },
  { icon: <Server className="w-4 h-4 text-blue-400" />,     title: "Port Scanning · TLS/SSL · Services",    desc: "Full 65535-port nmap scan, openssl TLS analysis (protocols, ciphers, cert expiry), exposed dangerous services" },
  { icon: <Bug className="w-4 h-4 text-orange-400" />,      title: "Safe Active Verification",              desc: "Bounded string canaries, harmless template evaluation, and read-only GraphQL introspection with redacted evidence" },
  { icon: <Zap className="w-4 h-4 text-yellow-400" />,      title: "SSTI · XXE · SSRF · Deserialization",   desc: "Arithmetic canary SSTI with RCE escalation, XXE file read, SSRF cloud metadata access, Java deserialization surface" },
  { icon: <KeyRound className="w-4 h-4 text-red-400" />,    title: "JWT Weakness · Log4Shell · Spring4Shell", desc: "alg:none bypass, weak HS256 secret cracking, missing exp claim, Log4Shell JNDI injection surface, Spring4Shell class loader" },
  { icon: <Lock className="w-4 h-4 text-emerald-400" />,    title: "Host Header · CRLF · Open Redirect",    desc: "Password-reset link poisoning, HTTP response splitting, open redirect to attacker-controlled domains" },
  { icon: <Fingerprint className="w-4 h-4 text-purple-400" />, title: "Tech Fingerprint · CVE Matching",    desc: "Stack detection (WordPress, Nginx, Next.js, Laravel…), NVD API CVE cross-reference against detected versions" },
  { icon: <Eye className="w-4 h-4 text-pink-400" />,        title: "50+ Sensitive Paths · Wayback Machine", desc: ".env, .git, backup.sql, credentials.json, SSH keys, Kubernetes configs, source maps, CI/CD files + historical URL analysis" },
  { icon: <Cpu className="w-4 h-4 text-indigo-400" />,      title: "API Surface · Auth · Rate Limits",      desc: "GraphQL introspection, Swagger/OpenAPI exposure, Spring Actuator, no rate limiting on login endpoints, CORS misconfigurations" },
  { icon: <AlertTriangle className="w-4 h-4 text-amber-400" />, title: "Headers · Cookies · XSS · CORS",   desc: "Full HTTP security header audit (HSTS/CSP/XFO/XCTO), cookie flag analysis, reflected XSS detection, CORS credential reflection" },
  { icon: <Shield className="w-4 h-4 text-foreground" />,   title: "Zero False Positives",                  desc: "Every finding uses baseline comparison, canary tokens, or content markers — no guessing, no noise" },
];

// ─── Main Dashboard ───────────────────────────────────────────────────────────

export function Dashboard() {
  const [url, setUrl] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [scanId, setScanId] = useState<number | null>(null);
  const [scanData, setScanData] = useState<ScanStatus | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [target, setTarget] = useState<string>("");

  const logRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Auto-scroll terminal
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [scanData?.scan?.logs]);

  const applyScanStatus = useCallback((data: ScanStatus) => {
    setScanData(data);
    if (data.scan.status === "completed") {
      window.localStorage.removeItem("sentinelx.activeScan");
      setPhase("complete");
      return false;
    }
    if (data.scan.status === "failed" || data.scan.status === "canceled") {
      window.localStorage.removeItem("sentinelx.activeScan");
      if (data.scan.status === "failed") {
        setErrorMsg("The scan stopped unexpectedly. Start a new scan to retry.");
        setPhase("error");
      } else {
        setPhase("complete");
      }
      return false;
    }
    setPhase("scanning");
    return true;
  }, []);

  const handleMissingScan = useCallback(() => {
    window.localStorage.removeItem("sentinelx.activeScan");
    setErrorMsg("This scan is no longer available.");
    setPhase("error");
  }, []);

  const startPolling = useScanPolling(applyScanStatus, handleMissingScan);

  const stopScan = async () => {
    if (!scanId) return;
    try {
      const res = await fetch(`/api/scans/${scanId}/stop`, { method: "POST" });
      if (!res.ok) throw new Error(`stop ${res.status}`);
      const stoppedScan: Scan = await res.json();
      applyScanStatus({ scan: stoppedScan, findings: scanData?.findings ?? [] });
    } catch {
      setErrorMsg("Could not stop the scan. The scan will continue polling.");
    }
  };

  // Restore the scan that was running before a browser refresh.
  useEffect(() => {
    const raw = window.localStorage.getItem("sentinelx.activeScan");
    if (!raw) return;
    try {
      const persisted = JSON.parse(raw) as PersistedScan;
      if (!Number.isInteger(persisted.scanId) || !persisted.target) throw new Error("invalid scan state");
      setScanId(persisted.scanId);
      setTarget(persisted.target);
      setUrl(persisted.target);
      startPolling(persisted.scanId);
    } catch {
      window.localStorage.removeItem("sentinelx.activeScan");
    }
  }, [startPolling]);

  const startScan = async () => {
    const trimmed = url.trim();
    if (!trimmed) { inputRef.current?.focus(); return; }
    setErrorMsg(null);
    setPhase("scanning");
    setScanData(null);
    setScanId(null);
    const normalized = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    setTarget(normalized);

    try {
      const res = await fetch("/api/quick-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: normalized, scanType: "full", profile: "deep_authorized" }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Scan failed to start" }));
        setErrorMsg(err.error ?? "Scan failed to start");
        setPhase("error");
        return;
      }
      const data = await res.json();
      setScanId(data.scanId);
      window.localStorage.setItem("sentinelx.activeScan", JSON.stringify({
        scanId: data.scanId,
        target: normalized,
      } satisfies PersistedScan));
      startPolling(data.scanId);
    } catch {
      setErrorMsg("Could not connect to the scan engine — is the API server running?");
      setPhase("error");
    }
  };

  const reset = () => {
    setPhase("idle");
    setScanId(null);
    setScanData(null);
    setErrorMsg(null);
    setUrl("");
    setTarget("");
    window.localStorage.removeItem("sentinelx.activeScan");
    setTimeout(() => inputRef.current?.focus(), 50);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && phase === "idle") startScan();
  };

  const scan = scanData?.scan;
  const findings = scanData?.findings ?? [];
  const sortedFindings = [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const logLines = (scan?.logs ?? "").split("\n").filter(Boolean);
  const latestLog = logLines[logLines.length - 1] ?? "";
  const isVerifying = phase === "scanning" && latestLog.includes("[Phase 24]") && !latestLog.includes("complete");

  const confirmedFindings = findings.filter(f => (f.verification ?? "verified") === "verified");
  const suspectedFindings = findings.filter(f => f.verification === "suspected");
  const boundedVerifiedFindings = findings.filter(f => f.verified === true);
  const threatLevel =
    sevCount(confirmedFindings, "critical") > 0 ? { label: "CRITICAL", color: "text-red-400",    ring: "border-red-500/40",    bg: "bg-red-500/10" } :
    sevCount(confirmedFindings, "high")     > 0 ? { label: "HIGH",     color: "text-orange-400", ring: "border-orange-500/40", bg: "bg-orange-500/10" } :
    sevCount(confirmedFindings, "medium")   > 0 ? { label: "MODERATE", color: "text-yellow-400", ring: "border-yellow-500/40", bg: "bg-yellow-500/10" } :
    confirmedFindings.length > 0             ? { label: "LOW",       color: "text-blue-400",   ring: "border-blue-500/40",   bg: "bg-blue-500/10" } :
    suspectedFindings.length > 0             ? { label: "SIGNALS",   color: "text-yellow-300", ring: "border-yellow-500/40", bg: "bg-yellow-500/10" } :
                                               { label: "CLEAN",     color: "text-primary",    ring: "border-primary/40",    bg: "bg-primary/10" };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight uppercase font-mono text-foreground">
            Scan Engine
          </h1>
          <p className="text-xs font-mono text-muted-foreground mt-1 tracking-wider uppercase">
            Full deep scan · bounded safe verification · no exploit or credential attacks
          </p>
        </div>
        {phase !== "idle" && (
          <button
            onClick={phase === "scanning" ? stopScan : reset}
            className="flex items-center gap-2 px-3 py-2 rounded-md border border-border bg-card text-xs font-mono text-muted-foreground hover:text-foreground hover:border-primary/40 transition-all"
          >
            {phase === "scanning" ? "Stop scan" : <><RefreshCw className="w-3.5 h-3.5" /> New Scan</>}
          </button>
        )}
      </div>

      {/* ── URL Input ──────────────────────────────────────────────────────── */}
      <div className={cn(
        "rounded-md border bg-card overflow-visible transition-all",
        phase === "idle" ? "border-border" : "border-primary/30",
      )}>
        <div className="p-4 flex items-center gap-3">
          <Search className="w-4 h-4 text-muted-foreground flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={phase === "scanning"}
            placeholder="https://example.com"
            className="flex-1 bg-transparent text-foreground placeholder:text-muted-foreground/50 font-mono text-sm outline-none disabled:opacity-50"
          />
          <button
            onClick={startScan}
            disabled={phase === "scanning" || !url.trim()}
            className={cn(
              "flex items-center gap-2 px-5 py-2 rounded font-mono text-xs font-bold tracking-widest uppercase transition-all",
              phase === "scanning"
                ? "bg-primary/20 text-primary border border-primary/30 cursor-wait"
                : "bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed"
            )}
          >
            {phase === "scanning" ? (
              <><Activity className="w-3.5 h-3.5 animate-pulse" /> Scanning</>
            ) : (
              <><Play className="w-3.5 h-3.5" /> Scan</>
            )}
          </button>
        </div>
        {phase === "idle" && (
          <div className="px-4 py-2 border-t border-border/40">
            <div className="text-[10px] font-mono text-muted-foreground flex items-center gap-2 flex-wrap">
              <Shield className="w-3 h-3 text-primary" />
              <span className="text-primary/80 font-bold uppercase tracking-wider">Full Deep Scan</span>
              <span className="text-muted-foreground/50">·</span>
              <span>21 phases · nmap · dig · whois · openssl · WAF bypass · 50+ paths · CVE lookup</span>
              <span className="text-muted-foreground/50">·</span>
              <span className="text-primary/70">Est. ~10–15 min</span>
            </div>
          </div>
        )}
      </div>

      {/* ── Error ──────────────────────────────────────────────────────────── */}
      {phase === "error" && errorMsg && (
        <div className="rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
          <span className="text-sm font-mono text-red-300">{errorMsg}</span>
        </div>
      )}

      {/* ── Progress bar ───────────────────────────────────────────────────── */}
      {(phase === "scanning" || phase === "complete") && scan && (
        <div className="rounded-md border border-border bg-card p-4 space-y-3">
          <div className="flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <div className={cn("w-2 h-2 rounded-full", phase === "scanning" ? "bg-primary animate-pulse" : scan.status === "canceled" ? "bg-muted-foreground" : "bg-emerald-400")} />
              <span className="text-foreground uppercase tracking-wider truncate max-w-[300px]">{target}</span>
              <span className="text-muted-foreground">· FULL DEEP SCAN</span>
            </div>
            <div className="flex items-center gap-3">
                {phase === "scanning" && scan.status === "running" && (
                  <span className={cn("animate-pulse text-[10px] tracking-widest", isVerifying ? "text-cyan-300" : "text-primary")}>
                    {isVerifying ? "VERIFYING" : "LIVE"}
                  </span>
              )}
              <span className={cn("font-bold", phase === "complete" ? scan.status === "canceled" ? "text-muted-foreground" : "text-emerald-400" : "text-primary")}>
                {phase === "complete" ? scan.status === "canceled" ? "CANCELED" : "COMPLETE" : `${scan.progress}%`}
              </span>
            </div>
          </div>

          <div className="h-1.5 bg-muted rounded-full overflow-hidden">
            <motion.div
              animate={{ width: `${scan.progress}%` }}
              transition={{ duration: 0.5, ease: "easeOut" }}
              className={cn("h-full rounded-full", phase === "complete" ? scan.status === "canceled" ? "bg-muted-foreground" : "bg-emerald-400" : "bg-primary")}
            />
          </div>

          {findings.length > 0 && <SeveritySummary findings={findings} />}
        </div>
      )}

      {/* ── Split view: terminal + live findings ─────────────────────────────── */}
      {(phase === "scanning" || phase === "complete") && (
        <div className="grid gap-4 lg:grid-cols-2">
          {/* Terminal */}
          <div className="rounded-md border border-border bg-card flex flex-col" style={{ minHeight: "480px", maxHeight: "640px" }}>
            <div className="flex items-center gap-2 px-4 py-3 border-b border-border flex-shrink-0">
              <Terminal className="w-3.5 h-3.5 text-primary" />
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">Live Scanner Output</span>
              {phase === "scanning" && <span className="ml-auto text-[10px] font-mono text-primary animate-pulse">● LIVE</span>}
              {phase === "complete" && <span className={cn("ml-auto text-[10px] font-mono", scan?.status === "canceled" ? "text-muted-foreground" : "text-emerald-400")}>{scan?.status === "canceled" ? "■ CANCELED" : "✓ DONE"}</span>}
            </div>
            <div
              ref={logRef}
              className="flex-1 overflow-y-auto p-4 font-mono text-[11px] leading-relaxed space-y-0.5 bg-black/20"
            >
              {logLines.length === 0 && phase === "scanning" && (
                <div className="text-muted-foreground animate-pulse">Initialising scan engine (21 phases)...</div>
              )}
              {logLines.map((line, i) => {
                const isCritical = line.includes("⚠") || line.includes("CRITICAL") || line.includes("CONFIRMED") || line.includes("CRACKED");
                const isWarn = line.includes("WARNING") || line.includes("OPEN PORT") || line.includes("SIGNAL") || line.includes("EXPOSED");
                const isDone = line.includes("SCAN COMPLETE") || line.includes("═══");
                const isPhase = line.includes("[Phase ");
                return (
                  <div key={i} className={cn(
                    "whitespace-pre-wrap break-all",
                    isCritical ? "text-red-400 font-bold" :
                    isWarn     ? "text-yellow-400" :
                    isDone     ? "text-emerald-400 font-bold" :
                    isPhase    ? "text-primary" :
                    "text-muted-foreground"
                  )}>
                    {line}
                  </div>
                );
              })}
              {phase === "scanning" && <div className="text-primary animate-pulse mt-1">▌</div>}
            </div>
          </div>

          {/* Findings */}
          <div className="rounded-md border border-border bg-card flex flex-col" style={{ minHeight: "480px", maxHeight: "640px" }}>
            <div className="flex items-center gap-2 px-4 py-3 border-b border-border flex-shrink-0">
              <AlertTriangle className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">Live Findings</span>
              {findings.length > 0 && (
                <span className="ml-auto font-mono text-xs text-primary font-bold">{findings.length}</span>
              )}
            </div>
            <div className="flex-1 overflow-y-auto p-3 space-y-2">
              {sortedFindings.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-muted-foreground py-16">
                  <Shield className="w-8 h-8 mb-3 opacity-20" />
                  <p className="text-xs font-mono uppercase">
                    {phase === "scanning" ? (isVerifying ? "Verifying detected signals..." : "Scanning...") : "No findings"}
                  </p>
                </div>
              ) : (
                sortedFindings.map(f => <FindingCard key={f.id} finding={f} />)
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Complete: full report ─────────────────────────────────────────────── */}
      {phase === "complete" && scan && (
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-md border bg-card overflow-hidden"
          style={{ borderColor: "hsl(var(--border))" }}
        >
          <div className="flex items-center gap-3 px-5 py-4 border-b border-border">
            <div className={cn("flex items-center gap-3 px-3 py-1.5 rounded border", threatLevel.bg, threatLevel.ring)}>
              <div className={cn("w-2 h-2 rounded-full",
                threatLevel.label === "CLEAN" ? "bg-primary" : threatLevel.label === "LOW" ? "bg-blue-400" :
                threatLevel.label === "MODERATE" ? "bg-yellow-400" : threatLevel.label === "HIGH" ? "bg-orange-400" : "bg-red-400"
              )} />
              <span className={cn("text-[11px] font-mono font-bold tracking-widest uppercase", threatLevel.color)}>
                THREAT: {threatLevel.label}
              </span>
            </div>
            <div className="flex-1">
              <div className="font-mono text-xs text-muted-foreground uppercase tracking-wider">
                Security Report — <span className="text-foreground">{target}</span>
              </div>
              <div className="text-[10px] font-mono text-muted-foreground mt-0.5 flex items-center gap-2">
                <Clock className="w-2.5 h-2.5" />
                {scan.startedAt ? new Date(scan.startedAt).toLocaleString() : "—"}
                <span>·</span>
                {confirmedFindings.length} verified · {boundedVerifiedFindings.length} canary-confirmed · {suspectedFindings.length} signal{suspectedFindings.length !== 1 ? "s" : ""}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Zap className="w-3 h-3 text-primary" />
              <span className="text-[10px] font-mono text-muted-foreground uppercase">Full Deep Scan</span>
            </div>
          </div>

          {findings.length > 0 && (
            <div className="px-5 py-3 border-b border-border/40 flex items-center gap-3 flex-wrap">
              <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider">Risk Summary:</span>
              <DashboardSeveritySummary findings={findings} />
              <span className="ml-auto text-[10px] font-mono text-primary border border-primary/30 bg-primary/10 rounded px-2 py-1">
                {boundedVerifiedFindings.length} CANARY VERIFIED
              </span>
            </div>
          )}

          {scan.wafBlocked && (
            <div className="mx-5 mb-3 flex items-start gap-3 rounded-md border border-yellow-500/40 bg-yellow-500/10 px-4 py-3 text-yellow-200">
              <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0 text-yellow-400" />
              <div>
                <p className="font-mono text-xs font-bold uppercase tracking-wider">WAF challenge detected</p>
                <p className="mt-1 text-xs text-yellow-100/80">
                  Active probes were suspended after the target served a WAF challenge. Findings from challenge responses are informational and may be false positives.
                </p>
              </div>
            </div>
          )}

          <div className="p-4 space-y-2">
            {sortedFindings.length === 0 ? (
              <div className="flex flex-col items-center py-12 text-muted-foreground">
                <CheckCircle2 className="w-10 h-10 mb-3 text-emerald-400 opacity-60" />
                <p className="font-mono text-sm text-emerald-400">No vulnerabilities detected</p>
                <p className="text-xs text-muted-foreground mt-1">Target passed all security checks</p>
              </div>
            ) : (
                sortedFindings.map(f => <DashboardFindingCard key={f.id} finding={f} />)
            )}
          </div>
        </motion.div>
      )}

      {/* ── Idle: capability grid ───────────────────────────────────────────── */}
      {phase === "idle" && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="grid gap-3 md:grid-cols-2 lg:grid-cols-3"
        >
          {CAPABILITIES.map(({ icon, title, desc }) => (
            <div key={title} className="rounded-md border border-border bg-card p-4">
              <div className="flex items-center gap-2 mb-2">
                {icon}
                <span className="text-xs font-mono font-bold text-foreground">{title}</span>
              </div>
              <p className="text-[11px] text-muted-foreground leading-relaxed">{desc}</p>
            </div>
          ))}
        </motion.div>
      )}
    </motion.div>
  );
}
