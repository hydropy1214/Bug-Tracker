import { useState, useEffect, useRef, useCallback } from "react";
import {
  Shield, Search, Zap, Terminal, AlertTriangle, CheckCircle2,
  ChevronDown, ChevronRight, ExternalLink, RefreshCw, Play,
  Clock, Activity, Lock, Globe, Server
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

type ScanType = "recon" | "enumeration" | "vulnerability" | "full";
type Phase = "idle" | "scanning" | "complete" | "error";

interface Scan {
  id: number;
  status: "pending" | "running" | "completed";
  progress: number;
  logs: string | null;
  findingsCount: number;
  startedAt: string | null;
  completedAt: string | null;
  type: string;
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
}

interface ScanStatus {
  scan: Scan;
  findings: Finding[];
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SCAN_TYPE_INFO: Record<ScanType, { label: string; icon: React.ReactNode; desc: string; time: string }> = {
  recon:         { label: "Recon",         icon: <Globe className="w-3.5 h-3.5" />,    desc: "DNS · TLS · Headers · Fingerprint", time: "~1 min" },
  enumeration:   { label: "Enumeration",   icon: <Server className="w-3.5 h-3.5" />,   desc: "Recon + Ports · Subdomains · Paths", time: "~3 min" },
  vulnerability: { label: "Vulnerability", icon: <AlertTriangle className="w-3.5 h-3.5"/>, desc: "Enum + SQLi · XSS · SSTI · SSRF · CORS", time: "~6 min" },
  full:          { label: "Full",          icon: <Shield className="w-3.5 h-3.5" />,   desc: "All checks + CVE · RCE · Deser · Wayback", time: "~10 min" },
};

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
      {/* Header row */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:brightness-110 transition-all"
      >
        <div className={cn("w-2 h-2 rounded-full flex-shrink-0 mt-1.5", s.dot)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={cn("text-[10px] font-mono font-bold tracking-widest", s.color)}>{s.label}</span>
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

      {/* Expanded content */}
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
              {/* Description */}
              <div className="pt-3">
                <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1.5">Description</div>
                <p className="text-sm text-foreground/80 leading-relaxed">{finding.description}</p>
              </div>

              {/* Evidence */}
              <div>
                <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                  <Terminal className="w-3 h-3" />
                  Evidence / Proof
                </div>
                <pre className="text-[11px] font-mono bg-black/40 border border-white/10 rounded p-3 overflow-x-auto text-primary/90 whitespace-pre-wrap leading-relaxed max-h-64 overflow-y-auto">
                  {finding.evidence}
                </pre>
              </div>

              {/* Remediation */}
              <div>
                <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  Remediation
                </div>
                <pre className="text-[11px] font-mono text-foreground/70 whitespace-pre-wrap leading-relaxed">{finding.remediation}</pre>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ─── Severity summary bar ──────────────────────────────────────────────────────

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

// ─── Main Dashboard ───────────────────────────────────────────────────────────

export function Dashboard() {
  const [url, setUrl] = useState("");
  const [scanType, setScanType] = useState<ScanType>("full");
  const [showTypes, setShowTypes] = useState(false);
  const [phase, setPhase] = useState<Phase>("idle");
  const [scanId, setScanId] = useState<number | null>(null);
  const [scanData, setScanData] = useState<ScanStatus | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [target, setTarget] = useState<string>("");

  const logRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Auto-scroll terminal
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [scanData?.scan?.logs]);

  // Cleanup poll on unmount
  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  // Poll for scan status
  const startPolling = useCallback((id: number) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/scans/${id}/status`);
        if (!res.ok) return;
        const data: ScanStatus = await res.json();
        setScanData(data);
        if (data.scan.status === "completed") {
          setPhase("complete");
          clearInterval(pollRef.current!);
          pollRef.current = null;
        }
      } catch { /* network error, retry next tick */ }
    }, 1500);
  }, []);

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
        body: JSON.stringify({ url: normalized, scanType }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Scan failed to start" }));
        setErrorMsg(err.error ?? "Scan failed to start");
        setPhase("error");
        return;
      }
      const data = await res.json();
      setScanId(data.scanId);
      startPolling(data.scanId);
    } catch {
      setErrorMsg("Could not connect to the scan engine — is the API server running?");
      setPhase("error");
    }
  };

  const reset = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    setPhase("idle");
    setScanId(null);
    setScanData(null);
    setErrorMsg(null);
    setUrl("");
    setTarget("");
    setTimeout(() => inputRef.current?.focus(), 50);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && phase === "idle") startScan();
    if (e.key === "Escape") setShowTypes(false);
  };

  const scan = scanData?.scan;
  const findings = scanData?.findings ?? [];
  const sortedFindings = [...findings].sort((a, b) => {
    const ai = SEV_ORDER.indexOf(a.severity);
    const bi = SEV_ORDER.indexOf(b.severity);
    return ai - bi;
  });
  const logLines = (scan?.logs ?? "").split("\n").filter(Boolean);
  const typeInfo = SCAN_TYPE_INFO[scanType]!;

  // Threat level for completed scans
  const threatLevel =
    sevCount(findings, "critical") > 0 ? { label: "CRITICAL", color: "text-red-400",    ring: "border-red-500/40",    bg: "bg-red-500/10" } :
    sevCount(findings, "high")     > 0 ? { label: "HIGH",     color: "text-orange-400", ring: "border-orange-500/40", bg: "bg-orange-500/10" } :
    sevCount(findings, "medium")   > 0 ? { label: "MODERATE", color: "text-yellow-400", ring: "border-yellow-500/40", bg: "bg-yellow-500/10" } :
    findings.length > 0                ? { label: "LOW",       color: "text-blue-400",   ring: "border-blue-500/40",   bg: "bg-blue-500/10" } :
                                         { label: "CLEAN",     color: "text-primary",    ring: "border-primary/40",    bg: "bg-primary/10" };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="space-y-6"
    >
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight uppercase font-mono text-foreground">
            Scan Engine
          </h1>
          <p className="text-xs font-mono text-muted-foreground mt-1 tracking-wider uppercase">
            Enter any URL to run a full security scan
          </p>
        </div>
        {phase !== "idle" && (
          <button
            onClick={reset}
            className="flex items-center gap-2 px-3 py-2 rounded-md border border-border bg-card text-xs font-mono text-muted-foreground hover:text-foreground hover:border-primary/40 transition-all"
          >
            <RefreshCw className="w-3.5 h-3.5" /> New Scan
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

          {/* Scan type picker */}
          <div className="relative flex-shrink-0">
            <button
              onClick={() => setShowTypes(o => !o)}
              disabled={phase === "scanning"}
              className="flex items-center gap-2 px-3 py-1.5 rounded border border-border bg-accent/50 text-xs font-mono text-foreground hover:border-primary/40 transition-all disabled:opacity-50"
            >
              {typeInfo.icon}
              {typeInfo.label}
              <ChevronDown className="w-3 h-3 text-muted-foreground" />
            </button>
            <AnimatePresence>
              {showTypes && (
                <motion.div
                  initial={{ opacity: 0, y: -4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -4 }}
                  className="absolute right-0 top-full mt-2 z-50 w-72 rounded-md border border-border bg-popover shadow-2xl overflow-hidden"
                >
                  {(Object.entries(SCAN_TYPE_INFO) as [ScanType, typeof typeInfo][]).map(([key, info]) => (
                    <button
                      key={key}
                      onClick={() => { setScanType(key); setShowTypes(false); }}
                      className={cn(
                        "w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-accent/60 transition-colors border-b border-border/40 last:border-0",
                        scanType === key && "bg-primary/10"
                      )}
                    >
                      <div className={cn("mt-0.5", scanType === key ? "text-primary" : "text-muted-foreground")}>{info.icon}</div>
                      <div>
                        <div className={cn("text-xs font-mono font-bold", scanType === key ? "text-primary" : "text-foreground")}>{info.label}</div>
                        <div className="text-[10px] font-mono text-muted-foreground mt-0.5">{info.desc}</div>
                        <div className="text-[10px] font-mono text-muted-foreground/60 mt-0.5">Est. {info.time}</div>
                      </div>
                    </button>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Scan button */}
          <button
            onClick={startScan}
            disabled={phase === "scanning" || !url.trim()}
            className={cn(
              "flex items-center gap-2 px-4 py-2 rounded font-mono text-xs font-bold tracking-widest uppercase transition-all",
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

        {/* Scan type description bar */}
        {phase === "idle" && (
          <div className="px-4 py-2 border-t border-border/40 flex items-center gap-4">
            <div className="text-[10px] font-mono text-muted-foreground flex items-center gap-1.5">
              {typeInfo.icon}
              <span className="uppercase tracking-wider">{typeInfo.label}:</span>
              <span>{typeInfo.desc}</span>
              <span className="ml-2 text-muted-foreground/50">· Est. {typeInfo.time}</span>
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
              <div className={cn("w-2 h-2 rounded-full", phase === "scanning" ? "bg-primary animate-pulse" : "bg-emerald-400")} />
              <span className="text-foreground uppercase tracking-wider">{target}</span>
              <span className="text-muted-foreground">·</span>
              <span className="text-muted-foreground uppercase">{scanType} scan</span>
            </div>
            <div className="flex items-center gap-3">
              {phase === "scanning" && scan.status === "running" && (
                <span className="text-primary animate-pulse text-[10px] tracking-widest">LIVE</span>
              )}
              <span className={cn("font-bold", phase === "complete" ? "text-emerald-400" : "text-primary")}>
                {phase === "complete" ? "COMPLETE" : `${scan.progress}%`}
              </span>
            </div>
          </div>

          <div className="h-1.5 bg-muted rounded-full overflow-hidden">
            <motion.div
              animate={{ width: `${scan.progress}%` }}
              transition={{ duration: 0.5, ease: "easeOut" }}
              className={cn("h-full rounded-full", phase === "complete" ? "bg-emerald-400" : "bg-primary")}
            />
          </div>

          {/* Stats row */}
          {findings.length > 0 && (
            <SeveritySummary findings={findings} />
          )}
        </div>
      )}

      {/* ── Scan active: split view ─────────────────────────────────────────── */}
      {(phase === "scanning" || phase === "complete") && (
        <div className="grid gap-4 lg:grid-cols-2">

          {/* Terminal */}
          <div className="rounded-md border border-border bg-card flex flex-col" style={{ minHeight: "480px", maxHeight: "600px" }}>
            <div className="flex items-center gap-2 px-4 py-3 border-b border-border flex-shrink-0">
              <Terminal className="w-3.5 h-3.5 text-primary" />
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">
                Live Scanner Output
              </span>
              {phase === "scanning" && (
                <span className="ml-auto text-[10px] font-mono text-primary animate-pulse">● LIVE</span>
              )}
              {phase === "complete" && (
                <span className="ml-auto text-[10px] font-mono text-emerald-400">✓ DONE</span>
              )}
            </div>
            <div
              ref={logRef}
              className="flex-1 overflow-y-auto p-4 font-mono text-[11px] leading-relaxed space-y-0.5 bg-black/20"
            >
              {logLines.length === 0 && phase === "scanning" && (
                <div className="text-muted-foreground animate-pulse">Initialising scan engine...</div>
              )}
              {logLines.map((line, i) => {
                const isCritical = line.includes("⚠") || line.includes("CRITICAL") || line.includes("CONFIRMED");
                const isWarn = line.includes("WARNING") || line.includes("OPEN PORT") || line.includes("finding");
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
              {phase === "scanning" && (
                <div className="text-primary animate-pulse mt-1">▌</div>
              )}
            </div>
          </div>

          {/* Findings */}
          <div className="rounded-md border border-border bg-card flex flex-col" style={{ minHeight: "480px", maxHeight: "600px" }}>
            <div className="flex items-center gap-2 px-4 py-3 border-b border-border flex-shrink-0">
              <AlertTriangle className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">
                Findings
              </span>
              {findings.length > 0 && (
                <span className="ml-auto font-mono text-xs text-primary font-bold">{findings.length}</span>
              )}
            </div>
            <div className="flex-1 overflow-y-auto p-3 space-y-2">
              {sortedFindings.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-muted-foreground py-16">
                  <Shield className="w-8 h-8 mb-3 opacity-20" />
                  <p className="text-xs font-mono uppercase">
                    {phase === "scanning" ? "Analysing target..." : "No findings"}
                  </p>
                </div>
              ) : (
                sortedFindings.map(f => <FindingCard key={f.id} finding={f} />)
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Complete: report summary ────────────────────────────────────────── */}
      {phase === "complete" && scan && (
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-md border bg-card overflow-hidden"
          style={{ borderColor: "hsl(var(--border))" }}
        >
          <div className="flex items-center gap-3 px-5 py-4 border-b border-border">
            <div className={cn("flex items-center gap-3 px-3 py-1.5 rounded border", threatLevel.bg, threatLevel.ring)}>
              <div className={cn("w-2 h-2 rounded-full", threatLevel.label === "CLEAN" ? "bg-primary" : threatLevel.label === "LOW" ? "bg-blue-400" : threatLevel.label === "MODERATE" ? "bg-yellow-400" : threatLevel.label === "HIGH" ? "bg-orange-400" : "bg-red-400")} />
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
                {scan.findingsCount} finding{scan.findingsCount !== 1 ? "s" : ""} discovered
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Zap className="w-3 h-3 text-primary" />
              <span className="text-[10px] font-mono text-muted-foreground uppercase">{scanType} scan</span>
            </div>
          </div>

          {/* Severity summary */}
          {findings.length > 0 && (
            <div className="px-5 py-3 border-b border-border/40 flex items-center gap-3 flex-wrap">
              <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider">Risk Summary:</span>
              <SeveritySummary findings={findings} />
            </div>
          )}

          {/* All findings */}
          <div className="p-4 space-y-2">
            {sortedFindings.length === 0 ? (
              <div className="flex flex-col items-center py-12 text-muted-foreground">
                <CheckCircle2 className="w-10 h-10 mb-3 text-emerald-400 opacity-60" />
                <p className="font-mono text-sm text-emerald-400">No vulnerabilities detected</p>
                <p className="text-xs text-muted-foreground mt-1">Target passed all security checks</p>
              </div>
            ) : (
              sortedFindings.map(f => <FindingCard key={f.id} finding={f} />)
            )}
          </div>
        </motion.div>
      )}

      {/* ── Idle: feature hints ────────────────────────────────────────────── */}
      {phase === "idle" && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="grid gap-3 md:grid-cols-2 lg:grid-cols-4"
        >
          {[
            { icon: <Shield className="w-4 h-4 text-primary" />,       title: "CVE Verification",    desc: "Real-time NVD database cross-reference for detected tech versions" },
            { icon: <Zap className="w-4 h-4 text-yellow-400" />,       title: "SSTI / RCE Probes",   desc: "Detects template injection that can escalate to remote code execution" },
            { icon: <Lock className="w-4 h-4 text-orange-400" />,      title: "SQLi & XSS",          desc: "Error-based SQL injection and reflected XSS reflection detection" },
            { icon: <Terminal className="w-4 h-4 text-emerald-400" />, title: "Evidence & Proof",    desc: "Every finding includes full request/response proof for validation" },
          ].map(({ icon, title, desc }) => (
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
