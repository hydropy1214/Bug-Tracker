import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Download,
  Filter,
  ListChecks,
  Loader2,
  Radio,
  RefreshCw,
  Search,
  Terminal,
  XCircle,
} from "lucide-react";
import { motion } from "framer-motion";
import { cn, formatDate } from "@/lib/utils";

type ScanStatus = "pending" | "running" | "completed" | "failed" | "canceled";
type FilterValue = "all" | "active" | "completed" | "failed";

interface ScanSummary {
  id: number;
  projectId: number;
  name: string;
  type: string;
  profile: string;
  status: ScanStatus;
  progress: number;
  findingsCount: number;
  wafBlocked: boolean;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
  projectName: string;
  target: string;
}

interface Finding {
  id: number;
  title: string;
  severity: string;
  cvss: number;
  verification?: string;
  confidence?: number;
  description: string;
  evidence: string;
  remediation: string;
}

interface ScanDetail {
  scan: ScanSummary & { logs: string | null };
  findings: Finding[];
}

const STATUS: Record<ScanStatus, {
  label: string;
  color: string;
  bg: string;
  border: string;
  dot: string;
}> = {
  pending: { label: "Queued", color: "text-yellow-300", bg: "bg-yellow-500/10", border: "border-yellow-500/30", dot: "bg-yellow-300" },
  running: { label: "Live", color: "text-primary", bg: "bg-primary/10", border: "border-primary/30", dot: "bg-primary" },
  completed: { label: "Completed", color: "text-emerald-300", bg: "bg-emerald-500/10", border: "border-emerald-500/30", dot: "bg-emerald-300" },
  failed: { label: "Failed", color: "text-red-300", bg: "bg-red-500/10", border: "border-red-500/30", dot: "bg-red-300" },
  canceled: { label: "Canceled", color: "text-muted-foreground", bg: "bg-muted/10", border: "border-border", dot: "bg-muted-foreground" },
};

const SEVERITY: Record<string, string> = {
  critical: "text-red-300 border-red-500/30 bg-red-500/10",
  high: "text-orange-300 border-orange-500/30 bg-orange-500/10",
  medium: "text-yellow-300 border-yellow-500/30 bg-yellow-500/10",
  low: "text-blue-300 border-blue-500/30 bg-blue-500/10",
  info: "text-muted-foreground border-border bg-accent",
};

const active = (status: ScanStatus) => status === "pending" || status === "running";

function StatusBadge({ status }: { status: ScanStatus }) {
  const style = STATUS[status];
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 text-[9px] font-mono font-bold uppercase tracking-widest", style.bg, style.border, style.color)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", style.dot, active(status) && "animate-pulse")} />
      {style.label}
    </span>
  );
}

function ProgressBar({ progress, status }: { progress: number; status: ScanStatus }) {
  const color = status === "completed" ? "bg-emerald-400" : status === "failed" ? "bg-red-400" : "bg-primary";
  return (
    <div className="flex items-center gap-3">
      <div className="h-1.5 flex-1 overflow-hidden rounded-full border border-border bg-background">
        <div className={cn("h-full transition-all duration-500", color)} style={{ width: `${Math.max(0, Math.min(100, progress))}%` }} />
      </div>
      <span className="w-9 text-right text-[10px] font-mono font-bold text-muted-foreground">{progress}%</span>
    </div>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="overflow-hidden rounded-sm border border-border bg-background/60">
      <button onClick={() => setOpen(value => !value)} className="flex w-full items-start gap-3 px-3 py-3 text-left hover:bg-accent/30">
        <span className={cn("mt-0.5 rounded-sm border px-1.5 py-0.5 text-[9px] font-mono font-bold uppercase", SEVERITY[finding.severity] ?? SEVERITY.info)}>
          {finding.severity}
        </span>
        <span className="min-w-0 flex-1 text-xs font-medium text-foreground">{finding.title}</span>
        <span className="flex items-center gap-2 text-[10px] font-mono text-muted-foreground">
          CVSS {Number(finding.cvss ?? 0).toFixed(1)}
          <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", open && "rotate-180")} />
        </span>
      </button>
      {open && (
        <div className="space-y-3 border-t border-border/60 px-3 py-3 text-[11px] leading-relaxed text-muted-foreground">
          <p className="text-foreground">{finding.description}</p>
          <div><span className="font-mono uppercase tracking-wider text-primary">Evidence</span><pre className="mt-1 whitespace-pre-wrap break-words rounded-sm border border-border bg-black/30 p-2 font-mono text-[10px] text-emerald-300">{finding.evidence || "No evidence recorded."}</pre></div>
          <div><span className="font-mono uppercase tracking-wider text-primary">Remediation</span><p className="mt-1">{finding.remediation || "No remediation recorded."}</p></div>
        </div>
      )}
    </div>
  );
}

export function Scans() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(() => {
    const value = Number(window.localStorage.getItem("sentinelx.selectedScan"));
    return Number.isInteger(value) && value > 0 ? value : null;
  });
  const [detail, setDetail] = useState<ScanDetail | null>(null);
  const [filter, setFilter] = useState<FilterValue>("all");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadScans = useCallback(async (showSpinner = false) => {
    if (showSpinner) setRefreshing(true);
    try {
      const response = await fetch("/api/scans", { cache: "no-store" });
      if (!response.ok) throw new Error(`Scan history unavailable (${response.status})`);
      const data = await response.json() as ScanSummary[];
      setScans(data);
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not load scan history");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  const loadDetail = useCallback(async (id: number) => {
    try {
      const response = await fetch(`/api/scans/${id}/status`, { cache: "no-store" });
      if (response.status === 404) {
        setDetail(null);
        setSelectedId(null);
        window.localStorage.removeItem("sentinelx.selectedScan");
        return;
      }
      if (!response.ok) throw new Error("Scan detail unavailable");
      setDetail(await response.json() as ScanDetail);
    } catch {
      // Keep the last detail visible while a restarting API reconnects.
    }
  }, []);

  useEffect(() => {
    void loadScans();
    const timer = window.setInterval(() => void loadScans(), 2000);
    return () => window.clearInterval(timer);
  }, [loadScans]);

  useEffect(() => {
    if (!scans.length) {
      setSelectedId(null);
      return;
    }
    const selectedStillExists = selectedId !== null && scans.some(scan => scan.id === selectedId);
    if (!selectedStillExists) {
      const next = scans.find(scan => active(scan.status)) ?? scans[0];
      setSelectedId(next.id);
      window.localStorage.setItem("sentinelx.selectedScan", String(next.id));
    }
  }, [scans, selectedId]);

  useEffect(() => {
    if (selectedId === null) {
      setDetail(null);
      return;
    }
    window.localStorage.setItem("sentinelx.selectedScan", String(selectedId));
    void loadDetail(selectedId);
    const selected = scans.find(scan => scan.id === selectedId);
    if (!selected || active(selected.status)) {
      const timer = window.setInterval(() => void loadDetail(selectedId), 1500);
      return () => window.clearInterval(timer);
    }
    return undefined;
  }, [selectedId, scans, loadDetail]);

  const filteredScans = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return scans.filter(scan => {
      const filterMatch = filter === "all"
        || filter === "active" && active(scan.status)
        || filter === "completed" && scan.status === "completed"
        || filter === "failed" && scan.status === "failed";
      const queryMatch = !normalized || [scan.name, scan.projectName, scan.target, scan.type].some(value => value.toLowerCase().includes(normalized));
      return filterMatch && queryMatch;
    });
  }, [filter, query, scans]);

  const selected = detail?.scan ?? scans.find(scan => scan.id === selectedId) ?? null;
  const findings = detail?.findings ?? [];
  const logLines = (detail?.scan.logs ?? "").split("\n").filter(Boolean);
  const activeCount = scans.filter(scan => active(scan.status)).length;
  const completedCount = scans.filter(scan => scan.status === "completed").length;
  const failedCount = scans.filter(scan => scan.status === "failed").length;

  const downloadReport = async (format: "json" | "sarif") => {
    if (!selected) return;
    const response = await fetch(`/api/scans/${selected.id}/report?format=${format}`);
    if (!response.ok) return;
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `sentinelx-scan-${selected.id}.${format === "sarif" ? "sarif" : "json"}`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
      <header className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-sm border border-primary/30 bg-primary/10 glow-primary"><ListChecks className="h-4 w-4 text-primary" /></div>
            <div>
              <h1 className="text-3xl font-bold uppercase tracking-tight font-mono text-foreground">Scan Vault</h1>
              <p className="text-[10px] font-mono uppercase tracking-[0.18em] text-muted-foreground">Every execution · live telemetry · retained findings</p>
            </div>
          </div>
        </div>
        <button onClick={() => void loadScans(true)} className="inline-flex items-center gap-2 self-start rounded-sm border border-border bg-card px-3 py-2 text-[10px] font-mono uppercase tracking-widest text-muted-foreground hover:border-primary/40 hover:text-primary lg:self-auto">
          <RefreshCw className={cn("h-3.5 w-3.5", refreshing && "animate-spin")} /> Refresh history
        </button>
      </header>

      <section className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {[
          { label: "Total scans", value: scans.length, icon: ListChecks, color: "text-foreground" },
          { label: "Live / queued", value: activeCount, icon: Radio, color: "text-primary" },
          { label: "Completed", value: completedCount, icon: CheckCircle2, color: "text-emerald-300" },
          { label: "Failed", value: failedCount, icon: XCircle, color: "text-red-300" },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-sm border border-border bg-card px-4 py-3">
            <div className="flex items-center justify-between"><span className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground">{label}</span><Icon className={cn("h-3.5 w-3.5", color)} /></div>
            <div className={cn("mt-1 text-2xl font-mono font-bold", color)}>{value}</div>
          </div>
        ))}
      </section>

      <div className="grid min-h-[620px] gap-4 xl:grid-cols-[minmax(360px,0.9fr)_minmax(0,1.5fr)]">
        <section className="flex min-h-0 flex-col overflow-hidden rounded-md border border-border bg-card">
          <div className="space-y-3 border-b border-border bg-background/50 p-4">
            <div className="flex items-center gap-2">
              <div className="relative flex-1"><Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" /><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search target, project, scan..." className="h-8 w-full rounded-sm border border-border bg-background pl-8 pr-2 text-[11px] font-mono text-foreground outline-none focus:border-primary/50" /></div>
              <Filter className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
            <div className="flex flex-wrap gap-1.5">
              {(["all", "active", "completed", "failed"] as FilterValue[]).map(value => (
                <button key={value} onClick={() => setFilter(value)} className={cn("rounded-sm border px-2 py-1 text-[9px] font-mono uppercase tracking-widest", filter === value ? "border-primary/40 bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground")}>{value}</button>
              ))}
            </div>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-2">
            {loading ? (
              <div className="space-y-2 p-2">{[1, 2, 3, 4].map(value => <div key={value} className="h-24 animate-pulse rounded-sm border border-border bg-background" />)}</div>
            ) : error && !scans.length ? (
              <div className="p-8 text-center"><AlertTriangle className="mx-auto mb-3 h-6 w-6 text-red-300" /><p className="text-xs font-mono text-red-300">{error}</p><button onClick={() => void loadScans(true)} className="mt-4 text-[10px] font-mono uppercase text-primary hover:underline">Retry</button></div>
            ) : !filteredScans.length ? (
              <div className="p-10 text-center text-muted-foreground"><ListChecks className="mx-auto mb-3 h-7 w-7 opacity-30" /><p className="text-[10px] font-mono uppercase tracking-widest">No matching scans</p><p className="mt-1 text-[10px]">Completed and live executions will appear here.</p></div>
            ) : (
              <div className="space-y-2">
                {filteredScans.map(scan => {
                  const style = STATUS[scan.status];
                  return (
                    <button key={scan.id} onClick={() => setSelectedId(scan.id)} className={cn("w-full rounded-sm border p-3 text-left transition-all", selectedId === scan.id ? "border-primary/50 bg-primary/5 shadow-[0_0_16px_rgba(0,255,128,0.05)]" : "border-border bg-background/50 hover:border-primary/25")}>
                      <div className="mb-2 flex items-start justify-between gap-2"><div className="min-w-0"><div className="truncate text-xs font-bold text-foreground">{scan.name}</div><div className="mt-1 truncate text-[10px] font-mono text-muted-foreground">{scan.target}</div></div><StatusBadge status={scan.status} /></div>
                      <ProgressBar progress={scan.progress ?? 0} status={scan.status} />
                      <div className="mt-2 flex items-center justify-between text-[9px] font-mono uppercase tracking-wider text-muted-foreground"><span className={style.color}>{scan.type} · {scan.projectName}</span><span>{scan.findingsCount} findings</span></div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </section>

        <section className="min-h-0 overflow-hidden rounded-md border border-border bg-card">
          {!selected ? (
            <div className="flex h-full min-h-[500px] flex-col items-center justify-center text-center text-muted-foreground"><Terminal className="mb-3 h-8 w-8 opacity-20" /><p className="text-xs font-mono uppercase tracking-widest">Select a scan</p><p className="mt-1 text-[10px]">Live and historical execution details will appear here.</p></div>
          ) : (
            <div className="flex h-full min-h-[620px] flex-col">
              <div className="border-b border-border bg-background/50 p-5">
                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between"><div className="min-w-0"><div className="mb-2 flex flex-wrap items-center gap-2"><StatusBadge status={selected.status} /><span className="rounded-sm border border-border bg-accent px-2 py-0.5 text-[9px] font-mono uppercase tracking-widest text-muted-foreground">#{selected.id}</span><span className="text-[9px] font-mono uppercase tracking-widest text-cyan-300">{selected.type}</span></div><h2 className="truncate text-lg font-bold text-foreground">{selected.name}</h2><p className="mt-1 truncate text-[11px] font-mono text-muted-foreground">{selected.target}</p></div><div className="flex shrink-0 gap-2">{selected.status === "completed" && <><button onClick={() => void downloadReport("json")} className="inline-flex items-center gap-1.5 rounded-sm border border-border px-2 py-1.5 text-[9px] font-mono uppercase text-muted-foreground hover:text-primary"><Download className="h-3 w-3" /> JSON</button><button onClick={() => void downloadReport("sarif")} className="inline-flex items-center gap-1.5 rounded-sm border border-border px-2 py-1.5 text-[9px] font-mono uppercase text-muted-foreground hover:text-primary"><Download className="h-3 w-3" /> SARIF</button></>}</div></div>
                <div className="mt-4"><ProgressBar progress={selected.progress ?? 0} status={selected.status} /></div>
                <div className="mt-3 grid gap-2 text-[9px] font-mono uppercase tracking-wider text-muted-foreground sm:grid-cols-3"><span>Project <b className="ml-1 text-foreground">{selected.projectName}</b></span><span>Started <b className="ml-1 text-foreground">{formatDate(selected.startedAt)}</b></span><span>Finished <b className="ml-1 text-foreground">{formatDate(selected.completedAt)}</b></span></div>
                {selected.wafBlocked && <div className="mt-3 rounded-sm border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-[10px] font-mono text-yellow-200">WAF challenge detected — active probes were suspended and affected findings were downgraded.</div>}
              </div>
              <div className="grid min-h-0 flex-1 gap-4 overflow-y-auto p-5 lg:grid-cols-[minmax(0,1.15fr)_minmax(260px,0.85fr)]">
                <div className="min-h-0"><div className="mb-2 flex items-center justify-between"><span className="flex items-center gap-2 text-[10px] font-mono font-bold uppercase tracking-widest text-muted-foreground"><Terminal className="h-3.5 w-3.5 text-primary" /> Execution log</span>{active(selected.status) && <span className="flex items-center gap-1.5 text-[9px] font-mono uppercase tracking-widest text-primary"><Loader2 className="h-3 w-3 animate-spin" /> Updating live</span>}</div><div className="terminal-bg h-[360px] overflow-y-auto rounded-sm border border-border p-3">{logLines.length ? <pre className="whitespace-pre-wrap break-words text-[10px] leading-relaxed text-emerald-300">{logLines.join("\n")}</pre> : <div className="text-[10px] font-mono text-muted-foreground">{active(selected.status) ? "Worker is starting and will stream logs here..." : "No log output recorded for this execution."}</div>}</div></div>
                <div className="min-h-0"><div className="mb-2 flex items-center justify-between"><span className="flex items-center gap-2 text-[10px] font-mono font-bold uppercase tracking-widest text-muted-foreground"><AlertTriangle className="h-3.5 w-3.5 text-orange-300" /> Findings</span><span className="text-[10px] font-mono text-foreground">{findings.length}</span></div>{findings.length ? <div className="space-y-2 overflow-y-auto lg:max-h-[360px]">{findings.map(finding => <FindingRow key={finding.id} finding={finding} />)}</div> : <div className="rounded-sm border border-dashed border-border p-6 text-center text-[10px] font-mono text-muted-foreground">{active(selected.status) ? "Findings will appear as phases complete." : selected.status === "failed" ? "No findings were saved before this scan failed." : "No findings recorded — clean result."}</div>}</div>
              </div>
            </div>
          )}
        </section>
      </div>
    </motion.div>
  );
}