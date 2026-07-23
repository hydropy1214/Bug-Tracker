import { useState, useEffect, useRef } from "react";
import {
  useListScans,
  useCreateScan,
  useGetScan,
  getListScansQueryKey,
  getGetScanQueryKey,
  type Scan,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Play, Terminal, Clock, RefreshCw, Radar, Zap, Globe, ShieldCheck, ChevronDown, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { formatDate, cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";

const SCAN_TYPES = [
  { value: "recon",         label: "Reconnaissance",  desc: "DNS, WHOIS, TLS, HTTP headers, tech fingerprinting",     icon: Globe,       eta: "~30s" },
  { value: "enumeration",   label: "Enumeration",     desc: "Ports (nmap), subdomains (crt.sh), sensitive paths, Wayback", icon: Radar,  eta: "~2-3 min" },
  { value: "vulnerability", label: "Vulnerability",   desc: "All above + SQLi, XSS, open redirect, API surface",     icon: ShieldCheck, eta: "~3-4 min" },
  { value: "full",          label: "Full Scan",       desc: "All 12 modules — deepest coverage, all real tools",      icon: Zap,         eta: "~5-6 min" },
];

const TYPE_STYLES: Record<string, { color: string; bg: string; border: string }> = {
  recon:         { color: "text-blue-400",    bg: "bg-blue-500/10",    border: "border-blue-500/25" },
  enumeration:   { color: "text-purple-400",  bg: "bg-purple-500/10",  border: "border-purple-500/25" },
  vulnerability: { color: "text-orange-400",  bg: "bg-orange-500/10",  border: "border-orange-500/25" },
  full:          { color: "text-primary",      bg: "bg-primary/10",     border: "border-primary/25" },
};

const STATUS_CONFIG: Record<string, { label: string; color: string; bg: string; border: string; dot: string; pulse?: boolean }> = {
  pending:   { label: "Queued",    color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/25",  dot: "bg-yellow-400",  pulse: true },
  running:   { label: "Executing", color: "text-primary",     bg: "bg-primary/10",     border: "border-primary/40",     dot: "bg-primary",     pulse: true },
  completed: { label: "Completed", color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/25", dot: "bg-emerald-400" },
  failed:    { label: "Failed",    color: "text-red-400",     bg: "bg-red-500/10",     border: "border-red-500/25",     dot: "bg-red-400" },
};

function StatusBadge({ status }: { status: string }) {
  const s = STATUS_CONFIG[status] ?? STATUS_CONFIG.pending;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm border text-[9px] font-mono uppercase tracking-widest font-bold", s.bg, s.border, s.color)}>
      <span className={cn("w-1.5 h-1.5 rounded-full", s.dot, s.pulse ? "animate-pulse" : "")} />
      {s.label}
    </span>
  );
}

function TypeBadge({ type }: { type: string }) {
  const s = TYPE_STYLES[type] ?? TYPE_STYLES.recon;
  const scanType = SCAN_TYPES.find(t => t.value === type);
  const Icon = scanType?.icon ?? Globe;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm border text-[9px] font-mono uppercase tracking-widest", s.bg, s.border, s.color)}>
      <Icon className="w-3 h-3" />
      {type}
    </span>
  );
}

const isActiveStatus = (status: string) => status === "running" || status === "pending";

export function ScansTab({ projectId, assetCount = 0 }: { projectId: number; assetCount?: number }) {
  const queryClient = useQueryClient();

  // Always poll every 2 s while the Scans tab is mounted.
  // Derive hasActiveScans from the freshly-fetched data, not stale cache.
  const { data: scans, isLoading } = useListScans(projectId, {
    query: { queryKey: getListScansQueryKey(projectId), refetchInterval: 2000 },
  });

  const hasActiveScans = scans?.some(s => isActiveStatus(s.status)) ?? false;

  const [isCreateOpen, setIsCreateOpen] = useState(false);
  // Track which scan is expanded for live log streaming
  const [expandedScanId, setExpandedScanId] = useState<number | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const createScan = useCreateScan();

  // Auto-expand the most recent running/pending scan on mount or when scans update
  useEffect(() => {
    if (!scans) return;
    const active = scans.find(s => isActiveStatus(s.status));
    if (active && expandedScanId === null) {
      setExpandedScanId(active.id);
    }
  }, [scans]);

  // Poll the expanded scan's details at 1.5 s while it's active (real-time log streaming)
  const expandedScan = scans?.find(s => s.id === expandedScanId);
  const expandedIsActive = expandedScan ? isActiveStatus(expandedScan.status) : false;

  const { data: scanDetail } = useGetScan(expandedScanId ?? 0, {
    query: {
      enabled: !!expandedScanId,
      queryKey: getGetScanQueryKey(expandedScanId ?? 0),
      // Poll fast while the expanded scan is running; stop when complete
      refetchInterval: expandedIsActive ? 1500 : false,
    },
  });

  // Auto-scroll log terminal to bottom as lines arrive
  useEffect(() => {
    if (scanDetail?.logs) {
      logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [scanDetail?.logs]);

  const handleCreate = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    createScan.mutate(
      {
        projectId,
        data: {
          name: f.get("name") as string,
          type: (f.get("type") as any) || "recon",
        },
      },
      {
        onSuccess: (newScan) => {
          toast.success("Scan queued — executing now");
          queryClient.invalidateQueries({ queryKey: getListScansQueryKey(projectId) });
          setIsCreateOpen(false);
          // Immediately expand the new scan to show live logs
          setExpandedScanId(newScan.id);
        },
        onError: () => toast.error("Failed to initiate scan"),
      },
    );
  };

  const progressColor = (pct: number) =>
    pct === 100 ? "bg-emerald-500" : pct > 60 ? "bg-primary" : pct > 30 ? "bg-yellow-500" : "bg-orange-500";

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between p-1 pb-2 border-b border-border/50">
        <div className="text-[11px] font-mono text-muted-foreground uppercase tracking-widest flex items-center gap-3">
          {scans?.length ? `${scans.length} execution(s)` : "No scans yet"}
          {hasActiveScans && (
            <span className="text-primary font-bold flex items-center gap-1.5 bg-primary/10 border border-primary/20 px-2 py-0.5 rounded-sm">
              <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
              SYSTEM ACTIVE
            </span>
          )}
        </div>

        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-2 font-mono text-xs uppercase tracking-wider rounded-sm h-8">
              <Play className="w-3.5 h-3.5" />
              Initiate Scan
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg bg-card border-border">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2 font-mono text-sm text-primary uppercase tracking-wider">
                <Radar className="w-4 h-4" /> Execute Scan Sequence
              </DialogTitle>
            </DialogHeader>

            {/* No-asset warning */}
            {assetCount === 0 && (
              <div className="flex items-start gap-3 rounded-sm border border-yellow-500/30 bg-yellow-500/10 px-4 py-3 text-yellow-400">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <div className="text-[11px] font-mono leading-relaxed">
                  <span className="font-bold uppercase tracking-wider">No assets indexed.</span>
                  {" "}Go to the Assets tab and add at least one domain, IP, or URL before scanning. The scanner has nothing to target without an asset.
                </div>
              </div>
            )}

            <form onSubmit={handleCreate} className="space-y-4 pt-1">
              <div className="space-y-2">
                <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Execution Name</Label>
                <Input
                  name="name"
                  required
                  placeholder="e.g. Daily Recon — example.com"
                  className="font-mono text-sm bg-background border-border rounded-sm"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Module Type</Label>
                <Select name="type" defaultValue="recon">
                  <SelectTrigger className="font-mono text-sm bg-background border-border rounded-sm h-auto py-2">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SCAN_TYPES.map(t => {
                      const Icon = t.icon;
                      return (
                        <SelectItem key={t.value} value={t.value}>
                          <div className="flex items-start gap-3 py-1">
                            <Icon className="w-4 h-4 mt-0.5 flex-shrink-0 text-muted-foreground" />
                            <div className="flex flex-col gap-0.5">
                              <div className="flex items-center gap-2">
                                <span className="font-mono font-bold text-xs uppercase">{t.label}</span>
                                <span className="text-[9px] font-mono text-muted-foreground border border-border px-1 rounded-sm">{t.eta}</span>
                              </div>
                              <span className="text-[10px] text-muted-foreground font-sans">{t.desc}</span>
                            </div>
                          </div>
                        </SelectItem>
                      );
                    })}
                  </SelectContent>
                </Select>
              </div>

              {/* Tool legend */}
              <div className="rounded-sm border border-border/40 bg-background/60 px-3 py-2.5 text-[10px] font-mono text-muted-foreground leading-relaxed">
                <span className="text-primary font-bold">Tools used:</span>
                {" "}nmap · dig · openssl · whois · crt.sh · ipinfo.io · Wayback Machine · fetch
              </div>

              <DialogFooter className="pt-2">
                <Button
                  type="submit"
                  disabled={createScan.isPending}
                  className="w-full gap-2 font-mono text-xs uppercase tracking-wider rounded-sm"
                >
                  <Play className="w-4 h-4" />
                  {createScan.isPending ? "Queuing..." : "Deploy Scanner"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Scan list */}
      {isLoading ? (
        <div className="space-y-2">
          {[1, 2, 3].map(i => (
            <div key={i} className="h-16 bg-card rounded-md border border-border animate-pulse" />
          ))}
        </div>
      ) : !scans?.length ? (
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground rounded-md border border-dashed border-border bg-card/30">
          <Radar className="w-8 h-8 mb-3 opacity-20" />
          <p className="text-xs font-mono uppercase tracking-widest mb-2">No Scans Executed</p>
          <p className="text-[10px] font-mono text-muted-foreground/60">
            {assetCount === 0 ? "Add assets first, then initiate a scan." : 'Click "Initiate Scan" to begin.'}
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {scans.map((scan: Scan) => {
            const active = isActiveStatus(scan.status);
            const pct = scan.progress ?? 0;
            const isExpanded = expandedScanId === scan.id;
            // Use live detail for expanded scan, fall back to list data
            const detail = isExpanded ? scanDetail : undefined;
            const liveLogs = detail?.logs ?? (isExpanded ? scan.logs : null);

            return (
              <div
                key={scan.id}
                className={cn(
                  "rounded-md border bg-card overflow-hidden transition-all duration-200",
                  active ? "border-primary/50 bg-primary/5 shadow-[0_0_12px_rgba(0,255,128,0.05)]" : "border-border hover:border-primary/20",
                  isExpanded && "ring-1 ring-primary/20",
                )}
              >
                {/* Row */}
                <div
                  className="flex items-center gap-4 p-4 cursor-pointer hover:bg-accent/20 select-none"
                  onClick={() => setExpandedScanId(isExpanded ? null : scan.id)}
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-2 flex-wrap">
                      <span className="font-mono text-sm font-bold text-foreground truncate">{scan.name}</span>
                      <TypeBadge type={scan.type || "recon"} />
                      <StatusBadge status={scan.status} />
                      {(scan.findingsCount ?? 0) > 0 && (
                        <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded-sm bg-orange-500/10 text-orange-400 border border-orange-500/20 uppercase tracking-widest">
                          {scan.findingsCount} finding{scan.findingsCount !== 1 ? "s" : ""}
                        </span>
                      )}
                    </div>
                    {/* Progress bar */}
                    <div className="flex items-center gap-3">
                      <div className="flex-1 h-1 bg-background border border-border rounded-full overflow-hidden">
                        <div
                          className={cn("h-full transition-all duration-700", progressColor(pct))}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="text-[10px] font-mono font-bold text-muted-foreground w-8 text-right">{pct}%</span>
                      <span className="text-[10px] text-muted-foreground font-mono hidden sm:flex items-center gap-1.5 uppercase tracking-widest border-l border-border/50 pl-3">
                        <Clock className="w-3 h-3" />
                        {scan.startedAt ? formatDate(scan.startedAt) : "—"}
                      </span>
                    </div>
                  </div>
                  <ChevronDown className={cn("w-4 h-4 flex-shrink-0 text-muted-foreground transition-transform duration-200", isExpanded && "rotate-180 text-primary")} />
                </div>

                {/* Live log terminal */}
                <AnimatePresence initial={false}>
                  {isExpanded && (
                    <motion.div
                      key="logs"
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.2 }}
                      className="border-t border-border/50 bg-[#030303]"
                    >
                      {/* Terminal header */}
                      <div className="px-4 py-2 border-b border-border/20 flex items-center justify-between bg-background/30">
                        <span className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground flex items-center gap-1.5">
                          <Terminal className="w-3 h-3" /> Execution Log
                          {liveLogs && (
                            <span className="text-muted-foreground/50 ml-1">
                              · {liveLogs.trim().split("\n").length} lines
                            </span>
                          )}
                        </span>
                        {active && (
                          <span className="text-[9px] font-mono uppercase tracking-widest text-primary flex items-center gap-1.5 animate-pulse">
                            <RefreshCw className="w-3 h-3 animate-spin" /> Live — polling 1.5s
                          </span>
                        )}
                        {!active && scan.status === "completed" && (
                          <span className="text-[9px] font-mono uppercase tracking-widest text-emerald-400 flex items-center gap-1.5">
                            ✓ Scan complete · {scan.findingsCount} finding{scan.findingsCount !== 1 ? "s" : ""}
                          </span>
                        )}
                      </div>

                      {/* Log body */}
                      <div className="p-4 max-h-96 overflow-y-auto" style={{ fontFamily: "monospace" }}>
                        {liveLogs ? (
                          <pre className="text-[11px] leading-relaxed text-emerald-400 whitespace-pre-wrap break-words">
                            {liveLogs}
                            <div ref={logsEndRef} />
                          </pre>
                        ) : active ? (
                          <div className="text-[11px] text-primary/60 font-mono animate-pulse">
                            {">"} Initialising scan worker...<br />
                            {">"} Loading modules: nmap · dig · openssl · whois · crt.sh<br />
                            {">"} Establishing connection to targets...
                          </div>
                        ) : (
                          <div className="text-[11px] text-muted-foreground font-mono">No log output recorded.</div>
                        )}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
