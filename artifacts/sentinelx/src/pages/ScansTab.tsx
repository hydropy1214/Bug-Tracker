import { useState, useEffect, useRef } from "react";
import {
  useListScans,
  useCreateScan,
  useGetScan,
  getListScansQueryKey,
  getGetScanQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Play, Terminal, CheckCircle2, AlertCircle, Clock, RefreshCw, Radar, Zap, Globe, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { formatDate, cn } from "@/lib/utils";

const SCAN_TYPES = [
  { value: "recon",         label: "Reconnaissance",  desc: "DNS, OSINT, subdomain & tech fingerprinting",   icon: Globe },
  { value: "enumeration",   label: "Enumeration",      desc: "Ports, services, endpoints & API surface",      icon: Radar },
  { value: "vulnerability", label: "Vulnerability",    desc: "CVE checks, injection & misconfiguration tests", icon: ShieldCheck },
  { value: "full",          label: "Full Scan",        desc: "All of the above in one comprehensive pass",    icon: Zap },
];

const TYPE_STYLES: Record<string, { color: string; bg: string; border: string }> = {
  recon:         { color: "text-blue-400",    bg: "bg-blue-500/10",    border: "border-blue-500/25" },
  enumeration:   { color: "text-purple-400",  bg: "bg-purple-500/10",  border: "border-purple-500/25" },
  vulnerability: { color: "text-orange-400",  bg: "bg-orange-500/10",  border: "border-orange-500/25" },
  full:          { color: "text-primary",      bg: "bg-primary/10",     border: "border-primary/25" },
};

const STATUS_CONFIG: Record<string, { label: string; color: string; bg: string; border: string; dot: string; pulse?: boolean }> = {
  pending:   { label: "Pending",   color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/25",  dot: "bg-yellow-400" },
  running:   { label: "Running",   color: "text-primary",     bg: "bg-primary/10",     border: "border-primary/25",     dot: "bg-primary",    pulse: true },
  completed: { label: "Completed", color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/25", dot: "bg-emerald-400" },
  failed:    { label: "Failed",    color: "text-red-400",     bg: "bg-red-500/10",     border: "border-red-500/25",     dot: "bg-red-400" },
};

function StatusBadge({ status }: { status: string }) {
  const s = STATUS_CONFIG[status] ?? STATUS_CONFIG.pending;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[10px] font-mono uppercase tracking-wider font-bold", s.bg, s.border, s.color)}>
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
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[10px] font-mono uppercase tracking-wider", s.bg, s.border, s.color)}>
      <Icon className="w-3 h-3" />
      {type}
    </span>
  );
}

export function ScansTab({ projectId }: { projectId: number }) {
  const { data: scans, isLoading } = useListScans(projectId);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [viewScanId, setViewScanId] = useState<number | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  const queryClient = useQueryClient();
  const createScan = useCreateScan();

  const isActive = (status: string) => status === "running" || status === "pending";
  const hasActiveScans = scans?.some(s => isActive(s.status)) ?? false;

  const { data: scanDetail } = useGetScan(viewScanId!, {
    query: {
      enabled: !!viewScanId,
      queryKey: getGetScanQueryKey(viewScanId!),
    },
  });

  // Poll scan list while any scans are active
  useEffect(() => {
    if (!hasActiveScans) return;
    const id = setInterval(() => {
      queryClient.invalidateQueries({ queryKey: getListScansQueryKey(projectId) });
    }, 3000);
    return () => clearInterval(id);
  }, [hasActiveScans, projectId, queryClient]);

  // Poll open scan detail when active
  useEffect(() => {
    if (!viewScanId || !scanDetail || !isActive(scanDetail.status)) return;
    const id = setInterval(() => {
      queryClient.invalidateQueries({ queryKey: getGetScanQueryKey(viewScanId) });
    }, 2000);
    return () => clearInterval(id);
  }, [viewScanId, scanDetail, queryClient]);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [scanDetail?.logs]);

  const handleCreate = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    createScan.mutate({
      projectId,
      data: {
        name: f.get("name") as string,
        type: (f.get("type") as any) || "recon",
      },
    }, {
      onSuccess: () => {
        toast.success("Scan queued — starting shortly");
        queryClient.invalidateQueries({ queryKey: getListScansQueryKey(projectId) });
        setIsCreateOpen(false);
      },
      onError: () => toast.error("Failed to launch scan"),
    });
  };

  const progressColor = (pct: number) =>
    pct === 100 ? "bg-emerald-500" : pct > 60 ? "bg-primary" : pct > 30 ? "bg-yellow-500" : "bg-orange-500";

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {scans?.length ? `${scans.length} scan${scans.length !== 1 ? "s" : ""}` : "No scans"}
          {hasActiveScans && (
            <span className="ml-3 text-primary font-mono text-xs inline-flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
              ACTIVE
            </span>
          )}
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-2">
              <Play className="w-4 h-4" />
              Launch Scan
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Radar className="w-4 h-4 text-primary" />
                Launch New Scan
              </DialogTitle>
            </DialogHeader>
            <form onSubmit={handleCreate} className="space-y-4 pt-1">
              <div className="space-y-2">
                <Label>Scan Name</Label>
                <Input name="name" required placeholder="e.g. Weekly Vulnerability Sweep" />
              </div>
              <div className="space-y-2">
                <Label>Scan Type</Label>
                <Select name="type" defaultValue="recon">
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {SCAN_TYPES.map(t => (
                      <SelectItem key={t.value} value={t.value}>
                        <div className="flex flex-col gap-0.5">
                          <span className="font-medium">{t.label}</span>
                          <span className="text-xs text-muted-foreground">{t.desc}</span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {/* Type info cards */}
              <div className="grid grid-cols-2 gap-2 pt-1">
                {SCAN_TYPES.map(t => {
                  const ts = TYPE_STYLES[t.value];
                  const Icon = t.icon;
                  return (
                    <div key={t.value} className={cn("p-3 rounded-lg border", ts.bg, ts.border)}>
                      <div className={cn("flex items-center gap-1.5 text-xs font-mono font-bold mb-1", ts.color)}>
                        <Icon className="w-3 h-3" />
                        {t.label}
                      </div>
                      <p className="text-[10px] text-muted-foreground leading-relaxed">{t.desc}</p>
                    </div>
                  );
                })}
              </div>
              <DialogFooter>
                <Button type="submit" disabled={createScan.isPending} className="w-full gap-2">
                  <Play className="w-4 h-4" />
                  {createScan.isPending ? "Queuing..." : "Launch Scan"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Log viewer dialog */}
      <Dialog open={!!viewScanId} onOpenChange={(o) => !o && setViewScanId(null)}>
        <DialogContent className="max-w-4xl max-h-[80vh] flex flex-col terminal-bg border-border/60">
          <DialogHeader className="flex-shrink-0 border-b border-border/40 pb-3">
            <DialogTitle className="font-mono text-primary flex items-center gap-2 text-sm">
              <Terminal className="w-4 h-4" />
              {scanDetail?.name ?? "Scan Logs"}
              {scanDetail && isActive(scanDetail.status) && (
                <span className="ml-2 flex items-center gap-1.5 text-xs text-muted-foreground">
                  <RefreshCw className="w-3 h-3 animate-spin" />
                  Live
                </span>
              )}
            </DialogTitle>
          </DialogHeader>

          {scanDetail && (
            <div className="flex-shrink-0 py-2 border-b border-border/30 space-y-2">
              <div className="flex items-center gap-4 text-xs">
                <StatusBadge status={scanDetail.status} />
                <TypeBadge type={scanDetail.type} />
                {scanDetail.findingsCount > 0 && (
                  <span className="ml-auto font-mono text-orange-400 font-bold">
                    {scanDetail.findingsCount} finding{scanDetail.findingsCount !== 1 ? "s" : ""} discovered
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3">
                <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className={cn("h-full rounded-full transition-all duration-500", progressColor(scanDetail.progress ?? 0))}
                    style={{ width: `${scanDetail.progress ?? 0}%` }}
                  />
                </div>
                <span className="text-xs font-mono text-muted-foreground w-10 text-right">{scanDetail.progress ?? 0}%</span>
              </div>
            </div>
          )}

          <div className="flex-1 overflow-auto min-h-[200px]">
            <pre className="font-mono text-xs text-emerald-400 whitespace-pre-wrap leading-5 p-4">
              {scanDetail?.logs || (isActive(scanDetail?.status ?? "pending") ? "Initializing scan engine..." : "No output available.")}
              <div ref={logsEndRef} />
            </pre>
          </div>

          {scanDetail?.completedAt && (
            <div className="flex-shrink-0 text-[11px] text-muted-foreground border-t border-border/30 pt-2 font-mono flex items-center gap-2">
              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
              Completed: {formatDate(scanDetail.completedAt)}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Scans list */}
      {isLoading ? (
        <div className="space-y-2">
          {[1,2].map(i => <div key={i} className="h-20 bg-card rounded-lg border border-border animate-pulse" />)}
        </div>
      ) : scans?.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground rounded-xl border border-border/60 bg-card/50">
          <Radar className="w-10 h-10 mb-3 opacity-20" />
          <p className="text-sm">No scans launched yet.</p>
          <p className="text-xs opacity-60 mt-1">Launch a scan to begin discovering vulnerabilities.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {scans?.map(scan => {
            const active = isActive(scan.status);
            const pct = scan.progress ?? 0;
            return (
              <div
                key={scan.id}
                className={cn(
                  "group flex items-center gap-4 p-4 rounded-lg border bg-card transition-all duration-150",
                  active ? "border-primary/25 bg-primary/5" : "border-border/60 hover:bg-accent/40 hover:border-primary/20"
                )}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <span className="font-medium text-sm text-foreground">{scan.name}</span>
                    <TypeBadge type={scan.type} />
                    <StatusBadge status={scan.status} />
                  </div>
                  {/* Progress bar */}
                  <div className="flex items-center gap-3">
                    <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                      <div
                        className={cn("h-full rounded-full transition-all duration-500", progressColor(pct))}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <span className="text-[11px] font-mono text-muted-foreground w-8 text-right">{pct}%</span>
                    <span className="text-[11px] text-muted-foreground font-mono hidden sm:block">
                      {scan.startedAt ? formatDate(scan.startedAt) : "—"}
                    </span>
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-2 flex-shrink-0 hover:text-primary hover:border-primary/40"
                  onClick={() => setViewScanId(scan.id)}
                >
                  <Terminal className="w-3.5 h-3.5" />
                  Logs
                </Button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
