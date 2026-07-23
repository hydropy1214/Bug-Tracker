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
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Play, Terminal, CheckCircle2, AlertCircle, Clock, RefreshCw, Radar, Zap, Globe, ShieldCheck, ChevronDown, ChevronUp } from "lucide-react";
import { toast } from "sonner";
import { formatDate, cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";

const SCAN_TYPES = [
  { value: "recon",         label: "Reconnaissance",  desc: "DNS, OSINT, subdomains",       icon: Globe },
  { value: "enumeration",   label: "Enumeration",     desc: "Ports, endpoints, services",   icon: Radar },
  { value: "vulnerability", label: "Vulnerability",   desc: "CVEs, misconfigurations",      icon: ShieldCheck },
  { value: "full",          label: "Full Attack",     desc: "All module checks combined",   icon: Zap },
];

const TYPE_STYLES: Record<string, { color: string; bg: string; border: string }> = {
  recon:         { color: "text-blue-400",    bg: "bg-blue-500/10",    border: "border-blue-500/25" },
  enumeration:   { color: "text-purple-400",  bg: "bg-purple-500/10",  border: "border-purple-500/25" },
  vulnerability: { color: "text-orange-400",  bg: "bg-orange-500/10",  border: "border-orange-500/25" },
  full:          { color: "text-primary",      bg: "bg-primary/10",     border: "border-primary/25" },
};

const STATUS_CONFIG: Record<string, { label: string; color: string; bg: string; border: string; dot: string; pulse?: boolean }> = {
  pending:   { label: "Queued",    color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/25",  dot: "bg-yellow-400" },
  running:   { label: "Executing", color: "text-primary",     bg: "bg-primary/10",     border: "border-primary/40",     dot: "bg-primary",    pulse: true },
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

export function ScansTab({ projectId }: { projectId: number }) {
  // Check active state without using refetchInterval on the whole list immediately
  const queryClient = useQueryClient();
  const scansData = queryClient.getQueryData<any[]>(getListScansQueryKey(projectId));
  const isActive = (status: string) => status === "running" || status === "pending";
  const hasActiveScans = scansData?.some(s => isActive(s.status)) ?? false;

  const { data: scans, isLoading } = useListScans(projectId, { 
    query: { refetchInterval: hasActiveScans ? 3000 : false } 
  });
  
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [expandedScanId, setExpandedScanId] = useState<number | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  const createScan = useCreateScan();

  const { data: scanDetail } = useGetScan(expandedScanId!, {
    query: {
      enabled: !!expandedScanId,
      queryKey: getGetScanQueryKey(expandedScanId!),
      refetchInterval: expandedScanId && hasActiveScans ? 2000 : false
    },
  });

  // Auto-scroll logs
  useEffect(() => {
    if (expandedScanId && scanDetail?.logs) {
      logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [scanDetail?.logs, expandedScanId]);

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
        toast.success("Scan sequence initiated");
        queryClient.invalidateQueries({ queryKey: getListScansQueryKey(projectId) });
        setIsCreateOpen(false);
      },
      onError: () => toast.error("Failed to initiate scan"),
    });
  };

  const progressColor = (pct: number) =>
    pct === 100 ? "bg-emerald-500" : pct > 60 ? "bg-primary" : pct > 30 ? "bg-yellow-500" : "bg-orange-500";

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between p-1 pb-2 border-b border-border/50">
        <div className="text-[11px] font-mono text-muted-foreground uppercase tracking-widest flex items-center gap-3">
          {scans?.length ? `Log contains ${scans.length} executions` : "Scan log empty"}
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
            <form onSubmit={handleCreate} className="space-y-4 pt-2">
              <div className="space-y-2">
                <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Execution Name</Label>
                <Input name="name" required placeholder="e.g. Daily Vulnerability Sweep" className="font-mono text-sm bg-background border-border rounded-sm" />
              </div>
              <div className="space-y-2">
                <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Module Type</Label>
                <Select name="type" defaultValue="recon">
                  <SelectTrigger className="font-mono text-sm bg-background border-border rounded-sm h-auto py-2"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {SCAN_TYPES.map(t => (
                      <SelectItem key={t.value} value={t.value}>
                        <div className="flex flex-col gap-1 py-1">
                          <span className="font-mono font-bold text-xs uppercase">{t.label}</span>
                          <span className="text-[10px] text-muted-foreground font-sans">{t.desc}</span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <DialogFooter className="pt-4">
                <Button type="submit" disabled={createScan.isPending} className="w-full gap-2 font-mono text-xs uppercase tracking-wider rounded-sm">
                  <Play className="w-4 h-4" />
                  {createScan.isPending ? "Queuing..." : "Deploy Scanner"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* List */}
      {isLoading ? (
        <div className="space-y-2">
          {[1,2,3].map(i => <div key={i} className="h-16 bg-card rounded-md border border-border animate-pulse" />)}
        </div>
      ) : scans?.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground rounded-md border border-dashed border-border bg-card/30">
          <Radar className="w-8 h-8 mb-3 opacity-20" />
          <p className="text-xs font-mono uppercase tracking-widest">No Scans Executed</p>
        </div>
      ) : (
        <div className="space-y-2">
          {scans?.map(scan => {
            const active = isActive(scan.status);
            const pct = scan.progress ?? 0;
            const isExpanded = expandedScanId === scan.id;
            
            return (
              <div
                key={scan.id}
                className={cn(
                  "rounded-md border bg-card overflow-hidden transition-all duration-300",
                  active ? "border-primary/40 bg-primary/5" : "border-border hover:border-primary/20",
                  isExpanded ? "ring-1 ring-primary/20" : ""
                )}
              >
                {/* Row Header */}
                <div 
                  className="flex items-center gap-4 p-4 cursor-pointer hover:bg-accent/20"
                  onClick={() => setExpandedScanId(isExpanded ? null : scan.id)}
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-2 flex-wrap">
                      <span className="font-mono text-sm font-bold text-foreground truncate">{scan.name}</span>
                      <TypeBadge type={scan.type || 'recon'} />
                      <StatusBadge status={scan.status} />
                      {scan.findingsCount !== undefined && scan.findingsCount > 0 && (
                        <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded-sm bg-orange-500/10 text-orange-400 border border-orange-500/20 uppercase tracking-widest">
                          {scan.findingsCount} Detections
                        </span>
                      )}
                    </div>
                    {/* Progress Track */}
                    <div className="flex items-center gap-3">
                      <div className="flex-1 h-1 bg-background border border-border rounded-full overflow-hidden">
                        <div
                          className={cn("h-full transition-all duration-1000", progressColor(pct), active ? "relative" : "")}
                          style={{ width: `${pct}%` }}
                        >
                          {active && <div className="absolute top-0 right-0 bottom-0 w-8 bg-gradient-to-r from-transparent to-white/30 animate-pulse" />}
                        </div>
                      </div>
                      <span className="text-[10px] font-mono font-bold text-muted-foreground w-8 text-right">{pct}%</span>
                      <span className="text-[10px] text-muted-foreground font-mono hidden sm:flex items-center gap-1.5 uppercase tracking-widest border-l border-border/50 pl-3">
                        <Clock className="w-3 h-3" />
                        {scan.startedAt ? formatDate(scan.startedAt) : "—"}
                      </span>
                    </div>
                  </div>
                  <Button variant="ghost" size="icon" className={cn("flex-shrink-0 transition-transform h-8 w-8 rounded-sm", isExpanded ? "rotate-180 text-primary" : "text-muted-foreground")}>
                    <ChevronDown className="w-4 h-4" />
                  </Button>
                </div>

                {/* Inline Logs Panel */}
                <AnimatePresence>
                  {isExpanded && (
                    <motion.div 
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      className="border-t border-border/50 bg-[#050505]"
                    >
                      <div className="p-2 border-b border-border/20 bg-background/50 flex items-center justify-between">
                         <span className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground flex items-center gap-1.5">
                           <Terminal className="w-3 h-3" /> Execution Log
                         </span>
                         {active && (
                           <span className="text-[9px] font-mono uppercase tracking-widest text-primary flex items-center gap-1.5">
                             <RefreshCw className="w-3 h-3 animate-spin" /> Live Stream
                           </span>
                         )}
                      </div>
                      <div className="p-4 max-h-80 overflow-y-auto custom-scrollbar">
                        <pre className="font-mono text-[11px] leading-relaxed text-emerald-500 whitespace-pre-wrap">
                          {scanDetail?.logs || (active ? "Initializing modules...\nEstablishing connection to targets...\n" : "No output available.")}
                          <div ref={logsEndRef} />
                        </pre>
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