import { useState } from "react";
import {
  useListFindings,
  useCreateFinding,
  useDeleteFinding,
  useGetFinding,
  useUpdateFinding,
  getListFindingsQueryKey,
  getGetFindingQueryKey,
} from "@workspace/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Plus, Trash2, ShieldAlert, ExternalLink, X, Search, Filter } from "lucide-react";
import { toast } from "sonner";
import { formatDate, cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";

const SEV: Record<string, { color: string; bg: string; border: string; bar: string; glow: string }> = {
  critical: { color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",    bar: "bg-red-500",    glow: "glow-critical" },
  high:     { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", bar: "bg-orange-500", glow: "glow-high" },
  medium:   { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", bar: "bg-yellow-500", glow: "" },
  low:      { color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30",   bar: "bg-blue-500",   glow: "" },
  info:     { color: "text-muted-foreground",  bg: "bg-accent",  border: "border-border",  bar: "bg-muted-foreground",  glow: "" },
};

const STATUS: Record<string, { color: string; bg: string; border: string }> = {
  open:        { color: "text-red-400",     bg: "bg-red-500/10",     border: "border-red-500/25" },
  in_progress: { color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/25" },
  resolved:    { color: "text-primary", bg: "bg-primary/10", border: "border-primary/25" },
  wont_fix:    { color: "text-muted-foreground",   bg: "bg-accent",   border: "border-border" },
};

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const CVSS_COLOR = (score: number) =>
  score >= 9.0 ? "text-red-400" :
  score >= 7.0 ? "text-orange-400" :
  score >= 4.0 ? "text-yellow-400" : "text-blue-400";

function SeverityBadge({ severity }: { severity: string }) {
  const s = SEV[severity] ?? SEV.info;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm border text-[9px] font-mono uppercase tracking-widest font-bold", s.bg, s.border, s.color)}>
      <span className={cn("w-1.5 h-1.5 rounded-full", s.bar)} />
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const s = STATUS[status] ?? STATUS.open;
  return (
    <span className={cn("inline-flex items-center px-2 py-0.5 rounded-sm border text-[9px] font-mono uppercase tracking-widest", s.bg, s.border, s.color)}>
      {status.replace("_", " ")}
    </span>
  );
}

function VerificationBadge({ verification, confidence }: { verification?: string; confidence?: number }) {
  const suspected = verification === "suspected";
  const versionMatch = verification === "version_match";
  const informational = verification === "informational";
  return (
    <span className={cn(
      "inline-flex items-center px-2 py-0.5 rounded-sm border text-[9px] font-mono uppercase tracking-widest",
      suspected ? "text-yellow-300 bg-yellow-500/10 border-yellow-500/25" :
      versionMatch ? "text-cyan-300 bg-cyan-500/10 border-cyan-500/25" :
      informational ? "text-muted-foreground bg-accent border-border" :
      "text-emerald-300 bg-emerald-500/10 border-emerald-500/25",
    )}>
      {suspected ? "suspected" : versionMatch ? "version match" : informational ? "informational" : "verified"}{confidence != null ? ` · ${confidence}%` : ""}
    </span>
  );
}

function CvssGauge({ score }: { score: number }) {
  const pct = (score / 10) * 100;
  const color = score >= 9 ? "var(--color-destructive)" : score >= 7 ? "#fb923c" : score >= 4 ? "#facc15" : "#60a5fa";
  return (
    <div className="relative w-16 h-8 overflow-hidden">
      <svg viewBox="0 0 100 50" className="w-full h-full overflow-visible">
        <path d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke="currentColor" strokeWidth="12" strokeLinecap="round" className="text-muted/30" />
        <path d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke={color} strokeWidth="12" strokeLinecap="round" strokeDasharray="125.6" strokeDashoffset={125.6 - (125.6 * pct) / 100} className="transition-all duration-1000 ease-out" />
      </svg>
      <div className="absolute bottom-0 w-full text-center font-mono font-bold text-sm" style={{ color }}>{score.toFixed(1)}</div>
    </div>
  );
}

export function FindingsTab({ projectId }: { projectId: number }) {
  const { data: findings, isLoading } = useListFindings(projectId);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [viewFindingId, setViewFindingId] = useState<number | null>(null);
  
  // Filters
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState("severity");

  const queryClient = useQueryClient();
  const createFinding = useCreateFinding();
  const deleteFinding = useDeleteFinding();
  const updateFinding = useUpdateFinding();

  const { data: findingDetail, isLoading: findingDetailLoading } = useGetFinding(viewFindingId!, {
    query: { enabled: !!viewFindingId, queryKey: getGetFindingQueryKey(viewFindingId!) },
  });

  const handleCreate = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    createFinding.mutate({
      projectId,
      data: {
        title:       f.get("title") as string,
        severity:    (f.get("severity") as any) || "medium",
        status:      (f.get("status") as any) || "open",
        verification: (f.get("verification") as any) || "verified",
        confidence:   f.get("confidence") ? parseInt(f.get("confidence") as string, 10) : 80,
        description: f.get("description") as string,
        cve:         (f.get("cve") as string) || undefined,
        cvss:        f.get("cvss") ? parseFloat(f.get("cvss") as string) : undefined,
        evidence:    (f.get("evidence") as string) || undefined,
        remediation: (f.get("remediation") as string) || undefined,
      },
    }, {
      onSuccess: () => {
        toast.success("Finding recorded");
        queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey(projectId) });
        setIsCreateOpen(false);
        (e.target as HTMLFormElement).reset();
      },
      onError: () => toast.error("Failed to record finding"),
    });
  };

  const handleUpdate = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!viewFindingId || !findingDetail) return;
    const f = new FormData(e.currentTarget);
    updateFinding.mutate({
      id: viewFindingId,
      data: {
        title:       f.get("title") as string,
        severity:    (f.get("severity") as any) || findingDetail.severity,
        status:      (f.get("status") as any) || findingDetail.status,
        verification: (f.get("verification") as any) || findingDetail.verification,
        confidence:   f.get("confidence") ? parseInt(f.get("confidence") as string, 10) : findingDetail.confidence,
        description: f.get("description") as string,
        cve:         (f.get("cve") as string) || undefined,
        cvss:        f.get("cvss") ? parseFloat(f.get("cvss") as string) : undefined,
        evidence:    (f.get("evidence") as string) || undefined,
        remediation: (f.get("remediation") as string) || undefined,
      },
    }, {
      onSuccess: () => {
        toast.success("Finding updated");
        queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey(projectId) });
        queryClient.invalidateQueries({ queryKey: getGetFindingQueryKey(viewFindingId) });
      },
      onError: () => toast.error("Failed to update finding"),
    });
  };

  const handleDelete = (id: number, e?: React.MouseEvent) => {
    e?.stopPropagation();
    if (confirm("Purge this finding? This cannot be undone.")) {
      deleteFinding.mutate({ id }, {
        onSuccess: () => {
          toast.success("Finding purged");
          queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey(projectId) });
          if (viewFindingId === id) setViewFindingId(null);
        },
        onError: () => toast.error("Failed to purge finding"),
      });
    }
  };

  const filtered = findings?.filter(f => f.title.toLowerCase().includes(search.toLowerCase()) || f.cve?.toLowerCase().includes(search.toLowerCase())) ?? [];
  const sorted = [...filtered].sort((a, b) => {
    if (sort === "severity") return (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
    if (sort === "cvss") return (b.cvss || 0) - (a.cvss || 0);
    if (sort === "date") return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
    return 0;
  });

  const FindingForm = ({ defaultValues, onSubmit, isPending, submitLabel }: any) => (
    <form onSubmit={onSubmit} className="space-y-4 pt-1">
      <div className="grid grid-cols-2 gap-4">
        <div className="col-span-2 space-y-2">
          <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Vulnerability Title *</Label>
          <Input name="title" required placeholder="SQL Injection in /api/login" className="font-mono text-sm bg-background border-border rounded-sm" defaultValue={defaultValues?.title} />
        </div>
        <div className="space-y-2">
          <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Severity</Label>
          <Select name="severity" defaultValue={defaultValues?.severity ?? "medium"}>
            <SelectTrigger className="font-mono text-sm bg-background border-border rounded-sm"><SelectValue /></SelectTrigger>
            <SelectContent>
              {["critical", "high", "medium", "low", "info"].map(s => (
                <SelectItem key={s} value={s} className="uppercase font-mono text-[11px] tracking-widest">{s}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Verification</Label>
          <Select name="verification" defaultValue={defaultValues?.verification ?? "verified"}>
            <SelectTrigger className="font-mono text-sm bg-background border-border rounded-sm"><SelectValue /></SelectTrigger>
            <SelectContent>
              {["verified", "suspected", "informational"].map(v => (
                <SelectItem key={v} value={v} className="uppercase font-mono text-[11px] tracking-widest">{v}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Confidence (0–100)</Label>
          <Input name="confidence" type="number" step="1" min="0" max="100" placeholder="80" className="font-mono text-sm bg-background border-border rounded-sm" defaultValue={defaultValues?.confidence ?? 80} />
        </div>
        <div className="space-y-2">
          <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Status</Label>
          <Select name="status" defaultValue={defaultValues?.status ?? "open"}>
            <SelectTrigger className="font-mono text-sm bg-background border-border rounded-sm"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="open" className="font-mono text-[11px] uppercase tracking-widest">Open</SelectItem>
              <SelectItem value="in_progress" className="font-mono text-[11px] uppercase tracking-widest">In Progress</SelectItem>
              <SelectItem value="resolved" className="font-mono text-[11px] uppercase tracking-widest">Resolved</SelectItem>
              <SelectItem value="wont_fix" className="font-mono text-[11px] uppercase tracking-widest">Won't Fix</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">CVE ID</Label>
          <Input name="cve" placeholder="CVE-2024-1234" className="font-mono text-sm bg-background border-border rounded-sm" defaultValue={defaultValues?.cve ?? ""} />
        </div>
        <div className="space-y-2">
          <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">CVSS Score</Label>
          <Input name="cvss" type="number" step="0.1" min="0" max="10" placeholder="9.8" className="font-mono text-sm bg-background border-border rounded-sm" defaultValue={defaultValues?.cvss ?? ""} />
        </div>
        <div className="col-span-2 space-y-2">
          <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Description</Label>
          <Textarea name="description" placeholder="Vulnerability mechanics..." className="h-20 resize-none font-mono text-sm bg-background border-border rounded-sm" defaultValue={defaultValues?.description ?? ""} />
        </div>
        <div className="col-span-2 space-y-2">
          <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Evidence / Payload</Label>
          <Textarea name="evidence" placeholder="HTTP request/response..." className="h-24 font-mono text-[11px] leading-relaxed resize-none bg-black border-border/50 text-emerald-500 rounded-sm p-3" defaultValue={defaultValues?.evidence ?? ""} />
        </div>
        <div className="col-span-2 space-y-2">
          <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Remediation</Label>
          <Textarea name="remediation" placeholder="Fix guidelines..." className="h-16 resize-none font-mono text-sm bg-background border-border rounded-sm" defaultValue={defaultValues?.remediation ?? ""} />
        </div>
      </div>
      
      <div className="pt-4 flex gap-2 w-full">
        {defaultValues && (
          <Button type="button" variant="destructive" size="sm" onClick={(e) => handleDelete(defaultValues.id, e)} disabled={deleteFinding.isPending} className="font-mono text-xs uppercase tracking-wider rounded-sm">
            <Trash2 className="w-3.5 h-3.5 mr-2" />Purge
          </Button>
        )}
        <Button type="submit" disabled={isPending} className="flex-1 font-mono text-xs uppercase tracking-wider rounded-sm">
          {isPending ? "Executing..." : submitLabel}
        </Button>
      </div>
    </form>
  );

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-1 border-b border-border/50 pb-4">
        <div className="flex items-center gap-4 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-64">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
            <Input 
              placeholder="Search findings or CVEs..." 
              value={search} 
              onChange={e => setSearch(e.target.value)} 
              className="pl-8 font-mono text-sm h-8 bg-background border-border rounded-sm" 
            />
          </div>
          <Select value={sort} onValueChange={setSort}>
            <SelectTrigger className="w-[140px] h-8 font-mono text-[10px] uppercase tracking-wider rounded-sm bg-background border-border"><Filter className="w-3 h-3 mr-2" /><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="severity" className="font-mono text-[10px] uppercase">Sort: Severity</SelectItem>
              <SelectItem value="cvss" className="font-mono text-[10px] uppercase">Sort: CVSS</SelectItem>
              <SelectItem value="date" className="font-mono text-[10px] uppercase">Sort: Date</SelectItem>
            </SelectContent>
          </Select>
        </div>
        
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-2 h-8 font-mono text-xs uppercase tracking-wider rounded-sm w-full sm:w-auto">
              <Plus className="w-3.5 h-3.5" />
              Manual Finding
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto bg-card border-border">
            <DialogHeader><DialogTitle className="font-mono text-sm text-primary uppercase tracking-wider flex items-center gap-2"><ShieldAlert className="w-4 h-4"/> Record Finding</DialogTitle></DialogHeader>
            <FindingForm onSubmit={handleCreate} isPending={createFinding.isPending} submitLabel="Commit Record" />
          </DialogContent>
        </Dialog>
      </div>

      {/* Main Content Area */}
      <div className="flex items-start gap-4 relative">
        {/* List */}
        <div className={cn("flex-1 space-y-2 transition-all duration-300", viewFindingId ? "xl:pr-[420px]" : "")}>
          {isLoading ? (
            [1,2,3].map(i => <div key={i} className="h-16 bg-card rounded-md border border-border animate-pulse" />)
          ) : sorted.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-muted-foreground rounded-md border border-dashed border-border bg-card/30">
              <ShieldAlert className="w-8 h-8 mb-3 opacity-20" />
              <p className="text-xs font-mono uppercase tracking-widest">No Findings Recorded</p>
            </div>
          ) : (
            sorted.map(finding => {
              const s = SEV[finding.severity] ?? SEV.info;
              const isSelected = viewFindingId === finding.id;
              return (
                <div
                  key={finding.id}
                  className={cn(
                    "group flex items-center gap-4 p-3 rounded-md border bg-card cursor-pointer transition-all duration-150",
                    isSelected ? "border-primary/50 bg-primary/5" : cn(s.border, "hover:bg-accent/40"),
                    (finding.severity === "critical" || finding.severity === "high") && !isSelected ? s.glow : ""
                  )}
                  onClick={() => setViewFindingId(isSelected ? null : finding.id)}
                >
                  {/* Left severity indicator */}
                  <div className={cn("w-1 h-10 rounded-full flex-shrink-0", s.bar)} />

                  {/* Main content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1.5">
                      <SeverityBadge severity={finding.severity} />
                      <VerificationBadge verification={finding.verification} confidence={finding.confidence} />
                      {finding.cve && (
                        <span className="text-[10px] font-mono text-muted-foreground/70 tracking-widest">{finding.cve}</span>
                      )}
                    </div>
                    <div className="font-mono text-sm text-foreground group-hover:text-primary transition-colors truncate">{finding.title}</div>
                  </div>

                  {/* Right side info */}
                  <div className="flex flex-col items-end justify-center gap-1.5 flex-shrink-0">
                    <StatusBadge status={finding.status} />
                    <div className="flex items-center gap-3">
                      {finding.cvss != null && (
                        <span className={cn("font-mono text-xs font-bold", CVSS_COLOR(finding.cvss))}>
                          CVSS: {finding.cvss.toFixed(1)}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Side Panel (Sticky) */}
        <AnimatePresence>
          {viewFindingId && (
            <motion.div 
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20, transition: { duration: 0.2 } }}
              className="hidden xl:flex w-[420px] flex-shrink-0 sticky top-4 flex-col bg-card border border-border rounded-md shadow-2xl h-[calc(100vh-14rem)] overflow-hidden"
            >
              {/* Header */}
              <div className="p-3 border-b border-border flex items-center justify-between bg-accent/30 flex-shrink-0">
                <div className="font-mono font-bold text-xs uppercase tracking-widest text-primary flex items-center gap-2">
                  <ShieldAlert className="w-3.5 h-3.5" /> Finding Details
                </div>
                <Button variant="ghost" size="icon" className="h-6 w-6 rounded-sm text-muted-foreground hover:text-foreground" onClick={() => setViewFindingId(null)}>
                  <X className="w-3.5 h-3.5" />
                </Button>
              </div>

              {/* Content */}
              <div className="flex-1 overflow-y-auto p-4 custom-scrollbar">
                {findingDetailLoading || !findingDetail ? (
                  <div className="py-12 text-center text-muted-foreground animate-pulse text-[10px] font-mono uppercase tracking-widest">Retrieving Record...</div>
                ) : (
                  <div className="space-y-6">
                    {/* Severity Banner */}
                    <div className={cn("flex items-center gap-4 p-4 rounded-md border", SEV[findingDetail.severity]?.bg, SEV[findingDetail.severity]?.border)}>
                      <div className="flex-1 space-y-2">
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={findingDetail.severity} />
                          <StatusBadge status={findingDetail.status} />
                          <VerificationBadge verification={findingDetail.verification} confidence={findingDetail.confidence} />
                        </div>
                        {findingDetail.cve && (
                          <div className="font-mono text-xs text-foreground flex items-center gap-1.5">
                            <ExternalLink className="w-3.5 h-3.5 text-muted-foreground" />
                            {findingDetail.cve}
                          </div>
                        )}
                      </div>
                      {findingDetail.cvss != null && (
                        <div className="flex-shrink-0 border-l border-border/50 pl-4">
                          <CvssGauge score={findingDetail.cvss} />
                        </div>
                      )}
                    </div>

                    <FindingForm
                      defaultValues={findingDetail}
                      onSubmit={handleUpdate}
                      isPending={updateFinding.isPending}
                      submitLabel="Save Changes"
                    />
                    
                    <div className="text-[9px] text-muted-foreground font-mono text-center pt-4 border-t border-border/40 uppercase tracking-widest">
                      Last modified: {formatDate(findingDetail.updatedAt)}
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      
      {/* Mobile detail dialog (when side panel is hidden via CSS) */}
      <Dialog open={!!viewFindingId && window.innerWidth < 1280} onOpenChange={(o) => !o && setViewFindingId(null)}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto bg-card border-border sm:rounded-md xl:hidden">
          <DialogHeader>
            <DialogTitle className="font-mono text-sm text-primary uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4"/> Finding Details
            </DialogTitle>
          </DialogHeader>
          {findingDetail && (
            <div className="mt-2 space-y-4">
              <div className={cn("flex items-center gap-4 p-4 rounded-md border", SEV[findingDetail.severity]?.bg, SEV[findingDetail.severity]?.border)}>
                <div className="flex-1 space-y-2">
                  <div className="flex items-center gap-2"><SeverityBadge severity={findingDetail.severity} /><StatusBadge status={findingDetail.status} /><VerificationBadge verification={findingDetail.verification} confidence={findingDetail.confidence} /></div>
                  {findingDetail.cve && <div className="font-mono text-xs">{findingDetail.cve}</div>}
                </div>
                {findingDetail.cvss != null && <CvssGauge score={findingDetail.cvss} />}
              </div>
              <FindingForm defaultValues={findingDetail} onSubmit={handleUpdate} isPending={updateFinding.isPending} submitLabel="Save Changes" />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}