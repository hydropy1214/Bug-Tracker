import { useState } from "react";
import {
  useListFindings,
  useCreateFinding,
  useDeleteFinding,
  useGetFinding,
  useUpdateFinding,
  getListFindingsQueryKey,
  getGetFindingQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Plus, Trash2, ShieldAlert, ExternalLink } from "lucide-react";
import { toast } from "sonner";
import { formatDate, cn } from "@/lib/utils";

const SEV: Record<string, { color: string; bg: string; border: string; bar: string; glow: string }> = {
  critical: { color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",    bar: "bg-red-500",    glow: "glow-critical" },
  high:     { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", bar: "bg-orange-500", glow: "glow-high" },
  medium:   { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", bar: "bg-yellow-500", glow: "" },
  low:      { color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30",   bar: "bg-blue-500",   glow: "" },
  info:     { color: "text-slate-400",  bg: "bg-slate-500/10",  border: "border-slate-500/30",  bar: "bg-slate-500",  glow: "" },
};

const STATUS: Record<string, { color: string; bg: string; border: string }> = {
  open:        { color: "text-red-400",     bg: "bg-red-500/10",     border: "border-red-500/25" },
  in_progress: { color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/25" },
  resolved:    { color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/25" },
  wont_fix:    { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/25" },
};

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const CVSS_COLOR = (score: number) =>
  score >= 9.0 ? "text-red-400" :
  score >= 7.0 ? "text-orange-400" :
  score >= 4.0 ? "text-yellow-400" : "text-blue-400";

function SeverityBadge({ severity }: { severity: string }) {
  const s = SEV[severity] ?? SEV.info;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[10px] font-mono uppercase tracking-widest font-bold", s.bg, s.border, s.color)}>
      <span className={cn("w-1.5 h-1.5 rounded-full", s.bar)} />
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const s = STATUS[status] ?? STATUS.open;
  return (
    <span className={cn("inline-flex items-center px-2.5 py-1 rounded-md border text-[10px] font-mono uppercase tracking-wider", s.bg, s.border, s.color)}>
      {status.replace("_", " ")}
    </span>
  );
}

const SEVERITY_FORM_OPTIONS = ["critical", "high", "medium", "low", "info"];
const STATUS_FORM_OPTIONS = [
  { value: "open", label: "Open" },
  { value: "in_progress", label: "In Progress" },
  { value: "resolved", label: "Resolved" },
  { value: "wont_fix", label: "Won't Fix" },
];

export function FindingsTab({ projectId }: { projectId: number }) {
  const { data: findings, isLoading } = useListFindings(projectId);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [viewFindingId, setViewFindingId] = useState<number | null>(null);

  const queryClient = useQueryClient();
  const createFinding = useCreateFinding();
  const deleteFinding = useDeleteFinding();
  const updateFinding = useUpdateFinding();

  const { data: findingDetail } = useGetFinding(viewFindingId!, {
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
        description: f.get("description") as string,
        cve:         (f.get("cve") as string) || undefined,
        cvss:        f.get("cvss") ? parseFloat(f.get("cvss") as string) : undefined,
        evidence:    (f.get("evidence") as string) || undefined,
        remediation: (f.get("remediation") as string) || undefined,
      },
    }, {
      onSuccess: () => {
        toast.success("Finding created");
        queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey(projectId) });
        setIsCreateOpen(false);
        (e.target as HTMLFormElement).reset();
      },
      onError: () => toast.error("Failed to create finding"),
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
        setViewFindingId(null);
      },
      onError: () => toast.error("Failed to update finding"),
    });
  };

  const handleDelete = (id: number, e?: React.MouseEvent) => {
    e?.stopPropagation();
    if (confirm("Delete this finding? This cannot be undone.")) {
      deleteFinding.mutate({ id }, {
        onSuccess: () => {
          toast.success("Finding deleted");
          queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey(projectId) });
          if (viewFindingId === id) setViewFindingId(null);
        },
        onError: () => toast.error("Failed to delete finding"),
      });
    }
  };

  const sorted = [...(findings ?? [])].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
  );

  const FindingForm = ({ defaultValues, onSubmit, isPending, submitLabel }: any) => (
    <form onSubmit={onSubmit} className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div className="col-span-2 space-y-2">
          <Label>Vulnerability Title *</Label>
          <Input name="title" required placeholder="SQL Injection in /api/login" defaultValue={defaultValues?.title} />
        </div>
        <div className="space-y-2">
          <Label>Severity</Label>
          <Select name="severity" defaultValue={defaultValues?.severity ?? "medium"}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              {SEVERITY_FORM_OPTIONS.map(s => (
                <SelectItem key={s} value={s} className="capitalize">{s.charAt(0).toUpperCase() + s.slice(1)}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Status</Label>
          <Select name="status" defaultValue={defaultValues?.status ?? "open"}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              {STATUS_FORM_OPTIONS.map(s => <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>CVE ID</Label>
          <Input name="cve" placeholder="CVE-2024-1234" className="font-mono text-xs" defaultValue={defaultValues?.cve ?? ""} />
        </div>
        <div className="space-y-2">
          <Label>CVSS Score</Label>
          <Input name="cvss" type="number" step="0.1" min="0" max="10" placeholder="9.8" className="font-mono" defaultValue={defaultValues?.cvss ?? ""} />
        </div>
        <div className="col-span-2 space-y-2">
          <Label>Description</Label>
          <Textarea name="description" placeholder="Detailed description of the vulnerability..." className="h-20 resize-none" defaultValue={defaultValues?.description ?? ""} />
        </div>
        <div className="col-span-2 space-y-2">
          <Label>Evidence</Label>
          <Textarea name="evidence" placeholder="HTTP request/response, PoC, screenshots..." className="h-20 font-mono text-xs resize-none" defaultValue={defaultValues?.evidence ?? ""} />
        </div>
        <div className="col-span-2 space-y-2">
          <Label>Remediation</Label>
          <Textarea name="remediation" placeholder="Steps to fix this vulnerability..." className="h-16 resize-none" defaultValue={defaultValues?.remediation ?? ""} />
        </div>
      </div>
      {defaultValues && (
        <DialogFooter className="gap-2 pt-2">
          <Button type="button" variant="destructive" size="sm" onClick={(e) => handleDelete(defaultValues.id, e)} disabled={deleteFinding.isPending}>
            <Trash2 className="w-3 h-3 mr-1.5" />Delete
          </Button>
          <Button type="submit" disabled={isPending}>{isPending ? "Saving..." : submitLabel}</Button>
        </DialogFooter>
      )}
      {!defaultValues && (
        <DialogFooter>
          <Button type="submit" disabled={isPending} className="w-full">{isPending ? "Creating..." : submitLabel}</Button>
        </DialogFooter>
      )}
    </form>
  );

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {sorted.length > 0 ? `${sorted.length} finding${sorted.length !== 1 ? "s" : ""}` : "No findings"}
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-2"><Plus className="w-4 h-4" />Add Finding</Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
            <DialogHeader><DialogTitle>Add Finding</DialogTitle></DialogHeader>
            <FindingForm onSubmit={handleCreate} isPending={createFinding.isPending} submitLabel="Create Finding" />
          </DialogContent>
        </Dialog>
      </div>

      {/* Detail dialog */}
      <Dialog open={!!viewFindingId} onOpenChange={(o) => !o && setViewFindingId(null)}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-muted-foreground" />
              Finding Details
            </DialogTitle>
          </DialogHeader>
          {findingDetail ? (
            <>
              {/* Severity header banner */}
              <div className={cn("flex items-center gap-3 p-3.5 rounded-lg border mb-1", SEV[findingDetail.severity]?.bg, SEV[findingDetail.severity]?.border, (findingDetail.severity === 'critical' || findingDetail.severity === 'high') ? SEV[findingDetail.severity]?.glow : '')}>
                <SeverityBadge severity={findingDetail.severity} />
                <StatusBadge status={findingDetail.status} />
                {findingDetail.cve && (
                  <span className="font-mono text-xs text-muted-foreground flex items-center gap-1">
                    <ExternalLink className="w-3 h-3" />{findingDetail.cve}
                  </span>
                )}
                {findingDetail.cvss != null && (
                  <span className={cn("ml-auto font-mono text-lg font-bold", CVSS_COLOR(findingDetail.cvss))}>
                    {findingDetail.cvss.toFixed(1)}
                  </span>
                )}
              </div>
              <FindingForm
                defaultValues={findingDetail}
                onSubmit={handleUpdate}
                isPending={updateFinding.isPending}
                submitLabel="Save Changes"
              />
              <div className="text-[11px] text-muted-foreground font-mono px-1">Updated: {formatDate(findingDetail.updatedAt)}</div>
            </>
          ) : (
            <div className="py-12 text-center text-muted-foreground animate-pulse text-sm">Loading...</div>
          )}
        </DialogContent>
      </Dialog>

      {/* Findings list */}
      {isLoading ? (
        <div className="space-y-2">
          {[1,2,3].map(i => <div key={i} className="h-16 bg-card rounded-lg border border-border animate-pulse" />)}
        </div>
      ) : sorted.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground rounded-xl border border-border/60 bg-card/50">
          <ShieldAlert className="w-10 h-10 mb-3 opacity-20" />
          <p className="text-sm">No findings recorded yet.</p>
          <p className="text-xs opacity-60 mt-1">Add manually or run a vulnerability scan.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {sorted.map(finding => {
            const s = SEV[finding.severity] ?? SEV.info;
            const st = STATUS[finding.status] ?? STATUS.open;
            return (
              <div
                key={finding.id}
                className={cn(
                  "group flex items-center gap-4 p-4 rounded-lg border bg-card cursor-pointer transition-all duration-150 hover:bg-accent/40",
                  s.border,
                  (finding.severity === "critical" || finding.severity === "high") ? s.glow : "hover:border-primary/30"
                )}
                onClick={() => setViewFindingId(finding.id)}
              >
                {/* Severity bar */}
                <div className={cn("w-1 h-10 rounded-full flex-shrink-0", s.bar)} />

                {/* Main content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <SeverityBadge severity={finding.severity} />
                    {finding.cve && (
                      <span className="text-[10px] font-mono text-muted-foreground/70">{finding.cve}</span>
                    )}
                  </div>
                  <div className="font-medium text-sm text-foreground group-hover:text-primary transition-colors truncate">{finding.title}</div>
                </div>

                {/* Right side */}
                <div className="flex items-center gap-3 flex-shrink-0">
                  <StatusBadge status={finding.status} />
                  {finding.cvss != null && (
                    <span className={cn("font-mono text-sm font-bold", CVSS_COLOR(finding.cvss))}>
                      {finding.cvss.toFixed(1)}
                    </span>
                  )}
                  <span className="text-[11px] text-muted-foreground font-mono hidden sm:block">{formatDate(finding.updatedAt)}</span>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="opacity-0 group-hover:opacity-100 text-destructive hover:text-destructive hover:bg-destructive/10 h-7 w-7 transition-opacity"
                    onClick={(e) => handleDelete(finding.id, e)}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
