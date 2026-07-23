import { useState } from "react";
import { 
  useListFindings, 
  useCreateFinding, 
  useDeleteFinding, 
  useGetFinding,
  useUpdateFinding,
  getListFindingsQueryKey,
  getGetFindingQueryKey
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Plus, Trash2, ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { formatDate } from "@/lib/utils";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-destructive/10 text-destructive border-destructive/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  low: "bg-blue-400/10 text-blue-400 border-blue-400/20",
  info: "bg-gray-400/10 text-gray-400 border-gray-400/20",
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

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
    const formData = new FormData(e.currentTarget);
    createFinding.mutate(
      {
        projectId,
        data: {
          title: formData.get("title") as string,
          severity: (formData.get("severity") as any) || "medium",
          status: (formData.get("status") as any) || "open",
          description: formData.get("description") as string,
          cve: (formData.get("cve") as string) || undefined,
          cvss: formData.get("cvss") ? parseFloat(formData.get("cvss") as string) : undefined,
          evidence: (formData.get("evidence") as string) || undefined,
          remediation: (formData.get("remediation") as string) || undefined,
        },
      },
      {
        onSuccess: () => {
          toast.success("Finding created");
          queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey(projectId) });
          setIsCreateOpen(false);
          (e.target as HTMLFormElement).reset();
        },
        onError: () => toast.error("Failed to create finding"),
      }
    );
  };

  const handleUpdate = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!viewFindingId || !findingDetail) return;
    const formData = new FormData(e.currentTarget);
    updateFinding.mutate(
      {
        id: viewFindingId,
        data: {
          title: formData.get("title") as string,
          severity: (formData.get("severity") as any) || findingDetail.severity,
          status: (formData.get("status") as any) || findingDetail.status,
          description: formData.get("description") as string,
          cve: (formData.get("cve") as string) || undefined,
          cvss: formData.get("cvss") ? parseFloat(formData.get("cvss") as string) : undefined,
          evidence: (formData.get("evidence") as string) || undefined,
          remediation: (formData.get("remediation") as string) || undefined,
        },
      },
      {
        onSuccess: () => {
          toast.success("Finding updated");
          queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey(projectId) });
          queryClient.invalidateQueries({ queryKey: getGetFindingQueryKey(viewFindingId) });
          setViewFindingId(null);
        },
        onError: () => toast.error("Failed to update finding"),
      }
    );
  };

  const handleDelete = (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    if (confirm("Delete this finding? This cannot be undone.")) {
      deleteFinding.mutate(
        { id },
        {
          onSuccess: () => {
            toast.success("Finding deleted");
            queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey(projectId) });
            if (viewFindingId === id) setViewFindingId(null);
          },
          onError: () => toast.error("Failed to delete finding"),
        }
      );
    }
  };

  const sorted = [...(findings ?? [])].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
  );

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium">Findings</h3>

        {/* Create Finding Dialog */}
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="w-4 h-4 mr-2" />
              Add Finding
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Add Finding</DialogTitle>
            </DialogHeader>
            <form onSubmit={handleCreate} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2 space-y-2">
                  <Label htmlFor="title">Vulnerability Title *</Label>
                  <Input id="title" name="title" required placeholder="SQL Injection in login endpoint" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="severity">Severity</Label>
                  <Select name="severity" defaultValue="medium">
                    <SelectTrigger id="severity"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="info">Info</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="status">Status</Label>
                  <Select name="status" defaultValue="open">
                    <SelectTrigger id="status"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="open">Open</SelectItem>
                      <SelectItem value="in_progress">In Progress</SelectItem>
                      <SelectItem value="resolved">Resolved</SelectItem>
                      <SelectItem value="wont_fix">Won't Fix</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="cve">CVE ID</Label>
                  <Input id="cve" name="cve" placeholder="CVE-2023-1234" className="font-mono" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="cvss">CVSS Score</Label>
                  <Input id="cvss" name="cvss" type="number" step="0.1" min="0" max="10" placeholder="9.8" className="font-mono" />
                </div>
                <div className="col-span-2 space-y-2">
                  <Label htmlFor="description">Description</Label>
                  <Textarea id="description" name="description" placeholder="Detailed description of the vulnerability..." className="h-24" />
                </div>
                <div className="col-span-2 space-y-2">
                  <Label htmlFor="evidence">Evidence</Label>
                  <Textarea id="evidence" name="evidence" placeholder="HTTP request/response, screenshots, PoC..." className="h-20 font-mono text-xs" />
                </div>
                <div className="col-span-2 space-y-2">
                  <Label htmlFor="remediation">Remediation</Label>
                  <Textarea id="remediation" name="remediation" placeholder="Steps to fix this vulnerability..." className="h-20" />
                </div>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={createFinding.isPending}>
                  {createFinding.isPending ? "Creating..." : "Create Finding"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        {/* Edit / View Finding Dialog */}
        <Dialog open={!!viewFindingId} onOpenChange={(o) => !o && setViewFindingId(null)}>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Finding Details</DialogTitle>
            </DialogHeader>
            {findingDetail ? (
              <form onSubmit={handleUpdate} className="space-y-4">
                {/* Status banner */}
                <div className={`flex items-center gap-3 p-3 rounded-md border ${SEVERITY_COLORS[findingDetail.severity]}`}>
                  <ShieldAlert className="w-4 h-4 flex-shrink-0" />
                  <div className="text-xs font-mono uppercase tracking-widest">{findingDetail.severity}</div>
                  {findingDetail.cvss && (
                    <div className="ml-auto font-mono text-sm font-bold">CVSS {findingDetail.cvss.toFixed(1)}</div>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="col-span-2 space-y-2">
                    <Label htmlFor="edit-title">Vulnerability Title</Label>
                    <Input id="edit-title" name="title" defaultValue={findingDetail.title} required />
                  </div>
                  <div className="space-y-2">
                    <Label>Severity</Label>
                    <Select name="severity" defaultValue={findingDetail.severity}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="critical">Critical</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="low">Low</SelectItem>
                        <SelectItem value="info">Info</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Status</Label>
                    <Select name="status" defaultValue={findingDetail.status}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="open">Open</SelectItem>
                        <SelectItem value="in_progress">In Progress</SelectItem>
                        <SelectItem value="resolved">Resolved</SelectItem>
                        <SelectItem value="wont_fix">Won't Fix</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="edit-cve">CVE ID</Label>
                    <Input id="edit-cve" name="cve" defaultValue={findingDetail.cve ?? ""} className="font-mono" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="edit-cvss">CVSS Score</Label>
                    <Input id="edit-cvss" name="cvss" type="number" step="0.1" min="0" max="10" defaultValue={findingDetail.cvss ?? ""} className="font-mono" />
                  </div>
                  <div className="col-span-2 space-y-2">
                    <Label htmlFor="edit-description">Description</Label>
                    <Textarea id="edit-description" name="description" defaultValue={findingDetail.description ?? ""} className="h-24" />
                  </div>
                  <div className="col-span-2 space-y-2">
                    <Label htmlFor="edit-evidence">Evidence</Label>
                    <Textarea id="edit-evidence" name="evidence" defaultValue={findingDetail.evidence ?? ""} className="h-20 font-mono text-xs" placeholder="HTTP request/response, screenshots, PoC..." />
                  </div>
                  <div className="col-span-2 space-y-2">
                    <Label htmlFor="edit-remediation">Remediation</Label>
                    <Textarea id="edit-remediation" name="remediation" defaultValue={findingDetail.remediation ?? ""} className="h-20" />
                  </div>
                </div>

                <div className="text-xs text-muted-foreground font-mono">
                  Last updated: {formatDate(findingDetail.updatedAt)}
                </div>

                <DialogFooter className="gap-2">
                  <Button
                    type="button"
                    variant="destructive"
                    size="sm"
                    onClick={(e) => handleDelete(findingDetail.id, e)}
                    disabled={deleteFinding.isPending}
                  >
                    <Trash2 className="w-3 h-3 mr-1" />
                    Delete
                  </Button>
                  <Button type="submit" disabled={updateFinding.isPending}>
                    {updateFinding.isPending ? "Saving..." : "Save Changes"}
                  </Button>
                </DialogFooter>
              </form>
            ) : (
              <div className="py-12 text-center text-muted-foreground animate-pulse">
                Loading finding details...
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>

      <div className="rounded-md border border-border bg-card/50">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Severity</TableHead>
              <TableHead>Title</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>CVSS</TableHead>
              <TableHead>Updated</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-6 text-muted-foreground">
                  Loading...
                </TableCell>
              </TableRow>
            ) : sorted.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-12 text-muted-foreground">
                  <ShieldAlert className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <div>No findings recorded yet.</div>
                </TableCell>
              </TableRow>
            ) : (
              sorted.map(finding => (
                <TableRow
                  key={finding.id}
                  className="group cursor-pointer hover:bg-accent/30"
                  onClick={() => setViewFindingId(finding.id)}
                >
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={`uppercase tracking-wider font-mono text-[10px] ${SEVERITY_COLORS[finding.severity]}`}
                    >
                      {finding.severity}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="font-medium text-foreground group-hover:text-primary transition-colors">
                      {finding.title}
                    </div>
                    {finding.cve && (
                      <div className="text-xs font-mono text-muted-foreground mt-0.5">{finding.cve}</div>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary" className="capitalize text-xs font-normal">
                      {finding.status.replace("_", " ")}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {finding.cvss != null ? (
                      <span className="font-mono text-sm">{finding.cvss.toFixed(1)}</span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {formatDate(finding.updatedAt)}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={(e) => handleDelete(finding.id, e)}
                      className="text-destructive hover:text-destructive hover:bg-destructive/10"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
