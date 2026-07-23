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
import { Plus, Trash2, Search } from "lucide-react";
import { toast } from "sonner";
import { formatDate } from "@/lib/utils";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-destructive/10 text-destructive border-destructive/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  low: "bg-blue-400/10 text-blue-400 border-blue-400/20",
  info: "bg-gray-400/10 text-gray-400 border-gray-400/20",
};

export function FindingsTab({ projectId }: { projectId: number }) {
  const { data: findings, isLoading } = useListFindings(projectId);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [viewFindingId, setViewFindingId] = useState<number | null>(null);

  const queryClient = useQueryClient();
  const createFinding = useCreateFinding();
  const deleteFinding = useDeleteFinding();
  const updateFinding = useUpdateFinding();

  const { data: findingDetail } = useGetFinding(viewFindingId!, { query: { enabled: !!viewFindingId, queryKey: getGetFindingQueryKey(viewFindingId!) } });

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
          cve: formData.get("cve") as string,
          cvss: formData.get("cvss") ? parseFloat(formData.get("cvss") as string) : undefined,
          remediation: formData.get("remediation") as string,
        }
      },
      {
        onSuccess: () => {
          toast.success("Finding created");
          queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey(projectId) });
          setIsCreateOpen(false);
        },
        onError: () => toast.error("Failed to create finding")
      }
    );
  };

  const handleUpdate = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!viewFindingId || !findingDetail) return;
    const formData = new FormData(e.currentTarget);

    updateFinding.mutate({
      id: viewFindingId,
      data: {
        title: formData.get("title") as string,
        severity: (formData.get("severity") as any) || findingDetail.severity,
        status: (formData.get("status") as any) || findingDetail.status,
        description: formData.get("description") as string,
        cve: formData.get("cve") as string,
        cvss: formData.get("cvss") ? parseFloat(formData.get("cvss") as string) : undefined,
        remediation: formData.get("remediation") as string,
      }
    }, {
      onSuccess: () => {
        toast.success("Finding updated");
        queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey(projectId) });
        queryClient.invalidateQueries({ queryKey: getGetFindingQueryKey(viewFindingId) });
        setViewFindingId(null);
      },
      onError: () => toast.error("Failed to update finding")
    });
  };

  const handleDelete = (id: number) => {
    if (confirm("Delete this finding?")) {
      deleteFinding.mutate({ id }, {
        onSuccess: () => {
          toast.success("Finding deleted");
          queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey(projectId) });
        }
      });
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium">Findings</h3>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="w-4 h-4 mr-2" />
              Add Finding
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Add Finding</DialogTitle>
            </DialogHeader>
            <form onSubmit={handleCreate} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2 space-y-2">
                  <Label htmlFor="title">Vulnerability Title</Label>
                  <Input id="title" name="title" required placeholder="SQL Injection in login endpoint" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="severity">Severity</Label>
                  <Select name="severity" defaultValue="medium">
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
                  <Label htmlFor="status">Status</Label>
                  <Select name="status" defaultValue="open">
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
                  <Label htmlFor="cve">CVE (Optional)</Label>
                  <Input id="cve" name="cve" placeholder="CVE-2023-1234" className="font-mono" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="cvss">CVSS Score (Optional)</Label>
                  <Input id="cvss" name="cvss" type="number" step="0.1" min="0" max="10" placeholder="9.8" className="font-mono" />
                </div>
                <div className="col-span-2 space-y-2">
                  <Label htmlFor="description">Description</Label>
                  <Textarea id="description" name="description" className="h-24" />
                </div>
                <div className="col-span-2 space-y-2">
                  <Label htmlFor="remediation">Remediation</Label>
                  <Textarea id="remediation" name="remediation" className="h-24" />
                </div>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={createFinding.isPending}>
                  {createFinding.isPending ? "Saving..." : "Save Finding"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        {/* Edit / View Finding Dialog */}
        <Dialog open={!!viewFindingId} onOpenChange={(o) => !o && setViewFindingId(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Finding Details</DialogTitle>
            </DialogHeader>
            {findingDetail ? (
              <form onSubmit={handleUpdate} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="col-span-2 space-y-2">
                    <Label htmlFor="edit-title">Vulnerability Title</Label>
                    <Input id="edit-title" name="title" defaultValue={findingDetail.title} required />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="edit-severity">Severity</Label>
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
                    <Label htmlFor="edit-status">Status</Label>
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
                    <Label htmlFor="edit-cve">CVE</Label>
                    <Input id="edit-cve" name="cve" defaultValue={findingDetail.cve || ""} className="font-mono" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="edit-cvss">CVSS Score</Label>
                    <Input id="edit-cvss" name="cvss" type="number" step="0.1" min="0" max="10" defaultValue={findingDetail.cvss || ""} className="font-mono" />
                  </div>
                  <div className="col-span-2 space-y-2">
                    <Label htmlFor="edit-description">Description</Label>
                    <Textarea id="edit-description" name="description" defaultValue={findingDetail.description || ""} className="h-32" />
                  </div>
                  <div className="col-span-2 space-y-2">
                    <Label htmlFor="edit-remediation">Remediation</Label>
                    <Textarea id="edit-remediation" name="remediation" defaultValue={findingDetail.remediation || ""} className="h-24" />
                  </div>
                </div>
                <DialogFooter>
                  <Button type="submit" disabled={updateFinding.isPending}>
                    {updateFinding.isPending ? "Updating..." : "Update Finding"}
                  </Button>
                </DialogFooter>
              </form>
            ) : (
              <div className="py-12 text-center text-muted-foreground animate-pulse">Loading finding details...</div>
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
              <TableHead className="text-right">Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow><TableCell colSpan={6} className="text-center py-6 text-muted-foreground">Loading...</TableCell></TableRow>
            ) : findings?.length === 0 ? (
              <TableRow><TableCell colSpan={6} className="text-center py-6 text-muted-foreground">No findings recorded.</TableCell></TableRow>
            ) : (
              findings?.map(finding => (
                <TableRow key={finding.id} className="group cursor-pointer" onClick={(e) => {
                    // prevent open if click was on trash button
                    if ((e.target as HTMLElement).closest('button')) return;
                    setViewFindingId(finding.id);
                  }}>
                  <TableCell>
                    <Badge variant="outline" className={`uppercase tracking-wider font-mono text-[10px] ${SEVERITY_COLORS[finding.severity]}`}>
                      {finding.severity}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="font-medium text-foreground group-hover:text-primary transition-colors">{finding.title}</div>
                    {finding.cve && <div className="text-xs font-mono text-muted-foreground mt-1">{finding.cve}</div>}
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary" className="capitalize text-xs font-normal">
                      {finding.status.replace('_', ' ')}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {finding.cvss ? (
                      <span className="font-mono text-sm">{finding.cvss.toFixed(1)}</span>
                    ) : <span className="text-muted-foreground">-</span>}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {formatDate(finding.updatedAt)}
                  </TableCell>
                  <TableCell className="text-right space-x-2">
                    <Button variant="ghost" size="icon" onClick={() => setViewFindingId(finding.id)} className="hover:bg-accent hover:text-accent-foreground">
                      <Search className="w-4 h-4" />
                    </Button>
                    <Button variant="ghost" size="icon" onClick={() => handleDelete(finding.id)} className="text-destructive hover:text-destructive hover:bg-destructive/10 z-10">
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
