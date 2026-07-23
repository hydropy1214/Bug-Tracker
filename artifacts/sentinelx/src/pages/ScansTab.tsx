import { useState, useEffect } from "react";
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
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Play, Terminal, CheckCircle2, AlertCircle, Clock } from "lucide-react";
import { toast } from "sonner";
import { formatDate } from "@/lib/utils";

const STATUS_ICONS: Record<string, React.ReactNode> = {
  running: <div className="flex items-center text-primary"><span className="w-2 h-2 rounded-full bg-primary animate-pulse mr-2" /> Running</div>,
  pending: <div className="flex items-center text-yellow-500"><Clock className="w-3 h-3 mr-2" /> Pending</div>,
  completed: <div className="flex items-center text-muted-foreground"><CheckCircle2 className="w-3 h-3 mr-2" /> Completed</div>,
  failed: <div className="flex items-center text-destructive"><AlertCircle className="w-3 h-3 mr-2" /> Failed</div>,
};

export function ScansTab({ projectId }: { projectId: number }) {
  const { data: scans, isLoading } = useListScans(projectId);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [viewScanId, setViewScanId] = useState<number | null>(null);

  const queryClient = useQueryClient();
  const createScan = useCreateScan();

  const { data: scanDetail } = useGetScan(viewScanId!, { query: { enabled: !!viewScanId, queryKey: getGetScanQueryKey(viewScanId!) } });

  const handleCreate = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    
    createScan.mutate(
      {
        projectId,
        data: {
          name: formData.get("name") as string,
          type: (formData.get("type") as any) || "recon",
        }
      },
      {
        onSuccess: () => {
          toast.success("Scan started");
          queryClient.invalidateQueries({ queryKey: getListScansQueryKey(projectId) });
          setIsCreateOpen(false);
        },
        onError: () => toast.error("Failed to start scan")
      }
    );
  };

  // simulate auto-refresh if any scan is running or pending
  useEffect(() => {
    const hasActiveScans = scans?.some(s => s.status === 'running' || s.status === 'pending');
    if (!hasActiveScans) return;
    const interval = setInterval(() => {
      queryClient.invalidateQueries({ queryKey: getListScansQueryKey(projectId) });
    }, 3000);
    return () => clearInterval(interval);
  }, [scans, projectId, queryClient]);

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium">Scans</h3>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Play className="w-4 h-4 mr-2" />
              Launch Scan
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Launch New Scan</DialogTitle>
            </DialogHeader>
            <form onSubmit={handleCreate} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="name">Scan Name</Label>
                <Input id="name" name="name" required placeholder="Weekly Vulnerability Scan" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="type">Profile</Label>
                <Select name="type" defaultValue="recon">
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="recon">Reconnaissance</SelectItem>
                    <SelectItem value="enumeration">Enumeration</SelectItem>
                    <SelectItem value="vulnerability">Vulnerability Scan</SelectItem>
                    <SelectItem value="full">Full Audit</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={createScan.isPending}>
                  {createScan.isPending ? "Starting..." : "Start Scan"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        {/* View Scan Logs Dialog */}
        <Dialog open={!!viewScanId} onOpenChange={(o) => !o && setViewScanId(null)}>
          <DialogContent className="max-w-4xl bg-black border-border">
            <DialogHeader>
              <DialogTitle className="font-mono text-primary flex items-center">
                <Terminal className="w-4 h-4 mr-2" />
                {scanDetail?.name || 'Scan Logs'}
              </DialogTitle>
            </DialogHeader>
            <div className="bg-gray-900 rounded-md p-4 mt-2 h-96 overflow-y-auto font-mono text-xs text-green-400 whitespace-pre-wrap border border-border shadow-inner relative">
              {scanDetail?.logs ? scanDetail.logs : 'Waiting for output...'}
              {(scanDetail?.status === 'running' || scanDetail?.status === 'pending') && (
                <span className="inline-block w-2 h-4 bg-green-400 animate-pulse align-middle ml-1"></span>
              )}
            </div>
            <div className="flex justify-between items-center text-xs text-muted-foreground mt-2">
              <div className="uppercase tracking-wider">{scanDetail?.status}</div>
              <div>{scanDetail?.progress}% Completed</div>
            </div>
          </DialogContent>
        </Dialog>

      </div>

      <div className="rounded-md border border-border bg-card/50">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Scan Name</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Progress</TableHead>
              <TableHead>Started</TableHead>
              <TableHead className="text-right">Logs</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow><TableCell colSpan={6} className="text-center py-6 text-muted-foreground">Loading...</TableCell></TableRow>
            ) : scans?.length === 0 ? (
              <TableRow><TableCell colSpan={6} className="text-center py-6 text-muted-foreground">No scans found.</TableCell></TableRow>
            ) : (
              scans?.map(scan => (
                <TableRow key={scan.id}>
                  <TableCell>
                    <div className="font-medium text-foreground">{scan.name}</div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="capitalize font-mono text-xs">{scan.type}</Badge>
                  </TableCell>
                  <TableCell>
                    <div className="text-xs font-medium uppercase tracking-wider">
                      {STATUS_ICONS[scan.status]}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <div className="w-24 h-1.5 bg-muted rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-primary transition-all duration-500" 
                          style={{ width: `${scan.progress || 0}%` }}
                        />
                      </div>
                      <span className="text-xs font-mono text-muted-foreground">{scan.progress || 0}%</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {scan.startedAt ? formatDate(scan.startedAt) : '-'}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="icon" onClick={() => setViewScanId(scan.id)} className="hover:bg-accent hover:text-primary">
                      <Terminal className="w-4 h-4" />
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
