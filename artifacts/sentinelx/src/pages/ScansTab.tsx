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
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Play, Terminal, CheckCircle2, AlertCircle, Clock, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { formatDate } from "@/lib/utils";

const STATUS_ICONS: Record<string, React.ReactNode> = {
  running: (
    <div className="flex items-center text-primary">
      <span className="w-2 h-2 rounded-full bg-primary animate-pulse mr-2" />
      Running
    </div>
  ),
  pending: (
    <div className="flex items-center text-yellow-500">
      <Clock className="w-3 h-3 mr-2" />
      Pending
    </div>
  ),
  completed: (
    <div className="flex items-center text-emerald-500">
      <CheckCircle2 className="w-3 h-3 mr-2" />
      Completed
    </div>
  ),
  failed: (
    <div className="flex items-center text-destructive">
      <AlertCircle className="w-3 h-3 mr-2" />
      Failed
    </div>
  ),
};

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
      refetchInterval: viewScanId && scanDetail && isActive(scanDetail.status) ? 2000 : false,
    },
  });

  // Poll the scan list while any scans are active
  useEffect(() => {
    if (!hasActiveScans) return;
    const id = setInterval(() => {
      queryClient.invalidateQueries({ queryKey: getListScansQueryKey(projectId) });
    }, 3000);
    return () => clearInterval(id);
  }, [hasActiveScans, projectId, queryClient]);

  // Also poll the open scan detail when it is active
  useEffect(() => {
    if (!viewScanId) return;
    if (!scanDetail || !isActive(scanDetail.status)) return;
    const id = setInterval(() => {
      queryClient.invalidateQueries({ queryKey: getGetScanQueryKey(viewScanId) });
    }, 2000);
    return () => clearInterval(id);
  }, [viewScanId, scanDetail, queryClient]);

  // Auto-scroll logs to bottom
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [scanDetail?.logs]);

  const handleCreate = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    createScan.mutate(
      {
        projectId,
        data: {
          name: formData.get("name") as string,
          type: (formData.get("type") as any) || "recon",
        },
      },
      {
        onSuccess: () => {
          toast.success("Scan queued — it will start momentarily");
          queryClient.invalidateQueries({ queryKey: getListScansQueryKey(projectId) });
          setIsCreateOpen(false);
        },
        onError: () => toast.error("Failed to start scan"),
      }
    );
  };

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
                <Label htmlFor="scan-name">Scan Name</Label>
                <Input id="scan-name" name="name" required placeholder="Weekly Vulnerability Scan" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="scan-type">Scan Type</Label>
                <Select name="type" defaultValue="recon">
                  <SelectTrigger id="scan-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="recon">Recon — DNS, OSINT, tech fingerprinting</SelectItem>
                    <SelectItem value="enumeration">Enumeration — ports, services, endpoints</SelectItem>
                    <SelectItem value="vulnerability">Vulnerability — CVE checks, injection tests</SelectItem>
                    <SelectItem value="full">Full — all of the above</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={createScan.isPending}>
                  {createScan.isPending ? "Queuing..." : "Launch Scan"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Scan Log Dialog */}
      <Dialog open={!!viewScanId} onOpenChange={(o) => !o && setViewScanId(null)}>
        <DialogContent className="max-w-4xl max-h-[80vh] flex flex-col bg-zinc-950 border-border">
          <DialogHeader className="flex-shrink-0">
            <DialogTitle className="font-mono text-primary flex items-center gap-2">
              <Terminal className="w-4 h-4" />
              {scanDetail?.name || "Scan Logs"}
              <span className="ml-auto text-xs text-muted-foreground font-normal">
                {scanDetail && isActive(scanDetail.status) && (
                  <span className="flex items-center gap-1">
                    <RefreshCw className="w-3 h-3 animate-spin" />
                    Live
                  </span>
                )}
              </span>
            </DialogTitle>
          </DialogHeader>

          {scanDetail && (
            <div className="flex items-center gap-4 text-xs text-muted-foreground flex-shrink-0 py-1 border-b border-border/30">
              <span className="uppercase tracking-wider font-mono">
                {STATUS_ICONS[scanDetail.status]}
              </span>
              <span className="font-mono">{scanDetail.progress ?? 0}%</span>
              <div className="flex-1">
                <Progress value={scanDetail.progress ?? 0} className="h-1" />
              </div>
              {scanDetail.findingsCount > 0 && (
                <span className="text-orange-400 font-mono">
                  {scanDetail.findingsCount} finding{scanDetail.findingsCount !== 1 ? "s" : ""} discovered
                </span>
              )}
            </div>
          )}

          <div className="flex-1 overflow-auto">
            <pre className="font-mono text-xs text-emerald-400 whitespace-pre-wrap leading-5 p-2 min-h-[200px]">
              {scanDetail?.logs
                ? scanDetail.logs
                : isActive(scanDetail?.status ?? "pending")
                  ? "Initializing..."
                  : "No output available."}
              <div ref={logsEndRef} />
            </pre>
          </div>

          {scanDetail?.completedAt && (
            <div className="flex-shrink-0 text-xs text-muted-foreground border-t border-border/30 pt-2 font-mono">
              Completed: {formatDate(scanDetail.completedAt)}
            </div>
          )}
        </DialogContent>
      </Dialog>

      <div className="rounded-md border border-border bg-card/50">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Progress</TableHead>
              <TableHead>Started</TableHead>
              <TableHead className="text-right">Logs</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-6 text-muted-foreground">
                  Loading...
                </TableCell>
              </TableRow>
            ) : scans?.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-12 text-muted-foreground">
                  <Terminal className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <div>No scans yet. Launch one to get started.</div>
                </TableCell>
              </TableRow>
            ) : (
              scans?.map(scan => (
                <TableRow key={scan.id}>
                  <TableCell>
                    <div className="font-medium text-foreground">{scan.name}</div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="capitalize font-mono text-xs">
                      {scan.type}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="text-xs font-medium">{STATUS_ICONS[scan.status]}</div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <div className="w-24 h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full bg-primary transition-all duration-500"
                          style={{ width: `${scan.progress ?? 0}%` }}
                        />
                      </div>
                      <span className="text-xs font-mono text-muted-foreground">
                        {scan.progress ?? 0}%
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {scan.startedAt ? formatDate(scan.startedAt) : "—"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => setViewScanId(scan.id)}
                      className="hover:bg-accent hover:text-primary"
                    >
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
