import { useState } from "react";
import {
  useListAssets,
  useCreateAsset,
  useDeleteAsset,
  useUpdateAsset,
  getListAssetsQueryKey
} from "@workspace/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Plus, Trash2, Globe, Server, Link as LinkIcon, Database, Asterisk, Edit2, Target } from "lucide-react";
import { toast } from "sonner";
import { formatDate, cn } from "@/lib/utils";
import type { Asset } from "@workspace/api-client";

const TYPE_CONFIG: Record<string, { icon: any; color: string; bg: string; border: string }> = {
  domain:   { icon: Globe,    color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/25" },
  wildcard: { icon: Asterisk, color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/25" },
  ip_range: { icon: Server,   color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/25" },
  url:      { icon: LinkIcon, color: "text-primary",    bg: "bg-primary/10",    border: "border-primary/25" },
  api:      { icon: Database, color: "text-emerald-400",bg: "bg-emerald-500/10",border: "border-emerald-500/25" },
};

const STATUS_CONFIG: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  active:   { color: "text-primary", bg: "bg-primary/10", border: "border-primary/30", dot: "bg-primary" },
  inactive: { color: "text-muted-foreground",   bg: "bg-accent",   border: "border-border",   dot: "bg-muted-foreground" },
  unknown:  { color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/25",  dot: "bg-yellow-400" },
};

function TypeBadge({ type }: { type: string }) {
  const c = TYPE_CONFIG[type] ?? TYPE_CONFIG.domain;
  const Icon = c.icon;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm border text-[9px] font-mono uppercase tracking-widest", c.bg, c.border, c.color)}>
      <Icon className="w-3 h-3" />
      {type.replace("_", " ")}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const c = STATUS_CONFIG[status] ?? STATUS_CONFIG.unknown;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm border text-[9px] font-mono uppercase tracking-widest", c.bg, c.border, c.color)}>
      <span className={cn("w-1.5 h-1.5 rounded-full", c.dot)} />
      {status}
    </span>
  );
}

export function AssetsTab({ projectId }: { projectId: number }) {
  const { data: assets, isLoading } = useListAssets(projectId);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);

  const queryClient = useQueryClient();
  const createAsset = useCreateAsset();
  const updateAsset = useUpdateAsset();
  const deleteAsset = useDeleteAsset();

  const handleCreate = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const technologies = (f.get("technologies") as string)?.split(",").map(t => t.trim()).filter(Boolean) ?? [];
    createAsset.mutate({
      projectId,
      data: {
        value: f.get("value") as string,
        type: (f.get("type") as any) || "domain",
        notes: f.get("notes") as string,
        technologies,
      }
    }, {
      onSuccess: () => {
        toast.success("Asset indexed");
        queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey(projectId) });
        setIsCreateOpen(false);
      },
      onError: () => toast.error("Failed to index asset"),
    });
  };

  const handleEdit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!editingAsset) return;
    const f = new FormData(e.currentTarget);
    const technologies = (f.get("technologies") as string)?.split(",").map(t => t.trim()).filter(Boolean) ?? [];
    updateAsset.mutate({
      id: editingAsset.id,
      data: {
        value: f.get("value") as string,
        type: (f.get("type") as any) || editingAsset.type,
        status: (f.get("status") as any) || editingAsset.status,
        notes: f.get("notes") as string,
        technologies,
      }
    }, {
      onSuccess: () => {
        toast.success("Asset record updated");
        queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey(projectId) });
        setEditingAsset(null);
      },
      onError: () => toast.error("Failed to update asset"),
    });
  };

  const handleDelete = (id: number) => {
    if (confirm("Remove this asset from index?")) {
      deleteAsset.mutate({ id }, {
        onSuccess: () => {
          toast.success("Asset purged");
          queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey(projectId) });
        },
        onError: () => toast.error("Failed to purge asset"),
      });
    }
  };

  const AssetForm = ({ defaultValues, onSubmit, isPending, submitLabel }: any) => (
    <form onSubmit={onSubmit} className="space-y-4 pt-2">
      <div className="space-y-2">
        <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Asset Value</Label>
        <Input name="value" required placeholder="api.target.com or 10.0.0.0/24" className="font-mono text-sm bg-background border-border rounded-sm" defaultValue={defaultValues?.value} />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Type</Label>
          <Select name="type" defaultValue={defaultValues?.type ?? "domain"}>
            <SelectTrigger className="font-mono text-sm bg-background border-border rounded-sm"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="domain">Domain</SelectItem>
              <SelectItem value="wildcard">Wildcard</SelectItem>
              <SelectItem value="ip_range">IP Range</SelectItem>
              <SelectItem value="url">URL</SelectItem>
              <SelectItem value="api">API Endpoint</SelectItem>
            </SelectContent>
          </Select>
        </div>
        {defaultValues && (
          <div className="space-y-2">
            <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Status</Label>
            <Select name="status" defaultValue={defaultValues.status ?? "active"}>
              <SelectTrigger className="font-mono text-sm bg-background border-border rounded-sm"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
                <SelectItem value="unknown">Unknown</SelectItem>
              </SelectContent>
            </Select>
          </div>
        )}
      </div>
      <div className="space-y-2">
        <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Fingerprint <span className="text-muted-foreground/50 font-normal lowercase">(comma-separated)</span></Label>
        <Input name="technologies" placeholder="Nginx, React, PostgreSQL" className="font-mono text-sm bg-background border-border rounded-sm" defaultValue={defaultValues?.technologies?.join(", ")} />
      </div>
      <div className="space-y-2">
        <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Analyst Notes</Label>
        <Textarea name="notes" placeholder="Context or observations..." className="resize-none font-mono text-sm bg-background border-border rounded-sm" rows={3} defaultValue={defaultValues?.notes ?? ""} />
      </div>
      <DialogFooter className="pt-2">
        <Button type="submit" disabled={isPending} className="w-full font-mono text-xs uppercase tracking-wider rounded-sm">{isPending ? "Executing..." : submitLabel}</Button>
      </DialogFooter>
    </form>
  );

  return (
    <div className="space-y-4">
      {/* Header Toolbar */}
      <div className="flex items-center justify-between p-1">
        <div className="text-[11px] font-mono text-muted-foreground uppercase tracking-widest">
          {assets?.length ? `Index contains ${assets.length} items` : "Index empty"}
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-2 font-mono text-xs uppercase tracking-wider rounded-sm h-8">
              <Plus className="w-4 h-4" />
              Index Asset
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md bg-card border-border">
            <DialogHeader><DialogTitle className="font-mono text-sm text-primary uppercase tracking-wider">Index New Asset</DialogTitle></DialogHeader>
            <AssetForm onSubmit={handleCreate} isPending={createAsset.isPending} submitLabel="Commit to Index" />
          </DialogContent>
        </Dialog>

        {/* Edit Dialog */}
        <Dialog open={!!editingAsset} onOpenChange={(o) => !o && setEditingAsset(null)}>
          <DialogContent className="max-w-md bg-card border-border">
            <DialogHeader><DialogTitle className="font-mono text-sm text-primary uppercase tracking-wider">Modify Asset Record</DialogTitle></DialogHeader>
            {editingAsset && (
              <AssetForm defaultValues={editingAsset} onSubmit={handleEdit} isPending={updateAsset.isPending} submitLabel="Save Record" />
            )}
          </DialogContent>
        </Dialog>
      </div>

      {/* Grid List */}
      {isLoading ? (
        <div className="grid sm:grid-cols-2 gap-3">
          {[1,2,3,4].map(i => <div key={i} className="h-20 bg-card rounded-md border border-border animate-pulse" />)}
        </div>
      ) : assets?.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground rounded-md border border-dashed border-border bg-card/30">
          <Target className="w-8 h-8 mb-3 opacity-20" />
          <p className="text-xs font-mono uppercase tracking-widest">No assets indexed.</p>
        </div>
      ) : (
        <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-3">
          {assets?.map(asset => {
            const tc = TYPE_CONFIG[asset.type] ?? TYPE_CONFIG.domain;
            const Icon = tc.icon;
            return (
              <div
                key={asset.id}
                className="group relative flex flex-col p-4 rounded-md border border-border bg-card hover:bg-accent/30 hover:border-primary/30 transition-all duration-150"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={cn("w-8 h-8 rounded-sm flex items-center justify-center flex-shrink-0 border", tc.bg, tc.border)}>
                      <Icon className={cn("w-3.5 h-3.5", tc.color)} />
                    </div>
                    <div className="min-w-0">
                      <div className="font-mono text-sm font-bold text-foreground truncate" title={asset.value}>{asset.value}</div>
                      <div className="text-[9px] font-mono text-muted-foreground mt-0.5 uppercase tracking-widest">{formatDate(asset.createdAt)}</div>
                    </div>
                  </div>
                  
                  {/* Actions (visible on hover) */}
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Button variant="ghost" size="icon" className="h-6 w-6 hover:text-primary rounded-sm" onClick={() => setEditingAsset(asset)}>
                      <Edit2 className="w-3 h-3" />
                    </Button>
                    <Button variant="ghost" size="icon" className="h-6 w-6 text-destructive hover:text-destructive hover:bg-destructive/10 rounded-sm" onClick={() => handleDelete(asset.id)}>
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-wrap mb-2">
                  <TypeBadge type={asset.type} />
                  <StatusBadge status={asset.status} />
                  {asset.technologies?.map(t => (
                    <span key={t} className="inline-flex items-center px-1.5 py-0.5 rounded-sm bg-accent border border-border text-[9px] font-mono text-muted-foreground uppercase tracking-widest">
                      {t}
                    </span>
                  ))}
                </div>

                {asset.notes && (
                  <p className="text-[11px] font-mono text-muted-foreground mt-auto pt-2 border-t border-border/40 line-clamp-2 leading-relaxed">
                    {asset.notes}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}