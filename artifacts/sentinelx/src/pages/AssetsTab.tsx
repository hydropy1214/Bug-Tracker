import { useState } from "react";
import {
  useListAssets,
  useCreateAsset,
  useDeleteAsset,
  useUpdateAsset,
  getListAssetsQueryKey
} from "@workspace/api-client-react";
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
import type { Asset } from "@workspace/api-client-react";

const TYPE_CONFIG: Record<string, { icon: any; color: string; bg: string; border: string }> = {
  domain:   { icon: Globe,    color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/25" },
  wildcard: { icon: Asterisk, color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/25" },
  ip_range: { icon: Server,   color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/25" },
  url:      { icon: LinkIcon, color: "text-primary",    bg: "bg-primary/10",    border: "border-primary/25" },
  api:      { icon: Database, color: "text-emerald-400",bg: "bg-emerald-500/10",border: "border-emerald-500/25" },
};

const STATUS_CONFIG: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  active:   { color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/25", dot: "bg-emerald-400" },
  inactive: { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/25",   dot: "bg-slate-400" },
  unknown:  { color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/25",  dot: "bg-yellow-400" },
};

function TypeBadge({ type }: { type: string }) {
  const c = TYPE_CONFIG[type] ?? TYPE_CONFIG.domain;
  const Icon = c.icon;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[10px] font-mono uppercase tracking-wider", c.bg, c.border, c.color)}>
      <Icon className="w-3 h-3" />
      {type.replace("_", " ")}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const c = STATUS_CONFIG[status] ?? STATUS_CONFIG.unknown;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[10px] font-mono uppercase tracking-wider", c.bg, c.border, c.color)}>
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
        toast.success("Asset added");
        queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey(projectId) });
        setIsCreateOpen(false);
      },
      onError: () => toast.error("Failed to add asset"),
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
        toast.success("Asset updated");
        queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey(projectId) });
        setEditingAsset(null);
      },
      onError: () => toast.error("Failed to update asset"),
    });
  };

  const handleDelete = (id: number) => {
    if (confirm("Delete this asset?")) {
      deleteAsset.mutate({ id }, {
        onSuccess: () => {
          toast.success("Asset deleted");
          queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey(projectId) });
        },
        onError: () => toast.error("Failed to delete asset"),
      });
    }
  };

  const AssetForm = ({ defaultValues, onSubmit, isPending, submitLabel }: any) => (
    <form onSubmit={onSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label>Asset Value</Label>
        <Input name="value" required placeholder="example.com or 10.0.0.0/24" className="font-mono text-sm" defaultValue={defaultValues?.value} />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Type</Label>
          <Select name="type" defaultValue={defaultValues?.type ?? "domain"}>
            <SelectTrigger><SelectValue /></SelectTrigger>
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
            <Label>Status</Label>
            <Select name="status" defaultValue={defaultValues.status ?? "active"}>
              <SelectTrigger><SelectValue /></SelectTrigger>
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
        <Label>Technologies <span className="text-muted-foreground font-normal">(comma-separated)</span></Label>
        <Input name="technologies" placeholder="Nginx, React, PostgreSQL" defaultValue={defaultValues?.technologies?.join(", ")} />
      </div>
      <div className="space-y-2">
        <Label>Notes</Label>
        <Textarea name="notes" placeholder="Additional context or observations..." className="resize-none" rows={3} defaultValue={defaultValues?.notes ?? ""} />
      </div>
      <DialogFooter>
        <Button type="submit" disabled={isPending} className="w-full">{isPending ? "Saving..." : submitLabel}</Button>
      </DialogFooter>
    </form>
  );

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {assets?.length ? `${assets.length} asset${assets.length !== 1 ? "s" : ""}` : "No assets"}
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-2"><Plus className="w-4 h-4" />Add Asset</Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader><DialogTitle>Add Asset</DialogTitle></DialogHeader>
            <AssetForm onSubmit={handleCreate} isPending={createAsset.isPending} submitLabel="Add Asset" />
          </DialogContent>
        </Dialog>

        {/* Edit dialog */}
        <Dialog open={!!editingAsset} onOpenChange={(o) => !o && setEditingAsset(null)}>
          <DialogContent className="max-w-md">
            <DialogHeader><DialogTitle>Edit Asset</DialogTitle></DialogHeader>
            {editingAsset && (
              <AssetForm defaultValues={editingAsset} onSubmit={handleEdit} isPending={updateAsset.isPending} submitLabel="Save Changes" />
            )}
          </DialogContent>
        </Dialog>
      </div>

      {/* Assets list */}
      {isLoading ? (
        <div className="space-y-2">
          {[1,2,3].map(i => <div key={i} className="h-16 bg-card rounded-lg border border-border animate-pulse" />)}
        </div>
      ) : assets?.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground rounded-xl border border-border/60 bg-card/50">
          <Target className="w-10 h-10 mb-3 opacity-20" />
          <p className="text-sm">No assets added yet.</p>
          <p className="text-xs opacity-60 mt-1">Add domains, IPs, URLs, or API endpoints to this project.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {assets?.map(asset => {
            const tc = TYPE_CONFIG[asset.type] ?? TYPE_CONFIG.domain;
            const Icon = tc.icon;
            return (
              <div
                key={asset.id}
                className="group flex items-center gap-4 p-4 rounded-lg border border-border/60 bg-card hover:bg-accent/40 hover:border-primary/20 transition-all duration-150"
              >
                {/* Type icon */}
                <div className={cn("w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0", tc.bg, tc.border, "border")}>
                  <Icon className={cn("w-4 h-4", tc.color)} />
                </div>

                {/* Main content */}
                <div className="flex-1 min-w-0">
                  <div className="font-mono text-sm font-medium text-primary truncate">{asset.value}</div>
                  <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                    <TypeBadge type={asset.type} />
                    <StatusBadge status={asset.status} />
                    {asset.technologies?.map(t => (
                      <span key={t} className="inline-flex items-center px-2 py-0.5 rounded-md bg-accent border border-border/60 text-[10px] font-mono text-muted-foreground">
                        {t}
                      </span>
                    ))}
                  </div>
                  {asset.notes && (
                    <p className="text-xs text-muted-foreground mt-1.5 line-clamp-1">{asset.notes}</p>
                  )}
                </div>

                {/* Meta & actions */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className="text-[11px] text-muted-foreground font-mono hidden md:block">{formatDate(asset.createdAt)}</span>
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Button variant="ghost" size="icon" className="h-7 w-7 hover:text-primary" onClick={() => setEditingAsset(asset)}>
                      <Edit2 className="w-3.5 h-3.5" />
                    </Button>
                    <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive hover:bg-destructive/10" onClick={() => handleDelete(asset.id)}>
                      <Trash2 className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
