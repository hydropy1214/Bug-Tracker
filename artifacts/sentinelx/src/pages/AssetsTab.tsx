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
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Plus, Trash2, Globe, Server, Link as LinkIcon, Database, Asterisk, Edit2 } from "lucide-react";
import { toast } from "sonner";
import { formatDate } from "@/lib/utils";
import type { Asset } from "@workspace/api-client-react";

const TYPE_ICONS: Record<string, React.ReactNode> = {
  domain: <Globe className="w-4 h-4" />,
  wildcard: <Asterisk className="w-4 h-4" />,
  ip_range: <Server className="w-4 h-4" />,
  url: <LinkIcon className="w-4 h-4" />,
  api: <Database className="w-4 h-4" />,
};

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
    const formData = new FormData(e.currentTarget);
    const technologiesStr = formData.get("technologies") as string;
    const technologies = technologiesStr ? technologiesStr.split(',').map(t => t.trim()).filter(Boolean) : [];

    createAsset.mutate(
      {
        projectId,
        data: {
          value: formData.get("value") as string,
          type: (formData.get("type") as any) || "domain",
          notes: formData.get("notes") as string,
          technologies,
        }
      },
      {
        onSuccess: () => {
          toast.success("Asset added");
          queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey(projectId) });
          setIsCreateOpen(false);
        },
        onError: () => toast.error("Failed to add asset")
      }
    );
  };

  const handleEdit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!editingAsset) return;
    const formData = new FormData(e.currentTarget);
    const technologiesStr = formData.get("technologies") as string;
    const technologies = technologiesStr ? technologiesStr.split(',').map(t => t.trim()).filter(Boolean) : [];

    updateAsset.mutate(
      {
        id: editingAsset.id,
        data: {
          value: formData.get("value") as string,
          type: (formData.get("type") as any) || editingAsset.type,
          status: (formData.get("status") as any) || editingAsset.status,
          notes: formData.get("notes") as string,
          technologies,
        }
      },
      {
        onSuccess: () => {
          toast.success("Asset updated");
          queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey(projectId) });
          setEditingAsset(null);
        },
        onError: () => toast.error("Failed to update asset")
      }
    );
  };

  const handleDelete = (id: number) => {
    if (confirm("Delete this asset?")) {
      deleteAsset.mutate({ id }, {
        onSuccess: () => {
          toast.success("Asset deleted");
          queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey(projectId) });
        }
      });
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium">Assets</h3>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="w-4 h-4 mr-2" />
              Add Asset
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add Asset</DialogTitle>
            </DialogHeader>
            <form onSubmit={handleCreate} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="value">Asset Value</Label>
                <Input id="value" name="value" required placeholder="example.com or 10.0.0.0/24" className="font-mono" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="type">Type</Label>
                <Select name="type" defaultValue="domain">
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
              <div className="space-y-2">
                <Label htmlFor="technologies">Technologies (comma-separated)</Label>
                <Input id="technologies" name="technologies" placeholder="Nginx, React, PHP" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="notes">Notes</Label>
                <Textarea id="notes" name="notes" placeholder="Additional context" />
              </div>
              <DialogFooter>
                <Button type="submit" disabled={createAsset.isPending}>
                  {createAsset.isPending ? "Adding..." : "Add"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        {/* Edit Dialog */}
        <Dialog open={!!editingAsset} onOpenChange={(o) => !o && setEditingAsset(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Edit Asset</DialogTitle>
            </DialogHeader>
            {editingAsset && (
              <form onSubmit={handleEdit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="edit-value">Asset Value</Label>
                  <Input id="edit-value" name="value" defaultValue={editingAsset.value} required className="font-mono" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="edit-type">Type</Label>
                  <Select name="type" defaultValue={editingAsset.type}>
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
                <div className="space-y-2">
                  <Label htmlFor="edit-status">Status</Label>
                  <Select name="status" defaultValue={editingAsset.status}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="active">Active</SelectItem>
                      <SelectItem value="inactive">Inactive</SelectItem>
                      <SelectItem value="unknown">Unknown</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="edit-technologies">Technologies (comma-separated)</Label>
                  <Input id="edit-technologies" name="technologies" defaultValue={editingAsset.technologies?.join(', ')} placeholder="Nginx, React, PHP" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="edit-notes">Notes</Label>
                  <Textarea id="edit-notes" name="notes" defaultValue={editingAsset.notes || ""} placeholder="Additional context" />
                </div>
                <DialogFooter>
                  <Button type="submit" disabled={updateAsset.isPending}>
                    {updateAsset.isPending ? "Saving..." : "Save Changes"}
                  </Button>
                </DialogFooter>
              </form>
            )}
          </DialogContent>
        </Dialog>
      </div>

      <div className="rounded-md border border-border bg-card/50">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Value</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Technologies</TableHead>
              <TableHead>Added</TableHead>
              <TableHead className="text-right">Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow><TableCell colSpan={6} className="text-center py-6 text-muted-foreground">Loading...</TableCell></TableRow>
            ) : assets?.length === 0 ? (
              <TableRow><TableCell colSpan={6} className="text-center py-6 text-muted-foreground">No assets added yet.</TableCell></TableRow>
            ) : (
              assets?.map(asset => (
                <TableRow key={asset.id}>
                  <TableCell>
                    <div className="font-mono text-sm text-primary">{asset.value}</div>
                    {asset.notes && <div className="text-xs text-muted-foreground mt-1">{asset.notes}</div>}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2 text-muted-foreground">
                      {TYPE_ICONS[asset.type] || <Globe className="w-4 h-4" />}
                      <span className="capitalize text-xs">{asset.type.replace('_', ' ')}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={asset.status === "active" ? "default" : "secondary"} className="capitalize text-[10px] font-normal">{asset.status}</Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {asset.technologies?.map(t => (
                        <Badge key={t} variant="secondary" className="text-[10px] font-mono">{t}</Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {formatDate(asset.createdAt)}
                  </TableCell>
                  <TableCell className="text-right space-x-2">
                    <Button variant="ghost" size="icon" onClick={() => setEditingAsset(asset)} className="hover:text-primary">
                      <Edit2 className="w-4 h-4" />
                    </Button>
                    <Button variant="ghost" size="icon" onClick={() => handleDelete(asset.id)} className="text-destructive hover:text-destructive hover:bg-destructive/10">
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
