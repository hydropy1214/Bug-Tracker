import { useState } from "react";
import { useLocation } from "wouter";
import {
  useGetProject,
  useDeleteProject,
  useUpdateProject,
  getGetProjectQueryKey,
  getListProjectsQueryKey
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { ArrowLeft, Trash2, Settings, Target, Shield, Hash, Calendar, Globe } from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { AssetsTab } from "./AssetsTab";
import { FindingsTab } from "./FindingsTab";
import { ScansTab } from "./ScansTab";
import { formatDate } from "@/lib/utils";
import { cn } from "@/lib/utils";

const STATUS_STYLES: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  active:   { color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30", dot: "bg-emerald-400" },
  paused:   { color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/30",  dot: "bg-yellow-400" },
  archived: { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/30",   dot: "bg-slate-400" },
};

export function ProjectDetail({ id, params, defaultTab = "assets" }: any) {
  const [, setLocation] = useLocation();
  const resolvedId = parseInt(id || params?.id, 10);

  const { data: project, isLoading } = useGetProject(resolvedId, {
    query: { enabled: !!resolvedId, queryKey: getGetProjectQueryKey(resolvedId) }
  });
  const deleteProject = useDeleteProject();
  const updateProject = useUpdateProject();
  const queryClient = useQueryClient();
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  if (isLoading) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-5 w-24 bg-muted rounded" />
        <div className="h-28 bg-card rounded-xl border border-border" />
        <div className="h-10 w-full bg-muted rounded-lg" />
        <div className="h-96 bg-card rounded-xl border border-border" />
      </div>
    );
  }

  if (!project) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-muted-foreground">
        <Shield className="w-12 h-12 mb-4 opacity-20" />
        <p className="text-sm">Project not found.</p>
      </div>
    );
  }

  const handleDelete = () => {
    if (confirm("Permanently delete this project and all associated assets, findings, and scans?")) {
      deleteProject.mutate({ id: resolvedId }, {
        onSuccess: () => {
          toast.success("Project deleted");
          queryClient.invalidateQueries({ queryKey: getListProjectsQueryKey() });
          setLocation("/projects");
        },
        onError: () => toast.error("Failed to delete project"),
      });
    }
  };

  const handleUpdate = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    updateProject.mutate({
      id: resolvedId,
      data: {
        name: formData.get("name") as string,
        description: formData.get("description") as string,
        scope: formData.get("scope") as string,
        status: (formData.get("status") as any) || project.status,
      }
    }, {
      onSuccess: () => {
        toast.success("Project updated");
        queryClient.invalidateQueries({ queryKey: getGetProjectQueryKey(resolvedId) });
        queryClient.invalidateQueries({ queryKey: getListProjectsQueryKey() });
        setIsSettingsOpen(false);
      },
      onError: () => toast.error("Failed to update project"),
    });
  };

  const handleTabChange = (value: string) => {
    setLocation(`/projects/${resolvedId}/${value}`, { replace: true });
  };

  const st = STATUS_STYLES[project.status] ?? STATUS_STYLES.archived;
  const hasCritical = (project.criticalCount ?? 0) > 0;

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      {/* Breadcrumb */}
      <Button variant="ghost" className="px-0 h-8 text-muted-foreground hover:text-foreground gap-1.5 -ml-1" onClick={() => setLocation("/projects")}>
        <ArrowLeft className="w-3.5 h-3.5" />
        <span className="text-sm">Projects</span>
      </Button>

      {/* Project hero */}
      <div className={cn(
        "rounded-xl border bg-card p-6 overflow-hidden relative",
        hasCritical ? "border-red-500/25" : "border-border/60"
      )}>
        {hasCritical && <div className="absolute inset-0 bg-gradient-to-br from-red-500/5 to-transparent pointer-events-none" />}
        <div className="relative flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-2 flex-wrap">
              <h1 className="text-2xl font-bold tracking-tight text-foreground">{project.name}</h1>
              <div className={cn("flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[10px] font-mono uppercase tracking-widest font-bold", st.bg, st.border, st.color)}>
                <span className={cn("w-1.5 h-1.5 rounded-full", st.dot, project.status === 'active' ? 'animate-pulse' : '')} />
                {project.status}
              </div>
            </div>
            <p className="text-sm text-muted-foreground">{project.description || "No description."}</p>
          </div>
          <div className="flex gap-2 flex-shrink-0">
            <Dialog open={isSettingsOpen} onOpenChange={setIsSettingsOpen}>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm" className="gap-2">
                  <Settings className="w-3.5 h-3.5" />
                  Edit
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-lg">
                <DialogHeader>
                  <DialogTitle>Edit Project</DialogTitle>
                </DialogHeader>
                <form onSubmit={handleUpdate} className="space-y-4 pt-1">
                  <div className="space-y-2">
                    <Label>Name</Label>
                    <Input name="name" defaultValue={project.name} required />
                  </div>
                  <div className="space-y-2">
                    <Label>Description</Label>
                    <Textarea name="description" defaultValue={project.description || ""} className="resize-none" rows={3} />
                  </div>
                  <div className="space-y-2">
                    <Label>Scope</Label>
                    <Textarea name="scope" defaultValue={project.scope || ""} className="font-mono resize-none text-xs" rows={3} />
                  </div>
                  <div className="space-y-2">
                    <Label>Status</Label>
                    <Select name="status" defaultValue={project.status}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="active">Active</SelectItem>
                        <SelectItem value="paused">Paused</SelectItem>
                        <SelectItem value="archived">Archived</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <DialogFooter>
                    <Button type="submit" disabled={updateProject.isPending}>
                      {updateProject.isPending ? "Saving..." : "Save Changes"}
                    </Button>
                  </DialogFooter>
                </form>
              </DialogContent>
            </Dialog>
            <Button variant="destructive" size="sm" onClick={handleDelete} className="gap-2">
              <Trash2 className="w-3.5 h-3.5" />
              Delete
            </Button>
          </div>
        </div>

        {/* Meta pills */}
        <div className="relative flex flex-wrap gap-3 mt-5 pt-5 border-t border-border/60">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Hash className="w-3.5 h-3.5" />
            <span className="font-mono text-foreground/70">PRJ-{project.id.toString().padStart(4, "0")}</span>
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Calendar className="w-3.5 h-3.5" />
            <span>{formatDate(project.createdAt)}</span>
          </div>
          {project.scope && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Globe className="w-3.5 h-3.5" />
              <span className="font-mono text-primary truncate max-w-[200px]">{project.scope}</span>
            </div>
          )}
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Target className="w-3.5 h-3.5" />
            <span className="font-mono">{project.assetCount ?? 0}</span> assets
          </div>
          {hasCritical && (
            <div className="flex items-center gap-1.5 text-xs font-mono text-red-400 bg-red-500/10 px-2.5 py-1 rounded-md border border-red-500/25 ml-auto">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
              {project.criticalCount} CRITICAL
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={defaultTab} onValueChange={handleTabChange} className="w-full">
        <TabsList className="w-full justify-start border-b border-border/60 rounded-none bg-transparent p-0 h-auto mb-0 gap-0">
          {[
            { value: "assets",   label: `Assets`, count: project.assetCount ?? 0 },
            { value: "findings", label: `Findings`, count: (project.criticalCount ?? 0) + (project.highCount ?? 0), danger: (project.criticalCount ?? 0) > 0 },
            { value: "scans",    label: `Scans` },
          ].map(tab => (
            <TabsTrigger
              key={tab.value}
              value={tab.value}
              className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none px-5 py-3 text-sm font-medium text-muted-foreground data-[state=active]:text-primary gap-2"
            >
              {tab.label}
              {tab.count !== undefined && tab.count > 0 && (
                <span className={cn(
                  "text-[10px] font-mono px-1.5 py-0.5 rounded font-bold",
                  tab.danger ? "bg-red-500/15 text-red-400" : "bg-primary/10 text-primary"
                )}>
                  {tab.count}
                </span>
              )}
            </TabsTrigger>
          ))}
        </TabsList>
        <div className="mt-6">
          <TabsContent value="assets"   className="mt-0"><AssetsTab   projectId={resolvedId} /></TabsContent>
          <TabsContent value="findings" className="mt-0"><FindingsTab projectId={resolvedId} /></TabsContent>
          <TabsContent value="scans"    className="mt-0"><ScansTab    projectId={resolvedId} /></TabsContent>
        </div>
      </Tabs>
    </motion.div>
  );
}
