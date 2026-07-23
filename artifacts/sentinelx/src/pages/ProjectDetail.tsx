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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { ArrowLeft, Trash2, Settings, Target, Shield, Hash, Calendar, Globe, Radar } from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { AssetsTab } from "./AssetsTab";
import { FindingsTab } from "./FindingsTab";
import { ScansTab } from "./ScansTab";
import { formatDate } from "@/lib/utils";
import { cn } from "@/lib/utils";

const STATUS_STYLES: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  active:   { color: "text-primary", bg: "bg-primary/10", border: "border-primary/30", dot: "bg-primary" },
  paused:   { color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/30",  dot: "bg-yellow-400" },
  archived: { color: "text-muted-foreground",   bg: "bg-accent",   border: "border-border",   dot: "bg-muted-foreground" },
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
  const [isEditingName, setIsEditingName] = useState(false);

  if (isLoading) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-4 w-20 bg-muted rounded-sm" />
        <div className="h-32 bg-card rounded-md border border-border" />
        <div className="h-10 w-full bg-border rounded-none" />
        <div className="h-96 bg-card rounded-md border border-border" />
      </div>
    );
  }

  if (!project) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-muted-foreground">
        <Shield className="w-12 h-12 mb-4 opacity-20" />
        <p className="text-xs font-mono uppercase tracking-widest">Target Unreachable</p>
      </div>
    );
  }

  const handleDelete = () => {
    if (confirm("Permanently delete this project and all associated data?")) {
      deleteProject.mutate({ id: resolvedId }, {
        onSuccess: () => {
          toast.success("Target purged");
          queryClient.invalidateQueries({ queryKey: getListProjectsQueryKey() });
          setLocation("/projects");
        },
        onError: () => toast.error("Failed to purge target"),
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
        toast.success("Target config updated");
        queryClient.invalidateQueries({ queryKey: getGetProjectQueryKey(resolvedId) });
        queryClient.invalidateQueries({ queryKey: getListProjectsQueryKey() });
        setIsSettingsOpen(false);
      },
      onError: () => toast.error("Failed to update config"),
    });
  };

  const handleNameSave = (e: React.FocusEvent<HTMLInputElement>) => {
    setIsEditingName(false);
    const newName = e.target.value.trim();
    if (newName && newName !== project.name) {
      updateProject.mutate({ id: resolvedId, data: { name: newName } }, {
        onSuccess: () => queryClient.invalidateQueries({ queryKey: getGetProjectQueryKey(resolvedId) }),
        onError: () => toast.error("Failed to rename target")
      });
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.currentTarget.blur();
    }
  };

  const handleTabChange = (value: string) => {
    setLocation(`/projects/${resolvedId}/${value}`, { replace: true });
  };

  const st = STATUS_STYLES[project.status] ?? STATUS_STYLES.archived;
  const hasCritical = (project.criticalCount ?? 0) > 0;

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      {/* Breadcrumb */}
      <Button variant="ghost" className="px-2 h-7 rounded-sm text-[10px] font-mono text-muted-foreground hover:text-foreground uppercase tracking-widest gap-1.5 -ml-2" onClick={() => setLocation("/projects")}>
        <ArrowLeft className="w-3.5 h-3.5" />
        Return to List
      </Button>

      {/* Target Hero */}
      <div className={cn(
        "rounded-md border bg-card p-6 relative overflow-hidden",
        hasCritical ? "border-red-500/40" : "border-border"
      )}>
        {hasCritical && <div className="absolute top-0 left-0 w-1 h-full bg-red-500" />}
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
        
        <div className="relative flex flex-col md:flex-row md:items-start justify-between gap-6">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-3 flex-wrap">
              {isEditingName ? (
                <Input 
                  defaultValue={project.name} 
                  onBlur={handleNameSave} 
                  onKeyDown={handleKeyDown}
                  autoFocus 
                  className="text-2xl font-bold font-sans h-auto py-1 px-2 w-full max-w-sm rounded-sm bg-background border-primary" 
                />
              ) : (
                <h1 
                  onClick={() => setIsEditingName(true)} 
                  className="text-2xl font-bold tracking-tight text-foreground cursor-text hover:text-primary transition-colors"
                  title="Click to edit name"
                >
                  {project.name}
                </h1>
              )}
              <div className={cn("flex items-center gap-1.5 px-2 py-0.5 rounded-sm border text-[9px] font-mono uppercase tracking-widest font-bold", st.bg, st.border, st.color)}>
                <span className={cn("w-1.5 h-1.5 rounded-full", st.dot, project.status === 'active' ? 'animate-pulse' : '')} />
                {project.status}
              </div>
            </div>
            <p className="text-xs font-mono text-muted-foreground leading-relaxed max-w-3xl">
              {project.description || "No context provided."}
            </p>
          </div>
          
          <div className="flex flex-wrap items-center gap-2 flex-shrink-0">
            <Button variant="outline" size="sm" onClick={() => handleTabChange("scans")} className="gap-2 text-[10px] font-mono uppercase tracking-wider rounded-sm h-8 border-primary/40 text-primary hover:bg-primary/10 hover:text-primary">
              <Radar className="w-3.5 h-3.5" />
              Launch Scan
            </Button>
            
            <Dialog open={isSettingsOpen} onOpenChange={setIsSettingsOpen}>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm" className="gap-2 text-[10px] font-mono uppercase tracking-wider rounded-sm h-8">
                  <Settings className="w-3.5 h-3.5" />
                  Config
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-lg rounded-md border-border bg-card">
                <DialogHeader>
                  <DialogTitle className="font-mono text-sm text-primary uppercase tracking-wider">Target Configuration</DialogTitle>
                </DialogHeader>
                <form onSubmit={handleUpdate} className="space-y-4 pt-2">
                  <div className="space-y-2">
                    <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Target Name</Label>
                    <Input name="name" defaultValue={project.name} required className="font-mono text-sm rounded-sm bg-background border-border" />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Context / Description</Label>
                    <Textarea name="description" defaultValue={project.description || ""} className="resize-none font-mono text-sm rounded-sm bg-background border-border" rows={3} />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Scope Definition</Label>
                    <Textarea name="scope" defaultValue={project.scope || ""} className="font-mono text-sm resize-none rounded-sm bg-background border-border" rows={3} />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Status</Label>
                    <Select name="status" defaultValue={project.status}>
                      <SelectTrigger className="font-mono text-sm rounded-sm bg-background border-border"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="active">Active</SelectItem>
                        <SelectItem value="paused">Paused</SelectItem>
                        <SelectItem value="archived">Archived</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <DialogFooter className="pt-2 gap-2">
                    <Button type="button" variant="destructive" size="sm" onClick={handleDelete} className="font-mono text-xs uppercase tracking-wider rounded-sm gap-2">
                      <Trash2 className="w-3.5 h-3.5" /> Purge Target
                    </Button>
                    <Button type="submit" disabled={updateProject.isPending} className="font-mono text-xs uppercase tracking-wider rounded-sm">
                      {updateProject.isPending ? "Applying..." : "Apply Config"}
                    </Button>
                  </DialogFooter>
                </form>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Meta Grid */}
        <div className="relative grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-5 border-t border-border/50">
          <div className="space-y-1">
            <div className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest flex items-center gap-1.5"><Hash className="w-3 h-3"/> Target ID</div>
            <div className="font-mono text-xs text-foreground font-bold">TRG-{project.id.toString().padStart(4, "0")}</div>
          </div>
          <div className="space-y-1">
            <div className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest flex items-center gap-1.5"><Calendar className="w-3 h-3"/> Initialized</div>
            <div className="font-mono text-xs text-foreground">{formatDate(project.createdAt)}</div>
          </div>
          <div className="space-y-1">
            <div className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest flex items-center gap-1.5"><Globe className="w-3 h-3"/> Root Scope</div>
            <div className="font-mono text-xs text-primary truncate max-w-[200px]" title={project.scope || "Any"}>{project.scope || "*"}</div>
          </div>
          <div className="space-y-1">
            <div className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest flex items-center gap-1.5"><Target className="w-3 h-3"/> Indexed Assets</div>
            <div className="font-mono text-xs text-foreground font-bold">{project.assetCount ?? 0} Items</div>
          </div>
        </div>
      </div>

      {/* Tabs Layout */}
      <Tabs value={defaultTab} onValueChange={handleTabChange} className="w-full">
        <div className="border-b border-border bg-card rounded-t-md px-2">
          <TabsList className="w-full justify-start rounded-none bg-transparent p-0 h-auto gap-1 border-none">
            {[
              { value: "assets",   label: `Assets`, count: project.assetCount ?? 0 },
              { value: "findings", label: `Findings`, count: (project.criticalCount ?? 0) + (project.highCount ?? 0), danger: (project.criticalCount ?? 0) > 0 },
              { value: "scans",    label: `Scans` },
            ].map(tab => (
              <TabsTrigger
                key={tab.value}
                value={tab.value}
                className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none px-6 py-3.5 text-xs font-mono uppercase tracking-wider text-muted-foreground data-[state=active]:text-foreground gap-2 transition-colors hover:text-foreground"
              >
                {tab.label}
                {tab.count !== undefined && tab.count > 0 && (
                  <span className={cn(
                    "text-[9px] font-bold px-1.5 py-0.5 rounded-sm",
                    tab.danger ? "bg-red-500/20 text-red-400" : "bg-primary/10 text-primary"
                  )}>
                    {tab.count}
                  </span>
                )}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        <div className="mt-4">
          <TabsContent value="assets"   className="mt-0 outline-none"><AssetsTab   projectId={resolvedId} /></TabsContent>
          <TabsContent value="findings" className="mt-0 outline-none"><FindingsTab projectId={resolvedId} /></TabsContent>
          <TabsContent value="scans"    className="mt-0 outline-none"><ScansTab    projectId={resolvedId} assetCount={project.assetCount ?? 0} /></TabsContent>
        </div>
      </Tabs>
    </motion.div>
  );
}