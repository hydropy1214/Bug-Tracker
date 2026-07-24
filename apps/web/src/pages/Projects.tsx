import { useState } from "react";
import { Link } from "wouter";
import { useListProjects, useCreateProject, getListProjectsQueryKey } from "@workspace/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Plus, Search, FolderKanban, ChevronRight, Shield, Target, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

const STATUS_STYLES: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  active:   { color: "text-primary", bg: "bg-primary/10", border: "border-primary/30", dot: "bg-primary" },
  paused:   { color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/30",  dot: "bg-yellow-400" },
  archived: { color: "text-muted-foreground",   bg: "bg-accent",   border: "border-border",   dot: "bg-muted-foreground" },
};

const containerVariants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.05 } },
};
const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.25 } },
};

export function Projects() {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const { data: projects, isLoading } = useListProjects();
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  
  const queryClient = useQueryClient();
  const createProject = useCreateProject();

  const handleCreate = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    createProject.mutate(
      {
        data: {
          name: formData.get("name") as string,
          description: formData.get("description") as string,
          scope: formData.get("scope") as string,
          status: (formData.get("status") as any) || "active",
        }
      },
      {
        onSuccess: () => {
          toast.success("Target initialized");
          queryClient.invalidateQueries({ queryKey: getListProjectsQueryKey() });
          setIsCreateOpen(false);
        },
        onError: () => toast.error("Failed to initialize target"),
      }
    );
  };

  const filtered = projects?.filter(p => {
    const matchesSearch = p.name.toLowerCase().includes(search.toLowerCase()) || p.description?.toLowerCase().includes(search.toLowerCase());
    const matchesFilter = filter === "all" || p.status === filter;
    return matchesSearch && matchesFilter;
  }) ?? [];

  return (
    <motion.div variants={containerVariants} initial="hidden" animate="show" className="space-y-6">
      {/* Header */}
      <motion.div variants={itemVariants} className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-3 uppercase font-sans">
            <FolderKanban className="w-5 h-5 text-primary" />
            Project Targets
          </h1>
          <p className="text-[11px] font-mono text-muted-foreground mt-1 uppercase tracking-widest">
            {projects?.length ?? 0} scopes indexed
          </p>
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button className="gap-2 font-mono text-xs uppercase tracking-wider rounded-sm">
              <Plus className="w-4 h-4" />
              Init Target
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg border-border bg-card">
            <DialogHeader>
              <DialogTitle className="font-mono text-sm text-primary uppercase tracking-wider">Initialize Project Scope</DialogTitle>
            </DialogHeader>
            <form onSubmit={handleCreate} className="space-y-4 pt-2">
              <div className="space-y-2">
                <Label className="text-xs font-mono uppercase tracking-wider text-muted-foreground">Target Name</Label>
                <Input name="name" required placeholder="e.g. Corp External Surface" className="font-mono text-sm bg-background border-border rounded-sm" />
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-mono uppercase tracking-wider text-muted-foreground">Context / Description</Label>
                <Textarea name="description" placeholder="Brief target overview..." className="resize-none font-mono text-sm bg-background border-border rounded-sm" rows={2} />
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-mono uppercase tracking-wider text-muted-foreground">Scope Definition</Label>
                <Textarea name="scope" placeholder="*.example.com, 10.0.0.0/24" className="font-mono text-sm bg-background border-border rounded-sm resize-none" rows={3} />
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-mono uppercase tracking-wider text-muted-foreground">Status</Label>
                <Select name="status" defaultValue="active">
                  <SelectTrigger className="font-mono text-sm rounded-sm bg-background border-border"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="paused">Paused</SelectItem>
                    <SelectItem value="archived">Archived</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <DialogFooter className="pt-2">
                <Button type="submit" disabled={createProject.isPending} className="w-full font-mono text-xs uppercase tracking-wider rounded-sm">
                  {createProject.isPending ? "Initializing..." : "Commit Target"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </motion.div>

      {/* Toolbar */}
      <motion.div variants={itemVariants} className="flex flex-col sm:flex-row justify-between gap-4 border-b border-border pb-4">
        {/* Status Tabs */}
        <div className="flex items-center gap-2 overflow-x-auto pb-2 sm:pb-0">
          {["all", "active", "paused", "archived"].map(st => {
            const count = st === "all" ? projects?.length : projects?.filter(p => p.status === st).length;
            const isActive = filter === st;
            return (
              <button 
                key={st} 
                onClick={() => setFilter(st)}
                className={cn(
                  "px-3 py-1.5 text-[11px] font-mono uppercase tracking-wider rounded-sm transition-colors border",
                  isActive ? "bg-primary/10 text-primary border-primary/30" : "text-muted-foreground hover:text-foreground border-transparent hover:border-border"
                )}
              >
                {st}
                <span className={cn("ml-2 px-1.5 py-0.5 rounded-sm", isActive ? "bg-primary/20 text-primary" : "bg-accent text-muted-foreground")}>
                  {count ?? 0}
                </span>
              </button>
            );
          })}
        </div>

        {/* Search */}
        <div className="relative w-full sm:w-64">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
          <Input
            className="pl-9 bg-background border-border rounded-sm font-mono text-sm h-9"
            placeholder="Search targets..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      </motion.div>

      {/* Grid */}
      {isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[1,2,3,4,5,6].map(i => <div key={i} className="h-40 bg-card rounded-md border border-border animate-pulse" />)}
        </div>
      ) : filtered.length === 0 ? (
        <motion.div variants={itemVariants} className="flex flex-col items-center justify-center py-24 text-muted-foreground rounded-md border border-dashed border-border bg-card/50">
          <FolderKanban className="w-8 h-8 mb-4 opacity-20" />
          <p className="text-xs font-mono uppercase tracking-widest">{search ? "No targets match." : "Database Empty"}</p>
        </motion.div>
      ) : (
        <motion.div variants={containerVariants} className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {filtered.map(project => {
            const st = STATUS_STYLES[project.status] ?? STATUS_STYLES.archived;
            const hasCritical = (project.criticalCount ?? 0) > 0;
            return (
              <motion.div key={project.id} variants={itemVariants}>
                <Link href={`/projects/${project.id}`} className={cn(
                  "block p-5 rounded-md border bg-card transition-all duration-200 hover:bg-accent/30 group cursor-pointer relative overflow-hidden",
                  hasCritical ? "border-red-500/25 hover:border-red-500/50" : "border-border hover:border-primary/40"
                )}>
                  {hasCritical && <div className="absolute top-0 left-0 w-1 h-full bg-red-500" />}

                  {/* Top row */}
                  <div className="flex items-start justify-between mb-4">
                    <div className={cn("flex items-center gap-1.5 px-2 py-0.5 rounded-sm border text-[9px] font-mono uppercase tracking-widest font-bold", st.bg, st.border, st.color)}>
                      <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", st.dot, project.status === 'active' ? "animate-pulse" : "")} />
                      {project.status}
                    </div>
                    <ChevronRight className="w-4 h-4 text-muted-foreground/30 group-hover:text-primary transition-colors" />
                  </div>

                  {/* Name & description */}
                  <div className="mb-5">
                    <h3 className="font-semibold text-foreground group-hover:text-primary transition-colors leading-snug">{project.name}</h3>
                    <p className="text-[11px] font-mono text-muted-foreground mt-1.5 line-clamp-2 leading-relaxed">{project.description || "No context provided."}</p>
                  </div>

                  {/* Stats row */}
                  <div className="flex items-center gap-3 pt-3 border-t border-border/50">
                    <div className="flex items-center gap-1.5 text-[10px] font-mono text-muted-foreground uppercase">
                      <Target className="w-3.5 h-3.5" />
                      <span className="font-bold text-foreground">{project.assetCount ?? 0}</span>
                      <span>assets</span>
                    </div>
                    
                    <div className="ml-auto flex gap-1.5">
                      {(project.criticalCount ?? 0) > 0 && (
                        <div className="flex items-center gap-1 text-[10px] font-mono font-bold text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded-sm border border-red-500/25">
                          {project.criticalCount}C
                        </div>
                      )}
                      {(project.highCount ?? 0) > 0 && (
                        <div className="flex items-center gap-1 text-[10px] font-mono font-bold text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded-sm border border-orange-500/25">
                          {project.highCount}H
                        </div>
                      )}
                      {!(project.criticalCount) && !(project.highCount) && (
                        <div className="flex items-center gap-1 text-[10px] font-mono font-bold text-primary bg-primary/10 border border-primary/20 px-1.5 py-0.5 rounded-sm">
                          CLEAN
                        </div>
                      )}
                    </div>
                  </div>
                </Link>
              </motion.div>
            );
          })}
        </motion.div>
      )}
    </motion.div>
  );
}