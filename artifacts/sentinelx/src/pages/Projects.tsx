import { useState } from "react";
import { Link } from "wouter";
import { useListProjects, useCreateProject, getListProjectsQueryKey } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Plus, Search, FolderKanban, ChevronRight, Shield, Target, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

const STATUS_STYLES: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  active:   { color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30", dot: "bg-emerald-400" },
  paused:   { color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/30",  dot: "bg-yellow-400" },
  archived: { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/30",   dot: "bg-slate-400" },
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
          toast.success("Project created");
          queryClient.invalidateQueries({ queryKey: getListProjectsQueryKey() });
          setIsCreateOpen(false);
        },
        onError: () => toast.error("Failed to create project"),
      }
    );
  };

  const filtered = projects?.filter(p =>
    p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.description?.toLowerCase().includes(search.toLowerCase())
  ) ?? [];

  return (
    <motion.div variants={containerVariants} initial="hidden" animate="show" className="space-y-6">
      {/* Header */}
      <motion.div variants={itemVariants} className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-3">
            <FolderKanban className="w-6 h-6 text-primary" />
            Projects
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            {projects?.length ?? 0} target{projects?.length !== 1 ? "s" : ""} registered
          </p>
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="w-4 h-4" />
              New Project
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>Create Project</DialogTitle>
            </DialogHeader>
            <form onSubmit={handleCreate} className="space-y-4 pt-1">
              <div className="space-y-2">
                <Label htmlFor="name">Project Name</Label>
                <Input id="name" name="name" required placeholder="e.g. Corp External Attack Surface" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Textarea id="description" name="description" placeholder="Brief overview of the target" className="resize-none" rows={3} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="scope">Scope</Label>
                <Textarea id="scope" name="scope" placeholder="*.example.com, 10.0.0.0/24" className="font-mono resize-none text-xs" rows={3} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="status">Initial Status</Label>
                <Select name="status" defaultValue="active">
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="paused">Paused</SelectItem>
                    <SelectItem value="archived">Archived</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={createProject.isPending} className="w-full">
                  {createProject.isPending ? "Creating..." : "Create Project"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </motion.div>

      {/* Search */}
      <motion.div variants={itemVariants} className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
        <Input
          className="pl-9 bg-card border-border/60"
          placeholder="Search projects..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </motion.div>

      {/* Project cards */}
      {isLoading ? (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {[1,2,3].map(i => <div key={i} className="h-44 bg-card rounded-xl border border-border animate-pulse" />)}
        </div>
      ) : filtered.length === 0 ? (
        <motion.div variants={itemVariants} className="flex flex-col items-center justify-center py-20 text-muted-foreground rounded-xl border border-border/60 bg-card/50">
          <FolderKanban className="w-12 h-12 mb-4 opacity-20" />
          <p className="text-sm font-medium">{search ? "No projects match your search." : "No projects yet."}</p>
          <p className="text-xs opacity-60 mt-1">{!search && "Create your first project to get started."}</p>
        </motion.div>
      ) : (
        <motion.div variants={containerVariants} className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {filtered.map(project => {
            const st = STATUS_STYLES[project.status] ?? STATUS_STYLES.archived;
            const hasCritical = (project.criticalCount ?? 0) > 0;
            return (
              <motion.div key={project.id} variants={itemVariants}>
                <Link href={`/projects/${project.id}`} className={cn(
                  "block p-5 rounded-xl border bg-card transition-all duration-200 hover:bg-accent/40 group cursor-pointer",
                  hasCritical ? "border-red-500/25 hover:border-red-500/40" : "border-border/60 hover:border-primary/30"
                )}>
                  {/* Top row */}
                  <div className="flex items-start justify-between mb-4">
                    <div className={cn("flex items-center gap-1.5 px-2 py-1 rounded-md border text-[10px] font-mono uppercase tracking-wider font-bold", st.bg, st.border, st.color)}>
                      <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", st.dot)} />
                      {project.status}
                    </div>
                    <ChevronRight className="w-4 h-4 text-muted-foreground/30 group-hover:text-primary transition-colors" />
                  </div>

                  {/* Name & description */}
                  <div className="mb-4">
                    <h3 className="font-semibold text-foreground group-hover:text-primary transition-colors leading-snug">{project.name}</h3>
                    <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{project.description || "No description provided."}</p>
                  </div>

                  {/* Stats row */}
                  <div className="flex items-center gap-3 pt-3 border-t border-border/60">
                    <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <Target className="w-3.5 h-3.5" />
                      <span className="font-mono">{project.assetCount ?? 0}</span>
                      <span>assets</span>
                    </div>
                    {(project.criticalCount ?? 0) > 0 && (
                      <div className="flex items-center gap-1 text-xs font-mono font-bold text-red-400 bg-red-500/10 px-2 py-0.5 rounded-md border border-red-500/25">
                        <AlertTriangle className="w-3 h-3" />
                        {project.criticalCount}C
                      </div>
                    )}
                    {(project.highCount ?? 0) > 0 && (
                      <div className="flex items-center gap-1 text-xs font-mono font-bold text-orange-400 bg-orange-500/10 px-2 py-0.5 rounded-md border border-orange-500/25">
                        {project.highCount}H
                      </div>
                    )}
                    {!(project.criticalCount) && !(project.highCount) && (
                      <div className="flex items-center gap-1.5 text-xs text-emerald-400">
                        <Shield className="w-3 h-3" />
                        Clean
                      </div>
                    )}
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
