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
import { ArrowLeft, Trash2, Settings, TerminalSquare } from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { AssetsTab } from "./AssetsTab";
import { FindingsTab } from "./FindingsTab";
import { ScansTab } from "./ScansTab";
import { formatDate } from "@/lib/utils";

export function ProjectDetail({ id, params, defaultTab = "assets" }: any) {
  const [location, setLocation] = useLocation();
  const resolvedId = parseInt(id || params?.id, 10);
  
  const { data: project, isLoading } = useGetProject(resolvedId, { query: { enabled: !!resolvedId, queryKey: getGetProjectQueryKey(resolvedId) } });
  const deleteProject = useDeleteProject();
  const updateProject = useUpdateProject();
  const queryClient = useQueryClient();
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  if (isLoading) {
    return <div className="animate-pulse space-y-6">
      <div className="h-10 w-32 bg-muted rounded"></div>
      <div className="h-24 bg-card rounded-lg border border-border"></div>
      <div className="h-10 w-full bg-muted rounded"></div>
      <div className="h-96 bg-card rounded-lg border border-border"></div>
    </div>;
  }

  if (!project) {
    return <div className="text-center py-12 text-muted-foreground">Project not found.</div>;
  }

  const handleDelete = () => {
    if (confirm("Are you sure you want to completely destroy this project and all associated data?")) {
      deleteProject.mutate({ id: resolvedId }, {
        onSuccess: () => {
          toast.success("Project annihilated.");
          queryClient.invalidateQueries({ queryKey: getListProjectsQueryKey() });
          setLocation("/projects");
        }
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
        toast.success("Project updated.");
        queryClient.invalidateQueries({ queryKey: getGetProjectQueryKey(resolvedId) });
        queryClient.invalidateQueries({ queryKey: getListProjectsQueryKey() });
        setIsSettingsOpen(false);
      },
      onError: () => toast.error("Failed to update project.")
    });
  };

  const handleTabChange = (value: string) => {
    setLocation(`/projects/${resolvedId}/${value}`, { replace: true });
  };

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <div>
        <Button variant="link" className="px-0 text-muted-foreground mb-4" onClick={() => setLocation("/projects")}>
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Projects
        </Button>
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-foreground flex items-center gap-3">
              {project.name}
              <Badge variant={project.status === "active" ? "default" : "secondary"} className="uppercase font-mono tracking-wider text-[10px]">
                {project.status}
              </Badge>
            </h1>
            <p className="text-muted-foreground mt-2 max-w-2xl">{project.description}</p>
          </div>
          <div className="flex gap-2">
            <Dialog open={isSettingsOpen} onOpenChange={setIsSettingsOpen}>
              <DialogTrigger asChild>
                <Button variant="outline" size="icon">
                  <Settings className="w-4 h-4" />
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Project Settings</DialogTitle>
                </DialogHeader>
                <form onSubmit={handleUpdate} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="name">Name</Label>
                    <Input id="name" name="name" defaultValue={project.name} required />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="description">Description</Label>
                    <Textarea id="description" name="description" defaultValue={project.description || ""} />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="scope">Scope Details</Label>
                    <Textarea id="scope" name="scope" defaultValue={project.scope || ""} className="font-mono" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="status">Status</Label>
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
            <Button variant="destructive" size="icon" onClick={handleDelete}>
              <Trash2 className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-card/50 border border-border rounded-lg p-4 backdrop-blur flex flex-col justify-center">
          <div className="text-sm font-medium text-muted-foreground mb-1">Scope Rules</div>
          <div className="font-mono text-sm text-primary break-all">
            {project.scope || "No explicit scope defined."}
          </div>
        </div>
        <div className="bg-card/50 border border-border rounded-lg p-4 backdrop-blur flex flex-col justify-center">
          <div className="text-sm font-medium text-muted-foreground mb-1">Project ID</div>
          <div className="font-mono text-sm text-foreground flex items-center gap-2">
            <TerminalSquare className="w-4 h-4 text-muted-foreground" />
            PRJ-{project.id.toString().padStart(4, '0')}
          </div>
        </div>
        <div className="bg-card/50 border border-border rounded-lg p-4 backdrop-blur flex flex-col justify-center">
          <div className="text-sm font-medium text-muted-foreground mb-1">Created</div>
          <div className="font-mono text-sm text-foreground">
            {formatDate(project.createdAt)}
          </div>
        </div>
      </div>

      <Tabs value={defaultTab} onValueChange={handleTabChange} className="w-full">
        <TabsList className="w-full justify-start border-b border-border rounded-none bg-transparent p-0 mb-4">
          <TabsTrigger 
            value="assets" 
            className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none px-6"
          >
            Assets ({project.assetCount || 0})
          </TabsTrigger>
          <TabsTrigger 
            value="findings" 
            className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none px-6"
          >
            Findings ({(project.criticalCount || 0) + (project.highCount || 0)} High/Crit)
          </TabsTrigger>
          <TabsTrigger 
            value="scans" 
            className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none px-6"
          >
            Scans
          </TabsTrigger>
        </TabsList>
        <TabsContent value="assets" className="mt-0">
          <AssetsTab projectId={resolvedId} />
        </TabsContent>
        <TabsContent value="findings" className="mt-0">
          <FindingsTab projectId={resolvedId} />
        </TabsContent>
        <TabsContent value="scans" className="mt-0">
          <ScansTab projectId={resolvedId} />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
