import { useGetDashboardStats, useGetDashboardActivity, useGetSeverityBreakdown, useListProjects } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Target, FolderHeart, Activity, AlertTriangle } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip } from "recharts";
import { motion } from "framer-motion";
import { cn, formatDate } from "@/lib/utils";
import { Link } from "wouter";

const SEVERITY_COLORS = {
  critical: "hsl(var(--chart-1))",
  high: "hsl(var(--chart-2))",
  medium: "hsl(var(--chart-3))",
  low: "hsl(var(--chart-4))",
  info: "hsl(var(--chart-5))",
};

export function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useGetDashboardStats();
  const { data: activity, isLoading: activityLoading } = useGetDashboardActivity({ limit: 10 });
  const { data: breakdown, isLoading: breakdownLoading } = useGetSeverityBreakdown();
  const { data: projects, isLoading: projectsLoading } = useListProjects();

  const loading = statsLoading || activityLoading || breakdownLoading || projectsLoading;

  if (loading) {
    return <div className="animate-pulse space-y-8">
      <div className="h-8 bg-muted rounded w-48 mb-8"></div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {[1,2,3,4].map(i => <div key={i} className="h-32 bg-muted rounded-lg border border-border"></div>)}
      </div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <div className="col-span-4 h-96 bg-muted rounded-lg border border-border"></div>
        <div className="col-span-3 h-96 bg-muted rounded-lg border border-border"></div>
      </div>
    </div>;
  }

  const pieData = breakdown ? [
    { name: 'Critical', value: breakdown.critical, color: SEVERITY_COLORS.critical },
    { name: 'High', value: breakdown.high, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: breakdown.medium, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: breakdown.low, color: SEVERITY_COLORS.low },
    { name: 'Info', value: breakdown.info, color: SEVERITY_COLORS.info },
  ].filter(d => d.value > 0) : [];

  const topProjects = projects?.sort((a, b) => (b.criticalCount || 0) - (a.criticalCount || 0)).slice(0, 5) || [];

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }} 
      animate={{ opacity: 1, y: 0 }} 
      className="space-y-8"
    >
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold tracking-tight text-primary">Overview</h1>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="bg-card/50 backdrop-blur">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Projects</CardTitle>
            <FolderHeart className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono">{stats?.totalProjects || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">
              <span className="text-primary">{stats?.activeProjects || 0}</span> active targets
            </p>
          </CardContent>
        </Card>
        
        <Card className="bg-card/50 backdrop-blur">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Assets Monitored</CardTitle>
            <Target className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono">{stats?.totalAssets || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">across all scopes</p>
          </CardContent>
        </Card>

        <Card className="bg-card/50 backdrop-blur border-destructive/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical / High</CardTitle>
            <Shield className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono text-destructive">
              {stats?.criticalFindings || 0} <span className="text-muted-foreground text-lg">/</span> <span className="text-orange-500">{stats?.highFindings || 0}</span>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {stats?.openFindings || 0} total open findings
            </p>
          </CardContent>
        </Card>

        <Card className="bg-card/50 backdrop-blur">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Scans</CardTitle>
            <Activity className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono text-primary flex items-center">
              {stats?.runningScans || 0}
              {stats?.runningScans ? <span className="ml-2 w-2 h-2 rounded-full bg-primary animate-pulse" /> : null}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {stats?.completedScans || 0} completed historically
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <Card className="col-span-4 bg-card/50 backdrop-blur">
          <CardHeader>
            <CardTitle>Top Vulnerable Projects</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {topProjects.length === 0 ? (
                <div className="text-sm text-muted-foreground">No vulnerable projects found.</div>
              ) : topProjects.map(p => (
                <div key={p.id} className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <AlertTriangle className={cn("w-4 h-4", p.criticalCount ? "text-destructive" : "text-orange-500")} />
                    <div>
                      <Link href={`/projects/${p.id}`} className="font-medium hover:underline text-sm">{p.name}</Link>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    {p.criticalCount ? <div className="text-xs font-mono px-2 py-1 bg-destructive/10 text-destructive rounded border border-destructive/20">{p.criticalCount} C</div> : null}
                    {p.highCount ? <div className="text-xs font-mono px-2 py-1 bg-orange-500/10 text-orange-500 rounded border border-orange-500/20">{p.highCount} H</div> : null}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="col-span-3 bg-card/50 backdrop-blur">
          <CardHeader>
            <CardTitle>Severity Breakdown</CardTitle>
          </CardHeader>
          <CardContent className="flex justify-center items-center h-[200px]">
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                    stroke="none"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))', borderRadius: '4px' }}
                    itemStyle={{ color: 'hsl(var(--foreground))', fontFamily: 'var(--font-mono)' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-sm text-muted-foreground">No findings recorded.</div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="bg-card/50 backdrop-blur">
        <CardHeader>
          <CardTitle>Recent Activity</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {activity?.length === 0 ? (
              <div className="text-sm text-muted-foreground">No recent activity.</div>
            ) : activity?.map(item => (
              <div key={item.id} className="flex items-start gap-4 text-sm pb-4 border-b border-border/50 last:border-0 last:pb-0">
                <div className="mt-0.5 text-muted-foreground font-mono text-xs whitespace-nowrap">
                  {formatDate(item.createdAt)}
                </div>
                <div>
                  <div className="font-medium text-foreground">{item.title}</div>
                  <div className="text-muted-foreground mt-0.5">{item.description}</div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

    </motion.div>
  );
}
