import { useState, useEffect } from "react";
import { useGetDashboardStats, useGetDashboardActivity, useGetSeverityBreakdown, useListProjects } from "@workspace/api-client-react";
import { Shield, Target, FolderKanban, Activity, AlertTriangle, TrendingUp, Clock, ChevronRight } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip } from "recharts";
import { motion } from "framer-motion";
import { cn, formatDate } from "@/lib/utils";
import { Link } from "wouter";

const SEVERITY_COLORS = {
  critical: "hsl(0 100% 60%)",
  high:     "hsl(24 98% 52%)",
  medium:   "hsl(43 95% 50%)",
  low:      "hsl(217 91% 60%)",
  info:     "hsl(240 5% 60%)",
};

const SEVERITY_LABELS: Record<string, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: "Critical", color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30" },
  high:     { label: "High",     color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  medium:   { label: "Medium",   color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
  low:      { label: "Low",      color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30" },
  info:     { label: "Info",     color: "text-muted-foreground",  bg: "bg-accent",  border: "border-border" },
};

const ACTIVITY_ICONS: Record<string, string> = {
  finding_created: "🚨",
  finding_updated: "✏️",
  finding_deleted: "🗑️",
  scan_completed:  "✅",
  scan_started:    "🚀",
};

const containerVariants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.05 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 16 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.3 } },
};

export function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useGetDashboardStats();
  const { data: activity, isLoading: activityLoading } = useGetDashboardActivity({ limit: 10 });
  const { data: breakdown, isLoading: breakdownLoading } = useGetSeverityBreakdown();
  const { data: projects, isLoading: projectsLoading } = useListProjects();

  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const loading = statsLoading || activityLoading || breakdownLoading || projectsLoading;

  if (loading) {
    return (
      <div className="space-y-8 animate-pulse">
        <div className="h-12 bg-muted rounded-md w-64" />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[1,2,3,4].map(i => <div key={i} className="h-32 bg-card rounded-md border border-border" />)}
        </div>
        <div className="grid gap-4 lg:grid-cols-7">
          <div className="col-span-4 h-80 bg-card rounded-md border border-border" />
          <div className="col-span-3 h-80 bg-card rounded-md border border-border" />
        </div>
      </div>
    );
  }

  const pieData = breakdown ? [
    { name: "Critical", value: breakdown.critical, color: SEVERITY_COLORS.critical },
    { name: "High",     value: breakdown.high,     color: SEVERITY_COLORS.high },
    { name: "Medium",   value: breakdown.medium,   color: SEVERITY_COLORS.medium },
    { name: "Low",      value: breakdown.low,      color: SEVERITY_COLORS.low },
    { name: "Info",     value: breakdown.info,     color: SEVERITY_COLORS.info },
  ].filter(d => d.value > 0) : [];

  const topProjects = projects
    ?.sort((a, b) => (b.criticalCount || 0) + (b.highCount || 0) - ((a.criticalCount || 0) + (a.highCount || 0)))
    .slice(0, 5) || [];

  const threatLevel =
    (stats?.criticalFindings ?? 0) > 0 ? { label: "CRITICAL", color: "text-red-400", ring: "border-red-500/40", bg: "bg-red-500/10" } :
    (stats?.highFindings ?? 0) > 0     ? { label: "HIGH",     color: "text-orange-400", ring: "border-orange-500/40", bg: "bg-orange-500/10" } :
    (stats?.openFindings ?? 0) > 0     ? { label: "MODERATE", color: "text-yellow-400", ring: "border-yellow-500/40", bg: "bg-yellow-500/10" } :
                                          { label: "LOW",      color: "text-primary", ring: "border-primary/40", bg: "bg-primary/10" };

  return (
    <motion.div variants={containerVariants} initial="hidden" animate="show" className="space-y-8">
      {/* Page header */}
      <motion.div variants={itemVariants} className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground uppercase font-sans">Command Center</h1>
          <div className="text-sm font-mono text-primary mt-1 tracking-widest uppercase">
            {time.toISOString().replace('T', ' ').slice(0, 19)} UTC
          </div>
        </div>
        
        {/* Threat level badge */}
        <div className={cn("flex items-center gap-3 px-4 py-2 rounded-sm border", threatLevel.bg, threatLevel.ring)}>
          <div className={cn("w-2 h-2 rounded-full animate-threat-pulse", 
            threatLevel.label === "LOW" ? "bg-primary" :
            threatLevel.label === "MODERATE" ? "bg-yellow-400" :
            threatLevel.label === "HIGH" ? "bg-orange-400" : "bg-red-400"
          )} />
          <span className={cn("text-[11px] font-mono font-bold tracking-widest uppercase", threatLevel.color)}>
            THREAT: {threatLevel.label}
          </span>
        </div>
      </motion.div>

      {/* Stat cards */}
      <motion.div variants={itemVariants} className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {/* Total Projects */}
        <div className="card-gradient-top relative rounded-md border border-border bg-card p-5">
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
          <div className="flex items-start justify-between mb-3">
            <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">Active Targets</div>
            <FolderKanban className="w-4 h-4 text-primary" />
          </div>
          <div className="text-4xl font-bold font-mono text-foreground stat-number-glow">{stats?.activeProjects ?? 0}</div>
          <div className="text-[10px] font-mono text-muted-foreground mt-2 uppercase">
            of {stats?.totalProjects ?? 0} total projects
          </div>
        </div>

        {/* Assets Monitored */}
        <div className="card-gradient-top relative rounded-md border border-border bg-card p-5">
          <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-transparent pointer-events-none" />
          <div className="flex items-start justify-between mb-3">
            <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">Total Assets</div>
            <Target className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-4xl font-bold font-mono text-foreground">{stats?.totalAssets ?? 0}</div>
          <div className="text-[10px] font-mono text-muted-foreground mt-2 uppercase">domains, ips, endpoints</div>
        </div>

        {/* Critical / High */}
        <div className={cn(
          "card-gradient-top card-critical relative rounded-md border bg-card p-5",
          (stats?.criticalFindings ?? 0) > 0 ? "border-red-500/30 glow-critical" : "border-border"
        )}>
          <div className="absolute inset-0 bg-gradient-to-br from-red-500/8 to-transparent pointer-events-none" />
          <div className="flex items-start justify-between mb-3">
            <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">Critical / High</div>
            <Shield className={cn("w-4 h-4", (stats?.criticalFindings ?? 0) > 0 ? "text-red-400" : "text-orange-400")} />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-bold font-mono text-red-400 stat-critical-glow">
              {stats?.criticalFindings ?? 0}
            </span>
            <span className="text-xl text-muted-foreground">/</span>
            <span className="text-2xl font-bold font-mono text-orange-400">{stats?.highFindings ?? 0}</span>
          </div>
          <div className="text-[10px] font-mono text-muted-foreground mt-2 uppercase">
            {stats?.openFindings ?? 0} open findings
          </div>
        </div>

        {/* Active Scans */}
        <div className="card-gradient-top relative rounded-md border border-border bg-card p-5">
          <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/5 to-transparent pointer-events-none" />
          <div className="flex items-start justify-between mb-3">
            <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">Active Scans</div>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-center gap-3">
            <span className="text-4xl font-bold font-mono text-foreground">{stats?.runningScans ?? 0}</span>
            {(stats?.runningScans ?? 0) > 0 && (
              <span className="text-[10px] text-emerald-400 font-mono tracking-widest border border-emerald-500/20 bg-emerald-500/10 px-1.5 py-0.5 rounded">
                LIVE
              </span>
            )}
          </div>
          <div className="text-[10px] font-mono text-muted-foreground mt-2 uppercase">
            {stats?.completedScans ?? 0} completed
          </div>
        </div>
      </motion.div>

      {/* Middle row */}
      <motion.div variants={itemVariants} className="grid gap-4 lg:grid-cols-7">
        {/* Severity breakdown */}
        <div className="lg:col-span-3 rounded-md border border-border bg-card flex flex-col">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
            <AlertTriangle className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">Risk Distribution</span>
          </div>
          <div className="p-5 flex-1 flex flex-col justify-center">
            {pieData.length > 0 ? (
              <>
                <div className="h-[180px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%" cy="50%"
                        innerRadius={60} outerRadius={80}
                        paddingAngle={2}
                        dataKey="value"
                        stroke="none"
                      >
                        {pieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <RechartsTooltip
                        contentStyle={{ backgroundColor: 'hsl(var(--popover))', borderColor: 'hsl(var(--border))', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}
                        itemStyle={{ color: 'hsl(var(--foreground))' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="grid grid-cols-2 gap-2 mt-4">
                  {(breakdown ? Object.entries(breakdown) : []).filter(([,v]) => (v as number) > 0).map(([key, value]) => {
                    const s = SEVERITY_LABELS[key];
                    if (!s) return null;
                    return (
                      <div key={key} className={cn("flex items-center justify-between px-3 py-1.5 rounded border", s.bg, s.border)}>
                        <span className={cn("text-[10px] font-mono uppercase tracking-wider", s.color)}>{s.label}</span>
                        <span className={cn("text-xs font-bold font-mono", s.color)}>{value as number}</span>
                      </div>
                    );
                  })}
                </div>
              </>
            ) : (
              <div className="flex flex-col items-center justify-center py-10 text-muted-foreground">
                <Shield className="w-8 h-8 mb-3 opacity-20" />
                <p className="text-xs font-mono uppercase">Zero Findings</p>
              </div>
            )}
          </div>
        </div>

        {/* Top vulnerable projects */}
        <div className="lg:col-span-4 rounded-md border border-border bg-card flex flex-col">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <div className="flex items-center gap-2">
              <TrendingUp className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">Top Risk Projects</span>
            </div>
            <Link href="/projects" className="text-[10px] font-mono text-muted-foreground hover:text-primary transition-colors flex items-center gap-1 uppercase">
              View All <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="p-0 flex-1 overflow-y-auto">
            {topProjects.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <FolderKanban className="w-8 h-8 mb-3 opacity-20" />
                <p className="text-xs font-mono uppercase">No Active Risk Data</p>
              </div>
            ) : (
              <div className="divide-y divide-border/50">
                {topProjects.map((p, i) => (
                  <Link key={p.id} href={`/projects/${p.id}`} className="flex items-center gap-4 p-4 hover:bg-accent/40 transition-colors group cursor-pointer">
                    <div className="text-xs font-mono text-muted-foreground/30 w-4 text-right flex-shrink-0">{(i + 1).toString().padStart(2, '0')}</div>
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm text-foreground group-hover:text-primary transition-colors truncate">{p.name}</div>
                      <div className="text-[10px] font-mono text-muted-foreground mt-0.5 uppercase tracking-wider">{p.assetCount || 0} Assets Indexed</div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {(p.criticalCount ?? 0) > 0 && (
                        <div className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/25">
                          {p.criticalCount} C
                        </div>
                      )}
                      {(p.highCount ?? 0) > 0 && (
                        <div className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/25">
                          {p.highCount} H
                        </div>
                      )}
                      {!(p.criticalCount) && !(p.highCount) && (
                        <div className="text-[10px] text-primary font-mono border border-primary/20 bg-primary/10 px-1.5 py-0.5 rounded">CLEAN</div>
                      )}
                    </div>
                    <ChevronRight className="w-3 h-3 text-muted-foreground/30 group-hover:text-primary transition-colors" />
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>
      </motion.div>

      {/* Activity feed */}
      <motion.div variants={itemVariants} className="rounded-md border border-border bg-card overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
          <Clock className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">Global Activity Log</span>
        </div>
        <div className="divide-y divide-border/40 max-h-[300px] overflow-y-auto">
          {!activity?.length ? (
            <div className="flex flex-col items-center justify-center py-10 text-muted-foreground">
              <Activity className="w-6 h-6 mb-2 opacity-20" />
              <p className="text-xs font-mono uppercase">Silence</p>
            </div>
          ) : activity.map(item => (
            <div key={item.id} className="flex items-start gap-4 px-4 py-3 hover:bg-accent/40 transition-colors">
              <div className="text-sm flex-shrink-0 mt-0.5">
                {ACTIVITY_ICONS[item.type] ?? "🔸"}
              </div>
              <div className="flex-1 min-w-0">
                <div className="font-medium text-sm text-foreground leading-snug">{item.title}</div>
                <div className="text-[11px] text-muted-foreground mt-0.5 line-clamp-1">{item.description}</div>
              </div>
              <div className="text-[10px] font-mono text-muted-foreground/60 flex-shrink-0 mt-0.5 uppercase tracking-wider">
                {formatDate(item.createdAt)}
              </div>
            </div>
          ))}
        </div>
      </motion.div>
    </motion.div>
  );
}