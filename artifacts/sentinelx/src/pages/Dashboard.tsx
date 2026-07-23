import { useGetDashboardStats, useGetDashboardActivity, useGetSeverityBreakdown, useListProjects } from "@workspace/api-client-react";
import { Shield, Target, FolderKanban, Activity, AlertTriangle, TrendingUp, Clock, ChevronRight } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip } from "recharts";
import { motion } from "framer-motion";
import { cn, formatDate } from "@/lib/utils";
import { Link } from "wouter";

const SEVERITY_COLORS = {
  critical: "hsl(0 90% 58%)",
  high:     "hsl(24 98% 52%)",
  medium:   "hsl(43 95% 50%)",
  low:      "hsl(217 91% 60%)",
  info:     "hsl(220 10% 42%)",
};

const SEVERITY_LABELS: Record<string, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: "Critical", color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30" },
  high:     { label: "High",     color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  medium:   { label: "Medium",   color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
  low:      { label: "Low",      color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30" },
  info:     { label: "Info",     color: "text-slate-400",  bg: "bg-slate-500/10",  border: "border-slate-500/30" },
};

const ACTIVITY_ICONS: Record<string, string> = {
  finding_created: "🔴",
  finding_updated: "🟡",
  finding_deleted: "⚫",
  scan_completed:  "✅",
  scan_started:    "🔵",
};

const containerVariants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.06 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 16 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.3 } },
};

export function Dashboard() {
  const { data: stats,     isLoading: statsLoading     } = useGetDashboardStats();
  const { data: activity,  isLoading: activityLoading  } = useGetDashboardActivity({ limit: 10 });
  const { data: breakdown, isLoading: breakdownLoading } = useGetSeverityBreakdown();
  const { data: projects,  isLoading: projectsLoading  } = useListProjects();

  const loading = statsLoading || activityLoading || breakdownLoading || projectsLoading;

  if (loading) {
    return (
      <div className="space-y-8 animate-pulse">
        <div className="h-8 bg-muted rounded w-40" />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[1,2,3,4].map(i => <div key={i} className="h-32 bg-card rounded-xl border border-border" />)}
        </div>
        <div className="grid gap-4 lg:grid-cols-7">
          <div className="col-span-4 h-80 bg-card rounded-xl border border-border" />
          <div className="col-span-3 h-80 bg-card rounded-xl border border-border" />
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
    (stats?.criticalFindings ?? 0) > 0 ? { label: "CRITICAL", color: "text-red-400", ring: "ring-red-500/40", bg: "bg-red-500/10" } :
    (stats?.highFindings ?? 0) > 0     ? { label: "HIGH",     color: "text-orange-400", ring: "ring-orange-500/40", bg: "bg-orange-500/10" } :
    (stats?.openFindings ?? 0) > 0     ? { label: "MODERATE", color: "text-yellow-400", ring: "ring-yellow-500/40", bg: "bg-yellow-500/10" } :
                                          { label: "LOW",      color: "text-emerald-400", ring: "ring-emerald-500/40", bg: "bg-emerald-500/10" };

  return (
    <motion.div variants={containerVariants} initial="hidden" animate="show" className="space-y-8">
      {/* Page header */}
      <motion.div variants={itemVariants} className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">Security Overview</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Real-time threat intelligence across all monitored targets.</p>
        </div>
        {/* Threat level badge */}
        <div className={cn("flex items-center gap-3 px-4 py-2 rounded-xl border ring-1", threatLevel.bg, threatLevel.ring, "border-transparent")}>
          <div className={cn("w-2 h-2 rounded-full animate-threat-pulse", 
            threatLevel.label === "LOW" ? "bg-emerald-400" :
            threatLevel.label === "MODERATE" ? "bg-yellow-400" :
            threatLevel.label === "HIGH" ? "bg-orange-400" : "bg-red-400"
          )} />
          <span className={cn("text-xs font-mono font-bold tracking-widest", threatLevel.color)}>
            THREAT LEVEL: {threatLevel.label}
          </span>
        </div>
      </motion.div>

      {/* Stat cards */}
      <motion.div variants={itemVariants} className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {/* Total Projects */}
        <div className="card-gradient-top relative rounded-xl border border-border/60 bg-card p-5 overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
          <div className="flex items-start justify-between mb-3">
            <div className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Projects</div>
            <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center">
              <FolderKanban className="w-4 h-4 text-primary" />
            </div>
          </div>
          <div className="text-4xl font-bold font-mono text-foreground stat-number-glow">{stats?.totalProjects ?? 0}</div>
          <div className="text-xs text-muted-foreground mt-2">
            <span className="text-primary font-mono">{stats?.activeProjects ?? 0}</span> active targets
          </div>
        </div>

        {/* Assets Monitored */}
        <div className="card-gradient-top relative rounded-xl border border-border/60 bg-card p-5 overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-transparent pointer-events-none" />
          <div className="flex items-start justify-between mb-3">
            <div className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Assets</div>
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center">
              <Target className="w-4 h-4 text-blue-400" />
            </div>
          </div>
          <div className="text-4xl font-bold font-mono text-foreground">{stats?.totalAssets ?? 0}</div>
          <div className="text-xs text-muted-foreground mt-2">across all scopes</div>
        </div>

        {/* Critical / High */}
        <div className={cn(
          "card-gradient-top card-critical relative rounded-xl border bg-card p-5 overflow-hidden",
          (stats?.criticalFindings ?? 0) > 0 ? "border-red-500/30 glow-critical" : "border-border/60"
        )}>
          <div className="absolute inset-0 bg-gradient-to-br from-red-500/8 to-transparent pointer-events-none" />
          <div className="flex items-start justify-between mb-3">
            <div className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Critical / High</div>
            <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center",
              (stats?.criticalFindings ?? 0) > 0 ? "bg-red-500/15" : "bg-orange-500/10"
            )}>
              <Shield className={cn("w-4 h-4", (stats?.criticalFindings ?? 0) > 0 ? "text-red-400" : "text-orange-400")} />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-bold font-mono text-red-400 stat-critical-glow">
              {stats?.criticalFindings ?? 0}
            </span>
            <span className="text-xl text-muted-foreground">/</span>
            <span className="text-2xl font-bold font-mono text-orange-400">{stats?.highFindings ?? 0}</span>
          </div>
          <div className="text-xs text-muted-foreground mt-2">
            {stats?.openFindings ?? 0} total open findings
          </div>
        </div>

        {/* Active Scans */}
        <div className="card-gradient-top relative rounded-xl border border-border/60 bg-card p-5 overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/5 to-transparent pointer-events-none" />
          <div className="flex items-start justify-between mb-3">
            <div className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Active Scans</div>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center">
              <Activity className="w-4 h-4 text-emerald-400" />
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-4xl font-bold font-mono text-foreground">{stats?.runningScans ?? 0}</span>
            {(stats?.runningScans ?? 0) > 0 && (
              <div className="flex gap-1 items-center">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-xs text-emerald-400 font-mono">LIVE</span>
              </div>
            )}
          </div>
          <div className="text-xs text-muted-foreground mt-2">
            <span className="font-mono">{stats?.completedScans ?? 0}</span> completed
          </div>
        </div>
      </motion.div>

      {/* Middle row */}
      <motion.div variants={itemVariants} className="grid gap-4 lg:grid-cols-7">
        {/* Top vulnerable projects */}
        <div className="lg:col-span-4 rounded-xl border border-border/60 bg-card overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-border/60">
            <div className="flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-muted-foreground" />
              <span className="font-semibold text-sm text-foreground">Top Vulnerable Projects</span>
            </div>
            <Link href="/projects" className="text-xs text-muted-foreground hover:text-primary transition-colors flex items-center gap-1">
              View all <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="p-5">
            {topProjects.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 text-muted-foreground">
                <FolderKanban className="w-10 h-10 mb-3 opacity-20" />
                <p className="text-sm">No vulnerable projects found.</p>
                <p className="text-xs opacity-60 mt-1">Start a scan to discover findings.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {topProjects.map((p, i) => (
                  <Link key={p.id} href={`/projects/${p.id}`} className="flex items-center gap-4 p-3 rounded-lg hover:bg-accent/50 transition-colors group cursor-pointer">
                    <div className="text-xs font-mono text-muted-foreground/50 w-4 text-right flex-shrink-0">{i + 1}</div>
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm text-foreground group-hover:text-primary transition-colors truncate">{p.name}</div>
                      <div className="text-xs text-muted-foreground mt-0.5">{p.assetCount || 0} assets</div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {(p.criticalCount ?? 0) > 0 && (
                        <div className="text-xs font-mono font-bold px-2 py-1 rounded-md bg-red-500/12 text-red-400 border border-red-500/25">
                          {p.criticalCount}C
                        </div>
                      )}
                      {(p.highCount ?? 0) > 0 && (
                        <div className="text-xs font-mono font-bold px-2 py-1 rounded-md bg-orange-500/12 text-orange-400 border border-orange-500/25">
                          {p.highCount}H
                        </div>
                      )}
                      {!(p.criticalCount) && !(p.highCount) && (
                        <div className="text-xs text-emerald-400 font-mono">Clean</div>
                      )}
                    </div>
                    <ChevronRight className="w-3 h-3 text-muted-foreground/30 group-hover:text-primary transition-colors" />
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Severity breakdown */}
        <div className="lg:col-span-3 rounded-xl border border-border/60 bg-card overflow-hidden">
          <div className="flex items-center gap-2 px-5 py-4 border-b border-border/60">
            <AlertTriangle className="w-4 h-4 text-muted-foreground" />
            <span className="font-semibold text-sm text-foreground">Severity Breakdown</span>
          </div>
          <div className="p-5">
            {pieData.length > 0 ? (
              <>
                <div className="h-[160px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%" cy="50%"
                        innerRadius={50} outerRadius={70}
                        paddingAngle={3}
                        dataKey="value"
                        stroke="none"
                      >
                        {pieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <RechartsTooltip
                        contentStyle={{ backgroundColor: 'hsl(var(--popover))', borderColor: 'hsl(var(--border))', borderRadius: '8px', fontSize: '12px', fontFamily: 'var(--font-mono)' }}
                        itemStyle={{ color: 'hsl(var(--foreground))' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                {/* Legend */}
                <div className="grid grid-cols-2 gap-2 mt-3">
                  {(breakdown ? Object.entries(breakdown) : []).filter(([,v]) => (v as number) > 0).map(([key, value]) => {
                    const s = SEVERITY_LABELS[key];
                    if (!s) return null;
                    return (
                      <div key={key} className={cn("flex items-center justify-between px-3 py-2 rounded-lg border", s.bg, s.border)}>
                        <span className={cn("text-xs font-mono uppercase", s.color)}>{s.label}</span>
                        <span className={cn("text-sm font-bold font-mono", s.color)}>{value as number}</span>
                      </div>
                    );
                  })}
                </div>
              </>
            ) : (
              <div className="flex flex-col items-center justify-center py-10 text-muted-foreground">
                <Shield className="w-10 h-10 mb-3 opacity-20" />
                <p className="text-sm">No findings recorded.</p>
                <p className="text-xs opacity-60 mt-1">Run a vulnerability scan to get started.</p>
              </div>
            )}
          </div>
        </div>
      </motion.div>

      {/* Activity feed */}
      <motion.div variants={itemVariants} className="rounded-xl border border-border/60 bg-card overflow-hidden">
        <div className="flex items-center gap-2 px-5 py-4 border-b border-border/60">
          <Clock className="w-4 h-4 text-muted-foreground" />
          <span className="font-semibold text-sm text-foreground">Recent Activity</span>
        </div>
        <div className="divide-y divide-border/40">
          {!activity?.length ? (
            <div className="flex flex-col items-center justify-center py-10 text-muted-foreground">
              <Activity className="w-8 h-8 mb-2 opacity-20" />
              <p className="text-sm">No recent activity.</p>
            </div>
          ) : activity.map(item => (
            <div key={item.id} className="flex items-start gap-4 px-5 py-3.5 hover:bg-accent/30 transition-colors group">
              <div className="mt-0.5 text-base flex-shrink-0">
                {ACTIVITY_ICONS[item.type] ?? "📋"}
              </div>
              <div className="flex-1 min-w-0">
                <div className="font-medium text-sm text-foreground leading-snug">{item.title}</div>
                <div className="text-xs text-muted-foreground mt-0.5 line-clamp-1">{item.description}</div>
              </div>
              <div className="text-[11px] font-mono text-muted-foreground/60 flex-shrink-0 mt-0.5 whitespace-nowrap">
                {formatDate(item.createdAt)}
              </div>
            </div>
          ))}
        </div>
      </motion.div>
    </motion.div>
  );
}
