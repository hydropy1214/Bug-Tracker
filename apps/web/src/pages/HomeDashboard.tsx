import { useEffect, useRef, useState } from 'react';
import { Link } from 'wouter';
import {
  Shield,
  AlertTriangle,
  FolderKanban,
  Target,
  Activity,
  Zap,
  Radio,
  ChevronRight,
  TrendingUp,
  Clock,
  ExternalLink,
  Bug,
  Globe,
  CheckCircle2,
  Server,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';
import {
  useGetDashboardStats,
  useGetDashboardActivity,
  useGetSeverityBreakdown,
} from '@workspace/api-client';

// ─── Types ─────────────────────────────────────────────────────────────────────

interface RecentFinding {
  id: number;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss: number;
  projectName: string;
  createdAt: string;
  affectedEndpoint: string | null;
}

// ─── Severity config ──────────────────────────────────────────────────────────

const SEV = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30', bar: 'bg-red-500', dot: 'bg-red-400', label: 'CRITICAL' },
  high:     { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30', bar: 'bg-orange-500', dot: 'bg-orange-400', label: 'HIGH' },
  medium:   { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', bar: 'bg-yellow-500', dot: 'bg-yellow-400', label: 'MEDIUM' },
  low:      { color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30', bar: 'bg-blue-500', dot: 'bg-blue-400', label: 'LOW' },
  info:     { color: 'text-muted-foreground', bg: 'bg-accent', border: 'border-border', bar: 'bg-muted-foreground', dot: 'bg-muted-foreground', label: 'INFO' },
} as const;

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  icon: Icon,
  color,
  bg,
  border,
  sub,
  pulse,
}: {
  label: string;
  value: number | string;
  icon: React.ElementType;
  color: string;
  bg: string;
  border: string;
  sub?: string;
  pulse?: boolean;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn('rounded-md border bg-card p-5 flex flex-col gap-3 relative overflow-hidden', border)}
    >
      <div className="flex items-center justify-between">
        <span className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground">{label}</span>
        <div className={cn('w-8 h-8 rounded-sm flex items-center justify-center border', bg, border)}>
          <Icon className={cn('w-4 h-4', color, pulse && 'animate-pulse')} />
        </div>
      </div>
      <div className={cn('text-3xl font-mono font-bold', color)}>{value}</div>
      {sub && <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider">{sub}</div>}
    </motion.div>
  );
}

// ─── Severity bar chart ───────────────────────────────────────────────────────

function SeverityChart({ breakdown }: { breakdown: Record<string, number> }) {
  const total = Object.values(breakdown).reduce((s, n) => s + n, 0);
  const maxVal = Math.max(...Object.values(breakdown), 1);

  return (
    <div className="space-y-3">
      {SEV_ORDER.map((sev) => {
        const count = breakdown[sev] ?? 0;
        const pct = total > 0 ? Math.round((count / total) * 100) : 0;
        const barPct = Math.round((count / maxVal) * 100);
        const s = SEV[sev];
        return (
          <div key={sev} className="flex items-center gap-3">
            <div className={cn('text-[9px] font-mono font-bold w-14 tracking-widest', s.color)}>{s.label}</div>
            <div className="flex-1 h-2 bg-background border border-border rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${barPct}%` }}
                transition={{ duration: 0.8, delay: SEV_ORDER.indexOf(sev) * 0.1 }}
                className={cn('h-full rounded-full', s.bar)}
              />
            </div>
            <div className="flex items-center gap-2 w-16 text-right justify-end">
              <span className={cn('text-xs font-mono font-bold', s.color)}>{count}</span>
              <span className="text-[9px] font-mono text-muted-foreground/50">({pct}%)</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Risk score gauge ─────────────────────────────────────────────────────────

function RiskGauge({ critical, high, medium }: { critical: number; high: number; medium: number }) {
  const score =
    critical * 10 + high * 6 + medium * 3;
  const normalized = Math.min(100, score);

  const grade =
    critical > 0 ? { label: 'F', color: 'text-red-400', ring: 'stroke-red-500' }
    : high >= 3  ? { label: 'D', color: 'text-orange-400', ring: 'stroke-orange-500' }
    : high >= 1  ? { label: 'C', color: 'text-yellow-400', ring: 'stroke-yellow-500' }
    : medium >= 3 ? { label: 'C', color: 'text-yellow-400', ring: 'stroke-yellow-500' }
    : medium >= 1 ? { label: 'B', color: 'text-blue-400', ring: 'stroke-blue-500' }
    :              { label: 'A', color: 'text-emerald-400', ring: 'stroke-emerald-500' };

  const r = 36;
  const circ = 2 * Math.PI * r;
  const dash = (normalized / 100) * circ;

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-28 h-28 flex items-center justify-center">
        <svg width="112" height="112" viewBox="0 0 112 112" className="-rotate-90">
          <circle cx="56" cy="56" r={r} fill="none" strokeWidth="8" className="stroke-border" />
          <motion.circle
            cx="56"
            cy="56"
            r={r}
            fill="none"
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={`${circ}`}
            initial={{ strokeDashoffset: circ }}
            animate={{ strokeDashoffset: circ - dash }}
            transition={{ duration: 1.2, ease: 'easeOut' }}
            className={grade.ring}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn('text-3xl font-mono font-bold', grade.color)}>{grade.label}</span>
          <span className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest">Risk</span>
        </div>
      </div>
      <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">
        Overall Security Grade
      </div>
    </div>
  );
}

// ─── Activity item ────────────────────────────────────────────────────────────

function ActivityItem({
  activity,
}: {
  activity: {
    id: number;
    type: string;
    title: string;
    description: string | null;
    projectName: string | null;
    createdAt: string;
  };
}) {
  const typeConfig = {
    scan_completed: { icon: CheckCircle2, color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
    finding_discovered: { icon: AlertTriangle, color: 'text-orange-400', bg: 'bg-orange-500/10' },
    project_created: { icon: FolderKanban, color: 'text-blue-400', bg: 'bg-blue-500/10' },
    asset_added: { icon: Target, color: 'text-purple-400', bg: 'bg-purple-500/10' },
    scan_started: { icon: Radio, color: 'text-primary', bg: 'bg-primary/10' },
  } as const;

  const cfg = typeConfig[activity.type as keyof typeof typeConfig] ?? {
    icon: Activity,
    color: 'text-muted-foreground',
    bg: 'bg-accent',
  };
  const Icon = cfg.icon;

  const elapsed = (() => {
    const ms = Date.now() - new Date(activity.createdAt).getTime();
    const m = Math.floor(ms / 60000);
    const h = Math.floor(m / 60);
    const d = Math.floor(h / 24);
    if (d > 0) return `${d}d ago`;
    if (h > 0) return `${h}h ago`;
    if (m > 0) return `${m}m ago`;
    return 'just now';
  })();

  return (
    <div className="flex items-start gap-3 py-3 border-b border-border/40 last:border-0">
      <div className={cn('w-7 h-7 rounded-sm flex items-center justify-center flex-shrink-0 mt-0.5', cfg.bg)}>
        <Icon className={cn('w-3.5 h-3.5', cfg.color)} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-xs font-medium text-foreground leading-snug">{activity.title}</div>
        {activity.description && (
          <div className="text-[10px] font-mono text-muted-foreground mt-0.5 line-clamp-1">{activity.description}</div>
        )}
        {activity.projectName && (
          <div className="text-[9px] font-mono text-primary/70 mt-0.5 uppercase tracking-widest">{activity.projectName}</div>
        )}
      </div>
      <div className="text-[9px] font-mono text-muted-foreground/50 flex-shrink-0 mt-0.5">{elapsed}</div>
    </div>
  );
}

// ─── Recent finding row ───────────────────────────────────────────────────────

function FindingRow({ finding }: { finding: RecentFinding }) {
  const s = SEV[finding.severity] ?? SEV.info;
  return (
    <div className="flex items-center gap-3 py-2.5 border-b border-border/40 last:border-0">
      <div className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', s.dot)} />
      <div className="flex-1 min-w-0">
        <div className="text-xs font-medium text-foreground truncate">{finding.title}</div>
        <div className="text-[9px] font-mono text-muted-foreground mt-0.5 truncate">
          {finding.affectedEndpoint ?? finding.projectName}
        </div>
      </div>
      <div className={cn('text-[9px] font-mono font-bold px-1.5 py-0.5 rounded-sm border flex-shrink-0', s.color, s.bg, s.border)}>
        {s.label}
      </div>
      {finding.cvss > 0 && (
        <div className="text-[9px] font-mono text-muted-foreground flex-shrink-0 w-12 text-right">
          {Number(finding.cvss).toFixed(1)}
        </div>
      )}
    </div>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────

export function HomeDashboard() {
  const { data: stats, isLoading: statsLoading } = useGetDashboardStats();
  const { data: activityRaw } = useGetDashboardActivity({ limit: 15 });
  const { data: severityBreakdown } = useGetSeverityBreakdown();

  // Fetch recent critical/high findings
  const [recentFindings, setRecentFindings] = useState<RecentFinding[]>([]);
  useEffect(() => {
    fetch('/api/dashboard/recent-findings?severity=critical,high&limit=8', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : []))
      .then((data) => setRecentFindings(Array.isArray(data) ? data : []))
      .catch(() => {});
  }, []);

  const activity = Array.isArray(activityRaw) ? activityRaw : [];
  const breakdown = (severityBreakdown as unknown as Record<string, number>) ?? {};
  const totalOpen = Object.values(breakdown).reduce((s, n) => s + n, 0);

  const criticalCount = (stats as any)?.criticalFindings ?? 0;
  const highCount = (stats as any)?.highFindings ?? 0;

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8">
      {/* ── Header ───────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight uppercase font-mono text-foreground flex items-center gap-3">
            <div className="w-8 h-8 rounded-sm bg-primary/10 border border-primary/30 flex items-center justify-center glow-primary">
              <Shield className="w-4 h-4 text-primary" />
            </div>
            Operations Dashboard
          </h1>
          <p className="text-[10px] font-mono text-muted-foreground mt-2 uppercase tracking-[0.18em]">
            Security posture · live telemetry · active findings
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/scan"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-sm border border-primary/40 bg-primary/5 text-primary text-[10px] font-mono uppercase tracking-widest hover:bg-primary/10 transition-all"
          >
            <Zap className="w-3.5 h-3.5" />
            Quick Scan
          </Link>
          <Link
            href="/projects"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-sm border border-border bg-card text-[10px] font-mono uppercase tracking-widest text-muted-foreground hover:text-foreground hover:border-primary/30 transition-all"
          >
            <FolderKanban className="w-3.5 h-3.5" />
            Projects
          </Link>
        </div>
      </div>

      {/* ── Stats row ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          label="Projects"
          value={statsLoading ? '—' : (stats as any)?.totalProjects ?? 0}
          icon={FolderKanban}
          color="text-blue-400"
          bg="bg-blue-500/10"
          border="border-blue-500/20"
          sub={`${(stats as any)?.activeProjects ?? 0} active`}
        />
        <StatCard
          label="Assets"
          value={statsLoading ? '—' : (stats as any)?.totalAssets ?? 0}
          icon={Target}
          color="text-purple-400"
          bg="bg-purple-500/10"
          border="border-purple-500/20"
        />
        <StatCard
          label="Open Findings"
          value={statsLoading ? '—' : (stats as any)?.openFindings ?? 0}
          icon={Bug}
          color="text-orange-400"
          bg="bg-orange-500/10"
          border="border-orange-500/20"
          sub={totalOpen > 0 ? `${criticalCount} critical` : undefined}
        />
        <StatCard
          label="Critical / High"
          value={statsLoading ? '—' : `${criticalCount}/${highCount}`}
          icon={AlertTriangle}
          color={criticalCount > 0 ? 'text-red-400' : 'text-orange-400'}
          bg={criticalCount > 0 ? 'bg-red-500/10' : 'bg-orange-500/10'}
          border={criticalCount > 0 ? 'border-red-500/30' : 'border-orange-500/20'}
          pulse={criticalCount > 0}
        />
        <StatCard
          label="Active Scans"
          value={statsLoading ? '—' : (stats as any)?.runningScans ?? 0}
          icon={Radio}
          color={(stats as any)?.runningScans > 0 ? 'text-primary' : 'text-muted-foreground'}
          bg={(stats as any)?.runningScans > 0 ? 'bg-primary/10' : 'bg-accent'}
          border={(stats as any)?.runningScans > 0 ? 'border-primary/30' : 'border-border'}
          sub={`${(stats as any)?.completedScans ?? 0} completed`}
          pulse={(stats as any)?.runningScans > 0}
        />
      </div>

      {/* ── Main content ──────────────────────────────────────────────────── */}
      <div className="grid gap-6 xl:grid-cols-[1fr_1fr_380px]">

        {/* Severity breakdown + risk gauge */}
        <div className="rounded-md border border-border bg-card overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-background/50">
            <TrendingUp className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">Finding Distribution</span>
            <span className="ml-auto text-[9px] font-mono text-muted-foreground uppercase tracking-widest">
              {totalOpen} open
            </span>
          </div>
          <div className="p-5 space-y-6">
            <SeverityChart breakdown={breakdown} />
            <div className="border-t border-border/50 pt-5 flex justify-center">
              <RiskGauge
                critical={criticalCount}
                high={highCount}
                medium={breakdown.medium ?? 0}
              />
            </div>
          </div>
        </div>

        {/* Recent critical/high findings */}
        <div className="rounded-md border border-border bg-card overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-background/50">
            <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
            <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">Top Open Findings</span>
            <Link href="/scans" className="ml-auto text-[9px] font-mono text-primary hover:underline uppercase tracking-widest flex items-center gap-1">
              All scans <ChevronRight className="w-2.5 h-2.5" />
            </Link>
          </div>
          <div className="px-4 py-2 max-h-[360px] overflow-y-auto">
            {recentFindings.length > 0 ? (
              recentFindings.map((f) => <FindingRow key={f.id} finding={f} />)
            ) : (
              <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <CheckCircle2 className="w-8 h-8 mb-3 opacity-20" />
                <p className="text-[10px] font-mono uppercase tracking-widest">No critical or high findings</p>
                <p className="text-[10px] mt-1 opacity-60">Run a scan to discover vulnerabilities</p>
              </div>
            )}
          </div>
        </div>

        {/* Activity feed */}
        <div className="rounded-md border border-border bg-card overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-background/50">
            <Activity className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">Activity Feed</span>
          </div>
          <div className="px-4 max-h-[480px] overflow-y-auto">
            {activity.length > 0 ? (
              activity.map((a: any) => <ActivityItem key={a.id} activity={a} />)
            ) : (
              <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <Clock className="w-8 h-8 mb-3 opacity-20" />
                <p className="text-[10px] font-mono uppercase tracking-widest">No activity yet</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Quick action cards ──────────────────────────────────────────────── */}
      <div className="grid sm:grid-cols-3 gap-4">
        {[
          {
            href: '/scan',
            icon: Zap,
            iconColor: 'text-primary',
            iconBg: 'bg-primary/10',
            iconBorder: 'border-primary/30',
            title: 'Quick Scan',
            desc: 'Point the engine at any domain, IP, or API for an instant 28-phase scan',
            border: 'border-primary/20 hover:border-primary/50',
          },
          {
            href: '/projects',
            icon: FolderKanban,
            iconColor: 'text-blue-400',
            iconBg: 'bg-blue-500/10',
            iconBorder: 'border-blue-500/30',
            title: 'Projects',
            desc: 'Organize targets into projects, manage assets and track findings over time',
            border: 'border-border hover:border-blue-500/40',
          },
          {
            href: '/scans',
            icon: Server,
            iconColor: 'text-purple-400',
            iconBg: 'bg-purple-500/10',
            iconBorder: 'border-purple-500/30',
            title: 'Scan Vault',
            desc: 'Browse every past execution with full logs, findings, and SARIF/JSON exports',
            border: 'border-border hover:border-purple-500/40',
          },
        ].map(({ href, icon: Icon, iconColor, iconBg, iconBorder, title, desc, border }) => (
          <Link
            key={href}
            href={href}
            className={cn(
              'flex items-start gap-4 p-5 rounded-md border bg-card transition-all duration-200 group',
              border,
            )}
          >
            <div className={cn('w-9 h-9 rounded-sm flex items-center justify-center flex-shrink-0 border', iconBg, iconBorder)}>
              <Icon className={cn('w-4 h-4', iconColor)} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="font-mono font-bold text-sm text-foreground group-hover:text-primary transition-colors uppercase tracking-wider">
                {title}
              </div>
              <p className="text-[10px] font-mono text-muted-foreground mt-1.5 leading-relaxed">{desc}</p>
            </div>
            <ChevronRight className="w-4 h-4 text-muted-foreground/30 group-hover:text-primary transition-colors flex-shrink-0 mt-0.5" />
          </Link>
        ))}
      </div>
    </motion.div>
  );
}

// React needs to be in scope for JSX
import React from 'react';
