import { motion } from "framer-motion";
import { useGetDashboardStats } from "@workspace/api-client-react";
import { Shield, Database, Server, Code2, Globe, Radar, Zap, ShieldCheck, Activity, FolderKanban, Target, AlertTriangle, CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/utils";

const STACK = [
  { label: "Frontend",   value: "React 19 · Vite 7 · Tailwind CSS 4",    icon: Globe,     color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/20" },
  { label: "API",        value: "Express 5 · TypeScript · Zod v4",        icon: Server,    color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20" },
  { label: "Database",   value: "PostgreSQL · Drizzle ORM",                icon: Database,  color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20" },
  { label: "Validation", value: "OpenAPI spec · generated types",          icon: Code2,     color: "text-primary",    bg: "bg-primary/10",    border: "border-primary/20" },
];

const SCAN_TYPES = [
  { type: "recon",         label: "Reconnaissance",  icon: Globe,      color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/20",   description: "DNS enumeration, WHOIS, subdomain discovery, technology fingerprinting, OSINT gathering." },
  { type: "enumeration",   label: "Enumeration",     icon: Radar,      color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20", description: "Port scanning, service banner grabbing, HTTP endpoint discovery, API surface mapping." },
  { type: "vulnerability", label: "Vulnerability",   icon: ShieldCheck,color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20", description: "CVE checks, injection testing (SQLi, XSS, SSTI), misconfigurations, exposed secrets and credentials." },
  { type: "full",          label: "Full Scan",       icon: Zap,        color: "text-primary",    bg: "bg-primary/10",    border: "border-primary/20",    description: "All recon, enumeration, and vulnerability checks combined in one comprehensive scan pass." },
];

const containerVariants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.06 } },
};
const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.25 } },
};

export function Settings() {
  const { data: stats } = useGetDashboardStats();

  const statCards = [
    { label: "Projects", value: stats?.totalProjects ?? "—", icon: FolderKanban, color: "text-blue-400",   bg: "bg-blue-500/10" },
    { label: "Assets",   value: stats?.totalAssets   ?? "—", icon: Target,       color: "text-purple-400", bg: "bg-purple-500/10" },
    { label: "Findings", value: stats?.totalFindings  ?? "—", icon: AlertTriangle,color: "text-orange-400", bg: "bg-orange-500/10" },
    { label: "Open",     value: stats?.openFindings   ?? "—", icon: Activity,     color: "text-red-400",    bg: "bg-red-500/10" },
    { label: "Scans",    value: stats?.completedScans ?? "—", icon: CheckCircle2, color: "text-emerald-400",bg: "bg-emerald-500/10" },
  ];

  return (
    <motion.div variants={containerVariants} initial="hidden" animate="show" className="space-y-8 max-w-3xl">
      {/* Header */}
      <motion.div variants={itemVariants}>
        <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
            <Shield className="w-4 h-4 text-primary" />
          </div>
          Settings
        </h1>
        <p className="text-sm text-muted-foreground mt-1">System information and platform configuration reference.</p>
      </motion.div>

      {/* Database status */}
      <motion.div variants={itemVariants} className="rounded-xl border border-border/60 bg-card overflow-hidden">
        <div className="flex items-center gap-2 px-5 py-4 border-b border-border/60">
          <Database className="w-4 h-4 text-muted-foreground" />
          <span className="font-semibold text-sm text-foreground">Database Status</span>
          <div className="ml-auto flex items-center gap-1.5 text-[10px] font-mono text-emerald-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            CONNECTED
          </div>
        </div>
        <div className="p-5 grid grid-cols-2 sm:grid-cols-5 gap-3">
          {statCards.map(({ label, value, icon: Icon, color, bg }) => (
            <div key={label} className={cn("rounded-lg p-4 text-center border border-border/40", bg)}>
              <div className={cn("flex justify-center mb-2", color)}>
                <Icon className="w-4 h-4" />
              </div>
              <div className={cn("text-2xl font-bold font-mono", color)}>{value}</div>
              <div className="text-[10px] text-muted-foreground mt-1 uppercase tracking-wider">{label}</div>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Scan types */}
      <motion.div variants={itemVariants} className="rounded-xl border border-border/60 bg-card overflow-hidden">
        <div className="flex items-center gap-2 px-5 py-4 border-b border-border/60">
          <Radar className="w-4 h-4 text-muted-foreground" />
          <span className="font-semibold text-sm text-foreground">Scan Type Reference</span>
        </div>
        <div className="p-5 grid gap-3">
          {SCAN_TYPES.map(s => {
            const Icon = s.icon;
            return (
              <div key={s.type} className={cn("flex items-start gap-4 p-4 rounded-lg border", s.bg, s.border)}>
                <div className={cn("w-8 h-8 rounded-md flex items-center justify-center flex-shrink-0 border", s.border, s.bg)}>
                  <Icon className={cn("w-4 h-4", s.color)} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-medium text-sm text-foreground">{s.label}</span>
                    <span className={cn("text-[10px] font-mono px-1.5 py-0.5 rounded border", s.bg, s.border, s.color)}>{s.type}</span>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">{s.description}</p>
                </div>
              </div>
            );
          })}
        </div>
      </motion.div>

      {/* Stack */}
      <motion.div variants={itemVariants} className="rounded-xl border border-border/60 bg-card overflow-hidden">
        <div className="flex items-center gap-2 px-5 py-4 border-b border-border/60">
          <Code2 className="w-4 h-4 text-muted-foreground" />
          <span className="font-semibold text-sm text-foreground">Tech Stack</span>
        </div>
        <div className="p-5 grid sm:grid-cols-2 gap-3">
          {STACK.map(({ label, value, icon: Icon, color, bg, border }) => (
            <div key={label} className={cn("flex items-center gap-3 p-4 rounded-lg border", bg, border)}>
              <div className={cn("w-8 h-8 rounded-md flex items-center justify-center flex-shrink-0 border", bg, border)}>
                <Icon className={cn("w-4 h-4", color)} />
              </div>
              <div>
                <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-0.5">{label}</div>
                <div className="font-mono text-xs text-foreground">{value}</div>
              </div>
            </div>
          ))}
        </div>
      </motion.div>

      {/* About */}
      <motion.div variants={itemVariants} className="rounded-xl border border-border/60 bg-card overflow-hidden">
        <div className="flex items-center gap-2 px-5 py-4 border-b border-border/60">
          <Shield className="w-4 h-4 text-muted-foreground" />
          <span className="font-semibold text-sm text-foreground">About SentinelX</span>
        </div>
        <div className="p-5 space-y-3">
          <p className="text-sm text-muted-foreground leading-relaxed">
            <span className="font-semibold text-foreground">SentinelX</span> is a security vulnerability management platform for DevSecOps teams.
            Track external attack surfaces, document findings with CVE/CVSS metadata, run automated scan workflows, and monitor remediation progress across multiple projects.
          </p>
          <div className="flex items-center gap-3 pt-2 border-t border-border/60">
            <div className="flex items-center gap-1.5 text-[10px] font-mono text-muted-foreground">
              <Zap className="w-3 h-3" />
              v0.1.0
            </div>
            <div className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              Production Ready
            </div>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}
