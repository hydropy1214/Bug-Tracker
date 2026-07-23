import { motion } from "framer-motion";
import { useGetDashboardStats, useHealthCheck } from "@workspace/api-client-react";
import { Shield, Database, Server, Code2, Globe, Radar, Zap, ShieldCheck, Activity, FolderKanban, Target, AlertTriangle, CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/utils";

const STACK = [
  { label: "Frontend UI",   value: "React 19 · Vite 7 · Tailwind 4",    icon: Globe,     color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/20" },
  { label: "API Gateway",   value: "Express 5 · TypeScript · Zod",        icon: Server,    color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20" },
  { label: "Data Store",    value: "PostgreSQL · Drizzle ORM",            icon: Database,  color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20" },
  { label: "Contracts",     value: "OpenAPI 3.1 · Orval Codegen",         icon: Code2,     color: "text-primary",    bg: "bg-primary/10",    border: "border-primary/20" },
];

const SCAN_TYPES = [
  { type: "recon",         label: "Reconnaissance",  icon: Globe,      color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/20",   description: "DNS enumeration, WHOIS, subdomain discovery, technology fingerprinting, OSINT gathering." },
  { type: "enumeration",   label: "Enumeration",     icon: Radar,      color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20", description: "Port scanning, service banner grabbing, HTTP endpoint discovery, API surface mapping." },
  { type: "vulnerability", label: "Vulnerability",   icon: ShieldCheck,color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20", description: "CVE checks, injection testing (SQLi, XSS), misconfigurations, exposed credentials." },
  { type: "full",          label: "Full Attack",     icon: Zap,        color: "text-primary",    bg: "bg-primary/10",    border: "border-primary/20",    description: "All recon, enumeration, and vulnerability checks combined in one comprehensive sequence." },
];

const containerVariants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.05 } },
};
const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.25 } },
};

export function Settings() {
  const { data: stats } = useGetDashboardStats();
  const { data: health } = useHealthCheck();

  const isOnline = health?.status === "ok" || !health;

  const statCards = [
    { label: "Targets",  value: stats?.totalProjects ?? "—", icon: FolderKanban, color: "text-blue-400",   bg: "bg-blue-500/10" },
    { label: "Assets",   value: stats?.totalAssets   ?? "—", icon: Target,       color: "text-purple-400", bg: "bg-purple-500/10" },
    { label: "Findings", value: stats?.totalFindings ?? "—", icon: AlertTriangle,color: "text-orange-400", bg: "bg-orange-500/10" },
    { label: "Open",     value: stats?.openFindings  ?? "—", icon: Activity,     color: "text-red-400",    bg: "bg-red-500/10" },
    { label: "Scans",    value: stats?.completedScans?? "—", icon: CheckCircle2, color: "text-primary",    bg: "bg-primary/10" },
  ];

  return (
    <motion.div variants={containerVariants} initial="hidden" animate="show" className="space-y-8 max-w-4xl">
      {/* Header */}
      <motion.div variants={itemVariants}>
        <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-3 uppercase font-sans">
          <div className="w-8 h-8 rounded-sm bg-primary/10 border border-primary/30 flex items-center justify-center glow-primary">
            <Settings className="w-4 h-4 text-primary" />
          </div>
          System Config
        </h1>
        <p className="text-[11px] font-mono text-muted-foreground mt-2 uppercase tracking-widest">Platform Telemetry & Architecture</p>
      </motion.div>

      <div className="grid md:grid-cols-2 gap-6">
        {/* API Health */}
        <motion.div variants={itemVariants} className="rounded-md border border-border bg-card overflow-hidden h-fit">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-background/50">
            <Activity className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">API Telemetry</span>
            <div className={cn("ml-auto flex items-center gap-1.5 text-[9px] font-mono font-bold uppercase tracking-widest px-2 py-0.5 rounded-sm border", isOnline ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" : "text-red-400 bg-red-500/10 border-red-500/30")}>
              <span className={cn("w-1.5 h-1.5 rounded-full animate-pulse", isOnline ? "bg-emerald-400" : "bg-red-400")} />
              {isOnline ? "Connected" : "Offline"}
            </div>
          </div>
          <div className="p-5 flex items-center gap-6">
             <div className="w-16 h-16 rounded-full border-4 border-emerald-500/20 flex items-center justify-center relative">
               <div className="absolute inset-0 rounded-full border-t-4 border-emerald-400 animate-spin" style={{ animationDuration: '3s' }} />
               <Zap className="w-6 h-6 text-emerald-400" />
             </div>
             <div>
               <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-1">Latency</div>
               <div className="text-2xl font-mono font-bold text-foreground">{'<'} 50<span className="text-sm text-muted-foreground">ms</span></div>
             </div>
          </div>
        </motion.div>

        {/* Database Stats */}
        <motion.div variants={itemVariants} className="rounded-md border border-border bg-card overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-background/50">
            <Database className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">Data Volume</span>
          </div>
          <div className="p-4 grid grid-cols-2 sm:grid-cols-3 gap-3">
            {statCards.map(({ label, value, icon: Icon, color, bg }) => (
              <div key={label} className={cn("rounded-sm p-3 text-center border border-border bg-background")}>
                <div className={cn("flex justify-center mb-1.5 opacity-80", color)}>
                  <Icon className="w-3.5 h-3.5" />
                </div>
                <div className={cn("text-lg font-bold font-mono", color)}>{value}</div>
                <div className="text-[9px] font-mono text-muted-foreground mt-1 uppercase tracking-widest">{label}</div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Modules */}
      <motion.div variants={itemVariants} className="rounded-md border border-border bg-card overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-background/50">
          <Radar className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">Scanner Modules</span>
        </div>
        <div className="p-4 grid sm:grid-cols-2 gap-4">
          {SCAN_TYPES.map(s => {
            const Icon = s.icon;
            return (
              <div key={s.type} className={cn("flex items-start gap-4 p-4 rounded-sm border bg-background transition-colors hover:bg-accent/30", s.border)}>
                <div className={cn("w-8 h-8 rounded-sm flex items-center justify-center flex-shrink-0 border", s.border, s.bg)}>
                  <Icon className={cn("w-4 h-4", s.color)} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="font-mono font-bold text-sm text-foreground uppercase tracking-wider">{s.label}</span>
                  </div>
                  <p className="text-[10px] font-mono text-muted-foreground leading-relaxed uppercase tracking-widest">{s.description}</p>
                </div>
              </div>
            );
          })}
        </div>
      </motion.div>

      {/* Architecture */}
      <motion.div variants={itemVariants} className="rounded-md border border-border bg-card overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-background/50">
          <Code2 className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">Architecture</span>
        </div>
        <div className="p-4 grid sm:grid-cols-2 gap-3">
          {STACK.map(({ label, value, icon: Icon, color, bg, border }) => (
            <div key={label} className={cn("flex items-center gap-3 p-3 rounded-sm border bg-background", border)}>
              <div className={cn("w-8 h-8 rounded-sm flex items-center justify-center flex-shrink-0 border", bg, border)}>
                <Icon className={cn("w-4 h-4", color)} />
              </div>
              <div>
                <div className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest mb-0.5">{label}</div>
                <div className="font-mono font-bold text-xs text-foreground uppercase">{value}</div>
              </div>
            </div>
          ))}
        </div>
      </motion.div>
    </motion.div>
  );
}