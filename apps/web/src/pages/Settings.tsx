import { useState } from "react";
import { motion } from "framer-motion";
import { useGetDashboardStats, useHealthCheck } from "@workspace/api-client";
import {
  Shield,
  Database,
  Server,
  Code2,
  Globe,
  Radar,
  Zap,
  ShieldCheck,
  Activity,
  FolderKanban,
  Target,
  AlertTriangle,
  CheckCircle2,
  Settings as SettingsIcon,
  Key,
  Save,
  Eye,
  EyeOff,
  Terminal,
  Cpu,
  Info,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

// ─── Static config ────────────────────────────────────────────────────────────

const STACK = [
  { label: "Frontend UI",   value: "React 19 · Vite 7 · Tailwind 4",  icon: Globe,     color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/20" },
  { label: "API Gateway",   value: "Express 5 · TypeScript · Zod",      icon: Server,    color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20" },
  { label: "Data Store",    value: "PostgreSQL · Drizzle ORM",          icon: Database,  color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20" },
  { label: "Contracts",     value: "OpenAPI 3.1 · Orval Codegen",       icon: Code2,     color: "text-primary",    bg: "bg-primary/10",    border: "border-primary/20" },
];

const SCAN_MODULES = [
  { type: "recon",       label: "Reconnaissance",  icon: Globe,       color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/20",   desc: "DNS, WHOIS, TLS, HTTP headers, tech fingerprinting, cert transparency (crt.sh)." },
  { type: "enumeration", label: "Enumeration",      icon: Radar,       color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20", desc: "Port scanning (nmap), subdomain brute-force, sensitive paths, Wayback Machine, cloud buckets." },
  { type: "attack",      label: "Deep Attack",      icon: ShieldCheck, color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20", desc: "SQLi, XSS, SSTI, XXE, SSRF, CMDi, NoSQL injection, JWT weakness, IDOR, HTTP smuggling, CORS." },
  { type: "full",        label: "Full Scan",        icon: Zap,         color: "text-primary",    bg: "bg-primary/10",    border: "border-primary/20",    desc: "All 28 phases in 5 parallel rounds. Nuclei CVE/template scan, JS secret extraction, OAuth, vhost." },
];

const SCAN_PROFILES = [
  { value: "passive",          label: "Passive",          budget: "80 req",   desc: "DNS/TLS/headers only. No active probes." },
  { value: "safe_active",      label: "Safe Active",      budget: "300 req",  desc: "Bounded active checks; no deep injection." },
  { value: "deep_authorized",  label: "Deep Authorized",  budget: "1,200 req",desc: "Full probes for authorized targets." },
  { value: "authenticated",    label: "Authenticated",    budget: "1,500 req",desc: "Uses supplied auth headers for session-aware checks." },
  { value: "lab",              label: "Lab",              budget: "2,000 req",desc: "Unrestricted deep checks for controlled lab environments." },
];

const containerVariants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.05 } },
};
const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.25 } },
};

// ─── NVD API key section ──────────────────────────────────────────────────────

function NvdApiKeySection() {
  const [show, setShow] = useState(false);
  const [value, setValue] = useState("");
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!value.trim()) return;
    setSaving(true);
    try {
      const res = await fetch("/api/settings/nvd-api-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: value.trim() }),
      });
      if (res.ok) {
        toast.success("NVD API key saved — will take effect on the next scan");
        setValue("");
      } else {
        toast.error("Failed to save NVD API key");
      }
    } catch {
      toast.error("Could not reach API server");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-start gap-3 p-3 rounded-sm border border-blue-500/20 bg-blue-500/5 text-[10px] font-mono text-blue-300 leading-relaxed">
        <Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
        <span>
          The NVD API is free but rate-limited to 5 req/30s without a key (50 req/30s with one).
          Get a free key at{" "}
          <a
            href="https://nvd.nist.gov/developers/request-an-api-key"
            target="_blank"
            rel="noopener noreferrer"
            className="underline hover:text-blue-200"
          >
            nvd.nist.gov
          </a>
          .
        </span>
      </div>
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <input
            type={show ? "text" : "password"}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void save()}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            className="w-full h-9 rounded-sm border border-border bg-background px-3 pr-10 text-[11px] font-mono text-foreground outline-none focus:border-primary/50 placeholder:text-muted-foreground/40"
          />
          <button
            type="button"
            onClick={() => setShow((s) => !s)}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
          >
            {show ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>
        </div>
        <button
          onClick={() => void save()}
          disabled={!value.trim() || saving}
          className="h-9 px-4 rounded-sm border border-primary/40 bg-primary/5 text-primary text-[10px] font-mono uppercase tracking-wider hover:bg-primary/10 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5 transition-all"
        >
          <Save className="w-3.5 h-3.5" />
          {saving ? "Saving…" : "Save Key"}
        </button>
      </div>
    </div>
  );
}

// ─── Main settings page ───────────────────────────────────────────────────────

export function Settings() {
  const { data: stats } = useGetDashboardStats();
  const { data: health } = useHealthCheck();
  const isOnline = health?.status === "ok" || !health;

  const statCards = [
    { label: "Targets",  value: (stats as any)?.totalProjects ?? "—", icon: FolderKanban, color: "text-blue-400",   bg: "bg-blue-500/10" },
    { label: "Assets",   value: (stats as any)?.totalAssets   ?? "—", icon: Target,       color: "text-purple-400", bg: "bg-purple-500/10" },
    { label: "Findings", value: (stats as any)?.totalFindings ?? "—", icon: AlertTriangle,color: "text-orange-400", bg: "bg-orange-500/10" },
    { label: "Open",     value: (stats as any)?.openFindings  ?? "—", icon: Activity,     color: "text-red-400",    bg: "bg-red-500/10" },
    { label: "Scans",    value: (stats as any)?.completedScans?? "—", icon: CheckCircle2, color: "text-primary",    bg: "bg-primary/10" },
  ];

  return (
    <motion.div variants={containerVariants} initial="hidden" animate="show" className="space-y-8 max-w-5xl">
      {/* Header */}
      <motion.div variants={itemVariants}>
        <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-3 uppercase font-sans">
          <div className="w-8 h-8 rounded-sm bg-primary/10 border border-primary/30 flex items-center justify-center glow-primary">
            <SettingsIcon className="w-4 h-4 text-primary" />
          </div>
          System Config
        </h1>
        <p className="text-[11px] font-mono text-muted-foreground mt-2 uppercase tracking-widest">
          Platform configuration · telemetry · architecture
        </p>
      </motion.div>

      {/* ── Top row: API health + data volume ─────────────────────────── */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* API Health */}
        <motion.div variants={itemVariants} className="rounded-md border border-border bg-card overflow-hidden h-fit">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-background/50">
            <Activity className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">API Telemetry</span>
            <div className={cn(
              "ml-auto flex items-center gap-1.5 text-[9px] font-mono font-bold uppercase tracking-widest px-2 py-0.5 rounded-sm border",
              isOnline
                ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
                : "text-red-400 bg-red-500/10 border-red-500/30"
            )}>
              <span className={cn("w-1.5 h-1.5 rounded-full animate-pulse", isOnline ? "bg-emerald-400" : "bg-red-400")} />
              {isOnline ? "Connected" : "Offline"}
            </div>
          </div>
          <div className="p-5 flex items-center gap-6">
            <div className="w-16 h-16 rounded-full border-4 border-emerald-500/20 flex items-center justify-center relative">
              <div className="absolute inset-0 rounded-full border-t-4 border-emerald-400 animate-spin" style={{ animationDuration: "3s" }} />
              <Zap className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-1">Status</div>
              <div className="text-2xl font-mono font-bold text-foreground">{isOnline ? "LIVE" : "DOWN"}</div>
              <div className="text-[9px] font-mono text-muted-foreground mt-1 uppercase tracking-widest">
                Express 5 · /api health endpoint
              </div>
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
              <div key={label} className="rounded-sm p-3 text-center border border-border bg-background">
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

      {/* ── NVD API Key ────────────────────────────────────────────────── */}
      <motion.div variants={itemVariants} className="rounded-md border border-border bg-card overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-background/50">
          <Key className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">CVE / NVD API Key</span>
          <span className="ml-auto text-[9px] font-mono text-muted-foreground/50 uppercase tracking-widest">Phase 23 · CVE Lookup</span>
        </div>
        <div className="p-5">
          <NvdApiKeySection />
        </div>
      </motion.div>

      {/* ── Scanner Modules ────────────────────────────────────────────── */}
      <motion.div variants={itemVariants} className="rounded-md border border-border bg-card overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-background/50">
          <Radar className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">Scanner Modules</span>
          <span className="ml-auto text-[9px] font-mono text-muted-foreground/50">28-phase pipeline</span>
        </div>
        <div className="p-4 grid sm:grid-cols-2 gap-4">
          {SCAN_MODULES.map((s) => {
            const Icon = s.icon;
            return (
              <div key={s.type} className={cn("flex items-start gap-4 p-4 rounded-sm border bg-background", s.border)}>
                <div className={cn("w-8 h-8 rounded-sm flex items-center justify-center flex-shrink-0 border", s.border, s.bg)}>
                  <Icon className={cn("w-4 h-4", s.color)} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="font-mono font-bold text-sm text-foreground uppercase tracking-wider">{s.label}</span>
                  </div>
                  <p className="text-[10px] font-mono text-muted-foreground leading-relaxed">{s.desc}</p>
                </div>
              </div>
            );
          })}
        </div>
      </motion.div>

      {/* ── Scan Profiles ─────────────────────────────────────────────── */}
      <motion.div variants={itemVariants} className="rounded-md border border-border bg-card overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-background/50">
          <Terminal className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">Scan Profiles & Budgets</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px] font-mono">
            <thead>
              <tr className="border-b border-border bg-background/30">
                <th className="px-4 py-2.5 text-left text-[9px] uppercase tracking-widest text-muted-foreground font-bold">Profile</th>
                <th className="px-4 py-2.5 text-left text-[9px] uppercase tracking-widest text-muted-foreground font-bold">Request Budget</th>
                <th className="px-4 py-2.5 text-left text-[9px] uppercase tracking-widest text-muted-foreground font-bold">Description</th>
              </tr>
            </thead>
            <tbody>
              {SCAN_PROFILES.map((p, i) => (
                <tr key={p.value} className={cn("border-b border-border/50", i % 2 === 0 ? "bg-background/20" : "")}>
                  <td className="px-4 py-3 font-bold text-primary uppercase tracking-wider">{p.label}</td>
                  <td className="px-4 py-3 text-muted-foreground">{p.budget}</td>
                  <td className="px-4 py-3 text-muted-foreground">{p.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </motion.div>

      {/* ── Architecture ──────────────────────────────────────────────── */}
      <motion.div variants={itemVariants} className="rounded-md border border-border bg-card overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-background/50">
          <Cpu className="w-3.5 h-3.5 text-muted-foreground" />
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

      {/* ── Scanner tools ──────────────────────────────────────────────── */}
      <motion.div variants={itemVariants} className="rounded-md border border-border bg-card overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-background/50">
          <Shield className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="font-mono text-xs font-bold uppercase tracking-wider text-foreground">External Tools Used</span>
        </div>
        <div className="p-4 grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { name: "nmap",      desc: "Port scanning",          color: "text-primary" },
            { name: "dig",       desc: "DNS enumeration",         color: "text-blue-400" },
            { name: "whois",     desc: "Domain intelligence",     color: "text-purple-400" },
            { name: "openssl",   desc: "TLS/SSL analysis",        color: "text-orange-400" },
            { name: "nuclei",    desc: "CVE / template scanning", color: "text-red-400" },
            { name: "crt.sh",    desc: "Cert transparency",       color: "text-cyan-400" },
            { name: "ipinfo.io", desc: "IP geolocation",          color: "text-yellow-400" },
            { name: "NVD API",   desc: "CVE database",            color: "text-emerald-400" },
          ].map(({ name, desc, color }) => (
            <div key={name} className="p-3 rounded-sm border border-border bg-background">
              <div className={cn("font-mono font-bold text-xs uppercase tracking-wider", color)}>{name}</div>
              <div className="text-[9px] font-mono text-muted-foreground mt-1">{desc}</div>
            </div>
          ))}
        </div>
      </motion.div>
    </motion.div>
  );
}
