import { motion } from "framer-motion";
import { useGetDashboardStats } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Shield, Database, Server, Code2, Globe } from "lucide-react";

const STACK = [
  { label: "Frontend", value: "React 19 + Vite 7 + TailwindCSS 4", icon: <Globe className="w-4 h-4" /> },
  { label: "API", value: "Express 5 + TypeScript", icon: <Server className="w-4 h-4" /> },
  { label: "Database", value: "PostgreSQL + Drizzle ORM", icon: <Database className="w-4 h-4" /> },
  { label: "Validation", value: "Zod v4, generated from OpenAPI spec", icon: <Code2 className="w-4 h-4" /> },
];

const SCAN_TYPES = [
  { type: "recon", label: "Reconnaissance", description: "DNS enumeration, WHOIS, subdomain discovery, tech fingerprinting, OSINT." },
  { type: "enumeration", label: "Enumeration", description: "Port scanning, service banner grabbing, HTTP endpoint discovery, API surface mapping." },
  { type: "vulnerability", label: "Vulnerability", description: "CVE checks, injection testing (SQLi, XSS, SSTI), misconfigurations, exposed secrets." },
  { type: "full", label: "Full Scan", description: "All of the above in a single comprehensive scan." },
];

export function Settings() {
  const { data: stats } = useGetDashboardStats();

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-8 max-w-3xl"
    >
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-primary flex items-center">
          <Shield className="mr-3 h-8 w-8" />
          Settings
        </h1>
        <p className="text-muted-foreground mt-1">Application information and configuration reference.</p>
      </div>

      {/* Stats summary */}
      <Card className="bg-card/50 backdrop-blur">
        <CardHeader>
          <CardTitle className="text-base">Database Status</CardTitle>
          <CardDescription>Live counts from the connected PostgreSQL database.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: "Projects", value: stats?.totalProjects ?? "—" },
              { label: "Assets", value: stats?.totalAssets ?? "—" },
              { label: "Findings", value: stats?.totalFindings ?? "—" },
              { label: "Open", value: stats?.openFindings ?? "—" },
            ].map(({ label, value }) => (
              <div key={label} className="text-center">
                <div className="text-2xl font-bold font-mono text-primary">{value}</div>
                <div className="text-xs text-muted-foreground mt-1">{label}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Scan types reference */}
      <Card className="bg-card/50 backdrop-blur">
        <CardHeader>
          <CardTitle className="text-base">Scan Types</CardTitle>
          <CardDescription>Reference for what each scan type covers.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {SCAN_TYPES.map((s, i) => (
            <div key={s.type}>
              {i > 0 && <Separator className="my-4" />}
              <div className="flex items-start gap-3">
                <Badge variant="outline" className="font-mono text-xs mt-0.5 flex-shrink-0">
                  {s.type}
                </Badge>
                <div>
                  <div className="text-sm font-medium">{s.label}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">{s.description}</div>
                </div>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Stack */}
      <Card className="bg-card/50 backdrop-blur">
        <CardHeader>
          <CardTitle className="text-base">Stack</CardTitle>
          <CardDescription>Technologies powering SentinelX.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {STACK.map(({ label, value, icon }) => (
            <div key={label} className="flex items-center gap-3">
              <div className="text-muted-foreground">{icon}</div>
              <div className="text-sm text-muted-foreground w-24 flex-shrink-0">{label}</div>
              <div className="text-sm font-mono text-foreground">{value}</div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card className="bg-card/50 backdrop-blur">
        <CardHeader>
          <CardTitle className="text-base">About</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            <span className="font-semibold text-foreground">SentinelX</span> is a security vulnerability management
            platform for DevSecOps teams. Track assets, document findings with CVSS/CVE metadata, and monitor
            remediation progress across multiple projects.
          </p>
          <p className="text-xs font-mono text-muted-foreground/60">v0.1.0</p>
        </CardContent>
      </Card>
    </motion.div>
  );
}
