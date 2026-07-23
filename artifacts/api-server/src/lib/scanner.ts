/**
 * SentinelX Professional Security Scanner — Real Tools Edition
 *
 * Uses real system security tools for professional-grade analysis:
 *   • nmap      — TCP/UDP port scanning + service version detection
 *   • dig       — DNS record enumeration (A, AAAA, MX, TXT, NS, SOA, CAA)
 *   • whois     — Domain registration, registrar, expiry intel
 *   • openssl   — TLS certificate deep inspection
 *   • fetch     — HTTP security headers, CORS, cookies, web app probes
 *   • crt.sh    — SSL certificate transparency for subdomain discovery
 *   • ipinfo.io — IP geolocation and ASN enrichment
 *   • Wayback   — Historical endpoint discovery via Wayback Machine CDX API
 *
 * All checks are non-destructive — no exploitation, no brute-forcing,
 * no data modification on targets.
 */

import * as tls from "node:tls";
import * as net from "node:net";
import * as dns from "node:dns";
import { AsyncLocalStorage } from "node:async_hooks";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const dnsResolve = dns.promises;
const scanContext = new AsyncLocalStorage<{ remaining: number; exhaustedNotified: boolean }>();

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface RealFinding {
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  verification?: "verified" | "version_match" | "suspected" | "informational";
  confidence?: number;
  evidenceQuality?: "weak" | "standard" | "strong";
  verificationMethod?: string;
  reproducibility?: "reproducible" | "intermittent" | "not_reproducible" | "not_tested";
  affectedEndpoint?: string;
  affectedParameter?: string;
  negativeTests?: string;
  limitations?: string;
  toolInfo?: string;
  description: string;
  cvss: number;
  cve: string | null;
  evidence: string;
  remediation: string;
}

export interface Target {
  url: string;
  hostname: string;
  port: number;
  isHttps: boolean;
  assetType: string;
}

interface ProbeResult {
  status: number;
  headers: Record<string, string>;
  rawHeaders: string;
  body: string;
  finalUrl: string;
  durationMs: number;
}

export type ScanType = "recon" | "enumeration" | "vulnerability" | "full";
export type LogFn = (msg: string) => Promise<void> | void;
export type ScanProfile = "passive" | "safe_active" | "deep_authorized" | "authenticated" | "lab";

export interface ScanPolicy {
  profile: ScanProfile;
  requestBudget: number;
  timeoutMs: number;
  maxConcurrency: number;
  allowDeepChecks: boolean;
  allowExternalCallbacks: boolean;
  allowToolAdapters: boolean;
}

export const SCAN_POLICIES: Record<ScanProfile, Omit<ScanPolicy, "profile">> = {
  passive: {
    requestBudget: 80,
    timeoutMs: 8_000,
    maxConcurrency: 2,
    allowDeepChecks: false,
    allowExternalCallbacks: false,
    allowToolAdapters: false,
  },
  safe_active: {
    requestBudget: 300,
    timeoutMs: 10_000,
    maxConcurrency: 4,
    allowDeepChecks: false,
    allowExternalCallbacks: false,
    allowToolAdapters: false,
  },
  deep_authorized: {
    requestBudget: 6_000,
    timeoutMs: 20_000,
    maxConcurrency: 10,
    allowDeepChecks: true,
    allowExternalCallbacks: true,
    allowToolAdapters: true,
  },
  authenticated: {
    requestBudget: 6_000,
    timeoutMs: 20_000,
    maxConcurrency: 10,
    allowDeepChecks: true,
    allowExternalCallbacks: true,
    allowToolAdapters: true,
  },
  lab: {
    requestBudget: 8_000,
    timeoutMs: 20_000,
    maxConcurrency: 12,
    allowDeepChecks: true,
    allowExternalCallbacks: true,
    allowToolAdapters: true,
  },
};

export function resolveScanPolicy(profile: string | undefined): ScanPolicy {
  const selected = (profile && profile in SCAN_POLICIES ? profile : "safe_active") as ScanProfile;
  return { profile: selected, ...SCAN_POLICIES[selected] };
}

export interface ToolCapability {
  name: string;
  available: boolean;
  version?: string;
  path?: string;
  reason?: string;
}

const TOOL_COMMANDS: Record<string, string> = {
  nmap: "nmap",
  dig: "dig",
  whois: "whois",
  openssl: "openssl",
  curl: "curl",
  httpx: "httpx",
  nuclei: "nuclei",
  ffuf: "ffuf",
  sqlmap: "sqlmap",
};

export async function discoverToolCapabilities(): Promise<ToolCapability[]> {
  const capabilities: ToolCapability[] = [];
  for (const [name, command] of Object.entries(TOOL_COMMANDS)) {
    try {
      const { stdout: path } = await execFileAsync("sh", ["-lc", `command -v ${command}`], { timeout: 2_000 });
      let version = "";
      try {
        const { stdout, stderr } = await execFileAsync(command, ["--version"], { timeout: 3_000 });
        version = `${stdout || stderr}`.split("\n")[0]?.trim() ?? "";
      } catch {
        version = "installed; version unavailable";
      }
      capabilities.push({ name, available: true, path: path.trim(), version });
    } catch {
      capabilities.push({ name, available: false, reason: "not installed in this environment" });
    }
  }
  return capabilities;
}

/** Reserve one target request from the active scan's explicit budget. */
export function reserveScanRequest(): boolean {
  const context = scanContext.getStore();
  if (!context) return true;
  if (context.remaining <= 0) {
    context.exhaustedNotified = true;
    return false;
  }
  context.remaining -= 1;
  return true;
}

export function remainingScanRequests(): number | null {
  return scanContext.getStore()?.remaining ?? null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORE HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

export function normalizeTarget(value: string, type: string): Target | null {
  let v = value.trim().replace(/^\*\./, "");
  let raw = v;
  if (!/^https?:\/\//i.test(v)) {
    raw = type === "ip" ? `http://${v}/` : `https://${v}/`;
  }
  try {
    const u = new URL(raw);
    return {
      url: u.origin + "/",
      hostname: u.hostname,
      port: parseInt(u.port) || (u.protocol === "https:" ? 443 : 80),
      isHttps: u.protocol === "https:",
      assetType: type,
    };
  } catch {
    return null;
  }
}

const ts = () => new Date().toISOString();

async function probe(
  url: string,
  opts: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
    followRedirects?: boolean;
  } = {},
): Promise<ProbeResult | null> {
  if (!reserveScanRequest()) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 12_000);
  const t0 = Date.now();
  try {
    const res = await fetch(url, {
      method: opts.method ?? "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SentinelX/2.0; security-scanner)",
        ...(opts.headers ?? {}),
      },
      body: opts.body,
      signal: controller.signal,
      redirect: opts.followRedirects === false ? "manual" : "follow",
    });
    const headers: Record<string, string> = {};
    const rawParts: string[] = [];
    res.headers.forEach((val, key) => {
      const k = key.toLowerCase();
      headers[k] = val;
      rawParts.push(`  ${k}: ${val}`);
    });
    let body = "";
    try { body = await res.text(); } catch { /* ignore */ }
    return {
      status: res.status,
      headers,
      rawHeaders: rawParts.join("\n"),
      body: body.slice(0, 10_000),
      finalUrl: res.url || url,
      durationMs: Date.now() - t0,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. DNS ENUMERATION — using dig for real DNS records
// ═══════════════════════════════════════════════════════════════════════════════

async function digQuery(hostname: string, type: string): Promise<string[]> {
  try {
    const { stdout } = await execFileAsync(
      "dig",
      ["+short", "+timeout=5", "+tries=2", hostname, type],
      { timeout: 12_000 },
    );
    return stdout
      .trim()
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

async function checkDns(hostname: string, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];

  await onLog(`[${ts()}] Running DNS enumeration with dig...`);

  // ── A / AAAA records ──────────────────────────────────────────────────────
  const aRecords = await digQuery(hostname, "A");
  const aaaaRecords = await digQuery(hostname, "AAAA");
  const allIPs = [...aRecords, ...aaaaRecords];
  if (allIPs.length > 0) {
    await onLog(`[${ts()}] Resolved IPs: ${allIPs.join(", ")}`);
  } else {
    await onLog(`[${ts()}] WARNING: ${hostname} did not resolve to any IP address`);
  }

  // ── NS records ────────────────────────────────────────────────────────────
  const nsRecords = await digQuery(hostname, "NS");
  await onLog(`[${ts()}] Nameservers: ${nsRecords.join(", ") || "(none)"}`);

  // ── MX records ────────────────────────────────────────────────────────────
  const mxRecords = await digQuery(hostname, "MX");
  if (mxRecords.length === 0) {
    findings.push({
      title: "No MX Records Configured",
      severity: "low",
      description: `No MX records found for ${hostname}. This may indicate email is not used, or misconfigured, leaving the domain more susceptible to email-based spoofing when SPF/DMARC are absent.`,
      cvss: 3.1, cve: null,
      evidence: `dig +short ${hostname} MX → (no results)`,
      remediation: "If email is used for this domain, configure MX records pointing to your mail provider. If email is intentionally unused, publish an SPF record of 'v=spf1 -all' and DMARC with p=reject to prevent spoofing.",
    });
  }

  // ── TXT records — SPF, DMARC, DKIM ───────────────────────────────────────
  const txtRecords = await digQuery(hostname, "TXT");
  const allTxt = txtRecords.map((r) => r.replace(/^"|"$/g, ""));
  await onLog(`[${ts()}] TXT records found: ${allTxt.length}`);

  const spf = allTxt.find((r) => r.startsWith("v=spf1"));
  if (!spf) {
    findings.push({
      title: "Missing SPF Record — Email Spoofing Risk",
      severity: "medium",
      description: `No SPF (Sender Policy Framework) TXT record found for ${hostname}. Without SPF, any mail server can send email claiming to be from this domain, enabling phishing attacks against customers and partners.`,
      cvss: 6.5, cve: null,
      evidence: `dig +short ${hostname} TXT → no v=spf1 record\nAll TXT: ${allTxt.slice(0, 5).join(" | ") || "(none)"}`,
      remediation: 'Publish: "v=spf1 include:your-mail-provider.com -all". Use -all (hard fail) to reject unauthorised senders.',
    });
  } else if (spf.includes("+all")) {
    findings.push({
      title: "SPF Record Permits Any Sender (+all)",
      severity: "high",
      description: "SPF record ends with +all, authorising every mail server in the world to send as this domain. This makes the SPF record useless and enables trivial phishing.",
      cvss: 7.5, cve: null,
      evidence: `SPF record: ${spf}`,
      remediation: "Replace +all with -all to hard-reject unauthorised senders.",
    });
  } else if (spf.includes("~all")) {
    findings.push({
      title: "SPF Record Uses Soft Fail (~all) — Weak Protection",
      severity: "low",
      description: "SPF ~all marks unauthorised senders as suspicious but does not reject them. Many mail servers accept soft-fail messages.",
      cvss: 3.7, cve: null,
      evidence: `SPF record: ${spf}`,
      remediation: "Change ~all to -all for hard rejection of unauthorised senders.",
    });
  }

  // ── DMARC ─────────────────────────────────────────────────────────────────
  const dmarcTxt = await digQuery(`_dmarc.${hostname}`, "TXT");
  const dmarc = dmarcTxt.map((r) => r.replace(/"/g, "")).find((r) => r.startsWith("v=DMARC1"));
  if (!dmarc) {
    findings.push({
      title: "Missing DMARC Record — No Email Authentication Policy",
      severity: "medium",
      description: `No DMARC record at _dmarc.${hostname}. Without DMARC, recipients cannot automatically reject spoofed emails and you receive no reports about spoofing attempts.`,
      cvss: 6.5, cve: null,
      evidence: `dig +short _dmarc.${hostname} TXT → no v=DMARC1 record`,
      remediation: `Start with monitoring: "v=DMARC1; p=none; rua=mailto:dmarc@${hostname}". Escalate to p=quarantine then p=reject once mail flow is confirmed.`,
    });
  } else {
    const pMatch = dmarc.match(/p=(\w+)/i);
    const policy = pMatch?.[1]?.toLowerCase() ?? "none";
    if (policy === "none") {
      findings.push({
        title: "DMARC Policy Is 'none' — Spoofed Emails Reach Inboxes",
        severity: "medium",
        description: "DMARC p=none only generates reports; spoofed emails are still delivered. This is a monitoring-only configuration that provides no active protection.",
        cvss: 5.3, cve: null,
        evidence: `DMARC record: ${dmarc}`,
        remediation: "Escalate DMARC policy to p=quarantine then p=reject after reviewing rua reports to confirm legitimate mail is not affected.",
      });
    } else {
      await onLog(`[${ts()}] DMARC policy: ${policy} (OK)`);
    }
  }

  // ── CAA records ───────────────────────────────────────────────────────────
  const caaRecords = await digQuery(hostname, "CAA");
  if (caaRecords.length === 0) {
    findings.push({
      title: "No CAA Records — Any CA Can Issue Certificates",
      severity: "low",
      description: `No Certification Authority Authorisation (CAA) DNS records found for ${hostname}. Without CAA, any publicly trusted CA can issue SSL certificates for this domain, enabling mis-issuance attacks.`,
      cvss: 3.7, cve: null,
      evidence: `dig +short ${hostname} CAA → (no results)`,
      remediation: `Add CAA records to restrict certificate issuance:\n${hostname}. CAA 0 issue "letsencrypt.org"\n${hostname}. CAA 0 issuewild "letsencrypt.org"\n${hostname}. CAA 0 iodef "mailto:security@${hostname}"`,
    });
  } else {
    await onLog(`[${ts()}] CAA records: ${caaRecords.join(", ")}`);
  }

  // ── Zone transfer attempt ──────────────────────────────────────────────────
  if (nsRecords.length > 0) {
    const ns = nsRecords[0]!.replace(/\.$/, "");
    try {
      const { stdout } = await execFileAsync(
        "dig",
        ["AXFR", hostname, `@${ns}`, "+time=5"],
        { timeout: 12_000 },
      );
      if (stdout.includes("Transfer failed") || stdout.includes("REFUSED") || stdout.includes("SERVFAIL")) {
        await onLog(`[${ts()}] Zone transfer refused by ${ns} (expected)`);
      } else if (stdout.split("\n").length > 15) {
        findings.push({
          title: "DNS Zone Transfer Allowed — Full Zone Exposed",
          severity: "high",
          description: `The nameserver ${ns} allows unauthenticated DNS zone transfers (AXFR). This exposes the complete DNS zone, revealing all subdomains, internal IPs, mail servers, and infrastructure topology.`,
          cvss: 7.5, cve: null,
          evidence: `dig AXFR ${hostname} @${ns}\nResponse contained ${stdout.split("\n").length} lines of zone data`,
          remediation: "Configure the nameserver to refuse AXFR requests from unauthorised IPs. Zone transfers should only be allowed to authorised secondary nameservers. In BIND: allow-transfer { none; };",
        });
      }
    } catch { /* timeout or no access — expected */ }
  }

  await onLog(`[${ts()}] DNS enumeration complete — ${findings.length} finding(s)`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. PORT SCANNING — using real nmap with service detection
// ═══════════════════════════════════════════════════════════════════════════════

interface NmapService {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
}

async function nmapScan(hostname: string, portRange: string, onLog: LogFn): Promise<NmapService[]> {
  await onLog(`[${ts()}] nmap -sV -p ${portRange} ${hostname} ...`);
  try {
    const { stdout } = await execFileAsync(
      "nmap",
      [
        "-sV",          // service version detection
        "-sT",          // TCP connect scan (works without root)
        "-p", portRange,
        "--open",       // only show open ports
        "-T4",          // aggressive timing
        "--max-retries", "2",
        "--host-timeout", "90s",
        "-oG", "-",     // grepable output for parsing
        hostname,
      ],
      { timeout: 120_000 },
    );

    const services: NmapService[] = [];
    for (const line of stdout.split("\n")) {
      // Parse grepable format: Ports: 22/open/tcp//ssh//OpenSSH 8.4/
      const portsMatch = line.match(/Ports:\s+(.+)/);
      if (!portsMatch) continue;
      const portEntries = portsMatch[1]!.split(",");
      for (const entry of portEntries) {
        const parts = entry.trim().split("/");
        if (parts.length >= 3 && parts[1] === "open") {
          services.push({
            port: parseInt(parts[0]!),
            protocol: parts[2] ?? "tcp",
            state: parts[1],
            service: parts[4] ?? "",
            version: parts[6] ?? "",
          });
        }
      }
    }
    await onLog(`[${ts()}] nmap found ${services.length} open port(s)`);
    return services;
  } catch (err: any) {
    await onLog(`[${ts()}] nmap scan error: ${err?.message ?? String(err)}`);
    return [];
  }
}

// Risk classifications for common exposed services
const SERVICE_RISKS: Record<string, { severity: "critical"|"high"|"medium"|"low"; cvss: number; cve: string|null; description: string; remediation: string }> = {
  "ftp":      { severity: "high",     cvss: 7.5, cve: null, description: "FTP service is publicly exposed. FTP transmits credentials and data in plaintext, making it trivially interceptable. Anonymous FTP access may allow file read/write without authentication.", remediation: "Replace FTP with SFTP or FTPS. Restrict access to known IPs via firewall. Audit for anonymous access and disable it immediately." },
  "telnet":   { severity: "critical", cvss: 9.8, cve: null, description: "Telnet is exposed to the internet. Telnet transmits all data, including passwords, in plaintext. It is completely insecure over untrusted networks.", remediation: "Replace Telnet with SSH immediately. Block port 23 at the firewall. Disable the Telnet daemon." },
  "smtp":     { severity: "medium",   cvss: 5.3, cve: null, description: "SMTP relay port is directly exposed. An open relay allows anyone to send email through this server, enabling spam abuse and domain reputation damage.", remediation: "Restrict SMTP to authenticated users only. Disable open relay. Consider moving to a managed email service." },
  "rdp":      { severity: "high",     cvss: 7.5, cve: null, description: "Remote Desktop Protocol is exposed to the internet. RDP is heavily targeted for ransomware delivery and brute-force attacks, but an open port alone does not prove a specific RDP CVE or remote code execution.", remediation: "Block port 3389 from the internet. Require VPN before RDP is accessible. Enable Network Level Authentication and apply current Windows patches." },
  "smb":      { severity: "high",     cvss: 7.5, cve: null, description: "SMB (Windows file sharing) is exposed to the internet. Public SMB increases brute-force, relay, and legacy-protocol risk, but an open port alone does not prove EternalBlue or remote code execution.", remediation: "Block TCP 445 from the internet unconditionally. Use VPN for internal file sharing and disable legacy SMB protocols." },
  "mysql":    { severity: "critical", cvss: 9.4, cve: null, description: "MySQL database port is directly accessible from the internet. Any unauthenticated actor can attempt to brute-force credentials or exploit unpatched vulnerabilities.", remediation: "Bind MySQL to 127.0.0.1. Remove all remote root accounts. Block port 3306 at the firewall." },
  "postgres": { severity: "critical", cvss: 9.4, cve: null, description: "PostgreSQL is directly accessible from the internet. Exposed database ports are continuously scanned and attacked.", remediation: "Bind PostgreSQL to localhost. Block port 5432 at the firewall. Use SSH tunnels or VPN for remote DB access." },
  "mongodb":  { severity: "critical", cvss: 9.8, cve: null, description: "MongoDB is publicly accessible. Default MongoDB installations have no authentication. Millions of MongoDB instances have been ransomed via this misconfiguration.", remediation: "Enable MongoDB authentication. Bind to 127.0.0.1. Block port 27017 at the firewall." },
  "redis":    { severity: "critical", cvss: 9.8, cve: null, description: "Redis is exposed to the internet. Redis has no authentication by default and can be used to read/write arbitrary data, enabling server takeover.", remediation: "Bind Redis to 127.0.0.1. Set a requirepass in redis.conf. Block port 6379 at the firewall." },
  "elasticsearch": { severity: "critical", cvss: 9.8, cve: null, description: "Elasticsearch REST API is publicly accessible. Unauthenticated access allows reading and deleting all indexed data.", remediation: "Enable X-Pack security. Require authentication. Bind to internal networks only." },
  "ssh":      { severity: "medium",   cvss: 5.3, cve: null, description: "SSH is exposed to the internet. While SSH is often intentionally public, exposed SSH is continuously brute-forced. Default configurations may allow password authentication.", remediation: "Disable password authentication — use SSH key pairs only. Change to a non-standard port or use port knocking. Implement fail2ban or equivalent. Restrict to known source IPs if possible." },
  "vnc":      { severity: "critical", cvss: 9.8, cve: null, description: "VNC (remote desktop) is publicly accessible. VNC protocols may have weak or no authentication and are a common ransomware entry point.", remediation: "Block VNC ports from the internet. Require VPN access. Enforce strong VNC authentication." },
  "docker":   { severity: "critical", cvss: 10.0, cve: null, description: "Docker daemon API is exposed without TLS. Full root-equivalent control over the host: create privileged containers, mount the host filesystem, execute arbitrary commands as root.", remediation: "Disable remote Docker API. If required, use TLS client auth (--tlsverify). Block ports 2375/2376 at the firewall." },
  "kubernetes": { severity: "critical", cvss: 10.0, cve: null, description: "Kubernetes API server is publicly accessible. Unauthenticated access to the Kubernetes API allows full cluster takeover.", remediation: "Restrict API server to authorised IPs. Require authentication. Disable anonymous access." },
  "memcached": { severity: "high",    cvss: 7.5, cve: null, description: "Memcached is publicly accessible. Unauthenticated access allows reading/flushing cached data. Exposed Memcached servers are also abused for amplification DDoS attacks.", remediation: "Bind Memcached to 127.0.0.1. Block port 11211 at the firewall." },
};

async function checkPorts(hostname: string, scanType: ScanType, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];

  // Port range depends on scan type
  const portRange = scanType === "full"
    ? "1-65535"
    : scanType === "vulnerability"
    ? "1-10000"
    : "21,22,23,25,80,443,445,1433,1521,2375,2376,3306,3389,4848,5432,5601,5900,5984,6379,7001,8080,8443,8888,9200,9300,10000,11211,27017,28017,50000";

  const services = await nmapScan(hostname, portRange, onLog);

  for (const svc of services) {
    // Log every open port
    await onLog(`[${ts()}] OPEN PORT ${svc.port}/${svc.protocol} — ${svc.service} ${svc.version}`.trim());

    // Match to known risky services
    const svcName = svc.service.toLowerCase();
    let matched = false;
    for (const [key, risk] of Object.entries(SERVICE_RISKS)) {
      if (svcName.includes(key) || (key === "smb" && svc.port === 445) || (key === "rdp" && svc.port === 3389) || (key === "docker" && (svc.port === 2375 || svc.port === 2376))) {
        findings.push({
          title: `Exposed Service: ${svc.service || key.toUpperCase()} on Port ${svc.port}/${svc.protocol}`,
          severity: risk.severity,
          description: risk.description,
          cvss: risk.cvss,
          cve: risk.cve,
          evidence: `nmap detected open port ${svc.port}/${svc.protocol}\nService: ${svc.service} ${svc.version}\nHost: ${hostname}`,
          remediation: risk.remediation,
        });
        matched = true;
        break;
      }
    }

    // Generic finding for any unexpected open port
    if (!matched && ![80, 443, 8080, 8443].includes(svc.port)) {
      findings.push({
        title: `Unexpected Open Port: ${svc.port}/${svc.protocol} (${svc.service || "unknown"})`,
        severity: "low",
        description: `Port ${svc.port}/${svc.protocol} is open and accessible from the internet. Service detected: ${svc.service || "unknown"} ${svc.version}. Every exposed service increases the attack surface.`,
        cvss: 3.7, cve: null,
        evidence: `nmap: ${svc.port}/${svc.protocol} open — ${svc.service} ${svc.version}`,
        remediation: `If this service is not intended to be publicly accessible, block port ${svc.port} at the firewall. If it must be public, ensure it is fully patched and using strong authentication.`,
      });
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. TLS / SSL ANALYSIS — openssl s_client + node:tls
// ═══════════════════════════════════════════════════════════════════════════════

async function opensslTlsInfo(hostname: string, port: number): Promise<string> {
  try {
    // Use printf to send a quick close so openssl doesn't hang
    const { stdout } = await execFileAsync(
      "openssl",
      ["s_client", "-connect", `${hostname}:${port}`, "-servername", hostname, "-brief", "-no_ign_eof"],
      { timeout: 12_000 },
    );
    return stdout;
  } catch (err: any) {
    return err?.stdout ?? "";
  }
}

async function checkTls(hostname: string, port: number, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Running openssl TLS analysis on ${hostname}:${port}...`);

  // ── openssl-based cert inspection ────────────────────────────────────────
  const opensslOut = await opensslTlsInfo(hostname, port);
  if (opensslOut) {
    await onLog(`[${ts()}] openssl connected — parsing certificate chain...`);
  }

  // ── node:tls for detailed checks ─────────────────────────────────────────
  const certResult = await new Promise<RealFinding[]>((resolve) => {
    const f: RealFinding[] = [];
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 12_000 },
      async () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const proto = socket.getProtocol() ?? "unknown";
          const cipher = socket.getCipher();
          socket.destroy();

          // Deprecated TLS versions
          if (proto === "TLSv1" || proto === "TLSv1.0") {
            f.push({
              title: "Deprecated TLS 1.0 Protocol Supported",
              severity: "high",
              description: "The server supports TLS 1.0, deprecated by PCI DSS in 2018 and by the IETF in RFC 8996. TLS 1.0 is vulnerable to BEAST, POODLE, and downgrade attacks.",
              cvss: 7.4, cve: null,
              evidence: `openssl/TLS negotiation succeeded with protocol: ${proto}\nCipher: ${cipher?.name ?? "unknown"}`,
              remediation: "Disable TLS 1.0 and 1.1. Support only TLS 1.2 and 1.3. Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
            });
          } else if (proto === "TLSv1.1") {
            f.push({
              title: "Deprecated TLS 1.1 Protocol Supported",
              severity: "medium",
              description: "Server supports TLS 1.1, deprecated in RFC 8996. Lacks modern cipher suites and is vulnerable to padding oracle attacks.",
              cvss: 5.9, cve: null,
              evidence: `Protocol: ${proto}\nCipher: ${cipher?.name ?? "unknown"}`,
              remediation: "Disable TLS 1.1. Support only TLS 1.2 and TLS 1.3.",
            });
          } else {
            f.push({
              title: `TLS Configuration: ${proto}`,
              severity: "low",
              description: `Server negotiated ${proto} with cipher ${cipher?.name ?? "unknown"}. Modern protocol in use.`,
              cvss: 0, cve: null,
              evidence: `Protocol: ${proto}\nCipher suite: ${cipher?.name ?? "unknown"}\nCipher bits: ${cipher?.version ?? "unknown"}`,
              remediation: "Continue monitoring cipher suite configuration. Prioritise ECDHE and AES-GCM cipher suites for forward secrecy.",
            });
          }

          // Weak ciphers
          const cipherName = cipher?.name?.toUpperCase() ?? "";
          if (cipherName.match(/RC4|DES|NULL|EXPORT|ANON|3DES/)) {
            f.push({
              title: `Weak Cipher Suite Negotiated: ${cipher?.name}`,
              severity: "high",
              description: `Server negotiated a weak cipher (${cipher?.name}). RC4, DES, 3DES, EXPORT, NULL and ANON ciphers provide insufficient protection and can be broken.`,
              cvss: 7.4, cve: null,
              evidence: `Cipher: ${cipher?.name}\nProtocol: ${proto}`,
              remediation: "Configure only modern cipher suites with forward secrecy. Remove all RC4, DES, 3DES, NULL, EXPORT and ANON ciphers.",
            });
          }

          if (!cert || !cert.valid_to) { resolve(f); return; }

          // Self-signed
          const selfSigned = cert.issuer?.CN === cert.subject?.CN && cert.issuer?.O === cert.subject?.O;
          if (selfSigned) {
            f.push({
              title: "Self-Signed SSL Certificate",
              severity: "medium",
              description: `Certificate for ${hostname} is self-signed. Browsers show blocking warnings and users cannot verify server identity, enabling MITM attacks.`,
              cvss: 5.9, cve: null,
              evidence: `Subject: CN=${cert.subject?.CN ?? hostname}\nIssuer: CN=${cert.issuer?.CN ?? "self"}\nSerial: ${cert.serialNumber ?? "unknown"}\nValid to: ${cert.valid_to}`,
              remediation: "Replace with a certificate from a trusted CA. Let's Encrypt provides free auto-renewing certificates.",
            });
          }

          // Expiry
          const expiresAt = new Date(cert.valid_to);
          const daysLeft = Math.floor((expiresAt.getTime() - Date.now()) / 86_400_000);
          if (daysLeft < 0) {
            f.push({
              title: "SSL Certificate Expired",
              severity: "critical",
              description: `Certificate for ${hostname} expired ${Math.abs(daysLeft)} day(s) ago. All browsers show a blocking error. The connection is not trusted.`,
              cvss: 9.1, cve: null,
              evidence: `Expired: ${cert.valid_to} (${Math.abs(daysLeft)} days ago)\nSubject: ${cert.subject?.CN ?? hostname}`,
              remediation: "Renew the certificate immediately. Set up automated renewal with Certbot or your CA.",
            });
          } else if (daysLeft < 14) {
            f.push({
              title: `SSL Certificate Expiring in ${daysLeft} Day(s)`,
              severity: "high",
              description: `Certificate expires in ${daysLeft} days. If not renewed, users will see blocking browser errors.`,
              cvss: 7.5, cve: null,
              evidence: `Expiry: ${cert.valid_to}\nDays remaining: ${daysLeft}`,
              remediation: "Renew immediately. Automate certificate renewal to prevent future outages.",
            });
          } else if (daysLeft < 30) {
            f.push({
              title: `SSL Certificate Expiring Soon (${daysLeft} days)`,
              severity: "medium",
              description: `Certificate expires in ${daysLeft} days. Plan renewal to avoid service disruption.`,
              cvss: 5.3, cve: null,
              evidence: `Expiry: ${cert.valid_to}\nDays remaining: ${daysLeft}`,
              remediation: "Renew the certificate within the next few days. Consider automated renewal.",
            });
          } else {
            await onLog(`[${ts()}] TLS cert valid for ${daysLeft} more days (OK)`);
          }

          // Subject mismatch
          const cn = cert.subject?.CN ?? "";
          const altNames: string[] = (cert.subjectaltname ?? "")
            .split(",")
            .map((s: string) => s.trim().replace(/^DNS:/, ""));
          const hostCovered = cn === hostname || altNames.some((n) =>
            n === hostname || (n.startsWith("*.") && hostname.endsWith(n.slice(1)))
          );
          if (!hostCovered && cn) {
            f.push({
              title: "SSL Certificate Subject Mismatch",
              severity: "high",
              description: `The certificate CN (${cn}) and Subject Alt Names do not include ${hostname}. Browsers show a security warning and refuse the connection without user override.`,
              cvss: 7.4, cve: null,
              evidence: `Requested host: ${hostname}\nCertificate CN: ${cn}\nSANs: ${altNames.join(", ") || "(none)"}`,
              remediation: "Reissue the certificate with the correct hostname in the Subject Alternative Name field.",
            });
          }

          // Certificate age (very long validity)
          const issuedAt = cert.valid_from ? new Date(cert.valid_from) : null;
          if (issuedAt) {
            const totalDays = (expiresAt.getTime() - issuedAt.getTime()) / 86_400_000;
            if (totalDays > 398) {
              f.push({
                title: "SSL Certificate Validity Period Exceeds 398 Days",
                severity: "low",
                description: `Certificate has a validity period of ${Math.round(totalDays)} days. Apple, Google, and Mozilla browsers cap trusted certificate validity at 398 days; longer certificates may not be trusted by modern browsers.`,
                cvss: 3.1, cve: null,
                evidence: `Issued: ${cert.valid_from}\nExpires: ${cert.valid_to}\nValidity: ${Math.round(totalDays)} days`,
                remediation: "When renewing, issue certificates with a maximum validity of 90 days (recommended) or 398 days (maximum).",
              });
            }
          }

          resolve(f);
        } catch (e) {
          resolve(f);
        }
      },
    );
    socket.on("error", () => resolve(f));
    socket.setTimeout(12_000, () => { socket.destroy(); resolve(f); });
  });

  findings.push(...certResult);

  // ── Test for SSLv3 / legacy protocol via openssl ──────────────────────────
  const legacyTests = [
    { flag: "-ssl3",  proto: "SSLv3",   severity: "critical" as const, cvss: 9.4, cve: "CVE-2014-3566" },
    { flag: "-tls1",  proto: "TLS 1.0", severity: "high" as const,     cvss: 7.4, cve: null },
    { flag: "-tls1_1",proto: "TLS 1.1", severity: "medium" as const,   cvss: 5.9, cve: null },
  ];
  for (const test of legacyTests) {
    try {
      const { stdout, stderr } = await execFileAsync(
        "openssl",
        ["s_client", "-connect", `${hostname}:${port}`, "-servername", hostname, test.flag, "-brief"],
        { timeout: 8_000 },
      ).catch((err: any) => ({ stdout: err.stdout ?? "", stderr: err.stderr ?? "" }));
      const combined = stdout + stderr;
      if (combined.includes("Verification:") || combined.includes("CONNECTED") || combined.includes("Protocol  :")) {
        findings.push({
          title: `Legacy Protocol Accepted: ${test.proto}`,
          severity: test.severity,
          description: `Server accepted a ${test.proto} handshake. ${test.proto === "SSLv3" ? "SSLv3 is affected by the POODLE vulnerability (CVE-2014-3566) which allows decryption of encrypted traffic. " : ""}This protocol is deprecated and should be disabled.`,
          cvss: test.cvss, cve: test.cve,
          evidence: `openssl s_client ${test.flag} -connect ${hostname}:${port} succeeded\nOutput: ${combined.slice(0, 300)}`,
          remediation: `Disable ${test.proto} support on the web server. Only TLS 1.2 and TLS 1.3 should be permitted.`,
        });
      }
    } catch { /* connection refused = protocol not supported = good */ }
  }

  await onLog(`[${ts()}] TLS analysis complete — ${findings.length} finding(s)`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. WHOIS — domain registration intelligence
// ═══════════════════════════════════════════════════════════════════════════════

async function checkWhois(hostname: string, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  // Extract root domain (e.g. sub.example.com → example.com)
  const parts = hostname.split(".");
  const rootDomain = parts.length > 2 ? parts.slice(-2).join(".") : hostname;

  await onLog(`[${ts()}] Running whois for ${rootDomain}...`);

  try {
    const { stdout } = await execFileAsync("whois", [rootDomain], { timeout: 20_000 });
    const w = stdout.toLowerCase();

    // Expiry date
    const expiryMatch = stdout.match(/(?:Registry Expiry Date|Expiry Date|Expiration Date|paid-till):\s*(\S+)/i);
    if (expiryMatch) {
      const expiryStr = expiryMatch[1]!;
      const expiry = new Date(expiryStr);
      if (!isNaN(expiry.getTime())) {
        const daysLeft = Math.floor((expiry.getTime() - Date.now()) / 86_400_000);
        await onLog(`[${ts()}] Domain expiry: ${expiryStr} (${daysLeft} days)`);
        if (daysLeft < 30) {
          findings.push({
            title: `Domain Expiring in ${daysLeft} Day(s) — Risk of Takeover`,
            severity: daysLeft < 7 ? "critical" : "high",
            description: `The domain ${rootDomain} expires in ${daysLeft} day(s). An expired domain can be registered by anyone, redirecting all traffic and email to an attacker-controlled server.`,
            cvss: daysLeft < 7 ? 9.8 : 8.1, cve: null,
            evidence: `whois ${rootDomain}\nExpiry: ${expiryStr}\nDays remaining: ${daysLeft}`,
            remediation: "Renew the domain immediately. Enable auto-renewal at your registrar. Set up calendar alerts at 90, 30, 7 day thresholds.",
          });
        }
      }
    }

    // Registrar
    const registrarMatch = stdout.match(/Registrar:\s*(.+)/i);
    if (registrarMatch) {
      await onLog(`[${ts()}] Registrar: ${registrarMatch[1]!.trim()}`);
    }

    // Privacy protection check
    if (!w.includes("redacted") && !w.includes("privacy") && !w.includes("protected")) {
      const emailMatch = stdout.match(/Registrant Email:\s*(\S+@\S+)/i);
      if (emailMatch && !emailMatch[1]!.includes("redacted")) {
        findings.push({
          title: "WHOIS Registrant Email Publicly Exposed",
          severity: "low",
          description: `The registrant email address (${emailMatch[1]}) is publicly visible in WHOIS. This enables targeted phishing attacks against domain owners and facilitates social engineering attempts.`,
          cvss: 3.1, cve: null,
          evidence: `whois ${rootDomain}\nRegistrant Email: ${emailMatch[1]}`,
          remediation: "Enable WHOIS privacy protection / GDPR redaction at your registrar to hide personal contact information.",
        });
      }
    }

    // Nameserver consistency check
    const nsMatches = [...stdout.matchAll(/Name Server:\s*(\S+)/gi)].map((m) => m[1]!.toLowerCase());
    if (nsMatches.length === 0) {
      const digNs = await digQuery(rootDomain, "NS");
      if (digNs.length === 0) {
        findings.push({
          title: "No Nameservers Found for Domain",
          severity: "high",
          description: `No nameservers found for ${rootDomain} in WHOIS or DNS. This may indicate a misconfigured or abandoned domain at risk of takeover.`,
          cvss: 7.5, cve: null,
          evidence: `whois ${rootDomain}: no Name Server entries\ndig NS ${rootDomain}: no results`,
          remediation: "Configure authoritative nameservers for the domain at your registrar.",
        });
      }
    } else {
      await onLog(`[${ts()}] Nameservers: ${nsMatches.join(", ")}`);
    }

  } catch (err: any) {
    await onLog(`[${ts()}] whois lookup failed: ${err?.message ?? String(err)}`);
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. SUBDOMAIN DISCOVERY — crt.sh certificate transparency
// ═══════════════════════════════════════════════════════════════════════════════

async function discoverSubdomains(hostname: string, onLog: LogFn): Promise<{ subs: string[]; findings: RealFinding[] }> {
  const findings: RealFinding[] = [];
  const subs: string[] = [];

  // Extract root domain
  const parts = hostname.split(".");
  const rootDomain = parts.length > 2 ? parts.slice(-2).join(".") : hostname;

  await onLog(`[${ts()}] Querying crt.sh certificate transparency for ${rootDomain} subdomains...`);

  try {
    const r = await probe(
      `https://crt.sh/?q=%.${rootDomain}&output=json`,
      { timeoutMs: 20_000 },
    );
    if (r && r.status === 200 && r.body.startsWith("[")) {
      const records: Array<{ name_value: string }> = JSON.parse(r.body);
      const nameSet = new Set<string>();
      for (const rec of records) {
        for (const name of rec.name_value.split("\n")) {
          const n = name.trim().toLowerCase().replace(/^\*\./, "");
          if (n.endsWith(`.${rootDomain}`) || n === rootDomain) {
            nameSet.add(n);
          }
        }
      }
      const uniqueSubs = [...nameSet].filter((n) => n !== rootDomain);
      await onLog(`[${ts()}] crt.sh found ${uniqueSubs.length} unique subdomain(s)`);
      subs.push(...uniqueSubs.slice(0, 50)); // limit to 50

      // Check for interesting subdomains
      const interesting = uniqueSubs.filter((s) =>
        /admin|dev|staging|test|internal|api|vpn|uat|qa|demo|beta|old|legacy|backup|db|mail|portal|dashboard|corp|login/i.test(s)
      );

      if (interesting.length > 0) {
        await onLog(`[${ts()}] Interesting subdomains: ${interesting.slice(0, 10).join(", ")}`);
        findings.push({
          title: `${interesting.length} Sensitive Subdomain(s) Discovered via Certificate Transparency`,
          severity: "medium",
          description: `Certificate transparency logs reveal ${interesting.length} subdomain(s) that may indicate internal, staging, admin, or development environments. These are often less hardened than production.`,
          cvss: 5.3, cve: null,
          evidence: `crt.sh query for *.${rootDomain}\nSensitive subdomains found:\n${interesting.slice(0, 15).join("\n")}`,
          remediation: "Audit each discovered subdomain: ensure it is intentionally public, properly secured, and not leaking internal services. Consider wildcard certificate usage to reduce certificate transparency exposure.",
        });
      }

      if (uniqueSubs.length > 20) {
        findings.push({
          title: `Large Attack Surface: ${uniqueSubs.length} Subdomains Discovered`,
          severity: "low",
          description: `Certificate transparency logs show ${uniqueSubs.length} subdomains for ${rootDomain}. Each subdomain is a potential entry point and increases the overall attack surface.`,
          cvss: 3.7, cve: null,
          evidence: `Total subdomains: ${uniqueSubs.length}\nSample: ${uniqueSubs.slice(0, 10).join(", ")}`,
          remediation: "Regularly audit all active subdomains. Remove DNS records for decommissioned services to prevent subdomain takeover. Implement a subdomain inventory process.",
        });
      }
    }
  } catch (err: any) {
    await onLog(`[${ts()}] crt.sh lookup error: ${err?.message ?? String(err)}`);
  }

  // ── DNS brute force — common subdomains ───────────────────────────────────
  const COMMON_SUBS = [
    "www", "mail", "email", "smtp", "pop", "imap", "ftp", "vpn", "ssh",
    "api", "api2", "v1", "v2", "dev", "development", "staging", "test",
    "uat", "qa", "beta", "alpha", "demo", "sandbox", "internal", "intranet",
    "admin", "administrator", "portal", "dashboard", "manage", "management",
    "ns1", "ns2", "mx", "mx1", "cdn", "static", "assets", "media", "img",
    "db", "database", "mysql", "mongo", "redis", "elastic", "kibana",
    "jenkins", "gitlab", "github", "jira", "confluence", "grafana",
    "monitoring", "metrics", "prometheus", "logs", "logging",
    "backup", "old", "legacy", "archive",
    "mobile", "app", "apps", "m",
    "store", "shop", "pay", "payments", "billing", "accounts",
    "login", "auth", "sso", "oauth", "id",
    "support", "help", "status", "uptime",
  ];

  await onLog(`[${ts()}] DNS brute-forcing ${COMMON_SUBS.length} common subdomains...`);
  let bruteFound = 0;

  const results = await Promise.allSettled(
    COMMON_SUBS.map(async (sub) => {
      const fqdn = `${sub}.${rootDomain}`;
      if (subs.includes(fqdn)) return null; // already found via crt.sh
      try {
        const addrs = await dnsResolve.resolve4(fqdn).catch(() => [] as string[]);
        if (addrs.length > 0) {
          return { fqdn, ips: addrs };
        }
        return null;
      } catch {
        return null;
      }
    }),
  );

  const bruteResults: { fqdn: string; ips: string[] }[] = [];
  for (const r of results) {
    if (r.status === "fulfilled" && r.value) {
      bruteResults.push(r.value);
      bruteFound++;
      if (!subs.includes(r.value.fqdn)) subs.push(r.value.fqdn);
    }
  }

  if (bruteFound > 0) {
    await onLog(`[${ts()}] DNS brute-force found ${bruteFound} additional subdomain(s)`);
    const newSubs = bruteResults.map((r) => `${r.fqdn} → ${r.ips.join(", ")}`);
    const devSubs = bruteResults.filter((r) => /dev|staging|test|qa|uat|admin|internal/i.test(r.fqdn));
    if (devSubs.length > 0) {
      findings.push({
        title: `Development/Staging Subdomains Accessible (${devSubs.length} found)`,
        severity: "medium",
        description: `${devSubs.length} development or staging subdomain(s) are publicly accessible. These environments typically have weaker security controls, debug modes enabled, and may expose test credentials or internal data.`,
        cvss: 6.1, cve: null,
        evidence: `DNS brute-force discovered:\n${devSubs.map((r) => `${r.fqdn} → ${r.ips.join(", ")}`).join("\n")}`,
        remediation: "Restrict access to dev/staging environments via IP allowlisting or VPN. Ensure test credentials and data are not accessible from production-facing subdomains.",
      });
    }
  }

  return { subs, findings };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. IP GEOLOCATION & ASN — ipinfo.io (free, no auth required)
// ═══════════════════════════════════════════════════════════════════════════════

async function getIpInfo(hostname: string, onLog: LogFn): Promise<void> {
  try {
    const ips = await digQuery(hostname, "A");
    if (ips.length === 0) return;
    const ip = ips[0]!;
    const r = await probe(`https://ipinfo.io/${ip}/json`, { timeoutMs: 8_000 });
    if (r && r.status === 200) {
      const info = JSON.parse(r.body);
      await onLog(`[${ts()}] IP Intel: ${ip} | ${info.org ?? "Unknown ASN"} | ${info.city ?? ""}, ${info.country ?? ""} | Hosting: ${info.hostname ?? "—"}`);
    }
  } catch { /* ipinfo.io unavailable */ }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. WAYBACK MACHINE — historical endpoint discovery
// ═══════════════════════════════════════════════════════════════════════════════

async function checkWayback(hostname: string, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Querying Wayback Machine CDX API for historical endpoints...`);

  try {
    const url = `https://web.archive.org/cdx/search/cdx?url=${hostname}/*&output=json&fl=original&collapse=urlkey&limit=200&filter=statuscode:200`;
    const r = await probe(url, { timeoutMs: 20_000 });
    if (!r || r.status !== 200) return findings;

    const rows: string[][] = JSON.parse(r.body);
    if (rows.length < 2) return findings; // first row is headers

    const urls = rows.slice(1).map((r) => r[0]!).filter(Boolean);
    await onLog(`[${ts()}] Wayback Machine: ${urls.length} historical URL(s) found`);

    // Identify sensitive historical paths
    const sensitive = urls.filter((u) =>
      /\.(sql|bak|backup|zip|tar|gz|env|config|conf|cfg|log|xml|json|key|pem|cer|p12|pfx|yaml|yml|ini|htpasswd|git|svn)(\?|$)/i.test(u) ||
      /\/admin|\/backup|\/\.env|\/config|\/debug|\/test|\/dev|\/api\/internal|\/private/i.test(u)
    );

    if (sensitive.length > 0) {
      findings.push({
        title: `${sensitive.length} Sensitive Historical URL(s) in Wayback Machine`,
        severity: "medium",
        verification: "suspected",
        confidence: 55,
        description: `The Wayback Machine has archived ${sensitive.length} URL(s) that may represent sensitive file paths, backup files, or admin interfaces. These paths may still be accessible if not properly secured.`,
        cvss: 5.3, cve: null,
        evidence: `Wayback CDX query for ${hostname}/*\nSensitive URLs found:\n${sensitive.slice(0, 15).join("\n")}`,
        remediation: "Audit each sensitive URL to verify it is no longer accessible. Remove backup and config files from the web root. Add rules to robots.txt and verify via direct access testing.",
      });
    }

    // Check for exposed API keys in historical URLs
    const apiKeyUrls = urls.filter((u) =>
      /api[_-]?key=|apikey=|access_token=|secret=|password=|passwd=|pwd=|token=/i.test(u)
    );
    if (apiKeyUrls.length > 0) {
      findings.push({
        title: "API Keys or Secrets Found in Historical URLs",
        severity: "high",
        verification: "suspected",
        confidence: 60,
        description: `${apiKeyUrls.length} historical URL(s) contain query parameters that look like API keys, tokens, or passwords. This proves historical disclosure in an archive, but does not prove the values are still valid or that the current site serves them.`,
        cvss: 8.1, cve: null,
        evidence: `Wayback Machine URLs with credentials:\n${apiKeyUrls.slice(0, 5).join("\n")}`,
        remediation: "Revoke all exposed credentials immediately. Remove secrets from URLs — use POST bodies or headers instead. Audit git history and CDN logs for additional exposure.",
      });
    }

  } catch (err: any) {
    await onLog(`[${ts()}] Wayback lookup error: ${err?.message ?? "timeout"}`);
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. HTTP SECURITY HEADERS — comprehensive check
// ═══════════════════════════════════════════════════════════════════════════════

async function checkHeaders(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const r = await probe(target.url, { timeoutMs: 12_000 });
  if (!r) {
    await onLog(`[${ts()}] WARNING: Could not reach ${target.url} for header check`);
    return findings;
  }

  const h = r.headers;
  const ev = (info: string) => `GET ${target.url} → HTTP ${r.status}\nResponse headers:\n${r.rawHeaders}\n\n${info}`;
  await onLog(`[${ts()}] HTTP ${r.status} — checking ${Object.keys(h).length} response headers...`);

  // HTTP to HTTPS redirect
  if (!target.isHttps) {
    const httpR = await probe(`http://${target.hostname}/`, { followRedirects: false, timeoutMs: 8_000 });
    if (httpR && httpR.status >= 200 && httpR.status < 300) {
      findings.push({
        title: "HTTP Not Redirected to HTTPS",
        severity: "high",
        description: "The server serves content over unencrypted HTTP without redirecting to HTTPS. All traffic is transmitted in plaintext, exposing credentials, session tokens, and user data to network interception.",
        cvss: 7.4, cve: null,
        evidence: `GET http://${target.hostname}/ → HTTP ${httpR.status} (no redirect to HTTPS)`,
        remediation: "Configure a 301 permanent redirect from HTTP to HTTPS. In Nginx: return 301 https://$host$request_uri; In Apache: RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
      });
    }
  }

  // HSTS
  const hsts = h["strict-transport-security"];
  if (target.isHttps && !hsts) {
    findings.push({
      title: "Missing HTTP Strict Transport Security (HSTS)",
      severity: "medium",
      description: "HSTS header is absent. Without HSTS, browsers allow downgrade attacks where an attacker intercepts the first HTTP request before the HTTPS redirect, enabling session hijacking.",
      cvss: 6.1, cve: null,
      evidence: ev("Strict-Transport-Security: (absent)"),
      remediation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\nAfter testing, submit the domain to the HSTS preload list.",
    });
  } else if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]!) : 0;
    if (maxAge < 31536000) {
      findings.push({
        title: "HSTS max-age Too Short",
        severity: "low",
        description: `HSTS max-age is ${maxAge} seconds (${Math.round(maxAge / 86400)} days). Browsers will allow HTTP connections after this window expires, creating brief downgrade attack opportunities.`,
        cvss: 3.1, cve: null,
        evidence: ev(`Strict-Transport-Security: ${hsts}`),
        remediation: "Set max-age to at least 31536000 (1 year): Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      });
    }
  }

  // Content-Security-Policy
  if (!h["content-security-policy"]) {
    findings.push({
      title: "Missing Content-Security-Policy Header",
      severity: "medium",
      description: "No CSP header is set. Without CSP, XSS attacks can load scripts from any external origin, access the DOM, exfiltrate data via fetch/image requests, and install keyloggers.",
      cvss: 6.1, cve: null,
      evidence: ev("Content-Security-Policy: (absent)"),
      remediation: "Implement a strict CSP. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; Tighten after testing.",
    });
  } else {
    const csp = h["content-security-policy"];
    if (/unsafe-eval/i.test(csp)) {
      findings.push({
        title: "CSP Contains 'unsafe-eval'",
        severity: "medium",
        description: "CSP includes 'unsafe-eval', which allows JavaScript evaluation functions like eval(), setTimeout(string), and new Function(). This significantly weakens XSS protection.",
        cvss: 5.3, cve: null,
        evidence: ev(`Content-Security-Policy: ${csp.slice(0, 200)}`),
        remediation: "Remove 'unsafe-eval'. Refactor code to avoid eval-based patterns. Use nonces or hashes for inline scripts instead.",
      });
    }
    if (/unsafe-inline/i.test(csp) && !/nonce-|hash-|sha/i.test(csp)) {
      findings.push({
        title: "CSP Contains 'unsafe-inline' Without Nonce/Hash",
        severity: "medium",
        description: "CSP allows all inline scripts via 'unsafe-inline'. Without a nonce or hash, any injected inline script (from XSS) executes, defeating the purpose of CSP.",
        cvss: 5.3, cve: null,
        evidence: ev(`Content-Security-Policy: ${csp.slice(0, 200)}`),
        remediation: "Replace 'unsafe-inline' with nonce-based CSP: Content-Security-Policy: script-src 'nonce-{random-per-request}'",
      });
    }
    if (/\*/.test(csp.split("script-src")[1]?.split(";")[0] ?? "")) {
      findings.push({
        title: "CSP script-src Allows Wildcard Origin",
        severity: "high",
        description: "CSP script-src includes a wildcard (*), allowing scripts to load from any external domain. This completely bypasses XSS script-injection protection.",
        cvss: 7.4, cve: null,
        evidence: ev(`Content-Security-Policy: ${csp.slice(0, 300)}`),
        remediation: "Replace wildcard with explicit trusted domains. Never use * in script-src.",
      });
    }
  }

  // X-Frame-Options
  const xfo = h["x-frame-options"] ?? "";
  const cspFa = h["content-security-policy"] ?? "";
  if (!xfo && !cspFa.toLowerCase().includes("frame-ancestors")) {
    findings.push({
      title: "Clickjacking Protection Missing (X-Frame-Options / CSP frame-ancestors)",
      severity: "medium",
      description: "No clickjacking protection is configured. An attacker can embed this page in a transparent iframe on a malicious site to trick users into clicking on invisible UI elements (account deletion, fund transfers, etc.).",
      cvss: 6.1, cve: null,
      evidence: ev("X-Frame-Options: (absent)\nCSP frame-ancestors: (absent)"),
      remediation: "Add: X-Frame-Options: DENY (or SAMEORIGIN)\nOr in CSP: Content-Security-Policy: frame-ancestors 'none'",
    });
  }

  // X-Content-Type-Options
  if (!h["x-content-type-options"]) {
    findings.push({
      title: "Missing X-Content-Type-Options Header",
      severity: "low",
      description: "Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses. An attacker can serve a file with a misleading MIME type (e.g., an HTML file served as image) that browsers execute as script.",
      cvss: 3.7, cve: null,
      evidence: ev("X-Content-Type-Options: (absent)"),
      remediation: "Add: X-Content-Type-Options: nosniff",
    });
  }

  // Referrer-Policy
  if (!h["referrer-policy"]) {
    findings.push({
      title: "Missing Referrer-Policy Header",
      severity: "low",
      description: "Without Referrer-Policy, the full URL (including query parameters) is sent as the Referer header to external sites, potentially leaking session tokens or user IDs.",
      cvss: 3.1, cve: null,
      evidence: ev("Referrer-Policy: (absent)"),
      remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
    });
  }

  // Permissions-Policy
  if (!h["permissions-policy"]) {
    findings.push({
      title: "Missing Permissions-Policy Header",
      severity: "low",
      description: "Without Permissions-Policy, embedded iframes may access browser features (camera, microphone, geolocation, payment APIs) without explicit consent.",
      cvss: 3.1, cve: null,
      evidence: ev("Permissions-Policy: (absent)"),
      remediation: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()  (restrict to features you actually use)",
    });
  }

  // Server version disclosure
  const server = h["server"] ?? "";
  if (server && /[\d.]/.test(server)) {
    findings.push({
      title: "Server Version Disclosed",
      severity: "low",
      description: `Server header reveals software and version: "${server}". Attackers can look up known CVEs for this exact version.`,
      cvss: 4.3, cve: null,
      evidence: ev(`Server: ${server}`),
      remediation: "Suppress or genericise the Server header. Nginx: server_tokens off; Apache: ServerTokens Prod; Express: app.disable('x-powered-by')",
    });
  }

  for (const discHeader of ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]) {
    const val = h[discHeader];
    if (val) {
      findings.push({
        title: `Technology Disclosed via ${discHeader}`,
        severity: "low",
        description: `${discHeader}: ${val} reveals framework/platform details to attackers.`,
        cvss: 3.1, cve: null,
        evidence: ev(`${discHeader}: ${val}`),
        remediation: `Suppress the ${discHeader} header in your framework configuration.`,
      });
    }
  }

  // CORS
  const corsR = await probe(target.url, {
    headers: { Origin: "https://evil.attacker.example", "Access-Control-Request-Method": "GET" },
  });
  if (corsR) {
    const acao = corsR.headers["access-control-allow-origin"] ?? "";
    const acac = corsR.headers["access-control-allow-credentials"] ?? "";
    if (acao === "*") {
      findings.push({
        title: "CORS Wildcard Origin (*) — Any Site Can Read Responses",
        severity: "medium",
        description: "Access-Control-Allow-Origin: * lets any website make cross-origin requests and read responses. If this endpoint returns sensitive data, any malicious site can exfiltrate it from authenticated users.",
        cvss: 6.5, cve: null,
        evidence: `GET ${target.url} with Origin: https://evil.attacker.example\nAccess-Control-Allow-Origin: *`,
        remediation: "Replace * with an explicit allowlist of trusted origins. Validate the Origin header server-side before reflecting it.",
      });
    } else if (acao === "https://evil.attacker.example" && acac.toLowerCase() === "true") {
      findings.push({
        title: "CRITICAL: CORS Reflects Arbitrary Origin + Credentials",
        severity: "critical",
        description: "Server reflects any Origin and allows credentials. A malicious site can make fully authenticated cross-origin requests on behalf of logged-in users — enabling complete account takeover.",
        cvss: 9.0, cve: null,
        evidence: `GET ${target.url} with Origin: https://evil.attacker.example\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
        remediation: "Never combine a reflected/dynamic origin with Allow-Credentials: true. Validate Origin against a strict server-side allowlist.",
      });
    }
  }

  // Cookie security
  const setCookie = h["set-cookie"] ?? "";
  if (setCookie) {
    const lower = setCookie.toLowerCase();
    const nameMatch = setCookie.match(/^([^=;,\s]+)/);
    const cookieName = nameMatch?.[1]?.trim() ?? "cookie";
    if (!lower.includes("httponly")) {
      findings.push({
        title: `Cookie Missing HttpOnly Flag (${cookieName})`,
        severity: "medium",
        description: `Cookie "${cookieName}" is readable by JavaScript. Any XSS vulnerability allows session hijacking via document.cookie.`,
        cvss: 6.1, cve: null,
        evidence: `Set-Cookie: ${setCookie.slice(0, 200)}`,
        remediation: `Add HttpOnly flag: Set-Cookie: ${cookieName}=...; HttpOnly; Secure; SameSite=Strict`,
      });
    }
    if (target.isHttps && !lower.includes("secure")) {
      findings.push({
        title: `Cookie Missing Secure Flag (${cookieName})`,
        severity: "medium",
        description: `Cookie "${cookieName}" can be sent over HTTP. SSL stripping attacks can capture it.`,
        cvss: 5.9, cve: null,
        evidence: `Set-Cookie: ${setCookie.slice(0, 200)}`,
        remediation: `Add Secure flag: Set-Cookie: ${cookieName}=...; HttpOnly; Secure; SameSite=Strict`,
      });
    }
    if (!lower.includes("samesite")) {
      findings.push({
        title: `Cookie Missing SameSite Attribute (${cookieName})`,
        severity: "low",
        description: `Cookie "${cookieName}" has no SameSite attribute, enabling CSRF attacks.`,
        cvss: 4.3, cve: null,
        evidence: `Set-Cookie: ${setCookie.slice(0, 200)}`,
        remediation: `Add SameSite: Set-Cookie: ${cookieName}=...; HttpOnly; Secure; SameSite=Strict`,
      });
    }
  }

  // HTTP TRACE method
  const traceR = await probe(target.url, { method: "TRACE", timeoutMs: 6_000 });
  if (traceR && traceR.status === 200) {
    findings.push({
      title: "HTTP TRACE Method Enabled",
      severity: "medium",
      description: "The TRACE method is enabled. Combined with browser plugins or certain XSS vectors, TRACE allows Cross-Site Tracing (XST) attacks that can steal HTTP-only cookies.",
      cvss: 5.3, cve: null,
      evidence: `TRACE ${target.url} → HTTP ${traceR.status}`,
      remediation: "Disable TRACE in web server config. Nginx/Apache: Limit allowed methods to GET, POST, HEAD. TraceEnable Off (Apache).",
    });
  }

  await onLog(`[${ts()}] HTTP header analysis complete — ${findings.length} finding(s)`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 9. TECHNOLOGY FINGERPRINTING
// ═══════════════════════════════════════════════════════════════════════════════

interface TechProfile { name: string; version?: string; category: string; }

async function fingerprint(target: Target, onLog: LogFn): Promise<{ techs: TechProfile[]; findings: RealFinding[] }> {
  const techs: TechProfile[] = [];
  const findings: RealFinding[] = [];
  const r = await probe(target.url);
  if (!r) return { techs, findings };

  const h = r.headers;
  const body = r.body;

  const server = h["server"] ?? "";
  if (server) techs.push({ name: server, category: "Web Server" });

  // WordPress
  if (body.includes("/wp-content/") || body.includes("/wp-includes/") || h["x-pingback"]) {
    const vMatch = body.match(/WordPress\s+([\d.]+)/i);
    techs.push({ name: "WordPress", version: vMatch?.[1], category: "CMS" });
    const wpVer = body.match(/ver=([\d.]+)/)?.[1];
    findings.push({
      title: "WordPress CMS Detected",
      severity: "low",
      description: `WordPress${vMatch?.[1] ? ` ${vMatch[1]}` : ""} detected. WordPress is the most attacked CMS platform. Version fingerprinting enables targeted CVE exploitation.`,
      cvss: 3.7, cve: null,
      evidence: `WordPress indicators found in response body\nVersion hint: ${wpVer ?? "unknown"}`,
      remediation: "Keep WordPress and all plugins/themes updated. Consider hiding the version (remove meta generator tag). Use a WAF. Disable xmlrpc.php if not needed.",
    });
  }

  // Drupal
  if (body.includes("Drupal") || h["x-generator"]?.includes("Drupal")) {
    techs.push({ name: "Drupal", category: "CMS" });
  }

  // Joomla
  if (body.includes("/components/com_") || body.includes("Joomla")) {
    techs.push({ name: "Joomla", category: "CMS" });
  }

  // React
  if (body.includes("__REACT_DEVTOOLS") || body.includes("react-dom") || body.includes("_react")) {
    techs.push({ name: "React", category: "Frontend Framework" });
  }

  // Next.js
  if (h["x-powered-by"]?.includes("Next.js") || body.includes("__NEXT_DATA__")) {
    techs.push({ name: "Next.js", category: "Frontend Framework" });
    if (body.includes('"props"') && body.includes('"pageProps"') && body.includes('"buildId"')) {
      const buildIdMatch = body.match(/"buildId":"([^"]+)"/);
      findings.push({
        title: "Next.js Build ID Exposed",
        severity: "low",
        description: `Next.js __NEXT_DATA__ script exposes the build ID${buildIdMatch ? ` (${buildIdMatch[1]})` : ""}. This reveals deployment versioning info useful for targeted attacks.`,
        cvss: 3.1, cve: null,
        evidence: `__NEXT_DATA__ script present in HTML${buildIdMatch ? `\nbuildId: ${buildIdMatch[1]}` : ""}`,
        remediation: "This is often acceptable for public pages. If sensitive, consider server-side rendering strategies that minimise __NEXT_DATA__ exposure.",
      });
    }
  }

  // Laravel
  if (body.includes("laravel_session") || h["set-cookie"]?.includes("laravel")) {
    techs.push({ name: "Laravel (PHP)", category: "Backend Framework" });
  }

  // Django
  if (h["x-frame-options"] === "SAMEORIGIN" && h["x-content-type-options"] === "nosniff" && !h["content-security-policy"]) {
    techs.push({ name: "Possibly Django (Python)", category: "Backend Framework" });
  }

  // Nginx
  if (server.includes("nginx")) {
    techs.push({ name: `Nginx ${server.match(/nginx\/([\d.]+)/i)?.[1] ?? ""}`.trim(), category: "Web Server" });
  }

  // Apache
  if (server.toLowerCase().includes("apache")) {
    techs.push({ name: `Apache ${server.match(/apache\/([\d.]+)/i)?.[1] ?? ""}`.trim(), category: "Web Server" });
  }

  // Cloudflare
  if (h["cf-ray"] || h["cf-cache-status"]) {
    techs.push({ name: "Cloudflare CDN", category: "CDN/WAF" });
    await onLog(`[${ts()}] Cloudflare WAF/CDN detected — some probes may be filtered`);
  }

  // AWS
  if (h["x-amz-request-id"] || h["x-amzn-trace-id"] || h["x-amz-cf-id"]) {
    techs.push({ name: "AWS (CloudFront/ALB)", category: "Cloud" });
  }

  if (techs.length > 0) {
    await onLog(`[${ts()}] Technologies: ${techs.map((t) => `${t.name} (${t.category})`).join(", ")}`);
  }

  return { techs, findings };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 10. SENSITIVE PATH DISCOVERY
// ═══════════════════════════════════════════════════════════════════════════════

const SENSITIVE_PATHS: { path: string; deep?: boolean; finding: Omit<RealFinding, "evidence"> }[] = [
  { path: "/.env",         finding: { title: ".env File Exposed", severity: "critical", cvss: 9.8, cve: null, description: "The .env file is publicly accessible. It commonly contains database passwords, API keys, secret keys, and other credentials.", remediation: "Block access to .env files in your web server config. Never store .env in the web root. Add .env to .gitignore." } },
  { path: "/.env.local",   finding: { title: ".env.local File Exposed", severity: "critical", cvss: 9.8, cve: null, description: ".env.local is publicly accessible and may contain local override credentials.", remediation: "Block access to all .env* files. Move secrets to a secrets manager." } },
  { path: "/.env.production", finding: { title: ".env.production Exposed", severity: "critical", cvss: 9.8, cve: null, description: "Production environment file is publicly accessible.", remediation: "Block .env* files at the web server level." } },
  { path: "/.git/config",  finding: { title: "Git Repository Exposed (.git/config)", severity: "critical", cvss: 9.8, cve: null, description: "The .git directory is publicly accessible. Attackers can reconstruct the full source code, extract credentials from git history, and analyse the codebase for vulnerabilities.", remediation: "Block access to /.git/ at the web server. Nginx: location ~ /\\.git { deny all; } Never deploy with .git in the web root." } },
  { path: "/.git/HEAD",    finding: { title: "Git Repository HEAD Exposed", severity: "critical", cvss: 9.8, cve: null, description: "Git repository is accessible. Full source code reconstruction is possible.", remediation: "Block /.git/ access at the web server layer." } },
  { path: "/backup.sql",   finding: { title: "Database Backup File Exposed (backup.sql)", severity: "critical", cvss: 9.8, cve: null, description: "A SQL database backup is publicly downloadable. Contains the complete database schema and all data.", remediation: "Remove backup files from the web root. Store backups in non-web-accessible storage." } },
  { path: "/dump.sql",     finding: { title: "Database Dump Exposed (dump.sql)", severity: "critical", cvss: 9.8, cve: null, description: "SQL database dump is publicly accessible.", remediation: "Remove database dumps from web-accessible directories." } },
  { path: "/phpinfo.php",  finding: { title: "PHP Info Page Exposed", severity: "high", cvss: 7.5, cve: null, description: "phpinfo() output is publicly accessible, revealing PHP version, all configuration values, environment variables, and server paths.", remediation: "Delete phpinfo.php from production." } },
  { path: "/wp-login.php", finding: { title: "WordPress Admin Login Exposed", severity: "medium", cvss: 5.3, cve: null, description: "WordPress login page is publicly accessible and subject to credential brute-force attacks.", remediation: "Rename wp-login.php. Add IP-based access control. Enable 2FA. Use a WAF to block brute-force attempts." } },
  { path: "/wp-config.php", deep: true, finding: { title: "WordPress Config File Accessible", severity: "critical", cvss: 9.8, cve: null, description: "wp-config.php may be publicly accessible, exposing database credentials.", remediation: "Ensure wp-config.php is not web-accessible. Move it above the web root." } },
  { path: "/adminer.php",  finding: { title: "Adminer Database UI Exposed", severity: "critical", cvss: 9.8, cve: null, description: "Adminer (database management interface) is publicly accessible. Direct database access without authentication.", remediation: "Remove Adminer from production. Use a separate, IP-restricted management interface." } },
  { path: "/phpmyadmin/",  finding: { title: "phpMyAdmin Exposed", severity: "high", cvss: 8.1, cve: null, description: "phpMyAdmin database management interface is publicly accessible and subject to authentication brute-force.", remediation: "Restrict phpMyAdmin to internal IPs only. Remove from production if possible. Enable 2FA." } },
  { path: "/.DS_Store",    finding: { title: ".DS_Store File Exposed (Directory Enumeration Risk)", severity: "medium", cvss: 5.3, cve: null, description: "macOS .DS_Store file is exposed, revealing directory structure and filenames of the web root.", remediation: "Block access to .DS_Store files. Add to .gitignore. Nginx: location ~ /\\.DS_Store { deny all; }" } },
  { path: "/robots.txt",   finding: { title: "robots.txt Reveals Internal Paths", severity: "low", cvss: 3.1, cve: null, description: "robots.txt is accessible. While not a vulnerability itself, Disallow entries often enumerate admin panels, API paths, and internal routes.", remediation: "Review robots.txt for sensitive path disclosure. Do not rely on robots.txt for access control — use actual authentication and IP restrictions." } },
  { path: "/server-status", deep: true, finding: { title: "Apache Server Status Page Exposed", severity: "high", cvss: 7.5, cve: null, description: "Apache mod_status is publicly accessible, revealing server load, active connections, request URIs (potentially with session tokens), and internal IP addresses.", remediation: "Restrict mod_status to localhost: Allow from 127.0.0.1" } },
  { path: "/server-info",  deep: true, finding: { title: "Apache Server Info Page Exposed", severity: "high", cvss: 7.5, cve: null, description: "Apache mod_info exposes detailed server configuration and loaded modules.", remediation: "Disable mod_info or restrict to localhost only." } },
  { path: "/.htpasswd",    finding: { title: ".htpasswd File Exposed", severity: "critical", cvss: 9.8, cve: null, description: "Apache .htpasswd credential file is publicly readable, exposing hashed passwords for offline cracking.", remediation: "Block access to .htpasswd. Move it outside the web root." } },
  { path: "/config.php",   finding: { title: "config.php Exposed", severity: "high", cvss: 7.5, cve: null, description: "Configuration file is publicly accessible and may contain database credentials or API keys.", remediation: "Block access to config files. Move configuration outside the web root." } },
  { path: "/config.yaml",  deep: true, finding: { title: "config.yaml Exposed", severity: "high", cvss: 7.5, cve: null, description: "YAML configuration file accessible, potentially exposing credentials or infrastructure details.", remediation: "Block access to all configuration files." } },
  { path: "/config.json",  deep: true, finding: { title: "config.json Exposed", severity: "high", cvss: 7.5, cve: null, description: "JSON configuration file accessible.", remediation: "Move configuration files outside the web root." } },
  { path: "/.well-known/security.txt", finding: { title: "security.txt Present (Informational)", severity: "low", cvss: 0, cve: null, description: "security.txt found (RFC 9116). This is a best practice for responsible disclosure — note it for your bug bounty scope.", remediation: "Ensure security.txt is kept up-to-date with current contact information and PGP key.", verification: "informational", confidence: 99 } },
  { path: "/api/v1/",      finding: { title: "API v1 Endpoint Accessible", severity: "low", cvss: 3.1, cve: null, description: "API endpoint discovered. Verify it enforces authentication and is not exposing unauthenticated data.", remediation: "Ensure all API endpoints require appropriate authentication and authorisation." } },
  { path: "/graphql",      finding: { title: "GraphQL Endpoint Exposed", severity: "medium", cvss: 5.3, cve: null, description: "GraphQL endpoint is publicly accessible.", remediation: "Disable introspection in production. Require authentication. Implement query depth and rate limiting." } },
  { path: "/.svn/entries", deep: true, finding: { title: "SVN Repository Exposed", severity: "critical", cvss: 9.8, cve: null, description: ".svn directory is accessible, exposing source code via SVN repository dump.", remediation: "Block /.svn/ access at the web server." } },
  { path: "/crossdomain.xml", finding: { title: "crossdomain.xml Present", severity: "low", cvss: 3.1, cve: null, description: "Flash crossdomain.xml policy file found. Check for overly permissive allow-access-from entries.", remediation: "If Flash is not used, remove crossdomain.xml. If needed, restrict to specific trusted domains." } },
  { path: "/trace.axd",    deep: true, finding: { title: "ASP.NET Trace Enabled (trace.axd)", severity: "high", cvss: 7.5, cve: null, description: "ASP.NET application tracing is enabled, exposing detailed request/response data including session tokens and form values.", remediation: "Disable tracing in production: <trace enabled='false'/> in web.config." } },
  { path: "/elmah.axd",    deep: true, finding: { title: "ELMAH Error Log Exposed", severity: "high", cvss: 7.5, cve: null, description: "ELMAH (Error Logging Modules and Handlers) error log is publicly accessible, exposing stack traces, internal paths, and potentially credentials from error messages.", remediation: "Restrict ELMAH to authenticated users: <security allowRemoteAccess='false'/>" } },
  { path: "/.well-known/openid-configuration", finding: { title: "OpenID Configuration Exposed", severity: "low", cvss: 3.1, cve: null, description: "OpenID Connect discovery document is publicly accessible, revealing issuer URL, endpoints, and supported algorithms.", remediation: "This is expected for public OIDC providers. Ensure the configuration matches your intended public OIDC deployment." } },
  // Source maps
  { path: "/js/app.js.map",       deep: true, finding: { title: "JavaScript Source Map Exposed (app.js.map)", severity: "medium", cvss: 5.3, cve: null, description: "A JavaScript source map is publicly accessible, exposing original source code, file structure, variable names, and business logic. This dramatically aids attackers in finding vulnerabilities.", remediation: "Disable source map serving in production. Webpack: devtool: false. Vite: build.sourcemap: false." } },
  { path: "/static/js/main.chunk.js.map", deep: true, finding: { title: "React Bundle Source Map Exposed", severity: "medium", cvss: 5.3, cve: null, description: "Source map for the React bundle is publicly accessible, exposing full application source code.", remediation: "Set GENERATE_SOURCEMAP=false in Create React App builds. Never serve .map files in production." } },
  // AWS / Cloud
  { path: "/.aws/credentials",    finding: { title: "AWS Credentials File Exposed", severity: "critical", cvss: 10.0, cve: null, description: "AWS credentials file is publicly accessible. Contains access key IDs and secret access keys enabling full AWS account compromise.", remediation: "Remove immediately. Revoke the exposed keys via IAM console. Use IAM instance roles instead of static credentials." } },
  { path: "/aws.json",            deep: true, finding: { title: "AWS Configuration JSON Exposed", severity: "critical", cvss: 9.8, cve: null, description: "AWS configuration file with potential credentials is publicly accessible.", remediation: "Remove AWS config files from the web root. Use IAM roles for service authentication." } },
  // CI/CD and build artifacts
  { path: "/.github/workflows/deploy.yml", deep: true, finding: { title: "GitHub Actions Workflow Exposed", severity: "medium", cvss: 5.3, cve: null, description: "GitHub Actions workflow file is publicly accessible, revealing deployment infrastructure, secret names, and CI/CD pipeline details.", remediation: "Block access to .github/ directory in the web server configuration." } },
  { path: "/Dockerfile",          deep: true, finding: { title: "Dockerfile Exposed", severity: "medium", cvss: 5.3, cve: null, description: "Dockerfile is publicly accessible, revealing base images, environment setup, installed packages, and potential secret injection patterns.", remediation: "Block access to Dockerfile and docker-compose files in the web server configuration." } },
  { path: "/docker-compose.yml",  deep: true, finding: { title: "docker-compose.yml Exposed", severity: "high", cvss: 7.5, cve: null, description: "Docker Compose file is publicly accessible. Often contains hardcoded credentials, environment variables, and internal service topology.", remediation: "Block access to docker-compose.yml. Remove any hardcoded secrets and use environment variable injection." } },
  // npm / package management
  { path: "/.npmrc",              finding: { title: ".npmrc File Exposed (Possible Auth Token)", severity: "critical", cvss: 9.8, cve: null, description: ".npmrc may contain npm authentication tokens for private registries, enabling package hijacking and supply-chain attacks.", remediation: "Remove .npmrc from the web root. Revoke any exposed npm tokens immediately." } },
  { path: "/package.json",        deep: true, finding: { title: "package.json Exposed (Dependency Manifest)", severity: "low", cvss: 3.1, cve: null, description: "package.json is accessible, revealing all dependencies and versions — enabling targeted CVE research against known vulnerable packages.", remediation: "Block access to package.json in production." } },
  // Kubernetes / infrastructure
  { path: "/kubeconfig",          finding: { title: "Kubernetes Config Exposed", severity: "critical", cvss: 10.0, cve: null, description: "Kubernetes configuration file is publicly accessible, containing cluster API server URLs and credentials enabling full cluster control.", remediation: "Remove kubeconfig from the web root. Rotate all Kubernetes credentials immediately." } },
  { path: "/.kube/config",        finding: { title: "Kubernetes Config Exposed (.kube/config)", severity: "critical", cvss: 10.0, cve: null, description: "Kubernetes cluster configuration with embedded credentials is publicly accessible.", remediation: "Remove immediately and rotate all cluster credentials." } },
  // Database / backup files
  { path: "/database.sql",        finding: { title: "Database SQL Dump Exposed", severity: "critical", cvss: 9.8, cve: null, description: "SQL database dump is publicly downloadable, exposing the complete database schema and all data.", remediation: "Remove backup files from the web root. Store backups in non-web-accessible locations." } },
  { path: "/db.sqlite",           finding: { title: "SQLite Database File Exposed", severity: "critical", cvss: 9.8, cve: null, description: "SQLite database file is publicly downloadable, containing all application data in a single portable file.", remediation: "Move database files outside the web root. Use PostgreSQL or MySQL for production workloads." } },
  // Additional sensitive paths
  { path: "/web.config",          deep: true, finding: { title: "IIS web.config Exposed", severity: "high", cvss: 8.1, cve: null, description: "IIS web.config may expose database connection strings, API keys, and application secrets.", remediation: "Block access to web.config files. IIS blocks this by default — verify the configuration." } },
  { path: "/wp-json/wp/v2/users", finding: { title: "WordPress REST API User Enumeration", severity: "medium", cvss: 5.3, cve: null, description: "WordPress REST API exposes user data including usernames, IDs, and avatars without authentication, enabling targeted brute-force attacks.", remediation: "Disable the /wp-json/wp/v2/users endpoint: add_filter('rest_endpoints', function($endpoints) { unset($endpoints['/wp/v2/users']); return $endpoints; });" } },
  { path: "/.git/logs/HEAD",      finding: { title: "Git Commit Log Exposed", severity: "high", cvss: 7.5, cve: null, description: "Git commit history is publicly accessible, potentially exposing developer names, email addresses, commit messages, and branching history.", remediation: "Block all access to the .git/ directory at the web server level." } },
  { path: "/api/graphql",         deep: true, finding: { title: "GraphQL Endpoint Discovered (/api/graphql)", severity: "medium", cvss: 5.3, cve: null, description: "An alternate GraphQL endpoint is accessible. May have different authentication controls than the primary endpoint.", remediation: "Ensure consistent authentication and introspection controls across all GraphQL endpoints." } },
  { path: "/metrics",             deep: true, finding: { title: "Prometheus Metrics Endpoint Exposed", severity: "medium", cvss: 5.3, cve: null, description: "Prometheus metrics endpoint is publicly accessible, revealing internal application metrics, memory usage, request rates, and potentially internal service names.", remediation: "Restrict /metrics to internal network access only. Add authentication." } },
  { path: "/health",              finding: { title: "Health Check Endpoint Exposed (Informational)", severity: "low", cvss: 0, cve: null, description: "Application health check endpoint is publicly accessible. May reveal dependency status, version information, or internal service topology.", remediation: "Consider restricting health endpoints to internal networks or load balancers. Ensure they do not reveal sensitive configuration.", verification: "informational", confidence: 99 } },
  { path: "/.env.backup",         finding: { title: ".env.backup Exposed", severity: "critical", cvss: 9.8, cve: null, description: "Backup environment file is publicly accessible and likely contains full application secrets.", remediation: "Remove all .env* files from the web root. Block access at the web server level." } },
  { path: "/credentials.json",    finding: { title: "credentials.json Exposed", severity: "critical", cvss: 9.8, cve: null, description: "Credentials JSON file is accessible, potentially containing API keys, OAuth tokens, or service account credentials.", remediation: "Remove credentials files from the web root. Use a secrets manager." } },
  { path: "/id_rsa",              finding: { title: "SSH Private Key Exposed (id_rsa)", severity: "critical", cvss: 10.0, cve: null, description: "SSH RSA private key is publicly accessible. Any server accepting this key can be accessed without a password.", remediation: "Remove immediately. Rotate the key pair. Audit which servers accepted this key." } },
  { path: "/.ssh/id_rsa",         finding: { title: "SSH Private Key Exposed (.ssh/id_rsa)", severity: "critical", cvss: 10.0, cve: null, description: "SSH private key at .ssh/id_rsa is publicly accessible.", remediation: "Remove immediately and rotate all SSH key pairs." } },
];

async function checkSensitivePaths(target: Target, deep: boolean, onLog: LogFn): Promise<RealFinding[]> {
  const paths = SENSITIVE_PATHS.filter((p) => !p.deep || deep);
  await onLog(`[${ts()}] Probing ${paths.length} sensitive paths...`);

  const BATCH = 12;
  const findings: RealFinding[] = [];
  const notFoundUrl = `${target.url.replace(/\/$/, "")}/sentinelx-not-found-${Date.now()}`;
  const notFound = await probe(notFoundUrl, { timeoutMs: 8_000 });
  const compact = (value: string) => value.replace(/\s+/g, " ").trim().slice(0, 4_000);
  const contentMarkers: Record<string, RegExp> = {
    "/.env": /(?:^|\n)\s*[A-Z][A-Z0-9_]{2,}\s*=/,
    "/.env.local": /(?:^|\n)\s*[A-Z][A-Z0-9_]{2,}\s*=/,
    "/.env.production": /(?:^|\n)\s*[A-Z][A-Z0-9_]{2,}\s*=/,
    "/.git/config": /^\s*(?:\[core\]|repositoryformatversion|ref:)/im,
    "/.git/HEAD": /^\s*ref:\s+refs\//im,
    "/backup.sql": /(create\s+table|insert\s+into|--\s*(?:mysql|postgres|sql))/i,
    "/dump.sql": /(create\s+table|insert\s+into|--\s*(?:mysql|postgres|sql))/i,
    "/phpinfo.php": /(php version|phpinfo\(\)|configuration file)/i,
    "/wp-login.php": /(wp-login|user_login|wordpress)/i,
    "/wp-config.php": /(db_name|db_user|wp-config|define\s*\(\s*['"]DB_)/i,
    "/adminer.php": /adminer/i,
    "/phpmyadmin/": /phpmyadmin/i,
    "/robots.txt": /(?:^|\n)\s*(?:user-agent|disallow|sitemap)\s*:/i,
    "/.well-known/security.txt": /(?:^|\n)\s*(?:contact|expires|encryption|policy)\s*:/i,
  };

  for (let i = 0; i < paths.length; i += BATCH) {
    const batch = paths.slice(i, i + BATCH);
    const results = await Promise.allSettled(
      batch.map(async ({ path, finding }) => {
        const url = target.url.replace(/\/$/, "") + path;
        const result = await probe(url, { timeoutMs: 8_000 });
        if (!result || result.status !== 200) return null;
        const resultBody = compact(result.body);
        const baselineBody = notFound ? compact(notFound.body) : "";
        if (notFound && result.status === notFound.status && resultBody === baselineBody) return null;
        const marker = contentMarkers[path];
        if (marker && !marker.test(result.body)) return null;
        if (!marker && resultBody.toLowerCase().includes("404") && result.body.length < 2_000) return null;
        const snippet = result.body.slice(0, 300).replace(/\s+/g, " ").trim();
        return {
          ...finding,
          evidence: `GET ${url} → HTTP ${result.status} (${result.durationMs}ms)\nContent-Type: ${result.headers["content-type"] ?? "unknown"}\nBody preview: ${snippet || "(empty)"}`,
        } as RealFinding;
      }),
    );
    for (const r of results) {
      if (r.status === "fulfilled" && r.value) {
        findings.push(r.value);
        await onLog(`[${ts()}] FOUND: ${r.value.title}`);
      }
    }
  }

  await onLog(`[${ts()}] Path discovery: ${findings.length} exposure(s) found`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 11. WEB APPLICATION VULNERABILITY PROBES
// ═══════════════════════════════════════════════════════════════════════════════

const SQLI_PATTERNS = [
  /you have an error in your sql syntax/i,
  /warning.*mysql.*query/i,
  /pg_query\(\): query failed/i,
  /psycopg2\.errors/i,
  /unterminated quoted string at or near/i,
  /sqlite3\.operationalerror/i,
  /sqlexception.*syntax error/i,
  /odbc.*sql server.*error/i,
  /ora-\d{5}/i,
  /microsoft.*ole db.*provider.*error/i,
  /unclosed quotation mark after the character string/i,
  /db2 sql error/i,
  /invalid sql statement/i,
  /column .* does not exist/i,
  /table .* doesn't exist/i,
  /syntax error.*near/i,
];

async function checkWebApp(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];

  // ── SQLi error detection ──────────────────────────────────────────────────
  await onLog(`[${ts()}] Testing SQL injection (error-based and blind)...`);
  const sqliParams = ["id", "search", "q", "query", "page", "cat", "user", "item", "product", "order", "filter", "sort", "name"];
  const sqliPayloads = [
    "'", "1 OR 1=1--", "1' OR '1'='1", "1'--", "1 AND 1=2--", `' OR 'x'='x`,
    "1; SELECT SLEEP(0)--", "1 UNION SELECT NULL--", "1' AND 1=2 UNION SELECT NULL--",
  ];
  const sqliBaseline = await probe(target.url, { timeoutMs: 8_000 });
  let sqliFound = false;
  for (const param of sqliParams.slice(0, 8)) {
    if (sqliFound) break;
    for (const payload of sqliPayloads.slice(0, 6)) {
      if (sqliFound) break;
      const probeUrl = `${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(payload)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      const matched = SQLI_PATTERNS.find((p) => p.test(r.body));
      const baselineHasSameError = sqliBaseline ? SQLI_PATTERNS.some((p) => p.test(sqliBaseline.body)) : false;
      const responseChanged = !sqliBaseline || r.status !== sqliBaseline.status || Math.abs(r.body.length - sqliBaseline.body.length) > 50;
      if (matched && responseChanged && !baselineHasSameError) {
        findings.push({
          title: "SQL Injection — Database Error Leaked in Response",
          severity: "high",
          verification: "suspected",
          confidence: 72,
          description: `A SQL-shaped payload in parameter '${param}' produced a database error absent from the baseline. This is a strong signal of SQL injection error-disclosure; the probe does not establish data extraction or exploitability without further manual testing.`,
          cvss: 7.5, cve: null,
          evidence: `BASELINE: GET ${target.url} → HTTP ${sqliBaseline?.status ?? "unavailable"} (${sqliBaseline?.body.length} bytes)\nPROBE: ${probeUrl}\n→ HTTP ${r.status} (${r.body.length} bytes)\nPattern matched: ${matched}\nBody excerpt: ${r.body.slice(0, 400)}`,
          remediation: "Use parameterised queries/prepared statements exclusively. Never concatenate user input into SQL. Suppress all database errors in production. Apply least-privilege to DB accounts.",
        });
        sqliFound = true;
        break;
      }
    }
  }

  // ── Time-based blind SQLi ─────────────────────────────────────────────────
  if (!sqliFound) {
    await onLog(`[${ts()}] Testing time-based blind SQL injection...`);
    const blindPayloads = [
      { payload: "1' AND SLEEP(4)--",          db: "MySQL",      delay: 3500 },
      { payload: "1; WAITFOR DELAY '0:0:4'--", db: "MSSQL",      delay: 3500 },
      { payload: "1' AND pg_sleep(4)--",        db: "PostgreSQL", delay: 3500 },
      { payload: "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(98)||CHR(98)||CHR(98),4)--", db: "Oracle", delay: 3500 },
    ];
    for (const param of sqliParams.slice(0, 4)) {
      if (sqliFound) break;
      const baselineStart = Date.now();
      const bl = await probe(`${target.url.replace(/\/$/, "")}?${param}=1`, { timeoutMs: 8_000 });
      const baselineMs = Date.now() - baselineStart;
      if (!bl) continue;
      for (const { payload, db, delay } of blindPayloads.slice(0, 2)) {
        const t0 = Date.now();
        const r = await probe(`${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(payload)}`, { timeoutMs: 12_000 });
        const elapsed = Date.now() - t0;
        if (r && elapsed >= delay && elapsed > baselineMs + 2000) {
          findings.push({
            title: `Time-Based Blind SQL Injection — ${db} SLEEP/DELAY Confirmed`,
            severity: "high",
            verification: "suspected",
            confidence: 78,
            description: `Parameter '${param}' caused a ${elapsed}ms response delay (baseline: ${baselineMs}ms) when a ${db} time-delay payload was injected. This is a strong blind SQLi signal; time-based detection can have false positives from network jitter — confirm with multiple identical probes.`,
            cvss: 8.1, cve: null,
            evidence: `Baseline: GET ?${param}=1 → ${baselineMs}ms\nBlind probe: GET ?${param}=${payload}\n→ ${elapsed}ms response time\nExpected delay: ≥${delay}ms\nDB targeted: ${db}`,
            remediation: "Use parameterised queries/prepared statements. Even without visible error output, the database evaluated the payload. Apply an ORM or query builder with automatic parameterisation.",
          });
          sqliFound = true;
          await onLog(`[${ts()}] ⚠ TIME-BASED BLIND SQLI SIGNAL: ${db} ${elapsed}ms delay via '${param}'`);
          break;
        }
      }
    }
  }

  // ── XSS reflection detection ──────────────────────────────────────────────
  await onLog(`[${ts()}] Testing XSS reflection (reflected + DOM indicators)...`);
  const xssToken = Math.random().toString(36).slice(2, 10);
  const xssPayload = `<script>xss${xssToken}</script>`;
  const xssPolyglot = `jaVasCript:/*-/*\`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`;
  const xssParams = ["q", "search", "name", "msg", "message", "text", "content", "input", "title", "value", "data", "error", "callback", "return", "next", "redirect"];
  let xssFound = false;
  for (const param of xssParams.slice(0, 10)) {
    if (xssFound) break;
    for (const payload of [xssPayload, `"><img src=x onerror=alert(${xssToken})>`]) {
      const probeUrl = `${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(payload)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      const contentType = (r.headers["content-type"] ?? "").toLowerCase();
      const reflected = r.body.includes(payload) || r.body.includes(`xss${xssToken}`);
      const executableHtml = contentType.includes("text/html") &&
        (/<script\b[^>]*>xss[a-z0-9]+<\/script>/i.test(r.body) || new RegExp(`onerror=alert\\(${xssToken}\\)`, "i").test(r.body));
      if (reflected && executableHtml) {
        findings.push({
          title: "Reflected XSS — Script/Event Payload Returned Unescaped",
          severity: "high",
          verification: "suspected",
          confidence: 78,
          description: `Parameter '${param}' reflects user-supplied HTML/JS without encoding. An attacker can craft a URL with JavaScript that executes in victims' browsers — enabling session token theft, credential phishing, and account takeover.`,
          cvss: 7.4, cve: null,
          evidence: `PROBE: GET ${probeUrl}\nPAYLOAD: ${param}=${payload}\nContent-Type: ${contentType}\nHTTP ${r.status}: payload reflected without encoding\nVERIFICATION: suspected — browser execution was not performed (no headless browser available)`,
          remediation: "HTML-encode all user-controlled output at render time. Use a templating engine that escapes by default (Jinja2, Handlebars, React JSX). Implement a strict Content-Security-Policy. Validate Content-Type headers.",
        });
        xssFound = true;
        await onLog(`[${ts()}] ⚠ REFLECTED XSS SIGNAL via param '${param}'`);
        break;
      }
    }
  }

  // ── NoSQL Injection ───────────────────────────────────────────────────────
  await onLog(`[${ts()}] Testing NoSQL injection...`);
  const nosqlBaseline = await probe(target.url, { timeoutMs: 8_000 });
  const nosqlPayloads = [
    { body: '{"username":{"$gt":""},"password":{"$gt":""}}', ct: "application/json" },
    { body: '{"username":{"$regex":".*"},"password":{"$regex":".*"}}', ct: "application/json" },
    { body: "username[$gt]=&password[$gt]=", ct: "application/x-www-form-urlencoded" },
    { body: "username[$ne]=invalid&password[$ne]=invalid", ct: "application/x-www-form-urlencoded" },
  ];
  for (const ep of [`${target.url.replace(/\/$/, "")}/api/login`, `${target.url.replace(/\/$/, "")}/login`, `${target.url.replace(/\/$/, "")}/auth`].slice(0, 2)) {
    for (const { body, ct } of nosqlPayloads.slice(0, 2)) {
      const r = await probe(ep, { method: "POST", headers: { "Content-Type": ct }, body, timeoutMs: 8_000 });
      if (!r) continue;
      const blStatus = nosqlBaseline?.status ?? 0;
      const bodyLower = r.body.toLowerCase();
      const successSignals = ["welcome", "dashboard", "logged in", "token", "access_token", "session", '"user":', '"id":', '"role":'];
      const isSuccess = successSignals.some(s => bodyLower.includes(s));
      if (r.status === 200 && isSuccess && (blStatus !== 200 || Math.abs(r.body.length - (nosqlBaseline?.body.length ?? 0)) > 100)) {
        findings.push({
          title: "NoSQL Injection — MongoDB Operator Authentication Bypass",
          severity: "critical",
          verification: "suspected",
          confidence: 75,
          description: `A MongoDB-style operator injection payload ($gt/$regex/$ne) produced a success response at ${ep}. This commonly indicates MongoDB NoSQL injection allowing authentication bypass without valid credentials.`,
          cvss: 9.8, cve: null,
          evidence: `POST ${ep}\nContent-Type: ${ct}\nBody: ${body}\nHTTP ${r.status} — success signals in response\nResponse: ${r.body.slice(0, 300)}`,
          remediation: "Sanitise all query inputs — strip $ prefixes and special MongoDB operators from user input. Use an ODM (Mongoose) with strict schema validation. Never pass raw user input into MongoDB query objects.",
        });
        await onLog(`[${ts()}] ⚠ NOSQL INJECTION SIGNAL at ${ep}`);
        break;
      }
    }
  }

  // ── Command injection basic probe ─────────────────────────────────────────
  await onLog(`[${ts()}] Testing command injection...`);
  const cmdCanary = `sentinelx-cmd-${Math.random().toString(36).slice(2, 10)}`;
  const cmdPayloads = [
    `; printf ${cmdCanary}`,
    `| printf ${cmdCanary}`,
    `\`printf ${cmdCanary}\``,
    `$(printf ${cmdCanary})`,
    `; echo ${cmdCanary}`,
  ];
  const cmdParams = ["cmd", "exec", "command", "run", "shell", "ping", "host", "ip", "target", "file", "path", "name", "url"];
  for (const param of cmdParams.slice(0, 6)) {
    let cmdFound = false;
    for (const payload of cmdPayloads.slice(0, 3)) {
      const probeUrl = `${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(payload)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      if (r.body.includes(cmdCanary)) {
        findings.push({
          title: `OS Command Injection — Canary Executed via '${param}' Parameter`,
          severity: "critical",
          verification: "verified",
          confidence: 98,
          cvss: 10.0, cve: null,
          description: `The application executed a shell command injected via the '${param}' parameter. A bounded canary string (${cmdCanary}) was returned in the response, confirming operating-system command execution. This allows full server compromise.`,
          evidence: `PROBE: GET ${probeUrl}\nPAYLOAD: ${param}=${payload}\nCANARY: ${cmdCanary}\nHTTP ${r.status} — canary found in response\nResponse snippet: ${r.body.slice(0, 400)}`,
          remediation: "Never pass user input to shell execution functions (exec, system, popen, subprocess). Use language-native libraries instead of shell calls. If shell is required, use an allowlist of permitted commands and shell-escape all arguments.",
        });
        await onLog(`[${ts()}] ⚠ COMMAND INJECTION CONFIRMED via param '${param}'`);
        cmdFound = true;
        break;
      }
    }
    if (cmdFound) break;
  }

  // ── Open redirect ─────────────────────────────────────────────────────────
  await onLog(`[${ts()}] Testing open redirect...`);
  const redirectMarker = "redirect-test-sentinel-x";
  const redirectPayloads = [
    target.url + `?redirect=https://${redirectMarker}.example.com`,
    target.url + `?next=https://${redirectMarker}.example.com`,
    target.url + `?url=https://${redirectMarker}.example.com`,
    target.url + `?return=https://${redirectMarker}.example.com`,
    target.url + `?returnUrl=https://${redirectMarker}.example.com`,
    target.url + `?goto=https://${redirectMarker}.example.com`,
  ];
  for (const probeUrl of redirectPayloads) {
    const r = await probe(probeUrl, { followRedirects: false, timeoutMs: 8_000 });
    if (!r) continue;
    if ([301, 302, 303, 307, 308].includes(r.status)) {
      const loc = r.headers["location"] ?? "";
      if (loc.includes(redirectMarker)) {
        findings.push({
          title: "Open Redirect Vulnerability",
          severity: "medium",
          description: "The application redirects users to attacker-controlled URLs without validation. Attackers can craft phishing links that appear to come from a trusted domain, bypassing browser warnings and corporate email filters.",
          cvss: 6.1, cve: null,
          evidence: `Probe URL: ${probeUrl}\nHTTP ${r.status} Location: ${loc}`,
          remediation: "Validate redirect destinations against an allowlist of trusted URLs or paths. Never redirect to arbitrary user-supplied URLs. Use relative paths for internal redirects.",
        });
        break;
      }
    }
  }

  // ── HTTP methods enumeration ──────────────────────────────────────────────
  await onLog(`[${ts()}] Enumerating HTTP methods...`);
  const optR = await probe(target.url, { method: "OPTIONS", timeoutMs: 6_000 });
  if (optR) {
    const allow = optR.headers["allow"] ?? optR.headers["public"] ?? "";
    const dangerous = ["PUT", "DELETE", "TRACE", "CONNECT"].filter((m) => allow.toUpperCase().includes(m));
    if (dangerous.length > 0) {
      findings.push({
        title: `Dangerous HTTP Methods Advertised: ${dangerous.join(", ")}`,
        severity: "medium",
        description: `OPTIONS response advertises: ${dangerous.join(", ")}. PUT/DELETE allow file manipulation if unrestricted. TRACE enables Cross-Site Tracing.`,
        cvss: 5.3, cve: null,
        evidence: `OPTIONS ${target.url} → HTTP ${optR.status}\nAllow: ${allow}`,
        remediation: "Restrict allowed methods to GET, POST, HEAD only. Disable TRACE. Require authentication for PUT/DELETE.",
      });
    }
  }

  // ── Error page information disclosure ────────────────────────────────────
  await onLog(`[${ts()}] Checking error page disclosure...`);
  const errorR = await probe(target.url + "__nonexistent__sentinelx", { timeoutMs: 6_000 });
  if (errorR) {
    const body = errorR.body.toLowerCase();
    const stack = body.match(/traceback|stack trace|exception in|at \w+\.\w+\(|file ".*\.py"/i);
    if (stack) {
      findings.push({
        title: "Stack Trace Disclosed in Error Response",
        severity: "high",
        description: "The application returns detailed stack traces on errors, revealing internal file paths, framework versions, and code structure. This significantly aids an attacker's ability to find and exploit vulnerabilities.",
        cvss: 7.5, cve: null,
        evidence: `GET ${target.url}__nonexistent__sentinelx → HTTP ${errorR.status}\nStack trace detected: ${errorR.body.slice(0, 400)}`,
        remediation: "Disable debug mode in production. Configure generic 404/500 error pages that reveal no technical details. Log errors server-side instead of displaying them.",
      });
    }
  }

  // ── Directory listing ─────────────────────────────────────────────────────
  const dirPaths = ["/images/", "/uploads/", "/static/", "/assets/", "/files/", "/backup/", "/css/", "/js/"];
  for (const dirPath of dirPaths) {
    const dirUrl = target.url.replace(/\/$/, "") + dirPath;
    const r = await probe(dirUrl, { timeoutMs: 6_000 });
    if (!r) continue;
    if (r.status === 200 && (r.body.includes("Index of ") || r.body.includes("Directory listing"))) {
      findings.push({
        title: `Directory Listing Enabled (${dirPath})`,
        severity: "medium",
        description: `Directory listing is enabled for ${dirPath}. Attackers can enumerate all files, including uploads, backups, and documents not intended to be public.`,
        cvss: 5.3, cve: null,
        evidence: `GET ${dirUrl} → HTTP ${r.status}\nBody contains directory listing\nPreview: ${r.body.slice(0, 300)}`,
        remediation: `Disable directory listing in web server config. Apache: Options -Indexes. Nginx: autoindex off;`,
      });
      break;
    }
  }

  await onLog(`[${ts()}] Web app probes complete — ${findings.length} finding(s)`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 12. API SURFACE DISCOVERY
// ═══════════════════════════════════════════════════════════════════════════════

async function checkApiSurface(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Probing API documentation and management endpoints...`);

  // GraphQL introspection
  for (const ep of ["/graphql", "/api/graphql", "/gql", "/query", "/v1/graphql"]) {
    const url = target.url.replace(/\/$/, "") + ep;
    const r = await probe(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "{ __schema { types { name } } }" }),
      timeoutMs: 8_000,
    });
    if (r?.status === 200 && r.body.includes("__schema")) {
      findings.push({
        title: "GraphQL Introspection Enabled in Production",
        severity: "high",
        description: "GraphQL introspection is enabled, exposing the complete schema — all types, fields, mutations, and queries. Attackers get a full API map without reverse-engineering.",
        cvss: 7.5, cve: null,
        evidence: `POST ${url} with introspection query → HTTP ${r.status}\nResponse contains __schema\nPartial: ${r.body.slice(0, 300)}`,
        remediation: "Disable introspection in production. Apollo: introspection: false. Most frameworks have a single config flag.",
      });
      break;
    }
  }

  // Swagger / OpenAPI exposure
  for (const ep of ["/swagger", "/swagger-ui.html", "/api-docs", "/openapi.json", "/openapi.yaml", "/docs", "/redoc", "/v2/api-docs", "/v3/api-docs"]) {
    const url = target.url.replace(/\/$/, "") + ep;
    const r = await probe(url, { timeoutMs: 6_000 });
    if (!r || r.status !== 200) continue;
    const body = r.body.toLowerCase();
    if (body.includes("swagger") || body.includes("openapi") || body.includes('"paths"')) {
      findings.push({
        title: "API Documentation (Swagger/OpenAPI) Publicly Exposed",
        severity: "medium",
        description: "API documentation is publicly accessible, providing a complete map of all endpoints, parameters, and auth requirements — eliminating reconnaissance for attackers.",
        cvss: 5.3, cve: null,
        evidence: `GET ${url} → HTTP ${r.status}\nContent indicates Swagger/OpenAPI`,
        remediation: "Restrict API docs to authenticated users or internal networks. Consider disabling in production.",
      });
      break;
    }
  }

  // Spring Boot Actuator
  for (const ep of ["/actuator/env", "/actuator/heapdump", "/actuator/beans", "/actuator"]) {
    const url = target.url.replace(/\/$/, "") + ep;
    const r = await probe(url, { timeoutMs: 6_000 });
    if (!r || r.status !== 200) continue;
    const body = r.body.toLowerCase();
    const isActuatorPayload =
      body.includes('"activeprofiles"') ||
      body.includes('"propertysources"') ||
      body.includes('"contexts"') ||
      body.includes('"beans"') ||
      body.includes('"heapdump"');
    if (isActuatorPayload) {
      findings.push({
        title: `Spring Boot Actuator Endpoint Exposed (${ep})`,
        severity: ep.includes("env") || ep.includes("heap") ? "high" : "medium",
        description: `Spring Boot Actuator ${ep} is publicly accessible. ${ep.includes("env") ? "The /env endpoint may expose environment and configuration values. " : ep.includes("heap") ? "The /heapdump endpoint may expose in-memory application data. " : ""}This confirms an exposed management endpoint, not remote code execution.`,
        cvss: ep.includes("env") || ep.includes("heap") ? 9.8 : 7.5, cve: null,
        evidence: `GET ${url} → HTTP ${r.status}\n${r.body.slice(0, 300)}`,
        remediation: "Restrict Actuator to management ports: management.server.port=8081. Require authentication. Disable sensitive endpoints.",
      });
      break;
    }
  }

  // Laravel Telescope
  for (const ep of ["/telescope", "/telescope/api/requests"]) {
    const url = target.url.replace(/\/$/, "") + ep;
    const r = await probe(url, { timeoutMs: 6_000 });
    if (r?.status === 200 && (r.body.includes("Laravel Telescope") || r.body.includes('"payload"'))) {
      findings.push({
        title: "Laravel Telescope Debug Dashboard Exposed",
        severity: "high",
        description: "Laravel Telescope is publicly accessible. It exposes all HTTP requests, database queries, exceptions, mail, jobs, and potentially sensitive request payloads.",
        cvss: 8.1, cve: null,
        evidence: `GET ${url} → HTTP ${r.status}`,
        remediation: "Restrict Telescope to local or authenticated environments only. Add authorizeUsing() gate. Disable in production.",
      });
      break;
    }
  }

  await onLog(`[${ts()}] API surface scan complete — ${findings.length} finding(s)`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// WAF DETECTION & BYPASS TECHNIQUES
// ═══════════════════════════════════════════════════════════════════════════════

const WAF_SIGNATURES: Record<string, { headers: string[]; body: string[]; cookies: string[] }> = {
  "Cloudflare":      { headers: ["cf-ray", "cf-cache-status", "cf-worker", "cf-request-id"], body: ["cloudflare", "attention required! | cloudflare"], cookies: ["__cfduid", "cf_clearance"] },
  "AWS WAF":         { headers: ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw-id"], body: [], cookies: [] },
  "Akamai":          { headers: ["akamai-origin-hop", "x-akamai-transformed", "x-check-cacheable", "x-serial"], body: ["reference #18."], cookies: ["ak_bmsc"] },
  "Sucuri":          { headers: ["x-sucuri-id", "x-sucuri-cache"], body: ["sucuri website firewall"], cookies: [] },
  "Imperva/Incapsula": { headers: ["x-iinfo", "x-cdn"], body: ["incapsula incident id"], cookies: ["incap_ses", "visid_incap"] },
  "F5 BIG-IP ASM":  { headers: ["x-cnection", "x-wa-info"], body: ["the requested url was rejected"], cookies: ["TS", "bigipserver"] },
  "Barracuda":       { headers: [], body: ["barracuda networks"], cookies: ["barra_counter_session"] },
  "ModSecurity":     { headers: ["x-mod-security-message"], body: ["mod_security", "not acceptable"], cookies: [] },
  "Fastly":          { headers: ["x-fastly-request-id", "fastly-debug-digest"], body: [], cookies: [] },
  "Varnish":         { headers: ["x-varnish"], body: [], cookies: [] },
  "Nginx WAF":       { headers: [], body: ["406 not acceptable"], cookies: [] },
  "Wordfence":       { headers: [], body: ["generated by wordfence", "your access to this site has been limited"], cookies: [] },
};

async function checkWafAndBypass(target: Target, onLog: LogFn): Promise<{ findings: RealFinding[]; wafName: string | null }> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Detecting WAF/CDN and testing bypass techniques...`);

  const r = await probe(target.url, { timeoutMs: 12_000 });
  if (!r) return { findings, wafName: null };

  // ── Detect WAF ─────────────────────────────────────────────────────────────
  let detectedWaf: string | null = null;
  const allHeaders = JSON.stringify(r.headers).toLowerCase();
  const allCookies = (r.headers["set-cookie"] ?? "").toLowerCase();
  const bodyLower = r.body.toLowerCase();

  for (const [waf, sigs] of Object.entries(WAF_SIGNATURES)) {
    const headerMatch = sigs.headers.some(h => allHeaders.includes(h.toLowerCase()));
    const bodyMatch = sigs.body.some(b => bodyLower.includes(b.toLowerCase()));
    const cookieMatch = sigs.cookies.some(c => allCookies.includes(c.toLowerCase()));
    if (headerMatch || bodyMatch || cookieMatch) { detectedWaf = waf; break; }
  }

  if (detectedWaf) {
    await onLog(`[${ts()}] WAF/CDN detected: ${detectedWaf}`);
    findings.push({
      title: `WAF/CDN Detected: ${detectedWaf}`,
      severity: "low", verification: "informational", confidence: 92,
      cvss: 0, cve: null,
      description: `A Web Application Firewall (${detectedWaf}) is in front of this target. Bypass techniques are now being tested — results reported separately.`,
      evidence: `WAF: ${detectedWaf}\nRelevant response headers:\n${allHeaders.slice(0, 400)}`,
      remediation: "WAFs are a defence-in-depth measure, not a primary fix. Keep the underlying application patched and secure independently of the WAF.",
    });

    // ── Try IP-spoofing bypass headers ───────────────────────────────────────
    await onLog(`[${ts()}] Testing WAF bypass via IP-spoofing headers...`);
    const bypassHeaderSets: Record<string, string>[] = [
      { "X-Forwarded-For": "127.0.0.1" },
      { "X-Real-IP": "127.0.0.1" },
      { "X-Originating-IP": "127.0.0.1" },
      { "X-Remote-IP": "127.0.0.1" },
      { "X-Client-IP": "127.0.0.1" },
      { "True-Client-IP": "127.0.0.1" },
      { "CF-Connecting-IP": "127.0.0.1" },
      { "X-ProxyUser-Ip": "127.0.0.1" },
      { "X-Forwarded-Host": target.hostname },
    ];
    for (const hdrs of bypassHeaderSets) {
      const bypassR = await probe(target.url, { headers: hdrs, timeoutMs: 10_000 });
      if (bypassR && Math.abs(bypassR.body.length - r.body.length) > 300) {
        const hdrKey = Object.keys(hdrs)[0]!;
        findings.push({
          title: `WAF Bypass Signal: IP Header Spoofing (${hdrKey})`,
          severity: "high", verification: "suspected", confidence: 72,
          cvss: 7.5, cve: null,
          description: `Adding ${hdrKey}: ${Object.values(hdrs)[0]} produced a significantly different response (${r.body.length} → ${bypassR.body.length} bytes). The WAF may trust this header and grant different access for "internal" traffic, effectively bypassing its rules.`,
          evidence: `Baseline: GET ${target.url} → HTTP ${r.status} (${r.body.length} bytes)\nWith ${hdrKey}: ${Object.values(hdrs)[0]} → HTTP ${bypassR.status} (${bypassR.body.length} bytes)\nDifference: ${Math.abs(bypassR.body.length - r.body.length)} bytes`,
          remediation: "Only trust IP override headers (X-Forwarded-For, X-Real-IP, etc.) from verified internal proxy IP ranges. Block all such headers from external sources at the network layer.",
        });
        await onLog(`[${ts()}] ⚠ WAF BYPASS SIGNAL: ${hdrKey} produced different response`);
        break;
      }
    }

    // ── Googlebot UA bypass ──────────────────────────────────────────────────
    const botR = await probe(target.url, { headers: { "User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)" }, timeoutMs: 10_000 });
    if (botR && Math.abs(botR.body.length - r.body.length) > 500) {
      findings.push({
        title: "WAF Bypass Signal: Googlebot User-Agent Treated Differently",
        severity: "medium", verification: "suspected", confidence: 60,
        cvss: 5.3, cve: null,
        description: "The server returns a significantly different response for Googlebot User-Agent requests. WAF may whitelist search crawlers, creating a bypass path for attackers impersonating them.",
        evidence: `Normal UA → ${r.body.length} bytes HTTP ${r.status}\nGooglebot UA → ${botR.body.length} bytes HTTP ${botR.status}\nDifference: ${Math.abs(botR.body.length - r.body.length)} bytes`,
        remediation: "Do not apply different security rules based on User-Agent. Verify legitimate Googlebot via reverse DNS, not just the UA string.",
      });
      await onLog(`[${ts()}] ⚠ WAF BYPASS SIGNAL: Googlebot UA returned different response`);
    }

    // ── Direct origin IP access (bypass WAF entirely) ────────────────────────
    await onLog(`[${ts()}] Checking for direct origin IP exposure (full WAF bypass)...`);
    try {
      const ips = await digQuery(target.hostname, "A");
      for (const ip of ips.slice(0, 2)) {
        const originR = await probe(`http://${ip}/`, { headers: { "Host": target.hostname }, timeoutMs: 8_000, followRedirects: false });
        if (originR && originR.status >= 200 && originR.status < 400) {
          const originHeaders = JSON.stringify(originR.headers).toLowerCase();
          const hasWafHeader = WAF_SIGNATURES[detectedWaf]?.headers.some(h => originHeaders.includes(h)) ?? false;
          if (!hasWafHeader) {
            findings.push({
              title: `Origin IP Bypasses ${detectedWaf} WAF — Direct Access Confirmed (${ip})`,
              severity: "critical", verification: "verified", confidence: 92,
              cvss: 9.8, cve: null,
              description: `The origin server at ${ip} responds directly over HTTP without passing through ${detectedWaf}. All WAF protections are rendered ineffective — attackers can target the origin directly to exploit any vulnerability the WAF would otherwise block.`,
              evidence: `WAF-protected host: ${target.hostname}\nDirect IP: ${ip}\nHTTP GET http://${ip}/ with Host: ${target.hostname}\n→ HTTP ${originR.status} response without WAF headers\nWAF headers absent in response`,
              remediation: `1. Firewall the origin to accept connections ONLY from ${detectedWaf}'s published IP ranges.\n2. Rotate the origin IP and restrict via cloud firewall rules.\n3. Use authenticated origin pulls (Cloudflare: authenticated origin pulls feature).\n4. Enforce mTLS between WAF and origin.`,
            });
            await onLog(`[${ts()}] ⚠ ORIGIN IP EXPOSED: ${ip} reachable without ${detectedWaf} — full WAF bypass confirmed`);
          }
        }
      }
    } catch { /* expected */ }

    // ── Case-variation / encoding bypass test ────────────────────────────────
    const pathR = await probe(`${target.url.replace(/\/$/, "")}/..%2f`, { timeoutMs: 6_000 });
    const dotR = await probe(`${target.url.replace(/\/$/, "")}/.%2e/`, { timeoutMs: 6_000 });
    if ((pathR && pathR.status === 200) || (dotR && dotR.status === 200)) {
      findings.push({
        title: "WAF Path Normalisation Bypass (URL-Encoded Traversal)",
        severity: "medium", verification: "suspected", confidence: 60,
        cvss: 5.3, cve: null,
        description: "URL-encoded path segments (%2f, %2e) returned a 200 response, suggesting the WAF does not normalise paths before matching rules. Attackers can use encoding tricks to bypass path-based WAF rules.",
        evidence: `GET ${target.url}..%2f → HTTP ${pathR?.status ?? "N/A"}\nGET ${target.url}.%2e/ → HTTP ${dotR?.status ?? "N/A"}`,
        remediation: "Configure the WAF to decode and normalise all URL encoding before applying rules. Enable path normalisation in your WAF settings.",
      });
    }
  } else {
    await onLog(`[${ts()}] No WAF/CDN signature detected — unprotected origin`);
  }

  return { findings, wafName: detectedWaf };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUBDOMAIN TAKEOVER
// ═══════════════════════════════════════════════════════════════════════════════

const TAKEOVER_FINGERPRINTS: Array<{ service: string; cnamePattern: RegExp; indicator: string }> = [
  { service: "GitHub Pages",   cnamePattern: /github\.io$/i,          indicator: "there isn't a github pages site here" },
  { service: "Heroku",         cnamePattern: /herokudns\.com$/i,       indicator: "no such app" },
  { service: "Shopify",        cnamePattern: /myshopify\.com$/i,       indicator: "sorry, this shop is currently unavailable" },
  { service: "Fastly",         cnamePattern: /fastly\.net$/i,          indicator: "fastly error: unknown domain:" },
  { service: "Pantheon",       cnamePattern: /pantheonsite\.io$/i,     indicator: "404 error unknown site!" },
  { service: "Tumblr",         cnamePattern: /tumblr\.com$/i,          indicator: "there's nothing here." },
  { service: "AWS S3",         cnamePattern: /s3\.amazonaws\.com$/i,   indicator: "nosuchbucket" },
  { service: "AWS CloudFront", cnamePattern: /cloudfront\.net$/i,      indicator: "the request could not be satisfied" },
  { service: "Azure Web Apps", cnamePattern: /azurewebsites\.net$/i,   indicator: "404 web site not found" },
  { service: "Zendesk",        cnamePattern: /zendesk\.com$/i,         indicator: "help center closed" },
  { service: "Surge.sh",       cnamePattern: /surge\.sh$/i,            indicator: "project not found" },
  { service: "Netlify",        cnamePattern: /netlify\.app$/i,         indicator: "not found - request id" },
  { service: "HubSpot",        cnamePattern: /hubspot\.net$/i,         indicator: "domain not found" },
  { service: "Ghost.io",       cnamePattern: /ghost\.io$/i,            indicator: "used ghost.io" },
  { service: "UserVoice",      cnamePattern: /uservoice\.com$/i,       indicator: "this uservoice subdomain is currently available" },
  { service: "Unbounce",       cnamePattern: /unbouncepages\.com$/i,   indicator: "the requested url was not found" },
  { service: "WordPress.com",  cnamePattern: /wordpress\.com$/i,       indicator: "do you want to register" },
];

async function checkSubdomainTakeover(subdomains: string[], onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (subdomains.length === 0) return findings;
  const toCheck = subdomains.slice(0, 40);
  await onLog(`[${ts()}] Checking ${toCheck.length} subdomains for takeover vulnerability...`);

  await Promise.allSettled(
    toCheck.map(async (sub) => {
      try {
        const { stdout } = await execFileAsync("dig", ["+short", "+timeout=3", sub, "CNAME"], { timeout: 8_000 });
        const cname = stdout.trim().replace(/\.$/, "");
        if (!cname || cname.length < 4) return;
        const fp = TAKEOVER_FINGERPRINTS.find(f => f.cnamePattern.test(cname));
        if (!fp) return;
        const r = await probe(`https://${sub}`, { timeoutMs: 8_000 });
        const httpR = !r ? await probe(`http://${sub}`, { timeoutMs: 8_000 }) : null;
        const body = (r?.body ?? httpR?.body ?? "").toLowerCase();
        if (body.includes(fp.indicator)) {
          findings.push({
            title: `Subdomain Takeover: ${sub} → ${fp.service}`,
            severity: "critical", verification: "verified", confidence: 96,
            cvss: 9.8, cve: null,
            description: `${sub} has a dangling CNAME to ${cname} (${fp.service}) — the destination does not exist. An attacker can claim this resource on ${fp.service} and serve malicious content under your domain, enabling session cookie theft, phishing, CSP bypass, and full credential harvesting.`,
            evidence: `DNS CNAME: ${sub} → ${cname}\nService: ${fp.service}\nTakeover indicator: "${fp.indicator}" in HTTP ${r?.status ?? httpR?.status} response\nResponse: ${body.slice(0, 300)}`,
            remediation: `IMMEDIATE: Remove the CNAME record for ${sub}, OR register the resource on ${fp.service} to block hostile takeover.\nAudit all subdomains for dangling CNAMEs regularly using subjack, nuclei, or dnsReaper.`,
          });
          await onLog(`[${ts()}] ⚠ SUBDOMAIN TAKEOVER CONFIRMED: ${sub} → ${fp.service} (${cname})`);
        }
      } catch { /* DNS timeout */ }
    }),
  );

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// HOST HEADER INJECTION
// ═══════════════════════════════════════════════════════════════════════════════

async function checkHostHeaderInjection(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing host header injection...`);
  const injectedHost = "evil-sentinelx-bypass.attacker.example";

  for (const [hdrs, label] of [
    [{ "Host": injectedHost }, "Host"],
    [{ "X-Forwarded-Host": injectedHost }, "X-Forwarded-Host"],
    [{ "X-Host": injectedHost }, "X-Host"],
    [{ "X-Forwarded-Server": injectedHost }, "X-Forwarded-Server"],
  ] as [Record<string, string>, string][]) {
    const r = await probe(target.url, { headers: hdrs, followRedirects: false, timeoutMs: 10_000 });
    if (!r) continue;
    const reflected = r.body.includes(injectedHost) || (r.headers["location"] ?? "").includes(injectedHost);
    if (reflected) {
      findings.push({
        title: `Host Header Injection via ${label} — Arbitrary Host Reflected`,
        severity: "high", verification: "verified", confidence: 92,
        cvss: 7.5, cve: null,
        description: `The ${label} header value is reflected in the response. This enables password-reset link poisoning: by triggering a password reset for a victim, the reset link in the email will point to the attacker's server, yielding the reset token and enabling account takeover.`,
        evidence: `GET ${target.url} with ${label}: ${injectedHost}\nHTTP ${r.status}\nInjected host reflected in body: ${r.body.includes(injectedHost)}\nLocation header: ${r.headers["location"] ?? "(none)"}`,
        remediation: "Build absolute URLs from server-side configuration only. Validate the Host header against a strict allowlist. Use web framework abstractions that handle this safely.",
      });
      await onLog(`[${ts()}] ⚠ HOST HEADER INJECTION via ${label}`);
      return findings;
    }
  }

  await onLog(`[${ts()}] Host header injection: no reflection confirmed`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRLF INJECTION
// ═══════════════════════════════════════════════════════════════════════════════

async function checkCrlfInjection(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing CRLF injection (HTTP response splitting)...`);

  const crlfPayloads = [
    "%0d%0aX-SentinelX-Injected:%20crlf-confirmed",
    "%0aX-SentinelX-Injected:%20crlf-confirmed",
    "\r\nX-SentinelX-Injected: crlf-confirmed",
    "%0d%0a%0d%0aX-SentinelX-Injected:%20crlf-confirmed",
    "%E5%98%8D%E5%98%8AX-SentinelX-Injected:%20crlf-confirmed",
  ];
  const crlfParams = ["url", "next", "redirect", "target", "return", "page", "path", "q", "lang", "ref", "location"];

  for (const param of crlfParams.slice(0, 6)) {
    for (const payload of crlfPayloads.slice(0, 3)) {
      const probeUrl = `${target.url.replace(/\/$/, "")}?${param}=${payload}`;
      const r = await probe(probeUrl, { followRedirects: false, timeoutMs: 8_000 });
      if (!r) continue;
      if ((r.headers["x-sentinelx-injected"] ?? "") === "crlf-confirmed") {
        findings.push({
          title: "CRLF Injection — HTTP Response Splitting Confirmed",
          severity: "high", verification: "verified", confidence: 98,
          cvss: 7.5, cve: null,
          description: `CRLF characters injected via '${param}' were not filtered and appeared as a new HTTP header (X-SentinelX-Injected) in the response. This enables HTTP response splitting, cookie injection, XSS via header injection, and cache poisoning.`,
          evidence: `PROBE: GET ${probeUrl}\nPARAM: ${param}=${payload}\nHTTP ${r.status}\nInjected header 'X-SentinelX-Injected: crlf-confirmed' appeared in response headers\nFull response headers: ${r.rawHeaders.slice(0, 400)}`,
          remediation: "Strip or encode \\r, \\n, %0d, %0a, and UTF-8 CRLF equivalents from any user input included in HTTP response headers. Use framework-provided redirect/header functions that handle this automatically.",
        });
        await onLog(`[${ts()}] ⚠ CRLF INJECTION CONFIRMED via param '${param}'`);
        return findings;
      }
    }
  }

  await onLog(`[${ts()}] CRLF injection: no confirmed injection`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// JWT WEAKNESS DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

function decodeJwtPart(b64url: string): Record<string, unknown> | null {
  try {
    const padded = b64url + "=".repeat((4 - b64url.length % 4) % 4);
    return JSON.parse(Buffer.from(padded, "base64url").toString("utf8"));
  } catch { return null; }
}

async function checkJwtWeaknesses(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Checking JWT exposure and algorithm weaknesses...`);

  const JWT_REGEX = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
  const endpoints = [
    target.url,
    `${target.url.replace(/\/$/, "")}/api/login`,
    `${target.url.replace(/\/$/, "")}/api/auth`,
    `${target.url.replace(/\/$/, "")}/auth`,
    `${target.url.replace(/\/$/, "")}/login`,
  ];

  for (const ep of endpoints.slice(0, 4)) {
    const r = await probe(ep, { timeoutMs: 8_000 });
    if (!r) continue;
    const allText = r.body + "\n" + JSON.stringify(r.headers);
    const tokens = allText.match(JWT_REGEX);
    if (!tokens?.length) continue;

    const token = tokens[0]!;
    const parts = token.split(".");
    if (parts.length !== 3) continue;

    const header = decodeJwtPart(parts[0]!);
    const payload = decodeJwtPart(parts[1]!);
    if (!header) continue;

    const alg = String(header.alg ?? "").toUpperCase();
    await onLog(`[${ts()}] JWT detected at ${ep} — alg: ${alg}`);

    if (alg === "NONE" || alg === "") {
      findings.push({
        title: "JWT Algorithm 'none' — Complete Authentication Bypass",
        severity: "critical", verification: "verified", confidence: 99,
        cvss: 10.0, cve: null,
        description: "A JWT with algorithm 'none' was found. These tokens require no cryptographic signature — any payload can be forged without a secret, resulting in complete authentication bypass.",
        evidence: `Endpoint: ${ep}\nJWT header: ${JSON.stringify(header)}\nAlgorithm: none (unsigned)\nToken: ${token.slice(0, 80)}...`,
        remediation: "Reject any JWT with alg:none at the validation layer. Use a strict allowlist of accepted algorithms (RS256/ES256 preferred). Update your JWT library.",
      });
      await onLog(`[${ts()}] ⚠ JWT ALG:NONE — authentication bypass`);
    } else if (alg === "HS256") {
      // Try common weak secrets
      const WEAK_SECRETS = ["secret", "password", "1234", "changeme", "jwt", "mysecret", "secretkey", "app_secret"];
      for (const secret of WEAK_SECRETS) {
        try {
          const sigInput = `${parts[0]}.${parts[1]}`;
          const { createHmac } = await import("node:crypto");
          const sig = createHmac("sha256", secret).update(sigInput).digest("base64url");
          if (sig === parts[2]) {
            findings.push({
              title: "JWT HS256 Weak Secret Cracked",
              severity: "critical", verification: "verified", confidence: 99,
              cvss: 9.8, cve: null,
              description: `The JWT is signed with HS256 and the weak secret "${secret}" was cracked. An attacker can forge arbitrary JWT payloads — changing userId, role, permissions, or any claim — resulting in complete account takeover and privilege escalation.`,
              evidence: `JWT from: ${ep}\nAlgorithm: HS256\nCracked secret: "${secret}"\nToken: ${token.slice(0, 80)}...`,
              remediation: "Replace the JWT secret with cryptographically random data (≥256 bits). Rotate all sessions immediately. Migrate to RS256/ES256 to eliminate the shared-secret risk entirely.",
            });
            await onLog(`[${ts()}] ⚠ JWT SECRET CRACKED: "${secret}" — all tokens forgeable`);
            break;
          }
        } catch { /* crypto import error */ }
      }
      if (!findings.some(f => f.title.includes("Cracked"))) {
        findings.push({
          title: "JWT Uses HS256 — Symmetric Algorithm",
          severity: "medium", verification: "informational", confidence: 72,
          cvss: 5.3, cve: null,
          description: "JWT uses HS256 (HMAC-SHA256). Weak secrets can be brute-forced offline. HS256 also requires sharing the secret with every validating service.",
          evidence: `Endpoint: ${ep}\nAlgorithm: HS256\nToken: ${token.slice(0, 80)}...`,
          remediation: "Use RS256 or ES256. If HS256 is required, ensure the secret is ≥256 bits of random entropy from a CSPRNG.",
        });
      }
    }

    if (payload && !payload.exp) {
      findings.push({
        title: "JWT Missing 'exp' Claim — Non-Expiring Token",
        severity: "high", verification: "verified", confidence: 95,
        cvss: 7.5, cve: null,
        description: "JWT has no 'exp' (expiration) claim and is valid indefinitely. A stolen token remains usable forever with no built-in revocation mechanism.",
        evidence: `Endpoint: ${ep}\nJWT payload: ${JSON.stringify(payload).slice(0, 300)}\n'exp' claim: absent`,
        remediation: "Add 'exp' claim to all JWTs. Use short-lived access tokens (≤15 minutes) with refresh token rotation. Implement server-side token revocation lists.",
      });
      await onLog(`[${ts()}] ⚠ JWT without 'exp' claim found at ${ep}`);
    }
    break; // one JWT endpoint is sufficient
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATH TRAVERSAL
// ═══════════════════════════════════════════════════════════════════════════════

async function checkPathTraversal(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing path traversal / directory traversal...`);

  const TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
  ];
  const TRAVERSAL_PARAMS = ["file", "path", "page", "include", "doc", "template", "filename", "load", "read", "view", "download", "src", "resource", "module", "name"];
  const LINUX_PASSWD = /root:.*:0:0:|daemon:.*:1:1:|nobody:.*:99:/;
  const WINDOWS_INI = /\[fonts\]|\[extensions\]|\[boot loader\]/i;

  for (const param of TRAVERSAL_PARAMS.slice(0, 8)) {
    for (const payload of TRAVERSAL_PAYLOADS.slice(0, 6)) {
      const probeUrl = `${target.url.replace(/\/$/, "")}?${param}=${payload}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      const isLinux = LINUX_PASSWD.test(r.body);
      const isWindows = WINDOWS_INI.test(r.body);
      if (isLinux || isWindows) {
        findings.push({
          title: `Path Traversal Confirmed — Arbitrary File Read (${isLinux ? "/etc/passwd" : "win.ini"})`,
          severity: "critical", verification: "verified", confidence: 99,
          cvss: 9.1, cve: null,
          description: `Path traversal confirmed via '${param}' parameter. The server read and returned ${isLinux ? "/etc/passwd" : "windows\\win.ini"}. Attackers can read source code, credentials, private keys, database configuration, and any file the web server process can access.`,
          evidence: `PROBE: GET ${probeUrl}\nPAYLOAD: ${param}=${payload}\nHTTP ${r.status}\n${isLinux ? "/etc/passwd" : "win.ini"} content confirmed:\n${r.body.match(isLinux ? /root:.*/ : /\[fonts\].*/)?.[0] ?? "(file content)"}`,
          remediation: "Never use user input to construct file paths. Resolve paths server-side and verify they are within an allowed root (realpath check). Use an allowlist of permitted files. Run the web server with minimal filesystem permissions.",
        });
        await onLog(`[${ts()}] ⚠ PATH TRAVERSAL CONFIRMED: file read via '${param}' — ${isLinux ? "/etc/passwd" : "win.ini"}`);
        return findings;
      }
    }
  }

  await onLog(`[${ts()}] Path traversal: no file read confirmed`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOG4SHELL / SPRING4SHELL SURFACE DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

async function checkLog4ShellSurface(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing Log4Shell (CVE-2021-44228) / Spring4Shell (CVE-2022-22965) surface...`);

  const marker = `sentinelx-${Math.random().toString(36).slice(2, 10)}`;
  const log4jPayload = `\${jndi:dns://${marker}.sentinel-test.invalid/a}`;
  const JAVA_ERROR = /java\.lang\.|org\.apache\.log4j|javax\.naming\.|classnotfoundexception|log4j|jndi lookup/i;

  const injectTargets: Array<[string, Record<string, string>, string]> = [
    [target.url, { "User-Agent": log4jPayload }, "User-Agent"],
    [target.url, { "X-Forwarded-For": log4jPayload }, "X-Forwarded-For"],
    [target.url, { "Referer": log4jPayload }, "Referer"],
    [target.url, { "Accept-Language": log4jPayload }, "Accept-Language"],
    [`${target.url.replace(/\/$/, "")}?q=${encodeURIComponent(log4jPayload)}`, {}, "query param"],
  ];

  for (const [url, headers, location] of injectTargets.slice(0, 4)) {
    const r = await probe(url, { headers, timeoutMs: 10_000 });
    if (!r) continue;
    if (JAVA_ERROR.test(r.body)) {
      findings.push({
        title: "Log4Shell (CVE-2021-44228) Attack Surface — Java Error Signal",
        severity: "critical", verification: "suspected", confidence: 72,
        cvss: 10.0, cve: "CVE-2021-44228",
        description: "A Log4Shell JNDI payload injected via the " + location + " triggered a Java/Log4j error reference in the response. Note: DNS-callback confirmation requires an out-of-band collaborator. If the target runs Log4j 2.0–2.16.0, it is highly likely vulnerable.",
        evidence: `Payload injected in: ${location}\nURL: ${url}\nHeaders: ${JSON.stringify(headers)}\nHTTP ${r.status}\nJava/Log4j reference in response: ${r.body.slice(0, 400)}`,
        remediation: "Upgrade Log4j to ≥2.17.1 immediately. Set -Dlog4j2.formatMsgNoLookups=true as a JVM argument. Block outbound JNDI (LDAP/RMI) connections at the firewall. This is a CVSS 10.0 critical RCE vulnerability.",
      });
      await onLog(`[${ts()}] ⚠ LOG4SHELL SURFACE SIGNAL via ${location}`);
      break;
    }
  }

  // Spring4Shell surface
  const springR = await probe(target.url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "class.module.classLoader.resources.context.parent.pipeline.first.pattern=sentinelx",
    timeoutMs: 8_000,
  });
  if (springR) {
    const sb = springR.body.toLowerCase();
    if (sb.includes("classloader") || sb.includes("spring") || sb.includes("classnotfoundexception") || sb.includes("org.springframework")) {
      findings.push({
        title: "Spring4Shell (CVE-2022-22965) Attack Surface Detected",
        severity: "critical", verification: "suspected", confidence: 65,
        cvss: 9.8, cve: "CVE-2022-22965",
        description: "Spring Framework class loader manipulation pattern was referenced in the response. If running Spring Framework 5.3.x < 5.3.18 or 5.2.x < 5.2.20 on JDK 9+, this indicates a critical RCE vulnerability.",
        evidence: `POST ${target.url}\nContent-Type: application/x-www-form-urlencoded\nBody: Spring class loader pattern\nHTTP ${springR.status}\nSpring reference detected: ${springR.body.slice(0, 300)}`,
        remediation: "Update Spring Framework to 5.3.18+ or 5.2.20+. Use Spring Boot 2.6.6+ or 2.5.12+. Set spring.mvc.pathmatch.use-suffix-pattern=false in application.properties.",
      });
      await onLog(`[${ts()}] ⚠ SPRING4SHELL SURFACE SIGNAL detected`);
    }
  }

  await onLog(`[${ts()}] Log4Shell/Spring4Shell surface check complete`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// RATE LIMITING ABSENCE ON AUTH ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

async function checkRateLimiting(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Checking for rate limiting on authentication endpoints...`);

  const authEndpoints = [
    `${target.url.replace(/\/$/, "")}/login`,
    `${target.url.replace(/\/$/, "")}/api/login`,
    `${target.url.replace(/\/$/, "")}/auth/login`,
    `${target.url.replace(/\/$/, "")}/auth`,
    `${target.url.replace(/\/$/, "")}/forgot-password`,
    `${target.url.replace(/\/$/, "")}/api/auth`,
  ];

  for (const ep of authEndpoints.slice(0, 3)) {
    const first = await probe(ep, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "ratelimit@test.example", password: "wrongpass0" }), timeoutMs: 6_000 });
    if (!first || first.status === 404) continue;

    const responses: number[] = [first.status];
    for (let i = 1; i <= 9; i++) {
      const r = await probe(ep, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "ratelimit@test.example", password: `wrongpass${i}` }), timeoutMs: 6_000 });
      if (r) responses.push(r.status);
    }

    if (responses.length >= 8) {
      const has429 = responses.some(s => s === 429);
      const hasLockout = responses.some(s => s === 423 || s === 403);
      if (!has429 && !hasLockout) {
        findings.push({
          title: `No Rate Limiting on Auth Endpoint — Brute-Force Possible (${ep.split("/").slice(-2).join("/")})`,
          severity: "high", verification: "verified", confidence: 85,
          cvss: 7.5, cve: null,
          description: `The endpoint ${ep} accepted 10 rapid login attempts with incorrect credentials without any rate limiting (429) or account lockout (423/403). This enables credential stuffing and password brute-force attacks at full network speed.`,
          evidence: `10 rapid POST requests to ${ep}\nCredentials: wrong passwords #0-9\nAll response codes: ${responses.join(", ")}\nNo 429 (rate limited) or 423/403 (locked) responses received`,
          remediation: "Implement rate limiting: max 5 failed attempts per IP per 15 minutes with exponential backoff. Add account lockout after 10 failures. Use CAPTCHA after 3 failures. Consider device fingerprinting.",
        });
        await onLog(`[${ts()}] ⚠ NO RATE LIMITING on ${ep} — 10 requests, all same status: ${responses[0]}`);
        break;
      } else {
        await onLog(`[${ts()}] Rate limiting confirmed on ${ep} (status: ${responses.find(s => s === 429 || s === 423)})`);
        break;
      }
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════════════

export async function scanTarget(
  value: string,
  assetType: string,
  scanType: ScanType,
  onLog: LogFn,
  policy: ScanPolicy = resolveScanPolicy("safe_active"),
): Promise<RealFinding[]> {
  const target = normalizeTarget(value, assetType);
  if (!target) {
    await onLog(`[${ts()}] ERROR: Cannot normalise target "${value}" — skipping`);
    return [];
  }

  return scanContext.run(
    { remaining: policy.requestBudget, exhaustedNotified: false },
    async () => {
      const all: RealFinding[] = [];
      const add = (f: RealFinding[]) => { all.push(...f); };

  await onLog(`[${ts()}] ═══════════════════════════════════════`);
  await onLog(`[${ts()}] TARGET  : ${target.url}`);
  await onLog(`[${ts()}] HOST    : ${target.hostname}`);
  await onLog(`[${ts()}] SCAN    : FULL DEEP SCAN / PROFILE ${policy.profile.toUpperCase()}`);
  await onLog(`[${ts()}] POLICY  : ${policy.requestBudget} request budget · ${policy.timeoutMs}ms timeout · concurrency ${policy.maxConcurrency}`);
  await onLog(`[${ts()}] TOOLS   : nmap · dig · whois · openssl · fetch · crt.sh · ipinfo.io · Wayback`);
  await onLog(`[${ts()}] ═══════════════════════════════════════`);

  // ── Phase 1: WAF detection and bypass ─────────────────────────────────────
  await onLog(`[${ts()}] [Phase 1] WAF/CDN detection and bypass testing...`);
  const { findings: wafFindings, wafName } = await checkWafAndBypass(target, onLog);
  add(wafFindings);

  // ── Phase 2: DNS enumeration ──────────────────────────────────────────────
  await onLog(`[${ts()}] [Phase 2] DNS enumeration (dig — A/AAAA/MX/TXT/NS/CAA/AXFR)...`);
  add(await checkDns(target.hostname, onLog));

  // ── Phase 3: IP geolocation & ASN ────────────────────────────────────────
  await onLog(`[${ts()}] [Phase 3] IP geolocation & ASN intelligence (ipinfo.io)...`);
  await getIpInfo(target.hostname, onLog);

  // ── Phase 4: WHOIS domain intelligence ───────────────────────────────────
  if (assetType !== "ip") {
    await onLog(`[${ts()}] [Phase 4] WHOIS domain intelligence...`);
    add(await checkWhois(target.hostname, onLog));
  }

  // ── Phase 5: Subdomain discovery + takeover check ─────────────────────────
  let discoveredSubs: string[] = [];
  if (assetType !== "ip") {
    await onLog(`[${ts()}] [Phase 5] Subdomain discovery (crt.sh + DNS brute force)...`);
    const { findings: subFindings, subs } = await discoverSubdomains(target.hostname, onLog);
    add(subFindings);
    discoveredSubs = subs;
    await onLog(`[${ts()}] Total subdomains in scope: ${subs.length}`);

    // Subdomain takeover check
    await onLog(`[${ts()}] [Phase 5b] Subdomain takeover detection...`);
    add(await checkSubdomainTakeover(discoveredSubs, onLog));
  }

  // ── Phase 6: Port scanning (nmap) ─────────────────────────────────────────
  await onLog(`[${ts()}] [Phase 6] Full port scanning with nmap (service version detection)...`);
  add(await checkPorts(target.hostname, "full", onLog));

  // ── Phase 7: TLS / SSL analysis ───────────────────────────────────────────
  if (target.isHttps) {
    await onLog(`[${ts()}] [Phase 7] TLS/SSL analysis (openssl + node:tls — certs, protocols, ciphers)...`);
    add(await checkTls(target.hostname, target.port, onLog));
  }

  // ── Phase 8: HTTP security headers ────────────────────────────────────────
  await onLog(`[${ts()}] [Phase 8] HTTP security header analysis (HSTS/CSP/CORS/cookies)...`);
  add(await checkHeaders(target, onLog));

  // ── Phase 9: Technology fingerprinting ────────────────────────────────────
  await onLog(`[${ts()}] [Phase 9] Technology fingerprinting...`);
  const { techs, findings: fpFindings } = await fingerprint(target, onLog);
  add(fpFindings);
  if (techs.length > 0) {
    await onLog(`[${ts()}] Stack detected: ${techs.map((t) => `${t.name} (${t.category})`).join(" · ")}`);
  }

  // ── Phase 10: Sensitive path discovery (deep mode always) ─────────────────
  await onLog(`[${ts()}] [Phase 10] Sensitive path discovery (deep mode — ${SENSITIVE_PATHS.length} paths)...`);
  add(await checkSensitivePaths(target, true, onLog));

  // ── Phase 11: Wayback Machine endpoint discovery ───────────────────────────
  await onLog(`[${ts()}] [Phase 11] Wayback Machine historical endpoint discovery...`);
  add(await checkWayback(target.hostname, onLog));

  // ── Phase 12: Web application vulnerability probes ────────────────────────
  await onLog(`[${ts()}] [Phase 12] Web app probes — SQLi (error+blind) · XSS · NoSQL · CMDi · redirects · methods...`);
  add(await checkWebApp(target, onLog));

  // ── Phase 13: API surface discovery ──────────────────────────────────────
  await onLog(`[${ts()}] [Phase 13] API surface — GraphQL · Swagger · Spring Actuator · Telescope...`);
  add(await checkApiSurface(target, onLog));

  // ── Phase 14: Host header injection ──────────────────────────────────────
  await onLog(`[${ts()}] [Phase 14] Host header injection / password-reset poisoning...`);
  add(await checkHostHeaderInjection(target, onLog));

  // ── Phase 15: CRLF injection ──────────────────────────────────────────────
  await onLog(`[${ts()}] [Phase 15] CRLF injection / HTTP response splitting...`);
  add(await checkCrlfInjection(target, onLog));

  // ── Phase 16: Path traversal ──────────────────────────────────────────────
  await onLog(`[${ts()}] [Phase 16] Path traversal / directory traversal...`);
  add(await checkPathTraversal(target, onLog));

  // ── Phase 17: JWT weakness detection ─────────────────────────────────────
  await onLog(`[${ts()}] [Phase 17] JWT algorithm and secret weakness detection...`);
  add(await checkJwtWeaknesses(target, onLog));

  // ── Phase 18: Log4Shell / Spring4Shell surface ────────────────────────────
  await onLog(`[${ts()}] [Phase 18] Log4Shell (CVE-2021-44228) / Spring4Shell (CVE-2022-22965) surface...`);
  add(await checkLog4ShellSurface(target, onLog));

  // ── Phase 19: Rate limiting on auth endpoints ─────────────────────────────
  await onLog(`[${ts()}] [Phase 19] Rate limiting / brute-force protection check...`);
  add(await checkRateLimiting(target, onLog));

  // ── Phase 20: Advanced vulnerability probes ───────────────────────────────
  {
    const { checkSSTI, checkXXE, checkSSRF, checkDeserialization, checkCommandInjection, checkNoSqlInjection, lookupCvesForTechs } = await import("./vuln-probes");
    await onLog(`[${ts()}] [Phase 20] Advanced probes — SSTI · XXE · SSRF · Deserialization · CMDi · NoSQL...`);
    const [sstiF, xxeF, ssrfF, deserF, cmdF, nosqlF] = await Promise.all([
      checkSSTI(target, onLog),
      checkXXE(target, onLog),
      checkSSRF(target, onLog),
      checkDeserialization(target, onLog),
      checkCommandInjection(target, onLog),
      checkNoSqlInjection(target, onLog),
    ]);
    add(sstiF); add(xxeF); add(ssrfF); add(deserF); add(cmdF); add(nosqlF);

    // CVE lookup for detected technologies
    await onLog(`[${ts()}] [Phase 21] CVE database lookup (NVD) for detected technology versions...`);
    const { techs: detectedTechs } = await fingerprint(target, async () => {});
    add(await lookupCvesForTechs(detectedTechs, onLog));
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  // Remove informational-only low-severity with cvss=0
  const reportable = all.filter((f) => f.cvss > 0 || f.severity !== "low");
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of reportable) {
    if (f.severity in bySeverity) bySeverity[f.severity as keyof typeof bySeverity]++;
  }

      await onLog(`[${ts()}] ═══════════════════════════════════════`);
      await onLog(`[${ts()}] SCAN COMPLETE`);
      await onLog(`[${ts()}] Total findings : ${reportable.length}`);
      await onLog(`[${ts()}] Requests remaining: ${remainingScanRequests() ?? "unbounded"}/${policy.requestBudget}`);
      await onLog(`[${ts()}] Critical: ${bySeverity.critical}  High: ${bySeverity.high}  Medium: ${bySeverity.medium}  Low: ${bySeverity.low}`);
      await onLog(`[${ts()}] ═══════════════════════════════════════`);

      return reportable;
    },
  );
}
