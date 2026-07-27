/**
 * Shared scan context — AsyncLocalStorage, budget tracking, WAF state,
 * and all low-level helpers used by every phase.
 *
 * Nothing in this file imports from scanner.ts; it IS the new root.
 */

import * as tls from 'node:tls';
import * as dns from 'node:dns';
import { AsyncLocalStorage } from 'node:async_hooks';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

export const execFileAsync = promisify(execFile);
export const dnsResolve = dns.promises;

// ─── Context store ──────────────────────────────────────────────────────────

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

export const scanContext = new AsyncLocalStorage<ScanContext>();

// ─── Public types ────────────────────────────────────────────────────────────

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
  // Passive — read-only reconnaissance only, no active probes
  passive: {
    requestBudget: 300,
    verificationRequestBudget: 0,
    timeoutMs: 12_000,
    maxConcurrency: 6,
    allowDeepChecks: false,
    allowExternalCallbacks: true,
    allowToolAdapters: true,
    allowVerification: false,
  },
  // Safe active — active checks with harmless canary payloads
  safe_active: {
    requestBudget: 1_500,
    verificationRequestBudget: 0,
    timeoutMs: 15_000,
    maxConcurrency: 10,
    allowDeepChecks: true,
    allowExternalCallbacks: true,
    allowToolAdapters: true,
    allowVerification: false,
  },
  // Deep authorized — full-depth scan (default for Quick Scan)
  deep_authorized: {
    requestBudget: 20_000,
    verificationRequestBudget: 500,
    timeoutMs: 30_000,
    maxConcurrency: 20,
    allowDeepChecks: true,
    allowExternalCallbacks: true,
    allowToolAdapters: true,
    allowVerification: true,
  },
  // Authenticated — full-depth with session context
  authenticated: {
    requestBudget: 20_000,
    verificationRequestBudget: 500,
    timeoutMs: 30_000,
    maxConcurrency: 20,
    allowDeepChecks: true,
    allowExternalCallbacks: true,
    allowToolAdapters: true,
    allowVerification: true,
  },
  // Lab — unrestricted; use only against isolated lab environments
  lab: {
    requestBudget: 50_000,
    verificationRequestBudget: 2_000,
    timeoutMs: 60_000,
    maxConcurrency: 32,
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

// ─── Tool capabilities ───────────────────────────────────────────────────────

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

// ─── Budget helpers ──────────────────────────────────────────────────────────

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

// ─── Auth & WAF helpers ──────────────────────────────────────────────────────

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

async function recordWafChallenge(): Promise<void> {
  const context = scanContext.getStore();
  if (!context || context.wafChallengeDetected) return;
  context.wafChallengeDetected = true;
  if (!context.wafChallengeLogEmitted) {
    context.wafChallengeLogEmitted = true;
    await context.onWafChallenge?.();
  }
}

export async function runActiveChecks<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  const context = scanContext.getStore();
  if (!context || context.wafChallengeDetected) return fallback;
  context.activeProbeDepth++;
  try {
    return await fn();
  } catch {
    return fallback;
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

// ─── WAF finding helpers ─────────────────────────────────────────────────────

export function downgradeWafChallengeFindings(findings: RealFinding[]): void {
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

export function suppressWafSensitiveFindings(findings: RealFinding[]): void {
  if (!isWafChallengeDetected()) return;
  for (let i = findings.length - 1; i >= 0; i--) {
    if (/\b(?:SSTI|NoSQL)\b/i.test(findings[i]!.title)) findings.splice(i, 1);
  }
}

// ─── Session capture (used by weaponized phases) ─────────────────────────────

export function storeCapturedSession(cookie: string): void {
  const ctx = scanContext.getStore();
  if (ctx && !ctx.capturedSession) ctx.capturedSession = cookie;
}

export function getCapturedSession(): string | undefined {
  return scanContext.getStore()?.capturedSession;
}

// ─── Core utilities ──────────────────────────────────────────────────────────

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

export const ts = () => new Date().toISOString();

export async function digQuery(hostname: string, type: string): Promise<string[]> {
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

// ─── tls export (needed by TLS phase and HTTP smuggling) ─────────────────────
export { tls };
