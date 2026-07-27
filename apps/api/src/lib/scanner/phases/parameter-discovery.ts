/**
 * Phase 13f — Parameter Discovery (reconFTW-style / Arjun-style)
 *
 * Probes discovered endpoints with large sets of common parameter names
 * to detect hidden/undocumented parameters. Uses response length difference
 * to fingerprint parameter existence.
 */

import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

// Common hidden parameter names (Arjun wordlist subset)
const COMMON_PARAMS = [
  // Auth/identity
  'token', 'key', 'api_key', 'apikey', 'secret', 'password', 'pass', 'auth',
  'access_token', 'refresh_token', 'session', 'sid', 'uid', 'user_id', 'userId',
  'username', 'email', 'login', 'account',
  // Navigation/flow
  'redirect', 'redirect_uri', 'return', 'returnUrl', 'return_url', 'next',
  'url', 'callback', 'dest', 'destination', 'continue', 'forward',
  // Debug/admin
  'debug', 'test', 'dev', 'admin', 'trace', 'verbose', 'log', 'mode',
  'preview', 'draft', 'internal', 'bypass', 'override', 'disable',
  // Data access
  'id', 'user', 'file', 'path', 'page', 'lang', 'locale', 'format', 'type',
  'action', 'command', 'cmd', 'exec', 'query', 'search', 'filter', 'sort',
  'order', 'limit', 'offset', 'start', 'end', 'from', 'to',
  // Feature flags
  'feature', 'flag', 'enable', 'disable', 'beta', 'version', 'v',
  // Upload/file
  'upload', 'src', 'source', 'include', 'template', 'view', 'layout',
  // Injection/traversal
  'dir', 'directory', 'folder', 'root', 'base', 'config', 'conf', 'setting',
  'host', 'hostname', 'port', 'server', 'ip', 'address', 'domain',
  // CORS/referrer
  'origin', 'referer', 'referrer', 'cors',
  // Hidden inputs commonly found
  'hidden', 'value', 'data', 'payload', 'body', 'content', 'text', 'msg',
  'message', 'subject', 'title', 'name', 'code', 'ref', 'slug',
  // PCI / finance
  'amount', 'price', 'discount', 'coupon', 'promo', 'plan', 'tier',
];

interface DiscoveredParam {
  endpoint: string;
  param: string;
  method: 'GET' | 'POST';
  baselineLength: number;
  testLength: number;
  delta: number;
}

export async function discoverParameters(
  target: Target,
  endpoints: string[],
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];

  // Limit endpoints to check
  const toCheck = endpoints.slice(0, 8);
  if (toCheck.length === 0) {
    // Fall back to root
    toCheck.push(target.url);
  }

  await onLog(`[${ts()}] Parameter discovery: testing ${COMMON_PARAMS.length} params on ${toCheck.length} endpoint(s)...`);

  const allDiscovered: DiscoveredParam[] = [];

  for (const endpoint of toCheck) {
    // Establish baseline
    const baseline = await probe(endpoint, { timeoutMs: 8_000 });
    if (!baseline) continue;
    const baseLen = baseline.body.length;

    // Test params in batches
    const BATCH = 20;
    for (let i = 0; i < COMMON_PARAMS.length; i += BATCH) {
      const batch = COMMON_PARAMS.slice(i, i + BATCH);
      const results = await Promise.allSettled(
        batch.map(async (param) => {
          // GET probe
          const sep = endpoint.includes('?') ? '&' : '?';
          const testUrl = `${endpoint}${sep}${param}=SentinelXProbe1`;
          const result = await probe(testUrl, { timeoutMs: 6_000 });
          if (!result) return null;

          const testLen = result.body.length;
          const delta = Math.abs(testLen - baseLen);
          // Significant response length change (>50 bytes) indicates param awareness
          if (delta > 50 && testLen !== baseLen) {
            return { endpoint, param, method: 'GET' as const, baselineLength: baseLen, testLength: testLen, delta };
          }
          return null;
        }),
      );

      for (const r of results) {
        if (r.status === 'fulfilled' && r.value) {
          allDiscovered.push(r.value);
        }
      }
    }
  }

  await onLog(`[${ts()}] Parameter discovery: ${allDiscovered.length} candidate parameter(s) found`);

  if (allDiscovered.length === 0) return findings;

  // Group by endpoint
  const byEndpoint = new Map<string, DiscoveredParam[]>();
  for (const d of allDiscovered) {
    const arr = byEndpoint.get(d.endpoint) ?? [];
    arr.push(d);
    byEndpoint.set(d.endpoint, arr);
  }

  // Check for dangerous params (redirect, file, cmd, etc.)
  const dangerousParams = allDiscovered.filter((d) =>
    /redirect|url|return|next|dest|file|path|dir|cmd|exec|command|include|template|host|server/i.test(d.param),
  );

  if (dangerousParams.length > 0) {
    findings.push({
      title: `${dangerousParams.length} Hidden Parameter(s) with Dangerous Names Discovered`,
      severity: 'high',
      cvss: 7.5,
      cve: null,
      verification: 'suspected',
      confidence: 72,
      description:
        `Parameter discovery found ${dangerousParams.length} undocumented parameter(s) with names suggesting ` +
        'potential for open redirect, SSRF, LFI, or command injection (redirect, file, path, cmd, etc.).',
      evidence:
        dangerousParams
          .slice(0, 15)
          .map((d) => `  ${d.method} ${d.endpoint}?${d.param}= (Δ${d.delta} bytes)`)
          .join('\n'),
      remediation:
        'Test these parameters for open redirect, SSRF, LFI, and command injection. ' +
        'Implement an explicit parameter allowlist. Reject or ignore undeclared parameters.',
      affectedEndpoint: dangerousParams[0].endpoint,
      affectedParameter: dangerousParams[0].param,
      compliance: {
        owasp: ['A01:2021 – Broken Access Control', 'A10:2021 – Server-Side Request Forgery'],
      },
    });
  }

  // Auth-related params
  const authParams = allDiscovered.filter((d) =>
    /token|key|secret|auth|password|session|admin|bypass|override|debug|internal/i.test(d.param),
  );
  if (authParams.length > 0) {
    findings.push({
      title: `${authParams.length} Hidden Auth/Debug Parameter(s) Discovered`,
      severity: 'high',
      cvss: 8.1,
      cve: null,
      verification: 'suspected',
      confidence: 70,
      description:
        `Parameter discovery found ${authParams.length} undocumented parameter(s) related to authentication, ` +
        'session management, or debug mode (token, key, secret, admin, debug, bypass, etc.). ' +
        'These may enable authentication bypass, privilege escalation, or debug mode activation.',
      evidence:
        authParams
          .slice(0, 15)
          .map((d) => `  ${d.method} ${d.endpoint}?${d.param}= (Δ${d.delta} bytes)`)
          .join('\n'),
      remediation:
        'Remove debug/admin parameters from production. Ensure authentication is enforced server-side. ' +
        'Audit any parameter that alters authentication state.',
      affectedEndpoint: authParams[0].endpoint,
      affectedParameter: authParams[0].param,
      compliance: {
        owasp: ['A07:2021 – Identification and Authentication Failures'],
      },
    });
  }

  // Summary of all discovered params
  findings.push({
    title: `${allDiscovered.length} Hidden/Undocumented Parameter(s) Discovered`,
    severity: allDiscovered.length > 10 ? 'medium' : 'low',
    cvss: allDiscovered.length > 10 ? 5.3 : 3.7,
    cve: null,
    verification: 'suspected',
    confidence: 68,
    description:
      `Parameter discovery identified ${allDiscovered.length} undocumented parameter(s) that cause measurable ` +
      'response variation. These may be legacy, debug, or unintended parameters that expose hidden functionality.',
    evidence:
      [...byEndpoint.entries()]
        .map(
          ([ep, params]) =>
            `${ep}:\n  ${params.map((p) => `${p.param} (Δ${p.delta}b)`).join(', ')}`,
        )
        .join('\n\n'),
    remediation:
      'Maintain an explicit allowlist of accepted parameters. Remove or disable undocumented parameters. ' +
      'Audit discovered parameters for hidden functionality.',
  });

  return findings;
}
