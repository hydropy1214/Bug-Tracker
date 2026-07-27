import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

export async function checkRateLimiting(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing rate limiting on sensitive endpoints...`);

  const sensitiveEndpoints = [
    { path: '/login', method: 'POST' },
    { path: '/api/login', method: 'POST' },
    { path: '/auth/login', method: 'POST' },
    { path: '/auth/token', method: 'POST' },
    { path: '/api/auth/login', method: 'POST' },
    { path: '/forgot-password', method: 'POST' },
    { path: '/reset-password', method: 'POST' },
    { path: '/api/v1/auth/login', method: 'POST' },
  ];

  const PROBE_COUNT = 15;
  const RATE_LIMIT_THRESHOLD = 429;

  for (const { path, method } of sensitiveEndpoints) {
    const url = target.url.replace(/\/$/, '') + path;
    const baseline = await probe(url, { method, headers: { 'Content-Type': 'application/json' }, body: '{"username":"test","password":"wrong"}', timeoutMs: 8_000 });
    if (!baseline || (baseline.status !== 200 && baseline.status !== 400 && baseline.status !== 401 && baseline.status !== 403 && baseline.status !== 422)) continue;

    let rateLimited = false;
    let statusCodes: number[] = [];
    for (let i = 0; i < PROBE_COUNT; i++) {
      const r = await probe(url, { method, headers: { 'Content-Type': 'application/json' }, body: `{"username":"brute${i}","password":"brute${i}"}`, timeoutMs: 8_000 });
      if (!r) continue;
      statusCodes.push(r.status);
      if (r.status === RATE_LIMIT_THRESHOLD || r.headers['retry-after'] || r.headers['x-ratelimit-remaining'] === '0') {
        rateLimited = true;
        await onLog(`[${ts()}] Rate limiting detected at ${path} (attempt ${i + 1})`);
        break;
      }
    }
    if (!rateLimited && statusCodes.length >= PROBE_COUNT - 2) {
      const lastStatuses = statusCodes.slice(-5);
      if (lastStatuses.every((s) => s === 200 || s === 400 || s === 401 || s === 422)) {
        findings.push({
          title: `No Rate Limiting on Authentication Endpoint (${path})`,
          severity: 'high',
          cvss: 7.5,
          cve: null,
          description: `The endpoint ${path} did not apply rate limiting after ${PROBE_COUNT} consecutive attempts.`,
          evidence: `Sent ${PROBE_COUNT} POST requests to ${url}\nNo HTTP 429 observed\nStatus codes: ${statusCodes.join(', ')}`,
          remediation: 'Implement rate limiting, account lockout, and CAPTCHA on authentication endpoints.',
        });
        await onLog(`[${ts()}] ⚠ NO RATE LIMITING: ${path}`);
      }
    }
  }

  // Also test if rate-limit headers exist on baseline
  const apiR = await probe(target.url, { timeoutMs: 6_000 });
  if (apiR) {
    const hasRateHeaders = apiR.headers['x-ratelimit-limit'] || apiR.headers['ratelimit-limit'] || apiR.headers['x-rate-limit'];
    if (!hasRateHeaders && findings.length > 0) {
      findings.push({
        title: 'Rate Limit Headers Absent in API Responses',
        severity: 'low',
        cvss: 3.1,
        cve: null,
        description: 'Standard rate-limit informational headers (X-RateLimit-*) are absent.',
        evidence: `GET ${target.url} — no X-RateLimit-Limit / X-RateLimit-Remaining headers`,
        remediation: 'Publish RateLimit headers per IETF draft-ietf-httpapi-ratelimit-headers.',
      });
    }
  }

  return findings;
}
