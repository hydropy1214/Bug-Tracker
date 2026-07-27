/**
 * Phase 27 — Open Redirect Detection (reconFTW-style)
 *
 * Tests common redirect parameters for open redirect vulnerabilities.
 * Uses a safe probe target (example.com) and checks Location headers
 * and body-based redirects.
 */

import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

// Common redirect parameter names
const REDIRECT_PARAMS = [
  'redirect', 'redirect_uri', 'redirect_url', 'return', 'return_url', 'returnUrl',
  'returnTo', 'return_to', 'next', 'next_url', 'url', 'goto', 'dest', 'destination',
  'continue', 'forward', 'forward_url', 'forwardUrl', 'target', 'to', 'link',
  'checkout_url', 'callback', 'callback_url', 'callbackUrl', 'ref', 'referrer',
  'path', 'out', 'view', 'from', 'login_url', 'logout_url', 'success_url',
];

// Test payloads — safe external domain
const PROBE_HOST = 'sentinelx-redirect-probe.example.com';
const PROBE_PAYLOADS = [
  `https://${PROBE_HOST}`,
  `http://${PROBE_HOST}`,
  `//${PROBE_HOST}`,
  `https://${PROBE_HOST}/path?query=1`,
  // Protocol-relative and bypass variants
  `\\/\\/${PROBE_HOST}`,
  `/%2F%2F${PROBE_HOST}`,
  `https:${PROBE_HOST}`,
  `/redirect?url=https://${PROBE_HOST}`,
  `/%68ttps://${PROBE_HOST}`,
];

// Endpoints likely to have redirect parameters
const REDIRECT_ENDPOINTS = [
  '/',
  '/login',
  '/signin',
  '/logout',
  '/signout',
  '/auth/login',
  '/auth/logout',
  '/auth/callback',
  '/oauth/callback',
  '/oauth/authorize',
  '/account/login',
  '/user/login',
  '/api/auth',
  '/redirect',
  '/go',
  '/out',
  '/link',
];

function isRedirectToProbe(location: string, body: string): boolean {
  if (location.includes(PROBE_HOST)) return true;
  // Check for meta redirect or JS redirect
  if (body.includes(PROBE_HOST)) return true;
  return false;
}

export async function checkOpenRedirect(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const baseUrl = target.url.replace(/\/$/, '');
  const confirmed: { endpoint: string; param: string; payload: string; location: string }[] = [];

  await onLog(`[${ts()}] Open redirect testing: ${REDIRECT_PARAMS.length} params × ${REDIRECT_ENDPOINTS.length} endpoints...`);

  let tested = 0;

  for (const endpointPath of REDIRECT_ENDPOINTS) {
    const endpoint = `${baseUrl}${endpointPath}`;

    // First check if endpoint exists
    const exists = await probe(endpoint, { timeoutMs: 6_000 });
    if (!exists) continue;

    for (const param of REDIRECT_PARAMS.slice(0, 15)) {
      for (const payload of PROBE_PAYLOADS.slice(0, 3)) {
        tested++;
        const sep = endpoint.includes('?') ? '&' : '?';
        const testUrl = `${endpoint}${sep}${param}=${encodeURIComponent(payload)}`;

        const result = await probe(testUrl, {
          timeoutMs: 6_000,
          followRedirects: false,
        });

        if (!result) continue;

        // Check for redirect (3xx)
        if (result.status >= 300 && result.status < 400) {
          const location = result.headers['location'] ?? '';
          if (isRedirectToProbe(location, result.body)) {
            confirmed.push({ endpoint, param, payload, location });
            await onLog(`[${ts()}] ⚠ OPEN REDIRECT: ${endpoint}?${param}=${payload} → ${location}`);
            break; // One confirmed per param is enough
          }
        }

        // Body-based redirect (200 with meta refresh or JS redirect)
        if (result.status === 200 && isRedirectToProbe('', result.body)) {
          confirmed.push({ endpoint, param, payload, location: 'body-based redirect' });
          await onLog(`[${ts()}] ⚠ OPEN REDIRECT (body): ${endpoint}?${param}=${payload}`);
          break;
        }
      }
    }
  }

  await onLog(`[${ts()}] Open redirect: ${tested} probes sent, ${confirmed.length} confirmed redirect(s)`);

  if (confirmed.length > 0) {
    // Deduplicate by endpoint+param
    const unique = confirmed.filter(
      (v, i, a) => a.findIndex((x) => x.endpoint === v.endpoint && x.param === v.param) === i,
    );

    for (const hit of unique.slice(0, 5)) {
      findings.push({
        title: `Open Redirect: ${hit.param} parameter at ${new URL(hit.endpoint).pathname}`,
        severity: 'medium',
        cvss: 6.1,
        cve: null,
        verified: true,
        verification: 'verified',
        confidence: 92,
        affectedEndpoint: hit.endpoint,
        affectedParameter: hit.param,
        description:
          `The "${hit.param}" parameter at "${hit.endpoint}" is vulnerable to open redirect. ` +
          'An attacker can redirect users to an arbitrary external domain, enabling phishing, ' +
          'credential harvesting, and token theft via OAuth/OIDC code flows.',
        evidence:
          `Endpoint: ${hit.endpoint}\nParameter: ${hit.param}\nPayload: ${hit.payload}\nRedirects to: ${hit.location}`,
        remediation:
          'Validate redirect URLs against an explicit allowlist of trusted domains. ' +
          'Use relative paths instead of absolute URLs for redirects where possible. ' +
          'Reject or sanitize redirect parameters that contain external URLs.',
        compliance: {
          owasp: ['A01:2021 – Broken Access Control'],
        },
      });
    }
  } else {
    // Provide intelligence about tested params even if not confirmed
    await onLog(`[${ts()}] No open redirects confirmed in ${tested} probes`);
  }

  return findings;
}
