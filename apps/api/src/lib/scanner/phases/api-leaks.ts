import type { PhaseContext } from '../types';
import { createFinding } from '../utils/findings';
import { probe } from '../utils/http';

const API_ENDPOINTS = [
  '/api/.env',
  '/api/config',
  '/api/config.json',
  '/api/debug',
  '/api/health',
  '/api/actuator/env',
  '/api/openapi.json',
  '/openapi.json',
  '/swagger.json',
  '/graphql',
];

const SECRET_MARKERS =
  /(?:api[_-]?key|secret|client[_-]?secret|access[_-]?token|private[_-]?key|authorization)\s*["'=:\s]+[A-Za-z0-9_./+=-]{12,}/i;
const JSON_API_MARKER = /"swagger"\s*:|"openapi"\s*:|"paths"\s*:|"data"\s*:|"errors"\s*:/i;

function redact(value: string): string {
  return value
    .replace(
      /((?:api[_-]?key|secret|token|password|private[_-]?key)\s*["'=:\s]+)[A-Za-z0-9_./+=-]{8,}/gi,
      '$1[REDACTED]',
    )
    .slice(0, 360)
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Looks for API responses that accidentally expose credentials or internal
 * service configuration. The phase only reports a critical leak when a
 * response is successful and contains a secret-shaped marker; normal JSON
 * endpoints are recorded as informational only by the existing API-surface
 * phase.
 */
export async function runApiLeaksPhase(context: PhaseContext): Promise<void> {
  await context.log(
    '[SentinelX] API leak checks — credential-shaped responses and internal configs...',
  );
  const base = context.target.url.replace(/\/$/, '');

  for (const endpoint of API_ENDPOINTS) {
    const url = `${base}${endpoint}`;
    const response = await probe(url, { timeoutMs: 8_000 });
    if (!response || response.status < 200 || response.status >= 300) continue;

    const contentType = response.headers['content-type'] ?? '';
    const body = response.body;
    const looksLikeApiResponse =
      contentType.includes('json') || JSON_API_MARKER.test(body) || endpoint.includes('.env');

    if (looksLikeApiResponse && SECRET_MARKERS.test(body)) {
      context.addFindings([
        createFinding({
          title: 'Critical API Credential Leak — Secret Material Exposed',
          severity: 'critical',
          verified: true,
          verification: 'verified',
          confidence: 98,
          evidenceQuality: 'strong',
          verificationMethod:
            'Successful unauthenticated response contained a secret-name/value marker; values were redacted before storage.',
          reproducibility: 'reproducible',
          affectedEndpoint: url,
          cvss: 9.8,
          cve: null,
          description: `The API endpoint ${endpoint} returned credential-shaped configuration data to an unauthenticated request.`,
          evidence: `GET ${url} → HTTP ${response.status}\nContent-Type: ${contentType || 'unknown'}\nRedacted preview: ${redact(body)}`,
          remediation:
            'Remove secrets from API responses, rotate any exposed credentials, require authentication for configuration endpoints, and enforce a server-side response allowlist.',
          compliance: { owasp: ['A02', 'A05'], pci: ['6.3.3'], nist: ['SC-28', 'SI-12'] },
        }),
      ]);
      await context.log(`[SentinelX] CRITICAL API LEAK CONFIRMED at ${endpoint}`);
      return;
    }
  }

  await context.log(
    '[SentinelX] API leak checks complete — no credential-shaped response confirmed',
  );
}
