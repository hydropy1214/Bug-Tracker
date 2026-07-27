import type { PhaseContext } from '../types';
import { isContextualReflection } from '../context';
import { createFinding } from '../utils/findings';
import { probe } from '../utils/http';

const PARAMETERS = [
  'q',
  'search',
  'query',
  'name',
  'message',
  'title',
  'value',
  'input',
  'error',
  'return',
];

/**
 * Reflected XSS phase kept separate from the broader web-app probe family.
 * It requires the executable marker to survive in an HTML response, which
 * avoids reporting plain text echoes as exploitable script injection.
 */
export async function runXssPhase(context: PhaseContext): Promise<void> {
  await context.log(
    '[SentinelX] XSS checks — contextual HTML reflection with executable marker...',
  );
  const token = `sx${Date.now().toString(36).slice(-7)}`;
  const payload = `<svg/onload=sentinelx_${token}>`;
  const base = context.target.url.replace(/\/$/, '');

  for (const parameter of PARAMETERS) {
    const url = `${base}?${parameter}=${encodeURIComponent(payload)}`;
    const response = await probe(url, { timeoutMs: 8_000 });
    if (!response) continue;

    const html = /text\/html|application\/xhtml/i.test(response.headers['content-type'] ?? '');
    const reflected =
      isContextualReflection(response.body, payload) ||
      response.body.includes(`sentinelx_${token}`);
    const executable = /<svg\b[^>]*onload\s*=\s*sentinelx_[a-z0-9]+/i.test(response.body);
    if (!html || !reflected || !executable) continue;

    context.addFindings([
      createFinding({
        title: 'Reflected XSS — Executable HTML Payload Returned Unescaped',
        severity: 'high',
        verification: 'verified',
        verified: true,
        confidence: 96,
        evidenceQuality: 'strong',
        verificationMethod:
          'Unique SVG event-handler canary survived in an HTML response without output encoding.',
        reproducibility: 'reproducible',
        affectedEndpoint: url,
        affectedParameter: parameter,
        cvss: 8.2,
        cve: null,
        description: `The ${parameter} parameter reflects an executable HTML event-handler payload without contextual encoding.`,
        evidence: `GET ${url}\nContent-Type: ${response.headers['content-type']}\nHTTP ${response.status}\nCanary: sentinelx_${token}`,
        remediation:
          'Contextually encode untrusted output, use a strict Content-Security-Policy, and validate inputs at the server boundary.',
        compliance: { owasp: ['A03'], pci: ['6.2.4'], nist: ['SI-10'] },
      }),
    ]);
    await context.log(`[SentinelX] REFLECTED XSS CONFIRMED via ${parameter}`);
    return;
  }

  await context.log('[SentinelX] XSS checks complete — no executable reflection confirmed');
}
