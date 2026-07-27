import type { PhaseContext } from '../types';
import { createFinding } from '../utils/findings';
import { probe } from '../utils/http';

const CONFIG_PATHS = [
  '/.env',
  '/.env.local',
  '/.env.production',
  '/config.json',
  '/config.js',
  '/settings.json',
  '/.git/config',
  '/server-status',
  '/debug',
];

const ENV_CONTENT =
  /(?:^|\n)\s*(?:database_url|aws_access_key_id|aws_secret_access_key|secret_key|jwt_secret|session_secret|private_key)\s*=/i;
const GIT_CONFIG_CONTENT = /^\s*\[(?:core|remote|branch)\]/im;
const DEBUG_CONTENT = /(?:stack trace|traceback|debug toolbar|environment variables|exception in)/i;

/**
 * Passive-by-default configuration exposure checks. Evidence is intentionally
 * truncated and redacted so a finding never becomes a second secret store.
 */
export async function runConfigExposurePhase(context: PhaseContext): Promise<void> {
  await context.log(
    '[SentinelX] Configuration exposure checks — environment, VCS, and debug surfaces...',
  );
  const base = context.target.url.replace(/\/$/, '');

  for (const path of CONFIG_PATHS) {
    const url = `${base}${path}`;
    const response = await probe(url, { timeoutMs: 7_000 });
    if (!response || response.status !== 200) continue;

    const body = response.body;
    const isEnv = path.startsWith('/.env') && ENV_CONTENT.test(body);
    const isGit = path === '/.git/config' && GIT_CONFIG_CONTENT.test(body);
    const isDebug = DEBUG_CONTENT.test(body);
    if (!isEnv && !isGit && !isDebug) continue;

    const severity = isEnv ? 'critical' : isDebug ? 'high' : 'medium';
    const title = isEnv
      ? 'Critical Configuration Leak — Environment Secrets Exposed'
      : isGit
        ? 'Git Repository Metadata Publicly Exposed'
        : 'Production Debug Information Exposed';

    context.addFindings([
      createFinding({
        title,
        severity,
        verified: true,
        verification: 'verified',
        confidence: 97,
        evidenceQuality: 'strong',
        verificationMethod: 'HTTP 200 response matched a configuration or debug-content marker.',
        reproducibility: 'reproducible',
        affectedEndpoint: url,
        cvss: isEnv ? 9.8 : isDebug ? 7.5 : 5.3,
        cve: null,
        description: `A publicly reachable ${path} response matched a high-confidence ${isEnv ? 'secret configuration' : isGit ? 'version-control' : 'debug'} marker.`,
        evidence: `GET ${url} → HTTP ${response.status}\nContent-Type: ${response.headers['content-type'] ?? 'unknown'}\nRedacted preview: ${redact(body)}`,
        remediation: isEnv
          ? 'Remove environment files from the web root, rotate every exposed secret, and deny dotfiles at the edge and origin.'
          : isGit
            ? 'Remove the .git directory from the deployed artifact and block VCS metadata at the web server.'
            : 'Disable production debug output and return generic error pages without stack traces or environment details.',
        compliance: { owasp: ['A02', 'A05'], pci: ['6.4.2'], nist: ['CM-7', 'SI-11'] },
      }),
    ]);
    await context.log(`[SentinelX] ${title} at ${path}`);
    return;
  }

  await context.log('[SentinelX] Configuration exposure checks complete — no confirmed exposure');
}

function redact(value: string): string {
  return value
    .replace(/((?:key|secret|token|password|url)\s*[=:]\s*)[^\s"'&]{8,}/gi, '$1[REDACTED]')
    .slice(0, 360)
    .replace(/\s+/g, ' ')
    .trim();
}
