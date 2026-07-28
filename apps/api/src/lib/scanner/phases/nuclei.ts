/**
 * Nuclei — runs projectdiscovery/nuclei against the target.
 *
 * Template categories: cves, exposures, misconfigurations, default-logins,
 * panels, takeovers, network, cloud, file, token, secret, injection
 *
 * Templates are downloaded/updated on first run via `nuclei -duc`.
 */

import { execFileAsync, ts } from '../context';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { RealFinding, LogFn, Target } from '../context';

// ─── nuclei severity → our severity ─────────────────────────────────────────
const SEV_MAP: Record<string, RealFinding['severity']> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'low',
  unknown: 'low',
};

const BASE_CVSS: Record<string, number> = {
  critical: 9.2,
  high: 7.8,
  medium: 5.5,
  low: 3.1,
  info: 0,
};

// Tags to scan — skip headless/fuzzing/dos for speed
const SCAN_TAGS = [
  'cve', 'exposure', 'exposures', 'misconfig', 'misconfiguration',
  'default-login', 'panel', 'takeover', 'network', 'cloud',
  'token', 'secret', 'injection', 'xss', 'sqli', 'ssrf',
  'lfi', 'rce', 'ssti', 'xxe', 'log4j', 'spring',
].join(',');

const EXCLUDE_TAGS = 'dos,fuzz,fuzzing,helper,helpers,headless,code,javascript'.split(',').join(',');

// Keep a promise so concurrent phase calls share one update
let templatesReady: Promise<boolean> | null = null;

export async function ensureNucleiTemplates(onLog: LogFn): Promise<boolean> {
  if (templatesReady) return templatesReady;

  templatesReady = (async () => {
    try {
      await execFileAsync('which', ['nuclei'], { timeout: 2_000 });
    } catch {
      await onLog(`[${ts()}] [Nuclei] Binary not found — phase skipped`);
      return false;
    }

    await onLog(`[${ts()}] [Nuclei] Downloading/updating templates (background)...`);
    try {
      // -duc = disable update check after initial, -ud = update templates only
      await execFileAsync('nuclei', ['-update-templates', '-duc', '-no-color'], {
        timeout: 240_000,
      });
      await onLog(`[${ts()}] [Nuclei] Templates ready`);
      return true;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      await onLog(`[${ts()}] [Nuclei] Template update warning: ${msg} — attempting scan anyway`);
      return true; // might still work with cached templates
    }
  })();

  return templatesReady;
}

// ─── Main scan function ───────────────────────────────────────────────────────

export async function runNucleiScan(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];

  const ready = await ensureNucleiTemplates(onLog);
  if (!ready) return findings;

  const tmpDir = await mkdtemp(join(tmpdir(), 'sentinelx-nuclei-'));
  const outputFile = join(tmpDir, 'output.jsonl');

  try {
    await onLog(
      `[${ts()}] [Nuclei] Scanning ${target.url} — tags: CVE, exposure, misconfig, default-login, panel, takeover, injection...`,
    );

    const args = [
      '-u', target.url,
      '-json-export', outputFile,
      '-tags', SCAN_TAGS,
      '-exclude-tags', EXCLUDE_TAGS,
      '-rl', '100',           // rate-limit: 100 req/sec
      '-c', '50',             // 50 concurrent templates
      '-timeout', '8',        // per-request timeout (seconds)
      '-max-host-error', '30',
      '-no-interactsh',       // disable OOB (no callback infra)
      '-no-color',
      '-silent',
      '-duc',                 // disable update check during scan
    ];

    let stdout = '';
    let stderr = '';
    try {
      const result = await execFileAsync('nuclei', args, { timeout: 420_000 });
      stdout = result.stdout ?? '';
      stderr = result.stderr ?? '';
    } catch (err: unknown) {
      // nuclei exits non-zero when it finds issues — that's fine
      if (err && typeof err === 'object' && 'stdout' in err) {
        stdout = (err as { stdout?: string }).stdout ?? '';
        stderr = (err as { stderr?: string }).stderr ?? '';
      } else {
        throw err;
      }
    }

    // Read JSONL output file
    let jsonlContent = '';
    try {
      jsonlContent = await readFile(outputFile, 'utf-8');
    } catch {
      // Fall back to stdout if file wasn't written
      jsonlContent = stdout;
    }

    const lines = jsonlContent
      .trim()
      .split('\n')
      .filter((l) => l.trim().startsWith('{'));

    await onLog(`[${ts()}] [Nuclei] ${lines.length} template match(es) — parsing results...`);

    for (const line of lines) {
      try {
        const r = JSON.parse(line);
        const info = r.info ?? {};
        const rawSev = (info.severity ?? 'unknown').toLowerCase();
        const severity = SEV_MAP[rawSev] ?? 'low';
        const baseCvss = BASE_CVSS[rawSev] ?? 0;

        // Extract CVE IDs and CVSS score from classification block
        const classification = info.classification ?? {};
        const cveIds: string[] = classification['cve-id'] ?? [];
        const cvssScore =
          typeof classification['cvss-score'] === 'number'
            ? classification['cvss-score']
            : baseCvss;

        const cve = cveIds[0] ?? null;
        const templateId: string = r['template-id'] ?? 'unknown';
        const matchedAt: string = r['matched-at'] ?? r.url ?? target.url;
        const matcherName: string = r['matcher-name'] ?? '';
        const extractedResults: string[] = r['extracted-results'] ?? [];

        // Skip pure-informational templates (info severity with no CVE)
        if (rawSev === 'info' && !cve && !templateId.includes('detect')) continue;

        const evidenceParts = [
          `Template   : ${templateId}`,
          `Matched at : ${matchedAt}`,
          matcherName ? `Matcher    : ${matcherName}` : null,
          cve ? `CVE        : ${cve}` : null,
          cvssScore > 0 ? `CVSS Score : ${cvssScore}` : null,
          extractedResults.length > 0
            ? `Extracted  : ${extractedResults.slice(0, 3).join(', ')}`
            : null,
          info.tags?.length > 0 ? `Tags       : ${(info.tags as string[]).join(', ')}` : null,
        ].filter(Boolean).join('\n');

        findings.push({
          title: `[Nuclei] ${info.name ?? templateId}`,
          severity,
          verified: true,
          verification: 'verified',
          confidence: 92,
          evidenceQuality: 'strong',
          verificationMethod: `Nuclei template match: ${templateId}`,
          reproducibility: 'reproducible',
          affectedEndpoint: matchedAt,
          cvss: cvssScore,
          cve,
          description:
            info.description ??
            `Nuclei detected "${info.name ?? templateId}" on ${matchedAt}.`,
          evidence: evidenceParts,
          remediation:
            info.remediation ??
            'Apply the vendor-recommended patch or configuration change. See the referenced CVE/advisory for details.',
          compliance: {
            owasp: severity === 'critical' || severity === 'high' ? ['A06', 'A05'] : ['A05'],
            pci: ['6.3.3', '11.3.2'],
            nist: ['SI-2', 'CM-7'],
          },
        });
      } catch {
        // Skip malformed JSON lines
      }
    }

    if (stderr && !stderr.includes('No results found')) {
      await onLog(`[${ts()}] [Nuclei] stderr: ${stderr.slice(0, 200)}`);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    await onLog(`[${ts()}] [Nuclei] Scan error: ${msg}`);
  } finally {
    try {
      await rm(tmpDir, { recursive: true, force: true });
    } catch {}
  }

  await onLog(`[${ts()}] [Nuclei] Complete — ${findings.length} finding(s) across all template categories`);
  return findings;
}
