/**
 * Phase 11g — Leaked Credential / Paste Site Detection (reconFTW-style)
 *
 * Checks public paste aggregators and GitHub gists for mentions of the
 * target domain — which may indicate credential dumps, data breaches,
 * or sensitive internal information leaks.
 */

import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

interface PasteHit {
  source: string;
  title: string;
  url: string;
  snippet: string;
  hasCredentials: boolean;
}

// Patterns indicating actual credential dumps
const CREDENTIAL_PATTERNS = [
  /password\s*[:=]\s*\S+/i,
  /passwd\s*[:=]\s*\S+/i,
  /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b.{0,20}[:=].{3,}/,
  /api[_-]?key\s*[:=]\s*\S+/i,
  /secret\s*[:=]\s*\S+/i,
  /(user|username)\s*[:=]\s*\S+.{0,30}(pass|password|pwd)\s*[:=]\s*\S+/is,
  /\b(?:user|email|login)[:=]\s*\S+\b.*\bpass(?:word)?[:=]\s*\S+/is,
];

function hasCredentialPattern(text: string): boolean {
  return CREDENTIAL_PATTERNS.some((p) => p.test(text));
}

async function checkPsbdmp(hostname: string, onLog: LogFn): Promise<PasteHit[]> {
  const hits: PasteHit[] = [];
  // psbdmp.ws is a public Pastebin search engine
  const url = `https://psbdmp.ws/api/v3/search/${encodeURIComponent(hostname)}`;
  const result = await probe(url, {
    timeoutMs: 15_000,
    skipAuth: true,
    headers: { Accept: 'application/json' },
  });

  if (!result || result.status !== 200) return hits;

  try {
    const data = JSON.parse(result.body);
    const pastes = (data.data as Array<{ id?: string; text?: string; title?: string }>) ?? [];

    for (const paste of pastes.slice(0, 10)) {
      if (!paste.id) continue;
      const pasteText = paste.text ?? '';
      const title = paste.title ?? `Paste ${paste.id}`;
      const url2 = `https://psbdmp.ws/${paste.id}`;

      hits.push({
        source: 'psbdmp.ws (Pastebin mirror)',
        title,
        url: url2,
        snippet: pasteText.slice(0, 300),
        hasCredentials: hasCredentialPattern(pasteText),
      });
    }
  } catch { /* parse error */ }

  return hits;
}

async function checkGitHubGists(hostname: string): Promise<PasteHit[]> {
  const hits: PasteHit[] = [];
  const url = `https://api.github.com/gists/public?per_page=10`;
  // We can't search gists without auth for specific domains directly,
  // so we check GitHub search for gists mentioning the domain
  const searchUrl = `https://api.github.com/search/code?q="${hostname}"+in:file+gist:true&per_page=5`;

  const result = await probe(searchUrl, {
    timeoutMs: 12_000,
    skipAuth: true,
    headers: { Accept: 'application/vnd.github.v3+json' },
  });

  if (!result || result.status !== 200) return hits;

  try {
    const data = JSON.parse(result.body);
    const items = (data.items as Array<{ html_url?: string; name?: string; repository?: { full_name?: string } }>) ?? [];

    for (const item of items.slice(0, 5)) {
      if (!item.html_url) continue;
      hits.push({
        source: 'GitHub Gists / Code',
        title: item.name ?? item.repository?.full_name ?? 'Unknown',
        url: item.html_url,
        snippet: `Code file mentioning ${hostname}`,
        hasCredentials: false, // Would need to fetch content to verify
      });
    }
  } catch { /* parse error */ }

  return hits;
}

async function checkIntelX(hostname: string): Promise<PasteHit[]> {
  // IntelligenceX has a free tier API
  const searchUrl = `https://2.intelx.io/intelligent/search`;
  const result = await probe(searchUrl, {
    method: 'POST',
    timeoutMs: 15_000,
    skipAuth: true,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ term: hostname, maxresults: 5, media: 0, sort: 4, terminate: [] }),
  });

  const hits: PasteHit[] = [];
  if (!result || result.status !== 200) return hits;

  try {
    const data = JSON.parse(result.body);
    if (data.status === 0 && Array.isArray(data.records)) {
      for (const rec of data.records.slice(0, 5)) {
        hits.push({
          source: 'IntelligenceX',
          title: rec.name ?? rec.bucket ?? 'Unknown',
          url: `https://intelx.io/?did=${rec.systemid ?? ''}`,
          snippet: rec.name ?? '',
          hasCredentials: false,
        });
      }
    }
  } catch { /* parse error */ }

  return hits;
}

export async function checkLeakDetection(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const hostname = target.hostname;
  const rootDomain = hostname.split('.').slice(-2).join('.');

  await onLog(`[${ts()}] Leak detection: checking paste sites and public dumps for "${rootDomain}"...`);

  // Run checks in parallel
  const [psbdmpHits, gistHits, intelxHits] = await Promise.allSettled([
    checkPsbdmp(rootDomain, onLog),
    checkGitHubGists(rootDomain),
    checkIntelX(rootDomain),
  ]);

  const allHits: PasteHit[] = [
    ...(psbdmpHits.status === 'fulfilled' ? psbdmpHits.value : []),
    ...(gistHits.status === 'fulfilled' ? gistHits.value : []),
    ...(intelxHits.status === 'fulfilled' ? intelxHits.value : []),
  ];

  await onLog(`[${ts()}] Leak detection: ${allHits.length} paste/code results found`);

  if (allHits.length === 0) return findings;

  const credentialLeaks = allHits.filter((h) => h.hasCredentials);
  const nonCredential = allHits.filter((h) => !h.hasCredentials);

  if (credentialLeaks.length > 0) {
    findings.push({
      title: `Credential Leak in Public Paste/Code (${credentialLeaks.length} source${credentialLeaks.length > 1 ? 's' : ''})`,
      severity: 'critical',
      cvss: 9.8,
      cve: null,
      verified: true,
      verification: 'verified',
      confidence: 88,
      description:
        `${credentialLeaks.length} paste(s) containing "${rootDomain}" appear to include credential patterns ` +
        '(password/key/secret indicators found in leaked content). This may indicate a data breach, credential dump, or insider leak.',
      evidence:
        credentialLeaks
          .slice(0, 5)
          .map(
            (h) =>
              `Source: ${h.source}\nTitle: ${h.title}\nURL: ${h.url}\nSnippet:\n${h.snippet}`,
          )
          .join('\n\n---\n\n'),
      remediation:
        'Immediately rotate any credentials found in these pastes. ' +
        'Investigate the source of the leak — employee device, breach, or insider threat. ' +
        'Set up breach monitoring with HaveIBeenPwned or similar services. ' +
        'Review access logs for unauthorized use of leaked credentials.',
      compliance: {
        owasp: ['A07:2021 – Identification and Authentication Failures'],
        pci: ['PCI DSS 8.3.6'],
      },
    });
    await onLog(`[${ts()}] ⚠ CRITICAL: ${credentialLeaks.length} paste(s) with credential patterns found!`);
  }

  if (nonCredential.length > 0) {
    findings.push({
      title: `${nonCredential.length} Public Paste/Code Reference(s) to ${rootDomain}`,
      severity: 'medium',
      cvss: 5.3,
      cve: null,
      verification: 'verified',
      confidence: 75,
      description:
        `${nonCredential.length} public paste(s) or code snippet(s) reference "${rootDomain}". ` +
        'These may contain internal URLs, configuration details, error messages, or other sensitive reconnaissance data.',
      evidence:
        nonCredential
          .slice(0, 8)
          .map((h) => `[${h.source}] ${h.title}\n  ${h.url}\n  ${h.snippet.slice(0, 150)}`)
          .join('\n\n'),
      remediation:
        'Review each paste for sensitive content. Request takedown of sensitive pastes. ' +
        'Set up monitoring for new pastes mentioning your domain (DNSTWIST, SpyCloud, etc.).',
    });
  }

  return findings;
}
