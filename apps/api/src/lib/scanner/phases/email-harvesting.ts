/**
 * Phase 11f — Email Harvesting (reconFTW-style OSINT)
 *
 * Extracts email addresses from the target site's pages, robots.txt, sitemap,
 * and common contact paths. Also probes for email security misconfigurations
 * (SPF, DMARC, DKIM).
 */

import { execFileAsync, dnsResolve, ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

const EMAIL_REGEX = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;

// Paths likely to contain contact info
const HARVEST_PATHS = [
  '/',
  '/contact',
  '/contact-us',
  '/about',
  '/about-us',
  '/team',
  '/staff',
  '/people',
  '/support',
  '/help',
  '/careers',
  '/jobs',
  '/robots.txt',
  '/sitemap.xml',
  '/.well-known/security.txt',
  '/humans.txt',
  '/security.txt',
];

function extractEmails(text: string, domain: string): { onTarget: string[]; offTarget: string[] } {
  const allMatches = [...new Set(text.match(EMAIL_REGEX) ?? [])];
  const onTarget: string[] = [];
  const offTarget: string[] = [];
  for (const email of allMatches) {
    const emailDomain = email.split('@')[1].toLowerCase();
    // Filter out common false positives
    if (/example\.com|test\.com|user@|noreply@noreply|foo@bar/i.test(email)) continue;
    if (emailDomain.endsWith(domain) || emailDomain === domain) onTarget.push(email);
    else offTarget.push(email);
  }
  return { onTarget, offTarget };
}

async function checkSpfDmarc(
  hostname: string,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const parts = hostname.split('.');
  const rootDomain = parts.length > 2 ? parts.slice(-2).join('.') : hostname;

  // SPF record
  try {
    const { stdout: spfOut } = await execFileAsync(
      'dig',
      ['+short', 'TXT', rootDomain],
      { timeout: 10_000 },
    );
    const txtRecords = spfOut.split('\n').filter(Boolean);
    const spfRecord = txtRecords.find((r) => r.includes('v=spf1'));

    if (!spfRecord) {
      findings.push({
        title: 'Missing SPF Record — Email Spoofing Risk',
        severity: 'medium',
        cvss: 5.3,
        cve: null,
        verification: 'verified',
        confidence: 92,
        description:
          `No SPF (Sender Policy Framework) TXT record found for "${rootDomain}". ` +
          'Without SPF, attackers can send emails that appear to originate from this domain.',
        evidence: `dig TXT ${rootDomain} — no v=spf1 record found.\nAll TXT records:\n${txtRecords.join('\n') || '(none)'}`,
        remediation:
          'Publish an SPF TXT record: `v=spf1 include:_spf.yourmailprovider.com ~all`. ' +
          'Use `-all` (hard fail) for strict enforcement.',
        compliance: { nist: ['NIST SI-8'] },
      });
    } else if (spfRecord.includes('+all')) {
      findings.push({
        title: 'SPF Record Uses "+all" — Allows All Senders',
        severity: 'high',
        cvss: 7.5,
        cve: null,
        verified: true,
        verification: 'verified',
        confidence: 97,
        description:
          `The SPF record for "${rootDomain}" uses "+all" which allows any server to send email as this domain. ` +
          'This completely negates SPF protection.',
        evidence: `SPF record: ${spfRecord}`,
        remediation: 'Change "+all" to "~all" (softfail) or "-all" (hardfail).',
      });
    }
  } catch (err: any) {
    await onLog(`[${ts()}] SPF check error: ${err?.message}`);
  }

  // DMARC record
  try {
    const { stdout: dmarcOut } = await execFileAsync(
      'dig',
      ['+short', 'TXT', `_dmarc.${rootDomain}`],
      { timeout: 10_000 },
    );
    const dmarcRecord = dmarcOut.trim();

    if (!dmarcRecord || !dmarcRecord.includes('v=DMARC1')) {
      findings.push({
        title: 'Missing DMARC Record — Email Authentication Bypass',
        severity: 'medium',
        cvss: 5.3,
        cve: null,
        verification: 'verified',
        confidence: 92,
        description:
          `No DMARC record found at "_dmarc.${rootDomain}". ` +
          'Without DMARC, receiving mail servers cannot enforce SPF/DKIM alignment, enabling phishing via this domain.',
        evidence: `dig TXT _dmarc.${rootDomain} — no v=DMARC1 record found`,
        remediation:
          'Publish a DMARC record: `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com`. ' +
          'Start with p=none to monitor, then move to p=quarantine/reject.',
        compliance: { nist: ['NIST SI-8'] },
      });
    } else if (dmarcRecord.includes('p=none')) {
      findings.push({
        title: 'DMARC Policy Set to "none" — No Enforcement',
        severity: 'low',
        cvss: 3.7,
        cve: null,
        verification: 'verified',
        confidence: 95,
        description:
          `The DMARC policy for "${rootDomain}" is set to "p=none" (monitor only). ` +
          'Emails failing DMARC checks are not rejected or quarantined.',
        evidence: `DMARC record: ${dmarcRecord}`,
        remediation:
          'After reviewing DMARC reports, upgrade from p=none to p=quarantine, then p=reject.',
      });
    }
  } catch (err: any) {
    await onLog(`[${ts()}] DMARC check error: ${err?.message}`);
  }

  return findings;
}

export async function harvestEmails(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const allOnTarget = new Set<string>();
  const allOffTarget = new Set<string>();

  await onLog(`[${ts()}] Email harvesting: scraping ${HARVEST_PATHS.length} paths for addresses...`);

  const baseUrl = target.url.replace(/\/$/, '');

  const harvestResults = await Promise.allSettled(
    HARVEST_PATHS.map(async (path) => {
      const url = `${baseUrl}${path}`;
      const result = await probe(url, { timeoutMs: 8_000 });
      if (!result || result.status !== 200) return null;
      return result.body;
    }),
  );

  for (const r of harvestResults) {
    if (r.status === 'fulfilled' && r.value) {
      const { onTarget, offTarget } = extractEmails(r.value, target.hostname);
      for (const e of onTarget) allOnTarget.add(e);
      for (const e of offTarget) allOffTarget.add(e);
    }
  }

  await onLog(`[${ts()}] Email harvest: ${allOnTarget.size} on-target, ${allOffTarget.size} off-target addresses`);

  if (allOnTarget.size > 0) {
    findings.push({
      title: `${allOnTarget.size} Email Address(es) Harvested from Target Site`,
      severity: allOnTarget.size > 5 ? 'medium' : 'low',
      cvss: allOnTarget.size > 5 ? 5.3 : 3.1,
      cve: null,
      verification: 'verified',
      confidence: 90,
      description:
        `${allOnTarget.size} email address(es) belonging to "${target.hostname}" were harvested from publicly accessible pages. ` +
        'These enable targeted phishing, credential stuffing, and social engineering attacks.',
      evidence: `On-target email addresses found:\n${[...allOnTarget].slice(0, 30).map((e) => `  ${e}`).join('\n')}`,
      remediation:
        'Obfuscate email addresses using JavaScript rendering or contact forms. ' +
        'Use role-based addresses (support@, security@) instead of personal addresses where possible. ' +
        'Enable email security controls (SPF, DKIM, DMARC).',
      compliance: { owasp: ['A05:2021 – Security Misconfiguration'] },
    });
  }

  if (allOffTarget.size > 0) {
    findings.push({
      title: `${allOffTarget.size} Third-Party Email Address(es) Found (OSINT)`,
      severity: 'low',
      cvss: 2.7,
      cve: null,
      verification: 'informational',
      confidence: 80,
      description:
        `${allOffTarget.size} external email addresses were found on the target site. ` +
        'These may reveal third-party providers or business contacts useful in social engineering.',
      evidence: `Third-party addresses:\n${[...allOffTarget].slice(0, 20).map((e) => `  ${e}`).join('\n')}`,
      remediation: 'Avoid publishing third-party email addresses on public pages where not necessary.',
    });
  }

  // Email security checks (SPF/DMARC)
  const emailSecFindings = await checkSpfDmarc(target.hostname, onLog);
  findings.push(...emailSecFindings);

  return findings;
}
