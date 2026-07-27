/**
 * Phase 5c — Subdomain Permutations (reconFTW-style)
 *
 * Takes discovered subdomains and generates permutations using common
 * prefixes, suffixes, and number appends. Resolves each via DNS and
 * reports newly found live hosts.
 */

import { dnsResolve, ts } from '../context';
import type { RealFinding, LogFn } from '../context';

const PERMUTATION_PREFIXES = [
  'dev', 'staging', 'prod', 'test', 'uat', 'qa', 'beta', 'alpha', 'demo',
  'new', 'old', 'legacy', 'internal', 'intranet', 'corp', 'private', 'secure',
  'admin', 'portal', 'dashboard', 'app', 'api', 'api2', 'api3', 'v1', 'v2',
  'mobile', 'cdn', 'static', 'assets', 'img', 'media', 'upload', 'uploads',
  'files', 'data', 'db', 'database', 'backup', 'bak', 'archive', 'log', 'logs',
  'mail', 'smtp', 'mx', 'vpn', 'remote', 'citrix', 'jump', 'bastion', 'ssh',
  'git', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence', 'jenkins',
  'ci', 'cd', 'deploy', 'release', 'preprod', 'pre-prod', 'stg', 'sandbox',
  'monitor', 'monitoring', 'grafana', 'kibana', 'elastic', 'splunk', 'prometheus',
  'k8s', 'kubernetes', 'docker', 'registry', 'hub', 'nexus', 'artifactory',
  'aws', 'gcp', 'azure', 'cloud', 's3', 'storage', 'bucket',
  'dev2', 'dev3', 'test2', 'test3', 'stage', 'stag',
];

const PERMUTATION_SUFFIXES = [
  '-dev', '-staging', '-prod', '-test', '-uat', '-qa', '-beta', '-demo',
  '-new', '-old', '-legacy', '-internal', '-api', '-app', '-portal', '-admin',
  '-2', '-3', '2', '3', '-v2', '-v3', '-backup', '-bak',
];

export async function checkSubdomainPermutations(
  rootDomain: string,
  knownSubs: string[],
  onLog: LogFn,
): Promise<{ subs: string[]; findings: RealFinding[] }> {
  const findings: RealFinding[] = [];
  const newSubs: string[] = [];

  // Extract second-level labels from known subs to permute
  const baseLabels = new Set<string>();
  for (const sub of knownSubs) {
    const withoutRoot = sub.replace(`.${rootDomain}`, '');
    // Take only the first label (leftmost)
    const parts = withoutRoot.split('.');
    baseLabels.add(parts[0]);
  }

  // Generate candidates: prefix.rootDomain and existinglabel-suffix.rootDomain
  const candidates = new Set<string>();

  // All prefixes against root domain
  for (const p of PERMUTATION_PREFIXES) {
    candidates.add(`${p}.${rootDomain}`);
  }

  // Permute existing sub labels with suffixes
  for (const label of baseLabels) {
    for (const suf of PERMUTATION_SUFFIXES) {
      candidates.add(`${label}${suf}.${rootDomain}`);
    }
  }

  // Remove already-known subs
  const knownSet = new Set(knownSubs);
  const toCheck = [...candidates].filter((c) => !knownSet.has(c)).slice(0, 200);

  await onLog(`[${ts()}] Permutation testing ${toCheck.length} subdomain candidates...`);

  const BATCH = 30;
  const found: { fqdn: string; ips: string[] }[] = [];

  for (let i = 0; i < toCheck.length; i += BATCH) {
    const batch = toCheck.slice(i, i + BATCH);
    const results = await Promise.allSettled(
      batch.map(async (fqdn) => {
        try {
          const addrs = await dnsResolve.resolve4(fqdn).catch(() => [] as string[]);
          if (addrs.length > 0) return { fqdn, ips: addrs };
          return null;
        } catch {
          return null;
        }
      }),
    );
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) {
        found.push(r.value);
        newSubs.push(r.value.fqdn);
      }
    }
  }

  await onLog(`[${ts()}] Permutation sweep: ${found.length} new subdomains resolved`);

  if (found.length > 0) {
    const sensitive = found.filter((f) =>
      /dev|staging|test|qa|uat|admin|internal|private|secure|backup|bak|legacy|preprod|stg|sandbox/i.test(
        f.fqdn,
      ),
    );

    findings.push({
      title: `${found.length} Subdomain(s) Found via Permutation`,
      severity: found.length > 10 ? 'medium' : 'low',
      cvss: found.length > 10 ? 5.3 : 3.7,
      cve: null,
      description:
        `Subdomain permutation testing revealed ${found.length} previously unknown live hosts. ` +
        `These hosts may be unpatched, expose internal services, or lack the same hardening as the primary domain.`,
      evidence:
        `Permutation-discovered hosts (${found.length}):\n` +
        found
          .slice(0, 30)
          .map((f) => `  ${f.fqdn} → ${f.ips.join(', ')}`)
          .join('\n'),
      remediation:
        'Audit all discovered subdomains. Restrict access to internal/dev hosts. ' +
        'Apply the same security controls to permutation-discovered hosts as the primary domain.',
      verification: found.length > 0 ? 'verified' : 'suspected',
      confidence: 90,
    });

    if (sensitive.length > 0) {
      findings.push({
        title: `${sensitive.length} Sensitive Subdomain(s) via Permutation (dev/staging/admin)`,
        severity: 'medium',
        cvss: 6.1,
        cve: null,
        description:
          `${sensitive.length} sensitive-named subdomains discovered via permutation. ` +
          `Development and staging hosts often run older software, weaker auth, or debug interfaces.`,
        evidence: sensitive.map((f) => `${f.fqdn} → ${f.ips.join(', ')}`).join('\n'),
        remediation:
          'Restrict dev/staging subdomains to VPN or IP allowlist. Apply patch management equally across all environments.',
        verification: 'verified',
        confidence: 92,
      });
    }
  }

  return { subs: newSubs, findings };
}
