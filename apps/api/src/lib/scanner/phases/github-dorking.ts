/**
 * Phase 11d — GitHub Dorking (reconFTW-style)
 *
 * Uses the GitHub public Search API (no token required for basic queries)
 * to find code, issues, and commits that mention the target domain —
 * potentially exposing API keys, passwords, and internal endpoints.
 */

import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

// Patterns that indicate credential or secret exposure
const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; severity: RealFinding['severity']; cvss: number }> = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/i, severity: 'critical', cvss: 9.8 },
  { name: 'AWS Secret Key', pattern: /aws_secret_access_key\s*[=:]\s*[A-Za-z0-9\/+]{40}/i, severity: 'critical', cvss: 9.8 },
  { name: 'Generic API Key', pattern: /api[_-]?key\s*[=:]\s*['"]?[A-Za-z0-9_\-]{16,}/i, severity: 'high', cvss: 7.5 },
  { name: 'Password', pattern: /password\s*[=:]\s*['"][^'"]{6,}['"]/i, severity: 'high', cvss: 7.5 },
  { name: 'Private Key', pattern: /-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/, severity: 'critical', cvss: 10.0 },
  { name: 'Database Connection String', pattern: /(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@/, severity: 'critical', cvss: 9.8 },
  { name: 'JWT Secret', pattern: /jwt[_-]?secret\s*[=:]\s*['"][^'"]{8,}['"]/i, severity: 'high', cvss: 7.5 },
  { name: 'SendGrid API Key', pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/, severity: 'critical', cvss: 9.8 },
  { name: 'Stripe Secret Key', pattern: /sk_(live|test)_[A-Za-z0-9]{24,}/, severity: 'critical', cvss: 9.8 },
  { name: 'GitHub Token', pattern: /ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{82}/, severity: 'critical', cvss: 9.8 },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/, severity: 'high', cvss: 8.1 },
  { name: 'Slack Token', pattern: /xox[baprs]-[0-9A-Za-z]{10,48}/, severity: 'high', cvss: 8.1 },
  { name: 'Twilio Token', pattern: /SK[0-9a-fA-F]{32}/, severity: 'high', cvss: 7.5 },
  { name: 'Internal URL/Endpoint', pattern: /https?:\/\/(internal|intranet|corp|vpn|dev|staging)\.[a-z0-9.-]+/, severity: 'medium', cvss: 5.3 },
];

interface GitHubSearchItem {
  name?: string;
  full_name?: string;
  html_url?: string;
  description?: string;
  text_matches?: Array<{ fragment?: string }>;
}

async function githubSearch(
  query: string,
  searchType: 'repositories' | 'code',
  onLog: LogFn,
): Promise<GitHubSearchItem[]> {
  const encodedQuery = encodeURIComponent(query);
  const url = `https://api.github.com/search/${searchType}?q=${encodedQuery}&per_page=10&sort=indexed`;

  const result = await probe(url, {
    timeoutMs: 15_000,
    headers: {
      Accept: 'application/vnd.github.v3.text-match+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    skipAuth: true,
  });

  if (!result || result.status === 403 || result.status === 422) {
    if (result?.status === 403) await onLog(`[${ts()}] GitHub API rate-limited`);
    return [];
  }

  try {
    const data = JSON.parse(result.body);
    return (data.items as GitHubSearchItem[]) ?? [];
  } catch {
    return [];
  }
}

export async function checkGitHubDorking(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const hostname = target.hostname;

  await onLog(`[${ts()}] GitHub dorking: searching public repos/code for "${hostname}"...`);

  // 1. Search for public repos mentioning this domain
  const repoItems = await githubSearch(`"${hostname}"`, 'repositories', onLog);
  if (repoItems.length > 0) {
    const repoList = repoItems
      .map((r) => `  ${r.full_name ?? r.name} — ${r.html_url}\n    ${r.description ?? ''}`)
      .join('\n');

    findings.push({
      title: `${repoItems.length} Public GitHub Repo(s) Reference ${hostname}`,
      severity: 'medium',
      cvss: 5.3,
      cve: null,
      verification: 'verified',
      confidence: 88,
      description:
        `${repoItems.length} public GitHub repositories reference "${hostname}". ` +
        'These may contain hardcoded credentials, internal API endpoints, or application source code.',
      evidence: `Repositories referencing ${hostname}:\n${repoList}`,
      remediation:
        'Review each repository for sensitive content. Request removal of credentials from commit history. ' +
        'Rotate any exposed secrets immediately.',
    });
    await onLog(`[${ts()}] GitHub: ${repoItems.length} public repos reference ${hostname}`);
  }

  // 2. Search code for secrets + domain
  const secretSearchQueries = [
    `"${hostname}" password`,
    `"${hostname}" api_key`,
    `"${hostname}" secret_key`,
    `"${hostname}" access_token`,
  ];

  let totalCodeHits = 0;
  const credentialFindings: { file: string; fragment: string; matched: string; severity: RealFinding['severity']; cvss: number }[] = [];

  for (const query of secretSearchQueries) {
    const codeItems = await githubSearch(query, 'code', onLog);
    if (codeItems.length === 0) continue;
    totalCodeHits += codeItems.length;

    for (const item of codeItems.slice(0, 5)) {
      // Check text matches for actual secret patterns
      const fragments = (item.text_matches ?? []).map((m) => m.fragment ?? '').join('\n');
      let matched: { name: string; severity: RealFinding['severity']; cvss: number } | null = null;

      for (const sp of SECRET_PATTERNS) {
        if (sp.pattern.test(fragments)) {
          matched = sp;
          break;
        }
      }

      if (matched) {
        credentialFindings.push({
          file: item.html_url ?? 'unknown',
          fragment: fragments.slice(0, 400),
          matched: matched.name,
          severity: matched.severity,
          cvss: matched.cvss,
        });
      }
    }
  }

  if (credentialFindings.length > 0) {
    const highest = credentialFindings.reduce((a, b) => (a.cvss >= b.cvss ? a : b));
    findings.push({
      title: `Credentials Exposed in Public GitHub Code (${credentialFindings.length} match${credentialFindings.length > 1 ? 'es' : ''})`,
      severity: highest.severity,
      cvss: highest.cvss,
      cve: null,
      verified: true,
      verification: 'verified',
      confidence: 85,
      description:
        `GitHub code search found ${credentialFindings.length} file(s) containing patterns matching "${hostname}" alongside ` +
        'credential or secret indicators. This may indicate exposed API keys, passwords, or connection strings.',
      evidence:
        `Matched secret types: ${[...new Set(credentialFindings.map((f) => f.matched))].join(', ')}\n\n` +
        credentialFindings
          .slice(0, 5)
          .map((f) => `File: ${f.file}\nPattern: ${f.matched}\nSnippet:\n${f.fragment}`)
          .join('\n\n---\n\n'),
      remediation:
        'Immediately rotate any exposed credentials. Remove secrets from git history using BFG Repo Cleaner or git filter-repo. ' +
        'Implement pre-commit hooks (git-secrets, gitleaks) to prevent future exposure.',
      compliance: { owasp: ['A07:2021 – Identification and Authentication Failures'] },
    });
    await onLog(`[${ts()}] ⚠ GitHub dorking found credential patterns in ${credentialFindings.length} file(s)`);
  } else if (totalCodeHits > 0) {
    findings.push({
      title: `${totalCodeHits} GitHub Code File(s) Reference ${hostname}`,
      severity: 'low',
      cvss: 3.7,
      cve: null,
      verification: 'suspected',
      confidence: 65,
      description:
        `${totalCodeHits} public code files reference "${hostname}". ` +
        'No confirmed credential patterns detected, but manual review is recommended.',
      evidence: `GitHub code search returned ${totalCodeHits} results for queries involving "${hostname}" and secret-related keywords.`,
      remediation: 'Review GitHub code results manually for any sensitive content related to this domain.',
    });
  }

  // 3. Check if the org/domain has a GitHub presence with public repos
  const orgName = hostname.split('.')[0];
  const orgResult = await probe(`https://api.github.com/orgs/${orgName}/repos?per_page=5`, {
    timeoutMs: 10_000,
    headers: { Accept: 'application/vnd.github.v3+json' },
    skipAuth: true,
  });

  if (orgResult && orgResult.status === 200) {
    try {
      const repos = JSON.parse(orgResult.body) as Array<{ full_name: string; html_url: string; private: boolean }>;
      const publicRepos = repos.filter((r) => !r.private);
      if (publicRepos.length > 0) {
        findings.push({
          title: `GitHub Organisation "${orgName}" Has ${publicRepos.length} Public Repo(s)`,
          severity: 'low',
          cvss: 3.1,
          cve: null,
          verification: 'verified',
          confidence: 95,
          description:
            `The GitHub organisation "${orgName}" has ${publicRepos.length} public repositories. ` +
            'Public repos may contain application source code, configuration, or historical secrets.',
          evidence: publicRepos.map((r) => `  ${r.full_name}: ${r.html_url}`).join('\n'),
          remediation: 'Audit public repositories for sensitive data. Ensure no secrets are committed to version control.',
        });
        await onLog(`[${ts()}] GitHub org "${orgName}": ${publicRepos.length} public repos found`);
      }
    } catch { /* parse error */ }
  }

  return findings;
}
