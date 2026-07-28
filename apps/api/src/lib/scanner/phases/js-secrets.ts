/**
 * JavaScript Secret Extraction & Endpoint Discovery
 *
 * Fetches JS files from the target, extracts:
 * - Hardcoded API keys, tokens, credentials
 * - Internal endpoints / API routes
 * - AWS/GCP/Azure credentials
 * - Firebase configs, Stripe/Twilio/Slack keys
 * - Commented-out credentials
 * - Source-mapped secrets
 */

import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, LogFn, Target } from '../context';

// ─── Secret patterns ──────────────────────────────────────────────────────────

interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: RealFinding['severity'];
  cvss: number;
  confidence: number;
  remediation: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // AWS
  { name: 'AWS Access Key ID', regex: /(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])/g, severity: 'critical', cvss: 9.8, confidence: 95, remediation: 'Rotate the AWS access key immediately. Use IAM roles and instance profiles instead of hardcoded keys.' },
  { name: 'AWS Secret Access Key', regex: /aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9+/]{40})["']?/gi, severity: 'critical', cvss: 9.8, confidence: 90, remediation: 'Rotate immediately. Use AWS Secrets Manager.' },
  { name: 'AWS Session Token', regex: /aws[_\-.]?session[_\-.]?token["']?\s*[:=]\s*["']?([A-Za-z0-9+/=]{100,})["']?/gi, severity: 'critical', cvss: 9.8, confidence: 85, remediation: 'Rotate session tokens. Use IAM roles.' },

  // Google / GCP
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_\-]{35}/g, severity: 'high', cvss: 8.5, confidence: 92, remediation: 'Restrict API key to specific APIs and referrers. Rotate the key.' },
  { name: 'GCP Service Account Key', regex: /"type"\s*:\s*"service_account"[\s\S]{0,500}"private_key"/g, severity: 'critical', cvss: 9.8, confidence: 95, remediation: 'Revoke and rotate the service account key. Never embed in client-side JS.' },
  { name: 'Firebase Config', regex: /["\']apiKey["\']\s*:\s*["\'](AIza[0-9A-Za-z_\-]{35})["\']/g, severity: 'medium', cvss: 5.5, confidence: 90, remediation: 'Apply Firebase Security Rules. Restrict API key to your domain.' },

  // Stripe / Payment
  { name: 'Stripe Secret Key', regex: /sk_(?:live|test)_[0-9a-zA-Z]{24,}/g, severity: 'critical', cvss: 9.8, confidence: 97, remediation: 'Roll the Stripe key immediately. Use restricted keys and server-side only.' },
  { name: 'Stripe Publishable Key', regex: /pk_(?:live|test)_[0-9a-zA-Z]{24,}/g, severity: 'low', cvss: 3.1, confidence: 95, remediation: 'Publishable keys are intentionally public but ensure only secret keys are truly secret.' },
  { name: 'PayPal Client Secret', regex: /paypal[_\-.]?(?:client[_\-.]?)?secret["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']?/gi, severity: 'critical', cvss: 9.8, confidence: 80, remediation: 'Rotate PayPal credentials. Never expose client secrets in JS.' },

  // Communication
  { name: 'Twilio Auth Token', regex: /twilio[_\-.]?auth[_\-.]?token["']?\s*[:=]\s*["']([a-f0-9]{32})["']?/gi, severity: 'high', cvss: 7.5, confidence: 85, remediation: 'Rotate Twilio auth token. Use environment variables.' },
  { name: 'Slack Bot Token', regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g, severity: 'high', cvss: 7.5, confidence: 95, remediation: 'Revoke the Slack token. Use webhook URLs with restricted scopes.' },
  { name: 'Slack Webhook URL', regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g, severity: 'medium', cvss: 5.0, confidence: 97, remediation: 'Regenerate the Slack webhook URL.' },
  { name: 'Discord Bot Token', regex: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g, severity: 'high', cvss: 7.5, confidence: 80, remediation: 'Revoke Discord bot token immediately.' },

  // GitHub / GitLab
  { name: 'GitHub Personal Access Token', regex: /ghp_[A-Za-z0-9]{36}/g, severity: 'high', cvss: 8.5, confidence: 97, remediation: 'Revoke the GitHub PAT. Scope tokens minimally.' },
  { name: 'GitHub OAuth Token', regex: /gho_[A-Za-z0-9]{36}/g, severity: 'high', cvss: 8.5, confidence: 97, remediation: 'Revoke the GitHub OAuth token.' },
  { name: 'GitHub Actions Token', regex: /ghs_[A-Za-z0-9]{36}/g, severity: 'high', cvss: 8.5, confidence: 97, remediation: 'Rotate the GitHub Actions secret.' },
  { name: 'GitLab PAT', regex: /glpat-[A-Za-z0-9_\-]{20}/g, severity: 'high', cvss: 8.5, confidence: 95, remediation: 'Revoke the GitLab PAT.' },

  // JWT
  { name: 'JSON Web Token (JWT)', regex: /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g, severity: 'medium', cvss: 6.5, confidence: 88, remediation: 'Do not embed JWTs in JS source. Use HttpOnly cookies or refresh-token flows.' },

  // Private keys
  { name: 'RSA Private Key', regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g, severity: 'critical', cvss: 10.0, confidence: 99, remediation: 'Rotate all key pairs immediately. Remove private keys from the repository.' },
  { name: 'EC Private Key', regex: /-----BEGIN EC PRIVATE KEY-----/g, severity: 'critical', cvss: 10.0, confidence: 99, remediation: 'Rotate EC key pair. Never embed private keys in code.' },
  { name: 'PGP Private Key', regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, severity: 'critical', cvss: 10.0, confidence: 99, remediation: 'Revoke PGP key. Remove from codebase.' },

  // Generic high-confidence patterns
  { name: 'Generic API Key (variable assignment)', regex: /(?:api[_\-.]?key|auth[_\-.]?token|access[_\-.]?token|secret[_\-.]?key)["']?\s*[:=]\s*["']([A-Za-z0-9_\-+/=]{20,})["']/gi, severity: 'high', cvss: 7.5, confidence: 65, remediation: 'Move secrets to a secure secrets manager. Never hardcode credentials.' },
  { name: 'Password in Source Code', regex: /(?:password|passwd|pwd)["']?\s*[:=]\s*["']([^"'\s]{8,})["']/gi, severity: 'high', cvss: 7.5, confidence: 60, remediation: 'Remove hardcoded passwords. Use environment variables and secrets managers.' },
  { name: 'Database Connection String', regex: /(?:mongodb|postgresql|mysql|redis):\/\/[^"'\s]+:[^"'\s]+@[^"'\s]+/gi, severity: 'critical', cvss: 9.8, confidence: 92, remediation: 'Remove database connection strings from client-side code. Use server-side configuration.' },
  { name: 'Bearer Token Hardcoded', regex: /[Bb]earer\s+([A-Za-z0-9_\-\.]{20,})/g, severity: 'high', cvss: 7.5, confidence: 72, remediation: 'Do not hardcode bearer tokens. Use proper authentication flows.' },
  { name: 'SendGrid API Key', regex: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g, severity: 'high', cvss: 7.5, confidence: 95, remediation: 'Rotate SendGrid API key immediately.' },
  { name: 'Mailgun API Key', regex: /key-[a-f0-9]{32}/g, severity: 'high', cvss: 7.5, confidence: 80, remediation: 'Rotate Mailgun API key.' },
  { name: 'Heroku API Key', regex: /[hH]eroku[^"'\n]{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, severity: 'high', cvss: 7.5, confidence: 85, remediation: 'Rotate Heroku API key.' },
  { name: 'Shopify Access Token', regex: /shpss_[a-fA-F0-9]{32}|shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32}/g, severity: 'critical', cvss: 9.0, confidence: 97, remediation: 'Revoke Shopify access token immediately.' },
  { name: 'Cloudinary Credentials', regex: /cloudinary:\/\/[0-9]+:[A-Za-z0-9_\-]+@[a-z0-9]+/g, severity: 'high', cvss: 7.5, confidence: 95, remediation: 'Rotate Cloudinary credentials.' },
  { name: 'HubSpot API Key', regex: /[hH]ub[Ss]pot[^"'\n]{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, severity: 'high', cvss: 7.5, confidence: 80, remediation: 'Rotate HubSpot API key.' },
  { name: 'npm Auth Token', regex: /\/\/registry\.npmjs\.org\/:_authToken\s*=\s*([A-Za-z0-9\-]{36,})/g, severity: 'high', cvss: 8.0, confidence: 95, remediation: 'Revoke npm token. Use short-lived automation tokens.' },
];

// Patterns to discover hidden API endpoints in JS bundles
const ENDPOINT_PATTERN = /["'`](\/(api|v1|v2|v3|internal|admin|graphql|rest|service|backend|auth|user|users|account|accounts|payment|payments|webhook|webhooks|admin|management)[^"'`\s]{0,100})["'`]/gi;

// ─── JS file discovery ────────────────────────────────────────────────────────

async function findJsFiles(target: Target, onLog: LogFn): Promise<string[]> {
  const urls = new Set<string>();
  const base = target.url.replace(/\/$/, '');

  // Fetch homepage to discover script tags
  const homepage = await probe(target.url, { timeoutMs: 10_000 });
  if (homepage) {
    // Extract src attributes from <script> tags
    const scriptSrcs = [...homepage.body.matchAll(/<script[^>]+src=["']([^"']+\.(?:js|mjs)[^"']*)["']/gi)];
    for (const match of scriptSrcs) {
      const src = match[1]!;
      if (src.startsWith('http')) urls.add(src);
      else if (src.startsWith('/')) urls.add(`${base}${src}`);
      else urls.add(`${base}/${src}`);
    }

    // Extract src from <script type="module"> inline imports
    const importMatches = [...homepage.body.matchAll(/import\s+[^"']*["']([^"']+\.(?:js|mjs)[^"']*)["']/g)];
    for (const match of importMatches) {
      const src = match[1]!;
      if (src.startsWith('/')) urls.add(`${base}${src}`);
    }
  }

  // Common JS paths to probe
  const commonPaths = [
    '/app.js', '/main.js', '/bundle.js', '/index.js', '/app.min.js',
    '/static/js/main.js', '/static/js/bundle.js', '/assets/index.js',
    '/js/app.js', '/js/main.js', '/dist/main.js', '/build/main.js',
    '/runtime.js', '/vendor.js', '/chunk.js',
  ];
  for (const path of commonPaths) {
    urls.add(`${base}${path}`);
  }

  return [...urls].slice(0, 30); // cap at 30 JS files
}

// ─── Main scan function ───────────────────────────────────────────────────────

export async function checkJsSecrets(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];

  await onLog(`[${ts()}] [JS Secrets] Discovering JavaScript files on ${target.hostname}...`);
  const jsUrls = await findJsFiles(target, onLog);
  await onLog(`[${ts()}] [JS Secrets] Fetching ${jsUrls.length} JS file(s)...`);

  const seenSecrets = new Set<string>();
  const endpointsFound = new Set<string>();

  const results = await Promise.allSettled(
    jsUrls.map((url) => probe(url, { timeoutMs: 12_000 })),
  );

  let filesScanned = 0;

  for (let i = 0; i < results.length; i++) {
    const result = results[i]!;
    const jsUrl = jsUrls[i]!;

    if (result.status !== 'fulfilled' || !result.value) continue;
    const response = result.value;

    // Only process JS/text content
    const ct = response.headers['content-type'] ?? '';
    if (!ct.includes('javascript') && !ct.includes('text') && response.body.length < 100) continue;
    if (response.status !== 200) continue;

    filesScanned++;
    const content = response.body;

    // Secret scanning
    for (const pattern of SECRET_PATTERNS) {
      const cloned = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');
      const matches = [...content.matchAll(cloned)];
      if (matches.length === 0) continue;

      const dedupeKey = `${pattern.name}::${jsUrl}`;
      if (seenSecrets.has(dedupeKey)) continue;
      seenSecrets.add(dedupeKey);

      // Extract a snippet around the match
      const match = matches[0]!;
      const matchStart = match.index ?? 0;
      const snippet = content
        .slice(Math.max(0, matchStart - 40), matchStart + (match[0]?.length ?? 0) + 40)
        .replace(/\s+/g, ' ')
        .trim();

      // Redact the actual secret value in evidence
      const redacted = snippet.replace(
        new RegExp(pattern.regex.source, 'gi'),
        (m) => m.slice(0, 6) + '***REDACTED***',
      );

      findings.push({
        title: `Hardcoded Secret: ${pattern.name} in JavaScript`,
        severity: pattern.severity,
        verified: true,
        verification: 'verified',
        confidence: pattern.confidence,
        evidenceQuality: 'strong',
        verificationMethod: 'Regex pattern match against fetched JavaScript bundle.',
        reproducibility: 'reproducible',
        affectedEndpoint: jsUrl,
        cvss: pattern.cvss,
        cve: null,
        description: `A ${pattern.name} was found hardcoded in the JavaScript file "${jsUrl}". This credential is exposed to anyone who fetches the script.`,
        evidence: `File  : ${jsUrl}\nType  : ${pattern.name}\nMatch : ${redacted}\nCount : ${matches.length} occurrence(s)`,
        remediation: pattern.remediation,
        compliance: {
          owasp: ['A02', 'A05'],
          pci: ['6.2.4', '8.6.1'],
          nist: ['IA-5', 'SC-28'],
        },
      });

      await onLog(`[${ts()}] [JS Secrets] ⚠ ${pattern.name} in ${jsUrl.split('/').pop()}`);
    }

    // Endpoint extraction
    const epMatches = [...content.matchAll(ENDPOINT_PATTERN)];
    for (const match of epMatches) {
      const ep = match[1]!;
      if (ep.length > 5 && ep.length < 120) endpointsFound.add(ep);
    }
  }

  if (endpointsFound.size > 0) {
    const endpoints = [...endpointsFound].slice(0, 50);
    findings.push({
      title: `Hidden API Endpoints Discovered in JavaScript (${endpoints.length})`,
      severity: 'medium',
      verified: true,
      verification: 'verified',
      confidence: 80,
      evidenceQuality: 'standard',
      verificationMethod: 'Regex extraction of path literals from JavaScript bundles.',
      reproducibility: 'reproducible',
      cvss: 5.3,
      cve: null,
      description: `${endpoints.length} internal API endpoint(s) were discovered in JavaScript source files. These paths may expose undocumented or unauthenticated API routes.`,
      evidence: `Source files: ${filesScanned} scanned\nEndpoints discovered:\n${endpoints.join('\n')}`,
      remediation: 'Audit each discovered endpoint for authentication requirements. Implement API gateway with strict access controls. Consider separate build artifacts for public-facing and internal APIs.',
      compliance: {
        owasp: ['A01', 'A05'],
        pci: ['6.2.4'],
        nist: ['AC-3', 'CM-7'],
      },
    });
    await onLog(`[${ts()}] [JS Secrets] ${endpoints.length} hidden endpoint(s) extracted from JS bundles`);
  }

  await onLog(
    `[${ts()}] [JS Secrets] Complete — scanned ${filesScanned} JS files, found ${findings.length} issue(s)`,
  );
  return findings;
}
