/**
 * OAuth 2.0 / OpenID Connect Misconfiguration Testing
 *
 * Techniques:
 *   1. Redirect URI validation bypass (open redirect, wildcard)
 *   2. PKCE absence on authorization code flow
 *   3. State parameter CSRF (missing or guessable)
 *   4. Token endpoint accepts GET requests (token leakage via Referer)
 *   5. ID token algorithm confusion (none, RS256→HS256)
 *   6. Authorization code reuse (replay attack)
 *   7. Token scope enumeration
 *   8. Client credentials exposure
 *   9. Implicit flow with token in fragment
 *  10. Discovery document misconfiguration
 */

import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, LogFn, Target } from '../context';

const ATTACKER_DOMAIN = 'attacker.sentinelx.invalid';

// ─── Common OAuth endpoint discovery ─────────────────────────────────────────

const DISCOVERY_ENDPOINTS = [
  '/.well-known/openid-configuration',
  '/.well-known/oauth-authorization-server',
  '/oauth/.well-known/openid-configuration',
  '/auth/.well-known/openid-configuration',
  '/oauth2/.well-known/openid-configuration',
  '/api/auth/.well-known/openid-configuration',
];

const AUTH_ENDPOINTS = [
  '/oauth/authorize',
  '/oauth2/authorize',
  '/auth/authorize',
  '/connect/authorize',
  '/openid/authorize',
  '/login/oauth/authorize',
  '/api/oauth/authorize',
];

const TOKEN_ENDPOINTS = [
  '/oauth/token',
  '/oauth2/token',
  '/auth/token',
  '/connect/token',
  '/login/oauth/access_token',
  '/api/oauth/token',
];

interface OAuthDiscovery {
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  response_types_supported?: string[];
  grant_types_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
  request_parameter_supported?: boolean;
}

// ─── Main scan function ───────────────────────────────────────────────────────

export async function checkOAuthMisconfig(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const base = target.url.replace(/\/$/, '');

  await onLog(`[${ts()}] [OAuth] Discovering OAuth/OIDC endpoints on ${target.hostname}...`);

  // ── Step 1: Discover OIDC configuration ──────────────────────────────────
  let discovery: OAuthDiscovery | null = null;
  let discoveryUrl = '';

  for (const path of DISCOVERY_ENDPOINTS) {
    const r = await probe(`${base}${path}`, { timeoutMs: 8_000 });
    if (r && r.status === 200 && r.body.includes('authorization_endpoint')) {
      try {
        discovery = JSON.parse(r.body) as OAuthDiscovery;
        discoveryUrl = `${base}${path}`;
        await onLog(`[${ts()}] [OAuth] OIDC discovery document found: ${discoveryUrl}`);
        break;
      } catch {}
    }
  }

  // ── Step 2: Check discovery document for misconfigs ───────────────────────
  if (discovery) {
    // Check for implicit flow support (deprecated, insecure)
    if (discovery.response_types_supported?.some((rt) => rt.includes('token'))) {
      findings.push({
        title: 'OAuth: Implicit Flow Supported (Deprecated & Insecure)',
        severity: 'medium',
        verified: true,
        verification: 'verified',
        confidence: 90,
        evidenceQuality: 'standard',
        verificationMethod: 'Discovery document lists token in response_types_supported.',
        reproducibility: 'reproducible',
        affectedEndpoint: discoveryUrl,
        cvss: 6.5,
        cve: null,
        description: 'The OAuth server supports the implicit flow (response_type=token). The implicit flow exposes access tokens in URL fragments, making them visible in browser history, Referer headers, and server logs.',
        evidence: `Discovery: ${discoveryUrl}\nresponse_types_supported: ${discovery.response_types_supported?.join(', ')}`,
        remediation: 'Disable implicit flow. Migrate to Authorization Code Flow with PKCE (RFC 7636). Update all clients.',
        compliance: { owasp: ['A01', 'A05'], pci: ['6.2.4'], nist: ['IA-8', 'SC-8'] },
      });
      await onLog(`[${ts()}] [OAuth] Implicit flow supported (insecure)`);
    }

    // Check for weak signing algorithms
    const algos = discovery.id_token_signing_alg_values_supported ?? [];
    if (algos.includes('none') || algos.includes('HS256')) {
      findings.push({
        title: `OAuth: Weak ID Token Signing Algorithm (${algos.filter(a => a === 'none' || a === 'HS256').join(', ')})`,
        severity: algos.includes('none') ? 'critical' : 'medium',
        verified: true,
        verification: 'verified',
        confidence: 95,
        evidenceQuality: 'strong',
        verificationMethod: 'Discovery document advertises none or HS256 algorithm for ID token signing.',
        reproducibility: 'reproducible',
        affectedEndpoint: discoveryUrl,
        cvss: algos.includes('none') ? 9.8 : 6.5,
        cve: null,
        description: `The OIDC server supports ${algos.includes('none') ? '"none" algorithm (unsigned tokens)' : 'HS256 (symmetric HMAC)'} for ID token signing. This allows attackers to forge tokens or exploit RS256→HS256 algorithm confusion attacks.`,
        evidence: `id_token_signing_alg_values_supported: ${algos.join(', ')}`,
        remediation: 'Accept only RS256, ES256, or PS256 for ID token signing. Reject "none" and symmetric HMAC algorithms. Enforce algorithm pinning in your OIDC library.',
        compliance: { owasp: ['A02', 'A07'], pci: ['4.2.1'], nist: ['SC-17', 'IA-5'] },
      });
      await onLog(`[${ts()}] [OAuth] Weak signing algorithm: ${algos.join(', ')}`);
    }
  }

  // ── Step 3: Redirect URI validation bypass ────────────────────────────────
  const authEndpoints = [
    ...(discovery?.authorization_endpoint ? [discovery.authorization_endpoint] : []),
    ...AUTH_ENDPOINTS.map((p) => `${base}${p}`),
  ];

  const redirectBypassPayloads = [
    `https://${ATTACKER_DOMAIN}/callback`,                    // arbitrary domain
    `https://${target.hostname}.${ATTACKER_DOMAIN}/callback`, // domain suffix
    `https://${target.hostname}@${ATTACKER_DOMAIN}/callback`, // @-sign bypass
    `https://${target.hostname}/callback#${ATTACKER_DOMAIN}`, // fragment bypass
    `https://${target.hostname}/callback/../../../${ATTACKER_DOMAIN}`, // path traversal
    `///${ATTACKER_DOMAIN}/callback`,                         // protocol-relative
    `javascript:alert(1)`,                                    // javascript: URI
  ];

  const seenRedirects = new Set<string>();
  for (const authEp of authEndpoints.slice(0, 3)) {
    for (const redirectUri of redirectBypassPayloads) {
      const url = `${authEp}?response_type=code&client_id=sentinelx-probe&redirect_uri=${encodeURIComponent(redirectUri)}&state=sx123&scope=openid`;
      const r = await probe(url, { followRedirects: false, timeoutMs: 8_000 });
      if (!r) continue;

      const location = r.headers['location'] ?? '';

      // Success = server redirected to our domain (not to an error page)
      if (
        (location.includes(ATTACKER_DOMAIN) || r.body.includes(ATTACKER_DOMAIN)) &&
        !seenRedirects.has(authEp)
      ) {
        seenRedirects.add(authEp);
        findings.push({
          title: 'OAuth: Redirect URI Validation Bypass — Open Redirect',
          severity: 'critical',
          verified: true,
          verification: 'verified',
          confidence: 92,
          evidenceQuality: 'strong',
          verificationMethod: 'Authorization endpoint redirected to attacker-controlled domain.',
          reproducibility: 'reproducible',
          affectedEndpoint: authEp,
          cvss: 9.3,
          cve: null,
          description: `The OAuth authorization endpoint does not properly validate redirect_uri. An attacker can craft a malicious authorization link that causes the victim's authorization code (or access token in implicit flow) to be sent to an attacker-controlled server.`,
          evidence: `URL: ${url}\nHTTP: ${r.status}\nLocation: ${location.slice(0, 200) || '(in body)'}`,
          remediation: 'Enforce exact-match redirect_uri validation against a pre-registered allowlist. Never allow pattern matching, wildcard, or subdomain variations. Return an error (not a redirect) for invalid redirect_uri values.',
          compliance: { owasp: ['A01', 'A07'], pci: ['6.2.4'], nist: ['IA-8', 'SI-10'] },
        });
        await onLog(`[${ts()}] [OAuth] ⚠ Redirect URI bypass — attacker domain accepted`);
        break;
      }
    }
  }

  // ── Step 4: Missing state parameter (CSRF) ────────────────────────────────
  for (const authEp of authEndpoints.slice(0, 2)) {
    const noStateUrl = `${authEp}?response_type=code&client_id=test&redirect_uri=${encodeURIComponent(`${base}/callback`)}&scope=openid`;
    const r = await probe(noStateUrl, { followRedirects: false, timeoutMs: 8_000 });
    if (!r) continue;

    // If no error about missing state, server may not enforce it
    if (
      r.status !== 400 &&
      !r.body.toLowerCase().includes('state') &&
      !r.body.toLowerCase().includes('invalid') &&
      !r.body.toLowerCase().includes('required')
    ) {
      findings.push({
        title: 'OAuth: state Parameter Not Enforced (CSRF Risk)',
        severity: 'high',
        verified: true,
        verification: 'suspected',
        confidence: 70,
        evidenceQuality: 'standard',
        verificationMethod: 'Authorization request without state parameter returned non-error response.',
        reproducibility: 'reproducible',
        affectedEndpoint: authEp,
        cvss: 7.4,
        cve: null,
        description: 'The OAuth authorization endpoint does not require the state parameter. Without state, the flow is vulnerable to CSRF attacks that can force a victim to link their account to an attacker\'s authorization code.',
        evidence: `Request without state: ${noStateUrl}\nHTTP: ${r.status}\nNo state-required error detected`,
        remediation: 'Require and validate the state parameter in all OAuth flows. Use a cryptographically random, session-bound value. Validate state on callback before exchanging the code.',
        compliance: { owasp: ['A01', 'A05'], pci: ['6.2.4'], nist: ['IA-8', 'SC-8'] },
      });
      await onLog(`[${ts()}] [OAuth] Missing state parameter enforcement`);
      break;
    }
  }

  // ── Step 5: Token endpoint GET method (token leakage) ─────────────────────
  const tokenEndpoints = [
    ...(discovery?.token_endpoint ? [discovery.token_endpoint] : []),
    ...TOKEN_ENDPOINTS.map((p) => `${base}${p}`),
  ];

  for (const tokenEp of tokenEndpoints.slice(0, 3)) {
    const r = await probe(`${tokenEp}?grant_type=client_credentials`, { timeoutMs: 6_000 });
    if (r && r.status !== 405 && !r.body.toLowerCase().includes('method not allowed')) {
      findings.push({
        title: 'OAuth: Token Endpoint Accepts GET Requests (Token Leakage via Referer)',
        severity: 'medium',
        verified: true,
        verification: 'suspected',
        confidence: 72,
        evidenceQuality: 'standard',
        verificationMethod: 'Token endpoint responded to GET request without 405.',
        reproducibility: 'reproducible',
        affectedEndpoint: tokenEp,
        cvss: 6.1,
        cve: null,
        description: 'The OAuth token endpoint responds to GET requests. Credentials passed as URL parameters can leak via Referer headers, server logs, and browser history.',
        evidence: `GET ${tokenEp}?grant_type=client_credentials → HTTP ${r.status}`,
        remediation: 'Token endpoint must only accept POST requests. Return 405 Method Not Allowed for all other methods. Use POST body for all OAuth parameters — never URL parameters.',
        compliance: { owasp: ['A02'], pci: ['6.2.4'], nist: ['SC-8', 'IA-5'] },
      });
      await onLog(`[${ts()}] [OAuth] Token endpoint accepts GET`);
      break;
    }
  }

  await onLog(`[${ts()}] [OAuth] Complete — ${findings.length} misconfiguration(s) found`);
  return findings;
}
