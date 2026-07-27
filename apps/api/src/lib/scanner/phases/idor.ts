import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

export async function checkIdorAndBola(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Testing IDOR / BOLA object enumeration...`);

  const idorEndpoints = [
    '/api/user/', '/api/users/', '/api/account/', '/api/accounts/',
    '/api/profile/', '/api/profiles/', '/api/order/', '/api/orders/',
    '/api/document/', '/api/documents/', '/api/file/', '/api/files/',
    '/api/invoice/', '/api/invoices/', '/api/report/', '/api/ticket/',
    '/user/', '/users/', '/account/', '/accounts/', '/profile/', '/order/',
  ];

  const baseIds = ['1', '2', '100', '1000'];
  const altIds = ['0', '3', '101', '9999', '999', '../1', '-1', '00000000-0000-0000-0000-000000000001'];

  for (const ep of idorEndpoints) {
    for (const id of baseIds) {
      const baseUrl = target.url.replace(/\/$/, '') + ep + id;
      const baseR = await probe(baseUrl, { timeoutMs: 8_000 });
      if (!baseR || baseR.status !== 200) continue;
      if (baseR.body.length < 30) continue;

      // Try neighbouring IDs
      for (const altId of altIds) {
        const altUrl = target.url.replace(/\/$/, '') + ep + altId;
        const altR = await probe(altUrl, { timeoutMs: 8_000 });
        if (!altR || altR.status !== 200) continue;
        const baseFields = (baseR.body.match(/"[a-z_]+"\s*:/gi) ?? []).length;
        const altFields = (altR.body.match(/"[a-z_]+"\s*:/gi) ?? []).length;
        if (Math.abs(altFields - baseFields) <= 2 && altFields >= 3 && altR.body !== baseR.body) {
          findings.push({
            title: `IDOR / BOLA — Direct Object Reference (${ep}${id} vs ${ep}${altId})`,
            severity: 'high',
            verification: 'suspected',
            confidence: 70,
            cvss: 8.1,
            cve: null,
            description: `Both IDs ${id} and ${altId} at '${ep}' returned similar JSON object structures without apparent authorisation checks.`,
            evidence: `GET ${baseUrl} → HTTP ${baseR.status} (${baseR.body.length}b)\nGET ${altUrl} → HTTP ${altR.status} (${altR.body.length}b)\nBoth contain JSON with ${altFields} fields`,
            remediation: 'Enforce object-level authorisation on every request.',
          });
          await onLog(`[${ts()}] ⚠ IDOR SIGNAL: ${ep}`);
          return findings;
        }
      }
      break; // Only check first successful baseId per endpoint
    }
  }

  // UUID IDOR
  const uuidEps = idorEndpoints.filter((e) => e.includes('api'));
  const testUuids = [
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000002',
  ];
  for (const ep of uuidEps.slice(0, 5)) {
    const r1 = await probe(target.url.replace(/\/$/, '') + ep + testUuids[0], { timeoutMs: 8_000 });
    const r2 = await probe(target.url.replace(/\/$/, '') + ep + testUuids[1], { timeoutMs: 8_000 });
    if (r1?.status === 200 && r2?.status === 200 && r1.body !== r2.body && r1.body.length > 50) {
      const fields1 = (r1.body.match(/"[a-z_]+"\s*:/gi) ?? []).length;
      const fields2 = (r2.body.match(/"[a-z_]+"\s*:/gi) ?? []).length;
      if (Math.abs(fields1 - fields2) <= 2 && fields1 >= 3) {
        findings.push({
          title: `IDOR / BOLA — UUID Object Reference (${ep})`,
          severity: 'high',
          verification: 'suspected',
          confidence: 68,
          cvss: 8.1,
          cve: null,
          description: `Different UUIDs at '${ep}' return similar JSON structures.`,
          evidence: `${ep}${testUuids[0]} → ${r1.status}, ${testUuids[1]} → ${r2.status}`,
          remediation: 'Apply object-level authorisation for every resource.',
        });
        await onLog(`[${ts()}] ⚠ UUID IDOR SIGNAL: ${ep}`);
        break;
      }
    }
  }

  return findings;
}
