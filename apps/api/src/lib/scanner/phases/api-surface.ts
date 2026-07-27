import { ts } from '../context';
import { probe } from '../utils/http';
import type { RealFinding, Target, LogFn } from '../context';

export async function checkApiSurface(target: Target, onLog: LogFn): Promise<RealFinding[]> {
  const findings: RealFinding[] = [];
  await onLog(`[${ts()}] Probing API documentation and management endpoints...`);

  // GraphQL introspection
  for (const ep of ['/graphql', '/api/graphql', '/gql', '/query', '/v1/graphql']) {
    const url = target.url.replace(/\/$/, '') + ep;
    const r = await probe(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: '{ __schema { types { name } } }' }), timeoutMs: 8_000 });
    if (r?.status === 200 && r.body.includes('__schema')) {
      findings.push({ title: 'GraphQL Introspection Enabled in Production', severity: 'high', cvss: 7.5, cve: null, description: 'GraphQL introspection is enabled, exposing the complete schema.', evidence: `POST ${url} → HTTP ${r.status}`, remediation: 'Disable introspection in production.' });
      break;
    }
  }

  // Swagger / OpenAPI
  for (const ep of ['/swagger','/swagger-ui.html','/api-docs','/openapi.json','/openapi.yaml','/docs','/redoc','/v2/api-docs','/v3/api-docs']) {
    const url = target.url.replace(/\/$/, '') + ep;
    const r = await probe(url, { timeoutMs: 6_000 });
    if (r?.status === 200 && (r.body.toLowerCase().includes('swagger') || r.body.toLowerCase().includes('openapi') || r.body.includes('"paths"'))) {
      findings.push({ title: 'API Documentation (Swagger/OpenAPI) Publicly Exposed', severity: 'medium', cvss: 5.3, cve: null, description: 'API documentation is publicly accessible.', evidence: `GET ${url} → HTTP ${r.status}`, remediation: 'Restrict API docs to authenticated users.' });
      break;
    }
  }

  // Spring Boot Actuator
  for (const ep of ['/actuator/env', '/actuator/heapdump', '/actuator/beans', '/actuator']) {
    const url = target.url.replace(/\/$/, '') + ep;
    const r = await probe(url, { timeoutMs: 6_000 });
    if (r?.status === 200 && (r.body.includes('"activeprofiles"') || r.body.includes('"propertysources"') || r.body.includes('"contexts"') || r.body.includes('"beans"'))) {
      findings.push({ title: `Spring Boot Actuator Endpoint Exposed (${ep})`, severity: ep.includes('env') || ep.includes('heap') ? 'high' : 'medium', cvss: ep.includes('env') || ep.includes('heap') ? 9.8 : 7.5, cve: null, description: `Spring Boot Actuator ${ep} is publicly accessible.`, evidence: `GET ${url} → HTTP ${r.status}`, remediation: 'Restrict Actuator to management port and require authentication.' });
      break;
    }
  }

  // GraphQL query depth limit
  for (const ep of ['/graphql', '/api/graphql', '/gql']) {
    const url = target.url.replace(/\/$/, '') + ep;
    const deepQuery = `{ a { b { c { d { e { f { g { h { i { j { k { l { m { n { o { __typename } } } } } } } } } } } } } } } }`;
    const r = await probe(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: deepQuery }), timeoutMs: 10_000 });
    if (r?.status === 200 && !r.body.toLowerCase().includes('query is too deep') && !r.body.includes('depth limit') && !r.body.includes('maxDepth')) {
      findings.push({ title: 'GraphQL Query Depth Limit Not Enforced', severity: 'medium', cvss: 5.9, cve: null, description: 'A deeply nested GraphQL query (15 levels) was accepted.', evidence: `POST ${url}\nDepth: 15 levels\nHTTP ${r.status}`, remediation: 'Implement query depth limits.' });
      break;
    }
  }

  await onLog(`[${ts()}] API surface scan complete — ${findings.length} finding(s)`);
  return findings;
}
