import type { LogFn, RealFinding, ScanPolicy, Target } from '../../types';
import { createFinding } from '../../utils/findings';
import { endpointFromFinding, verificationProbe } from './common';

export async function verifyGraphql(
  target: Target,
  policy: ScanPolicy,
  candidates: RealFinding[],
  log: LogFn,
): Promise<RealFinding[]> {
  if (!policy.allowVerification) return [];
  const candidate = candidates.find((finding) => /GraphQL Endpoint/i.test(finding.title));
  const endpoints = candidate
    ? [
        endpointFromFinding(candidate.title, candidate.evidence, target.url) ??
          `${target.url.replace(/\/$/, '')}/graphql`,
      ]
    : [`${target.url.replace(/\/$/, '')}/graphql`, `${target.url.replace(/\/$/, '')}/api/graphql`];
  const query = JSON.stringify({ query: '{__schema{queryType{name}}}' });
  for (const endpoint of endpoints) {
    const response = await verificationProbe(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: query,
      timeoutMs: policy.timeoutMs,
    });
    if (!response || response.status !== 200 || !response.body.includes('__schema')) continue;
    await log(
      `[Phase 24] GraphQL introspection VERIFIED at ${endpoint}; no sensitive fields queried.`,
    );
    return [
      createFinding({
        title: 'GraphQL Introspection Enabled',
        severity: 'medium',
        verified: true,
        verification: 'verified',
        confidence: 94,
        evidenceQuality: 'strong',
        verificationMethod: 'Phase 24 read-only GraphQL __schema query',
        reproducibility: 'reproducible',
        affectedEndpoint: endpoint,
        negativeTests:
          'Only the schema root name was requested; no mutations or application data were queried.',
        limitations:
          'This check confirms schema introspection only. It does not test authorization, query depth, or sensitive fields.',
        description:
          'The GraphQL endpoint accepted a minimal read-only introspection query and returned schema metadata.',
        cvss: 5.3,
        cve: null,
        evidence: `REQUEST: POST ${endpoint}\nQUERY: {__schema{queryType{name}}}\nRESPONSE: HTTP ${response.status}\nSCHEMA MARKER: __schema present`,
        remediation:
          'Disable introspection in production where it is not required, or restrict it to trusted tooling and authenticated development environments.',
      }),
    ];
  }
  return [];
}
