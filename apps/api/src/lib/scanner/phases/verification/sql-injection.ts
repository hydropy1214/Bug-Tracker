import type { LogFn, RealFinding, ScanPolicy, Target } from '../../types';
import { createFinding } from '../../utils/findings';
import {
  canaryEvidence,
  endpointFromFinding,
  parameterFromFinding,
  redact,
  verificationProbe,
} from './common';

export async function verifySqlInjection(
  target: Target,
  policy: ScanPolicy,
  candidates: RealFinding[],
  log: LogFn,
): Promise<RealFinding[]> {
  if (!policy.allowVerification) return [];
  const findings: RealFinding[] = [];
  const candidate = candidates.find(
    (finding) =>
      /SQL injection|SQLi/i.test(finding.title) &&
      finding.verification === 'suspected' &&
      !/blind/i.test(finding.title),
  );
  if (!candidate) return findings;

  const endpoint = endpointFromFinding(candidate.title, candidate.evidence, target.url);
  const parameter = parameterFromFinding(candidate.title, candidate.evidence);
  if (!endpoint || !parameter) {
    await log(
      '[Phase 24] SQLi verification skipped — no stable endpoint and parameter were captured.',
    );
    return findings;
  }

  const baselineValue = 'sentinelx-baseline';
  const canary = 'SENTINELX_SQLI_CANARY';
  const baseline = await verificationProbe(
    `${endpoint}${endpoint.includes('?') ? '&' : '?'}${encodeURIComponent(parameter)}=${baselineValue}`,
    { timeoutMs: policy.timeoutMs },
  );
  if (!baseline) return findings;

  const payload = `' UNION SELECT '${canary}'--`;
  const result = await verificationProbe(
    `${endpoint}${endpoint.includes('?') ? '&' : '?'}${encodeURIComponent(parameter)}=${encodeURIComponent(payload)}`,
    { timeoutMs: policy.timeoutMs },
  );
  if (!result || !result.body.includes(canary) || baseline.body.includes(canary)) return findings;

  findings.push(
    createFinding({
      title: 'Confirmed SQL Injection — Harmless Output Canary',
      severity: 'high',
      verified: true,
      verification: 'verified',
      confidence: 96,
      evidenceQuality: 'strong',
      verificationMethod: 'Phase 24 bounded UNION canary; no data extraction attempted',
      reproducibility: 'reproducible',
      affectedEndpoint: endpoint,
      affectedParameter: parameter,
      negativeTests: `Baseline value did not contain ${canary}.`,
      limitations:
        'Only a fixed canary was requested. No schema discovery, data extraction, authentication bypass, or modification was attempted.',
      description: `The suspected SQL injection at parameter '${parameter}' reproduced a unique server response containing a fixed canary string. This confirms SQL expression influence without extracting records.`,
      cvss: 8.1,
      cve: null,
      evidence: `${canaryEvidence(endpoint, 'GET', canary, result, 'Canary appeared only after the SQL-shaped input; baseline was clean.')}\nPAYLOAD (redacted form): ${redact(payload)}`,
      remediation:
        'Use parameterised queries or prepared statements for every database operation. Do not concatenate request values into SQL.',
    }),
  );
  await log(`[Phase 24] SQLi canary VERIFIED at ${endpoint} (${parameter})`);
  return findings;
}
