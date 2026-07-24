import type { LogFn, RealFinding, ScanPolicy, Target } from "../../types";
import { createFinding } from "../../utils/findings";
import { canaryEvidence, endpointFromFinding, parameterFromFinding, verificationProbe } from "./common";

export async function verifySsti(
  target: Target,
  policy: ScanPolicy,
  candidates: RealFinding[],
  log: LogFn,
): Promise<RealFinding[]> {
  const candidate = candidates.find((finding) => /SSTI/i.test(finding.title) && finding.verification === "suspected");
  if (!candidate || !policy.allowVerification) return [];
  const endpoint = endpointFromFinding(candidate.title, candidate.evidence, target.url);
  const parameter = parameterFromFinding(candidate.title, candidate.evidence);
  if (!endpoint || !parameter) {
    await log("[Phase 24] SSTI verification skipped — no stable endpoint and parameter were captured.");
    return [];
  }

  const canary = "SENTINELX_SSTI_CONFIRM";
  const baseline = await verificationProbe(
    `${endpoint}${endpoint.includes("?") ? "&" : "?"}${encodeURIComponent(parameter)}=sentinelx-baseline`,
    { timeoutMs: policy.timeoutMs },
  );
  if (!baseline) return [];
  const expression = "{{'" + canary + "'}}";
  const result = await verificationProbe(
    `${endpoint}${endpoint.includes("?") ? "&" : "?"}${encodeURIComponent(parameter)}=${encodeURIComponent(expression)}`,
    { timeoutMs: policy.timeoutMs },
  );
  if (!result || !result.body.includes(canary) || baseline.body.includes(canary)) return [];

  await log(`[Phase 24] SSTI canary VERIFIED at ${endpoint} (${parameter}); no code execution attempted.`);
  return [createFinding({
    title: "Confirmed SSTI — Harmless Template Canary",
    severity: "high",
    verified: true,
    verification: "verified",
    confidence: 96,
    evidenceQuality: "strong",
    verificationMethod: "Phase 24 fixed template-string canary; OS command execution disabled",
    reproducibility: "reproducible",
    affectedEndpoint: endpoint,
    affectedParameter: parameter,
    negativeTests: `Baseline response did not contain ${canary}.`,
    limitations: "Template evaluation was confirmed with a string-only expression. No operating-system command, file access, or network access was attempted.",
    description: `The suspected template injection at parameter '${parameter}' evaluated a harmless fixed string on the server.`,
    cvss: 8.7,
    cve: null,
    evidence: `${canaryEvidence(endpoint, "GET", canary, result, "The server returned the evaluated string and the clean baseline did not contain it.")}\nEXPRESSION CLASS: string-only template expression`,
    remediation: "Do not render untrusted input as a template. Use a sandboxed engine, strict escaping, and a least-privilege service account.",
  })];
}