import type { LogFn, RealFinding, ScanPolicy, Target } from "../../types";
import { activeProbesAllowed } from "../../../scanner";
import { verifyGraphql } from "./graphql";
import { logRestrictedVerificationModules } from "./restricted";
import { verifySsti } from "./ssti";
import { verifySqlInjection } from "./sql-injection";

export async function phase24Verification(
  target: Target,
  policy: ScanPolicy,
  candidates: RealFinding[],
  log: LogFn,
): Promise<RealFinding[]> {
  if (!policy.allowVerification || !activeProbesAllowed()) {
    await log("[Phase 24] Verification not run because the profile is not authorized or a WAF/rate-limit challenge was detected.");
    return [];
  }

  const findings: RealFinding[] = [];
  for (const verifier of [
    () => verifySqlInjection(target, policy, candidates, log),
    () => verifySsti(target, policy, candidates, log),
    () => verifyGraphql(target, policy, candidates, log),
  ]) {
    if (!activeProbesAllowed()) break;
    findings.push(...await verifier());
  }
  findings.push(...await logRestrictedVerificationModules(target, policy, log));
  await log(`[Phase 24] Verification complete — ${findings.length} bounded confirmation finding(s); allowance capped at ${policy.verificationRequestBudget} request(s).`);
  return findings;
}