import type { LogFn, RealFinding, ScanPolicy, Target } from "../../types";

/**
 * Explicit policy guard for verification requests that would cross the
 * read-only boundary. These modules intentionally produce no findings.
 */
export async function logRestrictedVerificationModules(
  _target: Target,
  policy: ScanPolicy,
  log: LogFn,
): Promise<RealFinding[]> {
  if (!policy.allowVerification) return [];
  await log("[Phase 24] Restricted verification modules skipped: command execution, file reads, internal/cloud probing, token forgery, credential attempts, account creation, and session/role manipulation are disabled.");
  return [];
}