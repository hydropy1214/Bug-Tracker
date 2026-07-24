import type { RealFinding } from "../types";

export type FindingInput = Omit<RealFinding, "confidence" | "evidenceQuality" | "reproducibility"> &
  Partial<Pick<RealFinding, "confidence" | "evidenceQuality" | "reproducibility">>;

/** Normalizes audit metadata for findings emitted by extracted phases. */
export function createFinding(input: FindingInput): RealFinding {
  return {
    ...input,
    confidence: Math.max(0, Math.min(100, Math.round(input.confidence ?? 80))),
    evidenceQuality: input.evidenceQuality ?? "standard",
    reproducibility: input.reproducibility ?? "not_tested",
  };
}