import { checkRateLimiting, runActiveChecks } from "../../scanner";
import type { PhaseContext } from "../types";

/** Phase 21 rate-limit adapter. */
export async function runRateLimitingPhase(context: PhaseContext): Promise<void> {
  context.addFindings(await runActiveChecks(
    () => checkRateLimiting(context.target, context.log),
    [],
  ));
}