import { checkCrlfInjection, runActiveChecks } from "../../scanner";
import type { PhaseContext } from "../types";

/** Phase 15 CRLF/response splitting adapter. */
export async function runCrlfPhase(context: PhaseContext): Promise<void> {
  context.addFindings(await runActiveChecks(
    () => checkCrlfInjection(context.target, context.log),
    [],
  ));
}