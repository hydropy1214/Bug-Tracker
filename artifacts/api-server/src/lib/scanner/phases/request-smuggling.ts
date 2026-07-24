import { checkHttpRequestSmuggling, runActiveChecks } from "../../scanner";
import type { PhaseContext } from "../types";

/** Phase 19 request-smuggling adapter. */
export async function runRequestSmugglingPhase(context: PhaseContext): Promise<void> {
  context.addFindings(await runActiveChecks(
    () => checkHttpRequestSmuggling(context.target, context.log),
    [],
  ));
}