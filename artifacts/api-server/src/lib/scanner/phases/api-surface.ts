import { checkApiSurface, runActiveChecks } from "../../scanner";
import type { PhaseContext } from "../types";

/** Phase 13 API surface discovery adapter. */
export async function runApiSurfacePhase(context: PhaseContext): Promise<void> {
  context.addFindings(await runActiveChecks(
    () => checkApiSurface(context.target, context.log),
    [],
  ));
}