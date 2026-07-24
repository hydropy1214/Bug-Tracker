import { checkJwtWeaknesses, runActiveChecks } from "../../scanner";
import type { PhaseContext } from "../types";

/** Phase 17 JWT weakness adapter. */
export async function runJwtPhase(context: PhaseContext): Promise<void> {
  context.addFindings(await runActiveChecks(
    () => checkJwtWeaknesses(context.target, context.log),
    [],
  ));
}