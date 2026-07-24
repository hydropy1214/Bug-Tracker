import { checkPathTraversal, runActiveChecks } from "../../scanner";
import type { PhaseContext } from "../types";

/** Phase 16 path traversal adapter. */
export async function runPathTraversalPhase(context: PhaseContext): Promise<void> {
  context.addFindings(await runActiveChecks(
    () => checkPathTraversal(context.target, context.log),
    [],
  ));
}