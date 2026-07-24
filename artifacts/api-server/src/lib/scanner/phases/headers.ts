import { checkHeaders } from "../../scanner";
import type { PhaseContext } from "../types";

/** Phase 8 HTTP security header and cookie adapter. */
export async function runHeadersPhase(context: PhaseContext): Promise<void> {
  context.addFindings(await checkHeaders(context.target, context.log));
}