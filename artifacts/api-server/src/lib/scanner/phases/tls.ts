import { checkTls } from "../../scanner";
import type { PhaseContext } from "../types";

/** Phase 7 TLS analysis adapter. */
export async function runTlsPhase(context: PhaseContext): Promise<void> {
  if (context.target.isHttps) {
    context.addFindings(await checkTls(context.target.hostname, context.target.port, context.log));
  }
}