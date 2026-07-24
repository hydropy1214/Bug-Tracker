import { checkPorts, runActiveChecks } from "../../scanner";
import type { PhaseContext } from "../types";

/** Phase 6 nmap/service discovery adapter. */
export async function runPortsPhase(context: PhaseContext): Promise<void> {
  context.addFindings(await runActiveChecks(
    () => checkPorts(context.target.hostname, "full", context.log),
    [],
  ));
}