import { checkSubdomainTakeover, discoverSubdomains, runActiveChecks } from "../../scanner";
import type { PhaseContext } from "../types";

/** Phases 5/5b subdomain discovery and takeover adapter. */
export async function runSubdomainsPhase(context: PhaseContext): Promise<void> {
  const discovered = await discoverSubdomains(context.target.hostname, context.log);
  context.addFindings(discovered.findings);
  context.addFindings(await runActiveChecks(
    () => checkSubdomainTakeover(discovered.subs, context.log),
    [],
  ));
}