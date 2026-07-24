import { checkWebApp, runActiveChecks } from '../../scanner';
import type { PhaseContext } from '../types';

/** Phase 12 application vulnerability probe adapter. */
export async function runWebAppProbesPhase(context: PhaseContext): Promise<void> {
  context.addFindings(await runActiveChecks(() => checkWebApp(context.target, context.log), []));
}
