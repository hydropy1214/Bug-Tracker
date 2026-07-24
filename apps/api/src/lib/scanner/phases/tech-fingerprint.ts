import { fingerprint } from '../../scanner';
import type { PhaseContext } from '../types';

/** Phase 9 technology fingerprinting adapter. */
export async function runTechnologyFingerprintPhase(context: PhaseContext): Promise<void> {
  const result = await fingerprint(context.target, context.log);
  context.addFindings(result.findings);
}
