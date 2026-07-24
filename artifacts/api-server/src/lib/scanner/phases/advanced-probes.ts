import {
  checkCommandInjection,
  checkDeserialization,
  checkNoSqlInjection,
  checkSSTI,
  checkSSRF,
  checkXXE,
} from "./advanced/index";
import type { PhaseContext } from "../types";

/** Phase 22/27 advanced vulnerability probe adapter. */
export async function runAdvancedProbesPhase(context: PhaseContext): Promise<void> {
  const results = await Promise.all([
    checkSSTI(context.target, context.log),
    checkXXE(context.target, context.log),
    checkSSRF(context.target, context.log),
    checkDeserialization(context.target, context.log),
    checkCommandInjection(context.target, context.log),
    checkNoSqlInjection(context.target, context.log),
  ]);
  results.forEach((findings) => context.addFindings(findings));
}