import type { HttpResponse } from '../types';
import { detected, notDetected } from './types';
import type { OracleInput, OracleResult } from './types';

/** Fracción del delay pedido que el ataque debe superar sobre la respuesta benigna y sobre el control. */
export const TIMING_DELAY_FRACTION = 0.8;

export interface TimingInput extends OracleInput {
  /** Petición de control: el mismo payload con delay 0. */
  control: HttpResponse;
  delaySeconds: number;
}

/**
 * Retardo inducido. `attack` es la menor de las dos confirmaciones (el runner envía el payload de delay dos
 * veces con un control entre medias), así que una sola medición lenta por azar no basta. Hace falta que el ataque
 * tarde frente a la benigna Y frente al control (la misma petición con delay 0), y que el control no tarde más
 * que la benigna: un servidor lento que tarda siempre no es inyección. La confianza tiene techo `medium`.
 */
export function timingOracle(input: TimingInput): OracleResult {
  const { baseline, attack, control, delaySeconds } = input;
  if (!(delaySeconds > 0)) return notDetected('no delay to check');
  if (attack.timedOut || attack.status === 0 || control.timedOut || control.status === 0) {
    return notDetected('a response did not complete');
  }
  const threshold = delaySeconds * 1000 * TIMING_DELAY_FRACTION;
  const attackDelta = attack.elapsedMs - baseline.elapsedMs;
  if (attackDelta < threshold) return notDetected('the attack is not slower than the benign response');
  if (attack.elapsedMs - control.elapsedMs < threshold) {
    return notDetected('the attack is not slower than the zero-delay control');
  }
  if (Math.abs(control.elapsedMs - baseline.elapsedMs) >= threshold) {
    return notDetected('the control request is slow too: a slow server, not injection');
  }
  return detected(`the payload delays the response by ${Math.round(attackDelta)} ms and the control does not`, 'medium');
}
