import type { HttpResponse } from '../types';
import { MAX_SCAN_CHARS, detected, notDetected } from './types';
import type { OracleInput, OracleResult } from './types';

/** El crecimiento solo cuenta si además es al menos esta fracción de la respuesta de ataque. */
const SIGNIFICANT_SHARE = 0.25;
/** Crecimiento mínimo en bytes: cubre lo que añade un reflejo del valor del parámetro (`{"$ne":"BS…"}`). */
const MIN_GROWTH_BYTES = 24;

export interface DiffInput extends OracleInput {
  /** Segundo ataque con el mismo payload (canario distinto): el cambio debe repetirse. */
  attack2: HttpResponse;
  /** Petición con un valor benigno distinto: mide la variación natural de la página. */
  neutral: HttpResponse;
  /** Tercera muestra benigna opcional: afina la variación natural. */
  neutral2?: HttpResponse;
  /**
   * Textos que el servidor puede reflejar en el body (valores benignos y canario). Se descuentan de la longitud
   * antes de comparar: un endpoint que repite el parámetro no cambia de tamaño "por inyección".
   */
  reflected?: string[];
}

function isSuccess(response: HttpResponse): boolean {
  return response.status >= 200 && response.status < 300;
}

/** Longitud del body sin las apariciones de los textos reflejados. Acotada a MAX_SCAN_CHARS. */
function effectiveLength(response: HttpResponse, reflected: string[]): number {
  const body = response.body.length > MAX_SCAN_CHARS ? response.body.slice(0, MAX_SCAN_CHARS) : response.body;
  let length = body.length;
  for (const token of reflected) {
    if (token === '') continue;
    length -= (body.split(token).length - 1) * token.length;
  }
  return length;
}

/**
 * Inyección de operadores NoSQL (p. ej. `param[$ne]=x`). Solo cuenta lo que se parece a un bypass: el ataque
 * responde con éxito (2xx) dos veces seguidas y
 *  - las benignas NO eran 2xx (404/401/403 → 200), o
 *  - las benignas eran 2xx y la respuesta CRECE de forma estable por encima de la variación natural de la página
 *    (el doble de la dispersión entre las muestras benignas), de al menos MIN_GROWTH_BYTES y del 25 %.
 * Un 4xx/5xx ante el operador (validación, `x.trim is not a function`) no es evidencia de inyección, y un cambio
 * que no se repite o que cae dentro de la variación natural (listas de tamaño aleatorio, marcas de tiempo) tampoco.
 * Confianza baja: el cambio es evidencia, no prueba.
 */
export function diffOracle(input: DiffInput): OracleResult {
  const { baseline, attack, attack2, neutral, neutral2 } = input;
  const reflected = [input.canary, ...(input.reflected ?? [])];
  const benign = neutral2 === undefined ? [baseline, neutral] : [baseline, neutral, neutral2];
  if ([...benign, attack, attack2].some((response) => response.status === 0 || response.timedOut)) {
    return notDetected('a response did not complete');
  }
  if (benign.some((response) => response.status !== baseline.status)) return notDetected('the benign response is not stable');
  if (!isSuccess(attack) || !isSuccess(attack2)) return notDetected('the operator does not produce a successful response');

  if (!isSuccess(baseline)) {
    if (attack.status !== attack2.status) return notDetected('the change does not repeat stably');
    return detected('the operator turns an unsuccessful response into a successful one, stably', 'low');
  }

  const benignLengths = benign.map((response) => effectiveLength(response, reflected));
  const natural = Math.max(...benignLengths) - Math.min(...benignLengths);
  const tolerance = 2 * natural;
  const first = effectiveLength(attack, reflected);
  const second = effectiveLength(attack2, reflected);
  if (Math.abs(first - second) > tolerance) return notDetected('the change does not repeat stably');

  const ceiling = Math.max(...benignLengths);
  const growth = Math.min(first, second) - ceiling;
  const size = Math.min(first, second);
  if (growth <= tolerance || growth < MIN_GROWTH_BYTES || growth < SIGNIFICANT_SHARE * size) {
    return notDetected('the change is within the natural variation of the page');
  }
  return detected('the operator makes the response grow, stably', 'low');
}
