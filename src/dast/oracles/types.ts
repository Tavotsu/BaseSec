import type { Confidence } from '../../rules/types';
import type { HttpResponse } from '../types';

/**
 * Tope de caracteres del body que escanea un oráculo. El body viene de un servidor posiblemente hostil (el cliente
 * lo limita a 8 MiB): las firmas se buscan con `includes` (lineal) y solo en este prefijo.
 */
export const MAX_SCAN_CHARS = 1_000_000;

/** Prefijo del body acotado por MAX_SCAN_CHARS. */
export function scanBody(response: HttpResponse): string {
  return response.body.length > MAX_SCAN_CHARS ? response.body.slice(0, MAX_SCAN_CHARS) : response.body;
}

/** Entrada común de los oráculos. Respuestas ya obtenidas; los oráculos no hacen peticiones. */
export interface OracleInput {
  /** Respuesta benigna del mismo punto de inyección. */
  baseline: HttpResponse;
  /** Respuesta al payload. */
  attack: HttpResponse;
  /** Canario del envío. */
  canary: string;
  /** Payload ya con el canario sustituido. */
  payloadText: string;
}

export interface OracleResult {
  detected: boolean;
  confidence: Confidence;
  /** Frase fija y corta que explica la decisión; nunca contiene texto del servidor. */
  detail: string;
}

export function notDetected(detail: string, confidence: Confidence = 'low'): OracleResult {
  return { detected: false, confidence, detail };
}

export function detected(detail: string, confidence: Confidence): OracleResult {
  return { detected: true, confidence, detail };
}
