import { detected, notDetected, scanBody } from './types';
import type { OracleInput, OracleResult } from './types';

/**
 * Firmas de error de driver SQL. Minúsculas. `unrecognized token: "` (con los dos puntos y la comilla de SQLite) y
 * no `unrecognized token` a secas: Jackson y otros parsers JSON dicen "Unrecognized token 'x'" ante cualquier
 * entrada no JSON, sin que haya SQL de por medio.
 */
const SQL_SIGNATURES = [
  'syntax error at or near',
  'you have an error in your sql syntax',
  'sqlite_error',
  'unrecognized token: "',
  'unclosed quotation mark',
  'incorrect syntax near',
];

/** Firmas de MongoDB/Mongoose. Minúsculas. Solo señal de NoSQLi, de confianza baja. */
const MONGO_SIGNATURES = ['mongoservererror', 'casterror'];

/**
 * Error de driver que aparece en el ataque y no en la respuesta benigna. La familia `mongo` solo sirve como
 * señal de NoSQLi (confianza baja, nunca basta sola): no cuenta como SQLi.
 */
export function sqlErrorOracle(input: OracleInput, family: 'sql' | 'mongo' = 'sql'): OracleResult {
  const { baseline, attack } = input;
  const signatures = family === 'sql' ? SQL_SIGNATURES : MONGO_SIGNATURES;
  const attackBody = scanBody(attack).toLowerCase();
  const baselineBody = scanBody(baseline).toLowerCase();
  const fresh = signatures.some((signature) => attackBody.includes(signature) && !baselineBody.includes(signature));
  if (!fresh) return notDetected(`no new ${family === 'sql' ? 'SQL error' : 'MongoDB error'} signature`);
  if (family === 'mongo') return detected('MongoDB error that appears only when an operator is injected', 'low');
  return detected('SQL driver error signature that appears only with the payload', 'medium');
}
