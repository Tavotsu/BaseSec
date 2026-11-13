import type { OutputFormat, Severity } from '../rules/types';

export const VALID_FORMATS: OutputFormat[] = ['terminal', 'json', 'sarif', 'html', 'markdown'];
export const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Combinaciones válidas de --emit-routes / --routes-out / --ai. Devuelve el mensaje de error
 * o undefined si son válidas.
 */
export function validateRouteOptions(options: {
  emitRoutes: boolean;
  routesOut?: string;
  ai: boolean;
}): string | undefined {
  if (options.routesOut !== undefined && !options.emitRoutes) {
    return '--routes-out requires --emit-routes.';
  }
  if (options.emitRoutes && options.ai) {
    return '--emit-routes cannot be combined with --ai (no LLM calls are made when only the route artifact is written).';
  }
  return undefined;
}

/**
 * Combinaciones válidas de --verify / --target / --dast-* en `scan`. Devuelve el mensaje de error o undefined.
 * `dastFlags` lista los flags de este bloque que el usuario pasó (p. ej. "--dast-rps").
 */
export function validateVerifyOptions(options: {
  verify: boolean;
  target?: string;
  emitRoutes: boolean;
  ai: boolean;
  dastFlags: string[];
}): string | undefined {
  if (!options.verify) {
    if (options.dastFlags.length > 0) {
      return `${options.dastFlags.join(', ')} require${options.dastFlags.length === 1 ? 's' : ''} --verify.`;
    }
    return undefined;
  }
  if (options.target === undefined || options.target.trim() === '') {
    return '--verify requires --target <url>.';
  }
  if (options.emitRoutes) {
    return '--verify cannot be combined with --emit-routes.';
  }
  if (options.ai) {
    return '--verify cannot be combined with --ai (the runtime check makes no LLM calls).';
  }
  return undefined;
}
