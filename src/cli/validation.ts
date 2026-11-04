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
