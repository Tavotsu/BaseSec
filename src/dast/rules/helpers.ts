import type { DastObservation, HttpResponse } from '../types';

/** Observaciones utilizables: los timeouts (status 0) se ignoran en todas las reglas. */
export function usableObservations(observations: DastObservation[]): DastObservation[] {
  return observations.filter((observation) => observation.response.status !== 0);
}

/** Valores de una cabecera (en minúsculas en el mapa). Vacío si no existe. */
export function headerValues(response: HttpResponse, name: string): string[] {
  const value = response.headers[name.toLowerCase()];
  if (value === undefined) return [];
  return Array.isArray(value) ? [...value] : [value];
}

/** Valor de una cabecera; las repetidas se unen con ", ". undefined si no existe. */
export function header(response: HttpResponse, name: string): string | undefined {
  const values = headerValues(response, name);
  return values.length === 0 ? undefined : values.join(', ');
}

/** true si la cabecera existe y tiene contenido no vacío. */
export function hasValue(value: string | undefined): value is string {
  return value !== undefined && value.trim() !== '';
}

/** true si content-type empieza por text/html o application/xhtml+xml (ignora parámetros). */
export function isHtmlResponse(response: HttpResponse): boolean {
  const contentType = header(response, 'content-type');
  if (contentType === undefined) return false;
  const mime = contentType.trim().toLowerCase();
  return mime.startsWith('text/html') || mime.startsWith('application/xhtml+xml');
}

/**
 * Políticas CSP aplicadas por el navegador. Cada cabecera repetida y cada trozo separado por coma dentro de
 * una cabecera es una política independiente, y el navegador las aplica TODAS (se intersectan).
 */
export function cspPolicies(response: HttpResponse): string[] {
  return headerValues(response, 'content-security-policy')
    .flatMap((value) => value.split(','))
    .map((policy) => policy.trim())
    .filter((policy) => policy !== '');
}

/** Directivas de una CSP: nombre en minúsculas → fuentes. Solo cuenta la primera aparición (CSP3). */
export function parseCsp(policy: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const raw of policy.split(';')) {
    const parts = raw.trim().split(/\s+/).filter((part) => part !== '');
    if (parts.length === 0) continue;
    const name = parts[0].toLowerCase();
    if (!directives.has(name)) directives.set(name, parts.slice(1));
  }
  return directives;
}

/**
 * Valor procedente del servidor, apto para incrustar en un mensaje (que acaba en Markdown/terminal):
 * solo caracteres inocuos, longitud acotada.
 */
export function safeText(value: string, maxLength = 100): string {
  const cleaned = value.replace(/[^A-Za-z0-9 ._/+:;=,()@-]/g, '?');
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength)}...` : cleaned;
}
