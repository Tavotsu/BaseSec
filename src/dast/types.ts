import type { Guard } from './guard';
import type { Finding, RuleCategory, Severity } from '../rules/types';
import type { HttpClient } from './http';
import type { ExtractedRoute } from '../framework/routes/types';

export type { Guard } from './guard';

export interface HttpResponse {
  status: number;
  /** Headers de respuesta en minúsculas. Valor string, o string[] para repetidos (set-cookie). */
  headers: Record<string, string | string[]>;
  /** Body decodificado como texto. '' si no había body o si no se pudo decodificar. */
  body: string;
  /** content-encoding observado en la respuesta final, en minúsculas, o null. */
  contentEncoding: string | null;
  /** false si el body venía en br y no se decodificó (Node no parcheado). */
  bodyDecoded: boolean;
  /** URL final tras seguir redirects. */
  url: string;
  /** Cadena de Location seguidos (vacía si no hubo). */
  redirects: string[];
  /** true si la petición se abortó por timeout. En ese caso status = 0. */
  timedOut: boolean;
  /** Milisegundos de la petición (incluye redirects). */
  elapsedMs: number;
}

export interface HttpRequestOptions {
  headers?: Record<string, string>;
  body?: string | Buffer;
  /** default true. */
  followRedirects?: boolean;
}

export interface HttpClientOptions {
  guard: Guard;
  rps?: number;
  concurrency?: number;
  maxRequests?: number;
  requestTimeout?: number;
  /** Cabeceras enviadas en todas las peticiones (auth del usuario). */
  defaultHeaders?: Record<string, string>;
  /** default 3. */
  maxRedirects?: number;
}

export type GuardErrorCode =
  | 'remote-blocked'
  | 'non-canonical-ip'
  | 'node-vulnerable'
  | 'link-local'
  | 'dns'
  | 'invalid-url'
  | 'method-blocked';

export class GuardError extends Error {
  readonly code: GuardErrorCode;

  constructor(code: GuardErrorCode, message: string) {
    super(message);
    this.name = 'GuardError';
    this.code = code;
  }
}

export class BudgetExceededError extends Error {
  readonly limit: number;

  constructor(limit: number) {
    super(`Presupuesto de peticiones agotado (límite: ${limit}). Análisis incompleto.`);
    this.name = 'BudgetExceededError';
    this.limit = limit;
  }
}

export interface DastTarget {
  /** Origen del target, sin path: "http://localhost:3000". */
  origin: string;
  /** true si el protocolo es https. */
  https: boolean;
}

export interface DastObservation {
  /** "GET /" o "GET /health". */
  endpoint: string;
  /** URL absoluta pedida. */
  url: string;
  method: string;
  response: HttpResponse;
  /** Cabeceras que envió el usuario (sin redactar). Solo para la evidencia. */
  requestHeaders?: Record<string, string>;
  /** Ruta del artefacto que originó esta petición (solo endpoints de la superficie). */
  route?: ExtractedRoute;
  /** Raíz absoluta del artefacto: base de la ubicación del handler. */
  artifactTarget?: string;
}

export interface DastProbeContext {
  target: DastTarget;
  /** Respuestas ya obtenidas (target y healthcheck en esta fase). */
  observations: DastObservation[];
  /** Para reglas que necesitan una petición extra (DAST-004). Pasa por guard, rate limit y budget. */
  client: Pick<HttpClient, 'request'>;
  /** Valores conocidos a redactar en la evidencia (cabeceras del usuario). */
  knownSecrets: string[];
}

export interface DastRule {
  id: string;
  name: string;
  description: string;
  category: RuleCategory;
  severity: Severity;
  /** true = corre una vez por target; false = sobre cada observación. */
  once: boolean;
  mutating?: boolean;
  optIn?: boolean;
  probe(ctx: DastProbeContext): Promise<Finding[]>;
}
