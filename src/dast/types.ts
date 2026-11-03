import type { Guard } from './guard';

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
