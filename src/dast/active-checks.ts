import type { Finding } from '../rules/types';
import type { ExtractedRoute } from '../framework/routes/types';
import type { HttpClient } from './http';
import type { DastObservation, DastRule, HttpResponse } from './types';
import { BudgetExceededError, CREDENTIAL_HEADER, GuardError } from './types';
import { dynamicFinding } from './probe';
import type { SurfaceEndpoint } from './surface';
import { logger } from '../utils/logger';

/** Comprobaciones activas que no son payloads de inyección. El runner las llama en modo full. */
export const ACTIVE_RULE_IDS: readonly string[] = ['DAST-008', 'DAST-010'];

/** Peticiones de la ráfaga de DAST-010 (plan §4.3). */
const RATE_LIMIT_BURST = 30;
/**
 * Métodos que DAST-008 pide sin credenciales. OPTIONS queda fuera: casi todo servidor responde 2xx al preflight CORS o
 * con `Allow` sin autenticar, y eso no prueba que el recurso sea alcanzable.
 */
const AUTH_CHECK_METHODS = new Set(['GET', 'HEAD']);
/** Palabras (en singular o plural) que, como palabra completa del path, hacen sensible una ruta. */
const SENSITIVE_WORDS = new Set([
  'admin', 'administrator', 'internal', 'debug', 'config', 'configuration', 'metrics', 'account', 'settings',
  'setting', 'dashboard', 'private', 'secret',
]);
/** Parámetros que nombran al dueño de un recurso: sensibles en cualquier ruta. */
const OWNER_PARAMS = new Set(['userid', 'uid', 'accountid', 'customerid', 'memberid', 'ownerid']);
/**
 * Recursos de usuario o cuenta: un parámetro (`:id`) tras ellos identifica datos de una persona. Tras `products`,
 * `posts`, `categories`… un `:id` es de un catálogo y no se considera sensible.
 */
const USER_RESOURCES = new Set([
  'user', 'users', 'account', 'accounts', 'customer', 'customers', 'member', 'members', 'profile', 'profiles', 'order',
  'orders', 'invoice', 'invoices', 'payment', 'payments', 'message', 'messages', 'cart', 'carts', 'wallet', 'wallets',
  'me',
]);
/** Parámetro de path de Express: `:id`, `:id?`, `:id(\\d+)`. */
const PARAM_SEGMENT = /^:(\w+)(?:\(.*\))?[?+*]?$/;
/** Palabras que, como palabra completa del path, marcan un login o una ruta de autenticación para DAST-010. */
const RATE_LIMIT_WORDS = new Set(['login', 'signin', 'auth', 'oauth', 'authenticate', 'token', 'tokens', 'session', 'sessions']);
/** Rutas públicas habituales: nunca se reportan por DAST-008. Comparadas en minúsculas. */
const PUBLIC_PATHS = new Set(['/', '/login', '/logout', '/register', '/signup', '/status', '/ready', '/live', '/ping', '/favicon.ico']);
/** Último segmento de una página de acceso (`/admin/login`): pública por naturaleza. */
const AUTH_ENTRY_SEGMENTS = new Set(['login', 'logout', 'register', 'signup', 'signin', 'forgot-password', 'reset-password']);
const HEALTH_SEGMENT = /^health(?:z|-?check)?$/;
/** Cabeceras de rate limit: retry-after, ratelimit (IETF), ratelimit-*, x-ratelimit-* y x-rate-limit-*. */
const RATE_LIMIT_HEADER = /^(?:retry-after|ratelimit(?:-.+)?|x-ratelimit(?:-.+)?|x-rate-limit(?:-.+)?)$/;
const LOGIN_FORM = /<input\b[^>]*\btype\s*=\s*["']?password/i;
const LOGIN_SCAN_CHARS = 200_000;

export const UNAUTH_RULE: Pick<DastRule, 'id' | 'name' | 'category' | 'severity' | 'once'> = {
  id: 'DAST-008',
  name: 'Unauthenticated sensitive endpoint',
  category: 'auth',
  severity: 'medium',
  once: false,
};

export const RATE_LIMIT_RULE: Pick<DastRule, 'id' | 'name' | 'category' | 'severity' | 'once'> = {
  id: 'DAST-010',
  name: 'Missing rate limiting',
  category: 'auth',
  severity: 'low',
  // false: si el objetivo es una ruta del artefacto, el hallazgo se ubica en su handler (ver dynamicFinding).
  once: false,
};

/** Ruta de la superficie resuelta contra el origen del target. */
export interface SurfaceTarget {
  endpoint: SurfaceEndpoint;
  url: string;
}

export interface ActiveCheckContext {
  client: Pick<HttpClient, 'request'>;
  /** Cabeceras que el usuario envía en cada petición (sin redactar). Solo para la evidencia. */
  requestHeaders: Record<string, string>;
  knownSecrets: string[];
  artifactTarget?: string;
  /** Patrones de `dast.publicRoutes`. */
  publicRoutes: string[];
  deadlineReached: () => boolean;
}

export interface ActiveCheckResult {
  findings: Finding[];
  /** Presente si la comprobación se cortó por presupuesto o por tiempo. Conserva los hallazgos ya obtenidos. */
  incomplete?: 'budget' | 'timeout';
}

/** Segmento a segmento: `*` casa con exactamente uno; el resto se compara literal, sin distinguir mayúsculas. */
function matchesPattern(routePath: string, pattern: string): boolean {
  const normalize = (value: string): string => value.replace(/\/+$/, '') || '/';
  const pathSegments = normalize(routePath.toLowerCase()).split('/');
  const patternSegments = normalize(pattern.toLowerCase()).split('/');
  if (pathSegments.length !== patternSegments.length) return false;
  return patternSegments.every((segment, index) => segment === '*' || segment === pathSegments[index]);
}

/** Palabras de un segmento estático: separa por no alfanuméricos y por camelCase (`getAdminUsers` → get, admin, users). */
function wordsOf(segment: string): string[] {
  return segment
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((word) => word !== '');
}

/**
 * Ruta sensible: contiene como palabra completa admin, internal, debug, config, metrics, account, settings,
 * dashboard, private o secret (no `international` ni `accounting`), o lleva un parámetro de dueño (`:userId`,
 * `:uid`, `:accountId`…) o un parámetro tras un recurso de usuario (`/users/:id`, `/orders/:id`). Un `:id` tras
 * `/products` no es sensible. Una colección sin parámetro (`/users`, `/profile`) tampoco lo es por sí sola: es una
 * decisión conservadora para no reportar listados públicos; añade el análisis de contenido en una fase posterior.
 */
export function isSensitivePath(routePath: string): boolean {
  const segments = routePath.split('/').filter((segment) => segment !== '');
  return segments.some((segment, index) => {
    if (!segment.startsWith(':')) {
      return wordsOf(segment).some((word) => SENSITIVE_WORDS.has(word) || SENSITIVE_WORDS.has(word.replace(/s$/, '')));
    }
    const param = PARAM_SEGMENT.exec(segment);
    if (param === null) return false;
    if (OWNER_PARAMS.has(param[1].toLowerCase())) return true;
    const previous = segments[index - 1];
    return previous !== undefined && !previous.startsWith(':') && USER_RESOURCES.has(previous.toLowerCase());
  });
}

/** Rutas públicas por convención, páginas de acceso o `dast.publicRoutes`. Sin distinguir mayúsculas ni `/` final. */
export function isPublicRoute(routePath: string, publicRoutes: string[]): boolean {
  const lower = routePath.toLowerCase().replace(/\/+$/, '') || '/';
  if (PUBLIC_PATHS.has(lower)) return true;
  const segments = lower.split('/').filter((segment) => segment !== '');
  if (segments.length > 0 && HEALTH_SEGMENT.test(segments[0])) return true;
  if (segments.length > 0 && AUTH_ENTRY_SEGMENTS.has(segments[segments.length - 1])) return true;
  return publicRoutes.some((pattern) => matchesPattern(routePath, pattern));
}

/**
 * Una respuesta 2xx que en realidad pide autenticar: formulario con campo de contraseña o `WWW-Authenticate`. No
 * prueba que el recurso sea alcanzable. Un login con otro formato (JSON, SPA) no se reconoce: limitación documentada.
 */
function looksLikeAuthWall(response: HttpResponse): boolean {
  if ('www-authenticate' in response.headers) return true;
  const type = response.headers['content-type'];
  const contentType = Array.isArray(type) ? type.join(';') : (type ?? '');
  if (!/html/i.test(contentType)) return false;
  return LOGIN_FORM.test(response.body.slice(0, LOGIN_SCAN_CHARS));
}

/** Cabeceras sin las de credenciales, para documentar en la evidencia lo que realmente se envió. */
function withoutCredentialHeaders(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(headers).filter(([name]) => !CREDENTIAL_HEADER.test(name)));
}

function hasRateLimitHeader(response: HttpResponse): boolean {
  return Object.keys(response.headers).some((name) => RATE_LIMIT_HEADER.test(name.toLowerCase()));
}

/**
 * DAST-008: una ruta sensible de solo lectura sin auth en el artefacto que responde 2xx sin credenciales. Hace como
 * mucho una petición por candidata; reutiliza la observación del endpoint solo si el usuario no envió credenciales.
 */
export async function runAuthCheck(
  targets: SurfaceTarget[],
  observations: DastObservation[],
  ctx: ActiveCheckContext,
): Promise<ActiveCheckResult> {
  const findings: Finding[] = [];
  const carriesCredentials = Object.keys(ctx.requestHeaders).some((name) => CREDENTIAL_HEADER.test(name));

  for (const { endpoint, url } of targets) {
    const { route } = endpoint;
    if (!AUTH_CHECK_METHODS.has(endpoint.method) || route.hasAuth !== false) continue;
    if (!isSensitivePath(route.path) || isPublicRoute(route.path, ctx.publicRoutes)) continue;
    if (ctx.deadlineReached()) return { findings, incomplete: 'timeout' };

    const label = `${endpoint.method} ${route.path}`;
    // La observación solo sirve si no llevaba credenciales y no siguió redirects: un /admin que redirige a un /login
    // con 200 no es "alcanzable". En ese caso se repite con followRedirects:false y el 3xx descarta el candidato.
    const reused = carriesCredentials
      ? undefined
      : observations.find(
          (o) =>
            o.url === url &&
            o.method === endpoint.method &&
            o.response.status !== 0 &&
            !o.response.timedOut &&
            o.response.redirects.length === 0,
        );

    let response: HttpResponse;
    let requestHeaders: Record<string, string>;
    if (reused) {
      response = reused.response;
      requestHeaders = reused.requestHeaders ?? {};
    } else {
      try {
        response = await ctx.client.request(endpoint.method, url, { followRedirects: false, withoutCredentials: true });
      } catch (e) {
        if (e instanceof BudgetExceededError) return { findings, incomplete: 'budget' };
        if (e instanceof GuardError) throw e;
        logger.warn(`DAST-008: fallo de red al pedir ${label}`, e);
        continue;
      }
      requestHeaders = withoutCredentialHeaders(ctx.requestHeaders);
    }

    if (response.timedOut || response.status === 0) continue;
    if (response.status < 200 || response.status > 299) continue;
    if (looksLikeAuthWall(response)) continue;

    findings.push(
      dynamicFinding({
        rule: UNAUTH_RULE,
        confidence: 'low',
        endpoint: label,
        message: `${label}: sensitive route is reachable without authentication (static analysis found no auth guard).`,
        remediation:
          'Add an authentication middleware or guard to this route. If it is meant to be public, list it in dast.publicRoutes in the configuration file.',
        references: [
          'https://cwe.mitre.org/data/definitions/306.html',
          'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/',
        ],
        codeSnippet: label,
        observation: {
          endpoint: label,
          url,
          method: endpoint.method,
          response,
          requestHeaders,
          route,
          artifactTarget: ctx.artifactTarget,
        },
        knownSecrets: ctx.knownSecrets,
      }),
    );
  }
  return { findings };
}

/**
 * Elige la base de DAST-010: el primer GET de la superficie cuyo path parece de login o autenticación; si no hay,
 * el healthcheck (o `/` si no respondió). undefined si no hay observación válida del objetivo o ya respondía error:
 * en ese caso la sonda no tiene sentido.
 */
export function pickRateLimitTarget(
  surface: SurfaceTarget[],
  observations: DastObservation[],
  healthUrl: string,
  rootUrl: string,
): DastObservation | undefined {
  const matching = surface.find(
    (target) =>
      target.endpoint.method === 'GET' &&
      target.endpoint.route.path.split('/').some((segment) =>
        !segment.startsWith(':') && wordsOf(segment).some((word) => RATE_LIMIT_WORDS.has(word)),
      ),
  );
  const observed = (url: string): boolean => observations.some((o) => o.method === 'GET' && o.url === url);
  const url = matching?.url ?? (observed(healthUrl) ? healthUrl : rootUrl);
  const base = observations.find((o) => o.method === 'GET' && o.url === url);
  if (base === undefined || base.response.status >= 400) return undefined;
  return base;
}

/**
 * DAST-010: 30 GET en ráfaga al objetivo sin el espaciado de rps. Reporta solo si todas las respuestas llegaron, ninguna
 * es 429 y ninguna trae cabeceras de rate limit. Si el presupuesto se agota a mitad, no concluye y marca `budget`.
 */
export async function runRateLimitCheck(base: DastObservation, ctx: ActiveCheckContext): Promise<ActiveCheckResult> {
  if (ctx.deadlineReached()) return { findings: [], incomplete: 'timeout' };

  const settled = await Promise.allSettled(
    Array.from({ length: RATE_LIMIT_BURST }, () =>
      ctx.client.request('GET', base.url, { bypassRateLimit: true, followRedirects: false }),
    ),
  );

  const responses: HttpResponse[] = [];
  let budgetHit = false;
  let failed = false;
  for (const result of settled) {
    if (result.status === 'fulfilled') {
      responses.push(result.value);
    } else if (result.reason instanceof GuardError) {
      throw result.reason;
    } else if (result.reason instanceof BudgetExceededError) {
      budgetHit = true;
    } else {
      failed = true;
      logger.warn('DAST-010: fallo de red en la ráfaga', result.reason);
    }
  }
  if (budgetHit) return { findings: [], incomplete: 'budget' };
  if (failed || responses.some((response) => response.timedOut || response.status === 0)) return { findings: [] };
  if (responses.some((response) => response.status === 429 || hasRateLimitHeader(response))) return { findings: [] };
  // Un error a mitad de la ráfaga (403 de un WAF, 503 por saturación) es otra forma de limitar o de caerse: no concluye.
  if (responses.some((response) => response.status >= 400)) return { findings: [] };

  const last = responses[responses.length - 1];
  const route: ExtractedRoute | undefined = base.route;
  const label = route !== undefined ? `GET ${route.path}` : `GET ${new URL(base.url).pathname}`;
  const finding = dynamicFinding({
    rule: RATE_LIMIT_RULE,
    confidence: 'low',
    endpoint: label,
    message: `No rate limiting observed on ${label} after ${RATE_LIMIT_BURST} rapid requests.`,
    remediation:
      'Apply rate limiting to authentication and other sensitive endpoints, for example express-rate-limit or an equivalent gateway limit. Answer with HTTP 429 and a Retry-After header when the limit is reached.',
    references: [
      'https://cwe.mitre.org/data/definitions/307.html',
      'https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/',
    ],
    codeSnippet: label,
    observation: {
      endpoint: label,
      url: base.url,
      method: 'GET',
      response: last,
      requestHeaders: ctx.requestHeaders,
      route,
      artifactTarget: ctx.artifactTarget,
    },
    knownSecrets: ctx.knownSecrets,
  });
  return { findings: [finding] };
}
