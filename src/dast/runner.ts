import { Guard } from './guard';
import { HttpClient } from './http';
import { ALL_DAST_RULES } from './rules/index';
import { createEvidenceWriter } from './evidence';
import { DastConfigError, expandEnvHeaders } from './config';
import { observationOf } from './probe';
import { BudgetExceededError, GuardError } from './types';
import type { DastObservation, DastProbeContext, DastRule } from './types';
import type { HttpResponse, HttpRequestOptions } from './types';
import { isDotSegment, toSurfaceEndpoints } from './surface';
import type { LoadedSurface, SurfaceEndpoint } from './surface';
import { ResultStore } from '../core/result-store';
import type { DastStats, Finding, ScanResult } from '../rules/types';
import { logger } from '../utils/logger';

export interface DastRunOptions {
  url: string;
  health?: string;               // path, default '/'
  headers?: Record<string, string>;
  allowRemote?: boolean;
  allowRemoteEnv?: boolean;
  allowVulnerableNode?: boolean;
  isTTY?: boolean;
  rps?: number;
  concurrency?: number;
  maxRequests?: number;
  timeout?: number;              // s, default 300
  requestTimeout?: number;       // ms, default 10000
  evidence?: boolean;            // default true
  evidenceDir?: string;
  rules?: string[];              // filtro de IDs DAST
  /** Superficie de ataque (artefacto de rutas). Sin ella, solo se observan `/` y el healthcheck. */
  surface?: LoadedSurface;
  onProgress?: (event: { done: number; total: number; requests: number; label: string }) => void;
  /** Inyección para tests. */
  resolver?: (hostname: string) => Promise<string[]>;
}

export class DastTargetUnreachableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DastTargetUnreachableError';
  }
}

const DEFAULT_TIMEOUT_S = 300;
const DEFAULT_REQUEST_TIMEOUT_MS = 10000;

function assertPositiveInteger(name: string, value: number | undefined): void {
  if (value !== undefined && !(Number.isInteger(value) && value > 0)) {
    throw new DastConfigError(`${name} must be a positive integer`);
  }
}

/** El healthcheck es un path del mismo origen: nunca un esquema, un host ni una barra invertida. */
function resolveHealth(origin: string, health: string): URL {
  if (!health.startsWith('/') || health.startsWith('//') || health.includes('\\') || health.includes('://')) {
    throw new DastConfigError('Healthcheck path must start with "/" and must not be an absolute URL');
  }
  const resolved = new URL(health, origin);
  if (resolved.origin !== origin) {
    throw new DastConfigError('Healthcheck path must stay on the target origin');
  }
  return resolved;
}

/**
 * Valores a redactar: los de las cabeceras del usuario y, para "Esquema credencial", la credencial sola
 * (un servidor que repita el token sin el esquema tampoco debe filtrarlo).
 */
function collectSecrets(headers: Record<string, string>): string[] {
  const secrets = new Set<string>();
  for (const value of Object.values(headers)) {
    if (value === '') continue;
    secrets.add(value);
    const credential = /^\S+\s+(\S{3,})$/.exec(value.trim())?.[1];
    if (credential) secrets.add(credential);
  }
  return [...secrets];
}

/**
 * URL absoluta de un endpoint de la superficie, o undefined si no queda en el origen del target
 * (plan §2: segunda barrera además de la validación del artefacto).
 */
export function resolveEndpointUrl(origin: string, concretePath: string): string | undefined {
  // new URL colapsa "." y ".." (también %2e) y trata "//host" y "\\" como autoridad: se descartan antes de resolver.
  if (!concretePath.startsWith('/') || concretePath.startsWith('//') || concretePath.includes('\\')) return undefined;
  if (concretePath.split('/').some(isDotSegment)) return undefined;
  try {
    const url = new URL(concretePath, origin);
    return url.origin === origin ? url.href : undefined;
  } catch (e) {
    logger.warn('Ruta de endpoint no válida', e);
    return undefined;
  }
}

function selectRules(ids: string[] | undefined): DastRule[] {
  const byId = (a: DastRule, b: DastRule): number => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const wanted = (ids ?? []).map((id) => id.trim().toUpperCase()).filter((id) => id !== '');
  if (wanted.length === 0) return [...ALL_DAST_RULES].sort(byId);
  const known = new Set(ALL_DAST_RULES.map((rule) => rule.id));
  const unknown = wanted.filter((id) => !known.has(id));
  if (unknown.length > 0) {
    throw new DastConfigError(
      `Unknown DAST rule ID(s): ${unknown.join(', ')}. Valid IDs: ${[...known].sort().join(', ')}`,
    );
  }
  return ALL_DAST_RULES.filter((rule) => wanted.includes(rule.id)).sort(byId);
}

/**
 * Ejecuta el análisis DAST: GET a `/` y al healthcheck y las reglas DAST-001…007. Con `surface`, además
 * GET/HEAD/OPTIONS a cada endpoint del artefacto (los mutantes se cuentan y no se piden). Lanza GuardError
 * (barandillas), DastConfigError y DastTargetUnreachableError; el resto de fallos de reglas se registran con
 * logger.warn y no detienen el análisis.
 */
export async function runDast(opts: DastRunOptions): Promise<ScanResult> {
  const started = Date.now();
  assertPositiveInteger('rps', opts.rps);
  assertPositiveInteger('concurrency', opts.concurrency);
  assertPositiveInteger('maxRequests', opts.maxRequests);
  assertPositiveInteger('timeout', opts.timeout);
  assertPositiveInteger('requestTimeout', opts.requestTimeout);
  const deadline = started + (opts.timeout ?? DEFAULT_TIMEOUT_S) * 1000;

  const headers = expandEnvHeaders(opts.headers ?? {});
  const knownSecrets = collectSecrets(headers);

  const guard = new Guard({
    allowRemote: opts.allowRemote,
    allowRemoteEnv: opts.allowRemoteEnv,
    allowVulnerableNode: opts.allowVulnerableNode,
    resolver: opts.resolver,
  });
  guard.assertNodeSupported();
  await guard.assertTargetAllowed(opts.url, { isTTY: opts.isTTY });

  const parsed = new URL(opts.url);
  const origin = parsed.origin;
  const healthUrl = resolveHealth(origin, opts.health ?? '/');
  const rules = selectRules(opts.rules);

  const client = new HttpClient({
    guard,
    rps: opts.rps,
    concurrency: opts.concurrency,
    maxRequests: opts.maxRequests,
    requestTimeout: opts.requestTimeout ?? DEFAULT_REQUEST_TIMEOUT_MS,
    defaultHeaders: headers,
  });

  // Todos los intercambios HTTP, incluidas las peticiones extra de las reglas (p. ej. DAST-004), indexados
  // por el objeto de respuesta: cada hallazgo apunta (observationOf) a la observación que lo produjo y su
  // respuesta identifica el intercambio exacto, sin comparar textos.
  const exchanges = new Map<HttpResponse, DastObservation>();
  let budgetHit = false;
  let guardFailure: GuardError | undefined;
  const trackedClient: Pick<HttpClient, 'request'> = {
    async request(method: string, url: string, reqOpts: HttpRequestOptions = {}): Promise<HttpResponse> {
      try {
        const response = await client.request(method, url, reqOpts);
        if (!response.timedOut) {
          exchanges.set(response, {
            endpoint: `${method.toUpperCase()} ${new URL(url).pathname}`,
            url,
            method: method.toUpperCase(),
            response,
            requestHeaders: { ...headers, ...(reqOpts.headers ?? {}) },
          });
        }
        return response;
      } catch (e) {
        if (e instanceof BudgetExceededError) budgetHit = true;
        // Una barandilla que salta a mitad de análisis (p. ej. el DNS ahora apunta fuera) es fatal aunque una regla la trague.
        if (e instanceof GuardError && guardFailure === undefined) guardFailure = e;
        throw e;
      }
    },
  };

  const targets: Array<{ label: string; url: string }> = [{ label: 'GET /', url: `${origin}/` }];
  if (healthUrl.href !== `${origin}/`) {
    targets.push({ label: `GET ${healthUrl.pathname}`, url: healthUrl.href });
  }

  // Superficie: solo los endpoints de lectura se piden. Un GET que resuelve a la URL de `/` o del healthcheck
  // no se repite: esa observación ya existe y solo se le asocia la ruta (ubicación del handler).
  const surface = opts.surface;
  const surfaceEndpoints = surface ? toSurfaceEndpoints(surface.artifact) : [];
  const readOnlyEndpoints = surfaceEndpoints.filter((endpoint) => !endpoint.mutating);
  const skippedMutating = surfaceEndpoints.length - readOnlyEndpoints.length;
  let unresolvedEndpoints = 0;
  const endpointRequests: Array<{ endpoint: SurfaceEndpoint; url: string }> = [];
  const routeOfTarget = new Map<string, SurfaceEndpoint>();
  for (const endpoint of readOnlyEndpoints) {
    const url = resolveEndpointUrl(origin, endpoint.concretePath);
    if (url === undefined) {
      unresolvedEndpoints++;
      logger.warn(`Endpoint descartado (fuera del origen del target): ${endpoint.method} ${endpoint.path}`);
      continue;
    }
    if (endpoint.method === 'GET' && targets.some((target) => target.url === url)) {
      if (!routeOfTarget.has(url)) routeOfTarget.set(url, endpoint);
      continue;
    }
    endpointRequests.push({ endpoint, url });
  }

  const total = targets.length + endpointRequests.length + rules.length;
  let done = 0;
  const progress = (label: string): void => {
    done++;
    opts.onProgress?.({ done, total, requests: client.requestCount, label });
  };

  let incomplete: DastStats['incomplete'];
  const observations: DastObservation[] = [];
  const store = new ResultStore();
  let rulesRun = 0;

  for (const target of targets) {
    if (Date.now() > deadline) {
      incomplete = 'timeout';
      break;
    }
    try {
      const response = await trackedClient.request('GET', target.url);
      if (response.timedOut || response.status === 0) {
        logger.warn(`Sin respuesta de ${target.url} (tiempo agotado)`);
      } else {
        const known = routeOfTarget.get(target.url);
        observations.push({
          endpoint: target.label,
          url: target.url,
          method: 'GET',
          response,
          requestHeaders: headers,
          ...(known ? { route: known.route, artifactTarget: surface?.artifact.target } : {}),
        });
      }
    } catch (e) {
      if (budgetHit) {
        incomplete = 'budget';
        break;
      }
      if (guardFailure) throw guardFailure;
      logger.warn(`Fallo de red al pedir ${target.url}`, e);
    }
    progress(target.label);
    if (budgetHit) {
      incomplete = 'budget';
      break;
    }
  }

  if (incomplete === undefined && observations.length === 0) {
    throw new DastTargetUnreachableError(`Target unreachable: ${origin}`);
  }

  const endpointObservations: DastObservation[] = [];
  for (const { endpoint, url } of endpointRequests) {
    if (incomplete !== undefined) break;
    if (Date.now() > deadline) {
      incomplete = 'timeout';
      break;
    }
    const label = `${endpoint.method} ${endpoint.path}`;
    try {
      const response = await trackedClient.request(endpoint.method, url);
      if (response.timedOut || response.status === 0) {
        logger.warn(`Sin respuesta de ${label} (tiempo agotado)`);
      } else {
        endpointObservations.push({
          endpoint: label,
          url,
          method: endpoint.method,
          response,
          requestHeaders: headers,
          route: endpoint.route,
          artifactTarget: surface?.artifact.target,
        });
      }
    } catch (e) {
      if (budgetHit) {
        incomplete = 'budget';
        break;
      }
      if (guardFailure) throw guardFailure;
      logger.warn(`Fallo de red al pedir ${label}`, e);
    }
    progress(label);
    if (budgetHit) {
      incomplete = 'budget';
      break;
    }
  }

  // Un presupuesto agotado no descarta lo ya observado, con o sin superficie: las reglas de inspección no
  // piden nada nuevo (las que sí piden, como DAST-004, fallan sin enviar). Un timeout sí corta: pasada la
  // fecha límite el bucle de reglas se detendría en la primera de todos modos.
  const inspect = incomplete === undefined || incomplete === 'budget';
  if (inspect) {
    // Las reglas por endpoint (once: false) ven toda la superficie. Las de nivel target (once: true) ven
    // `/`, el healthcheck y, detrás, los endpoints que respondieron sin error: así una CSP débil que solo
    // sirve una página HTML que no es `/` no se pierde, y una página 404 de otro endpoint no genera hallazgos.
    // `/` va primero, de modo que sigue mandando cuando existe.
    const targetCtx: DastProbeContext = {
      target: { origin, https: parsed.protocol === 'https:' },
      observations: [...observations, ...endpointObservations.filter((o) => o.response.status < 400)],
      client: trackedClient,
      knownSecrets,
    };
    const endpointCtx: DastProbeContext = {
      ...targetCtx,
      observations: [...observations, ...endpointObservations],
    };
    for (const rule of rules) {
      if (Date.now() > deadline) {
        incomplete = 'timeout';
        break;
      }
      let produced: Finding[] = [];
      try {
        produced = await rule.probe(rule.once ? targetCtx : endpointCtx);
      } catch (e) {
        logger.warn(`La regla ${rule.id} falló`, e);
      }
      if (guardFailure) throw guardFailure;
      rulesRun++;
      store.addMany(produced);
      progress(rule.id);
      if (budgetHit) incomplete = 'budget';
    }
  }

  const findings = store.getFindings();
  let evidenceDir: string | undefined;
  if (opts.evidence !== false && findings.length > 0) {
    const writer = createEvidenceWriter(opts.evidenceDir);
    let written = 0;
    for (const finding of findings) {
      const observation = observationOf(finding);
      const exchange = observation && (exchanges.get(observation.response) ?? observation);
      if (!exchange) {
        logger.warn(`Sin petición asociada para la evidencia de ${finding.ruleId}`);
        continue;
      }
      const file = writer.write(finding, exchange, knownSecrets);
      if (file !== undefined) {
        if (finding.evidence) finding.evidence.file = file;
        written++;
      }
    }
    if (written > 0) evidenceDir = writer.dir;
  }

  const dast: DastStats = surface
    ? {
        target: origin,
        mode: 'full',
        routesSource: surface.source,
        routesStale: surface.stale,
        readOnly: true,
        agent: false,
        endpoints: {
          total: surfaceEndpoints.length,
          analyzed: endpointObservations.length + observations.filter((o) => o.route !== undefined).length,
          skippedMutating,
          unresolved: surface.artifact.unresolved.length + unresolvedEndpoints,
        },
        requests: client.requestCount,
        ...(incomplete !== undefined ? { incomplete } : {}),
        ...(evidenceDir !== undefined ? { evidenceDir } : {}),
      }
    : {
        target: origin,
        mode: 'no-source',
        routesSource: 'none',
        routesStale: false,
        readOnly: true,
        agent: false,
        endpoints: { total: targets.length, analyzed: observations.length, skippedMutating: 0, unresolved: 0 },
        requests: client.requestCount,
        ...(incomplete !== undefined ? { incomplete } : {}),
        ...(evidenceDir !== undefined ? { evidenceDir } : {}),
      };

  return {
    findings,
    stats: { filesScanned: 0, filesSkipped: 0, rulesRun, frameworks: [], dast },
    duration: Date.now() - started,
  };
}
