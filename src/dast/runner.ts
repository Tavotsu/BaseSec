import { Guard } from './guard';
import { HttpClient } from './http';
import { ALL_DAST_RULES } from './rules/index';
import { createEvidenceWriter } from './evidence';
import { DastConfigError, expandEnvHeaders } from './config';
import { observationOf } from './probe';
import { INJECTION_RULE_IDS, runInjection } from './inject';
import type { InjectionTrace } from './inject';
import { linkAgentEvents } from './agent-link';
import type { AgentEventSource } from './agent-client';
import { ACTIVE_RULE_IDS, pickRateLimitTarget, runAuthCheck, runRateLimitCheck } from './active-checks';
import type { ActiveCheckContext, ActiveCheckResult, SurfaceTarget } from './active-checks';
import { clampDelaySeconds } from './payloads';
import type { InjectionPoint } from './inject';
import { BudgetExceededError, GuardError } from './types';
import type { DastObservation, DastProbeContext, DastRule } from './types';
import type { HttpResponse, HttpRequestOptions } from './types';
import { resolveEndpointUrl, toSurfaceEndpoints } from './surface';
export { resolveEndpointUrl } from './surface';
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
  rules?: string[];              // filtro de IDs DAST (pasivas, activas e inyección)
  /** Patrones de rutas públicas para DAST-008 (dast.publicRoutes). */
  publicRoutes?: string[];
  /** Activa DAST-010 (--probe-rate-limit o dast.probeRateLimit). Apagada por defecto. */
  probeRateLimit?: boolean;
  /** Segundos del payload de delay de la inyección activa (1 o 2). Por defecto 2; los tests lo bajan. */
  injectionDelaySeconds?: number;
  /** Superficie de ataque (artefacto de rutas). Sin ella, solo se observan `/` y el healthcheck. */
  surface?: LoadedSurface;
  onProgress?: (event: { done: number; total: number; requests: number; label: string }) => void;
  /**
   * Fuente de eventos del agente IAST (`--agent`). Sin ella, la inyección no se correlaciona con sinks reales.
   */
  agent?: AgentEventSource;
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
/** Cuerpo que se guarda de cada envío de inyección para la evidencia de un hallazgo confirmado por el agente. */
const TRACE_BODY_LIMIT = 16 * 1024;

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

/** IDs pedidos con --rules, en mayúsculas y sin vacíos. Lista vacía = todas. */
function normalizeRuleIds(ids: string[] | undefined): string[] {
  return (ids ?? []).map((id) => id.trim().toUpperCase()).filter((id) => id !== '');
}

function selectRules(wanted: string[]): DastRule[] {
  const byId = (a: DastRule, b: DastRule): number => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  if (wanted.length === 0) return [...ALL_DAST_RULES].sort(byId);
  const known = new Set([...ALL_DAST_RULES.map((rule) => rule.id), ...ACTIVE_RULE_IDS, ...INJECTION_RULE_IDS]);
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
  const wantedRules = normalizeRuleIds(opts.rules);
  const rules = selectRules(wantedRules);
  // undefined = inyección con todas sus reglas; si --rules solo nombra reglas pasivas, la inyección no corre.
  const injectionRules =
    wantedRules.length === 0 ? undefined : wantedRules.filter((id) => INJECTION_RULE_IDS.includes(id));
  // DAST-008 (sin superficie no hay rutas) y DAST-010 (opt-in). --rules sin DAST-010 no la activa por sí solo.
  const authWanted = wantedRules.length === 0 || wantedRules.includes('DAST-008');
  const rateWanted = wantedRules.length === 0 || wantedRules.includes('DAST-010');
  const rateEnabled = opts.probeRateLimit === true && rateWanted;
  if (wantedRules.includes('DAST-010') && opts.probeRateLimit !== true) {
    logger.warn('DAST-010 no corre sin --probe-rate-limit (o dast.probeRateLimit)');
  }

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
  // `record: false` (inyección): cientos de respuestas con body de hasta 8 MiB no se retienen; solo se guardan,
  // después, las de los hallazgos.
  const trackClient = (record: boolean): Pick<HttpClient, 'request'> => ({
    async request(method: string, url: string, reqOpts: HttpRequestOptions = {}): Promise<HttpResponse> {
      try {
        const response = await client.request(method, url, reqOpts);
        if (record && !response.timedOut) {
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
  });
  const trackedClient = trackClient(true);
  // Las comprobaciones activas usan un cliente sin registro: su evidencia sale de la observación que devuelven, con las
  // cabeceras que realmente enviaron (la del DAST-008 no lleva credenciales).
  const activeContext = (): ActiveCheckContext => ({
    client: trackClient(false),
    requestHeaders: headers,
    knownSecrets,
    artifactTarget: surface?.artifact.target,
    publicRoutes: opts.publicRoutes ?? [],
    deadlineReached: () => Date.now() > deadline,
  });
  const mergeIncomplete = (
    current: DastStats['incomplete'],
    outcome: ActiveCheckResult,
    budgetSeen: boolean,
  ): DastStats['incomplete'] => {
    if (budgetSeen || outcome.incomplete === 'budget') return 'budget';
    if (current !== undefined) return current;
    return outcome.incomplete;
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
  const resolvedReadOnly: SurfaceTarget[] = [];
  for (const endpoint of readOnlyEndpoints) {
    const url = resolveEndpointUrl(origin, endpoint.concretePath);
    if (url === undefined) {
      unresolvedEndpoints++;
      logger.warn(`Endpoint descartado (fuera del origen del target): ${endpoint.method} ${endpoint.path}`);
      continue;
    }
    resolvedReadOnly.push({ endpoint, url });
    if (endpoint.method === 'GET' && targets.some((target) => target.url === url)) {
      if (!routeOfTarget.has(url)) routeOfTarget.set(url, endpoint);
      continue;
    }
    endpointRequests.push({ endpoint, url });
  }

  const activeSlots = (surface && authWanted ? 1 : 0) + (rateEnabled ? 1 : 0);
  const total = targets.length + endpointRequests.length + rules.length + activeSlots;
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

    // DAST-008: solo con superficie. Va antes de la inyección: sus peticiones son pocas y no dependen de ella.
    if (surface && authWanted && incomplete === undefined) {
      const outcome = await runAuthCheck(resolvedReadOnly, [...observations, ...endpointObservations], activeContext());
      rulesRun++;
      store.addMany(outcome.findings);
      progress('DAST-008');
      incomplete = mergeIncomplete(incomplete, outcome, budgetHit);
    }
  }

  // Inyección activa (plan §7.5): solo con superficie, solo sobre GET/HEAD/OPTIONS y sus params de path/query, y
  // solo si el presupuesto y el tiempo siguen holgados. Sin superficie no hay parámetros y no se envía nada.
  let attackedEndpoints: number | undefined;
  const injectionEnabled = surface !== undefined && (injectionRules === undefined || injectionRules.length > 0);
  if (injectionEnabled && incomplete === undefined) {
    const points: InjectionPoint[] = [];
    for (const { endpoint } of resolvedReadOnly) {
      for (const param of endpoint.route.params) {
        if (param.in === 'path' || param.in === 'query') points.push({ endpoint, param });
      }
    }
    // Con agente: cada envío con respuesta queda indexado por su canario (en memoria) para enlazar los sinks.
    const trace = opts.agent !== undefined ? new Map<string, InjectionTrace>() : undefined;
    const outcome = await runInjection(points, {
      client: trackClient(false),
      origin,
      artifactTarget: surface?.artifact.target,
      knownSecrets,
      delaySeconds: clampDelaySeconds(opts.injectionDelaySeconds),
      rulesFilter: injectionRules,
      deadlineReached: () => Date.now() > deadline,
      ...(trace !== undefined
        ? {
            trace: (entry: InjectionTrace): void => {
              trace.set(entry.canary, {
                ...entry,
                response: { ...entry.response, body: entry.response.body.slice(0, TRACE_BODY_LIMIT) },
              });
            },
          }
        : {}),
    });
    if (opts.agent !== undefined && trace !== undefined) {
      const events = await opts.agent.collect();
      linkAgentEvents(outcome.findings, events, {
        trace,
        knownSecrets,
        ...(surface?.artifact.target !== undefined ? { artifactTarget: surface.artifact.target } : {}),
      });
    }
    // El intercambio de cada hallazgo se asocia ahora (con las cabeceras de la petición) para la evidencia.
    for (const finding of outcome.findings) {
      const observation = observationOf(finding);
      if (observation) exchanges.set(observation.response, { ...observation, requestHeaders: { ...headers } });
    }
    store.addMany(outcome.findings);
    attackedEndpoints = outcome.attackedEndpoints;
    if (outcome.budgetExceeded || budgetHit) incomplete = 'budget';
    else if (outcome.timedOut) incomplete = 'timeout';
  }

  // DAST-010 va al final: su ráfaga de 30 peticiones no debe alterar los oráculos de la inyección.
  if (rateEnabled && incomplete === undefined) {
    const base = pickRateLimitTarget(
      resolvedReadOnly,
      [...observations, ...endpointObservations],
      healthUrl.href,
      `${origin}/`,
    );
    if (base !== undefined) {
      const outcome = await runRateLimitCheck(base, activeContext());
      store.addMany(outcome.findings);
      incomplete = mergeIncomplete(incomplete, outcome, budgetHit);
    } else {
      logger.warn('DAST-010 omitido: el objetivo no tiene una respuesta válida sin error');
    }
    rulesRun++;
    progress('DAST-010');
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
        agent: opts.agent !== undefined,
        endpoints: {
          total: surfaceEndpoints.length,
          analyzed: endpointObservations.length + observations.filter((o) => o.route !== undefined).length,
          skippedMutating,
          unresolved: surface.artifact.unresolved.length + unresolvedEndpoints,
          attacked: attackedEndpoints ?? 0,
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
        agent: opts.agent !== undefined,
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
