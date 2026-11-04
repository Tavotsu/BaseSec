import { randomBytes } from 'node:crypto';
import type { DastEvidence, Finding, RuleCategory, Severity } from '../rules/types';
import type { ExtractedRoute, RouteParam } from '../framework/routes/types';
import type { HttpClient } from './http';
import type { DastObservation, HttpResponse } from './types';
import { BudgetExceededError, GuardError } from './types';
import { dynamicFinding } from './probe';
import { resolveEndpointUrl } from './surface';
import type { SurfaceEndpoint } from './surface';
import { MAX_DELAY_SECONDS, PAYLOAD_CLASSES, buildPayloads, newCanary } from './payloads';
import type { ConcretePayload, InjectionClass } from './payloads';
import { diffOracle } from './oracles/diff';
import { redirectOracle } from './oracles/redirect';
import { reflectionOracle, signatureOracle } from './oracles/reflection';
import { sqlErrorOracle } from './oracles/sql-error';
import { TIMING_DELAY_FRACTION, timingOracle } from './oracles/timing';
import type { OracleInput, OracleResult } from './oracles/types';
import { logger } from '../utils/logger';

/** Reglas de inyección activa. Se seleccionan con --rules igual que las pasivas, pero no están en ALL_DAST_RULES. */
export const INJECTION_RULE_IDS: readonly string[] = [
  'DAST-011',
  'DAST-101',
  'DAST-102',
  'DAST-103',
  'DAST-104',
  'DAST-105',
];

/** Métodos de solo lectura: los únicos sobre los que se inyecta (§8.2, §0). */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const DEFAULT_DELAY_SECONDS = 2;
const DEFAULT_MAX_PAYLOADS_PER_ENDPOINT = 40;
/** Peticiones seguidas sin respuesta tras las que se deja un endpoint: puede estar colgado por nuestro payload. */
const MAX_CONSECUTIVE_TIMEOUTS = 3;
const PARAM_TOKEN = /:(\w+)([?+*]?)/g;
const PATH_PARAM = /:(\w+)/g;

export interface InjectionPoint {
  endpoint: SurfaceEndpoint;
  /** Solo path o query: los parámetros de body se ignoran. */
  param: RouteParam;
}

/**
 * Un envío de inyección con respuesta: qué canario viajó, a qué endpoint, parámetro y clase. Solo lo usa la
 * correlación con el agente (en memoria, no se persiste).
 */
export interface InjectionTrace {
  canary: string;
  cls: InjectionClass;
  /** Etiqueta del endpoint ("GET /users/:id"), la misma que lleva su hallazgo. */
  endpoint: string;
  route: ExtractedRoute;
  param: RouteParam;
  method: string;
  url: string;
  payloadText: string;
  response: HttpResponse;
}

export interface InjectionOptions {
  client: Pick<HttpClient, 'request'>;
  /** Recibe cada envío de un payload que obtuvo respuesta. */
  trace?: (entry: InjectionTrace) => void;
  /** Origen del target, sin path. Toda URL de ataque debe quedar en él. */
  origin: string;
  artifactTarget?: string;
  knownSecrets: string[];
  /** Segundos del payload de delay. Entero entre 1 y 2. Por defecto 2. */
  delaySeconds?: number;
  /** IDs DAST-1xx / DAST-011 a ejecutar. undefined = todos; [] = ninguno. */
  rulesFilter?: string[];
  /** Tope de peticiones por endpoint (incluida la benigna). Por defecto 40. */
  maxPayloadsPerEndpoint?: number;
  deadlineReached: () => boolean;
}

/**
 * Resultado de la inyección. Además de los hallazgos, indica si se agotó el presupuesto o el tiempo (para que el
 * runner marque `incomplete`) y en cuántos endpoints se envió algún payload.
 */
export interface InjectionResult {
  findings: Finding[];
  budgetExceeded: boolean;
  timedOut: boolean;
  attackedEndpoints: number;
}

export interface ClassMeta {
  id: string;
  name: string;
  category: RuleCategory;
  severity: Severity;
  /** Qué reglas estáticas son el posible origen de esta clase (solo se mencionan, no se enlazan: Fase 5). */
  matchesStatic: (ruleId: string) => boolean;
  references: string[];
  remediation: string;
}

/** Metadatos por clase. Exportado para que tests/cli/rules-dast.test.ts compruebe que el catálogo de `basesec rules` coincide. */
export const CLASS_META: Record<InjectionClass, ClassMeta> = {
  sqli: {
    id: 'DAST-101',
    name: 'SQL injection (confirmed at runtime)',
    category: 'sql-injection',
    severity: 'critical',
    matchesStatic: (id) => id.startsWith('SQLI-'),
    references: ['https://cwe.mitre.org/data/definitions/89.html'],
    remediation:
      'Use parameterized queries or the ORM query builder for every value that comes from the request. Never concatenate request data into SQL text.',
  },
  nosqli: {
    id: 'DAST-102',
    name: 'NoSQL injection (confirmed at runtime)',
    category: 'nosql-injection',
    severity: 'high',
    matchesStatic: (id) => id.startsWith('NOSQL-'),
    references: ['https://cwe.mitre.org/data/definitions/943.html'],
    remediation:
      'Require scalar values of the expected type for each query field (for example, a string). Reject objects that carry operators such as $ne or $gt before they reach the query.',
  },
  cmdi: {
    id: 'DAST-103',
    name: 'Command injection (confirmed at runtime)',
    category: 'command-injection',
    severity: 'critical',
    matchesStatic: (id) => id.startsWith('CMDI-'),
    references: ['https://cwe.mitre.org/data/definitions/78.html'],
    remediation:
      'Do not pass request data to a shell. Use execFile or spawn with an argument array, and validate the value against an allowlist.',
  },
  'path-traversal': {
    id: 'DAST-104',
    name: 'Path traversal (confirmed at runtime)',
    category: 'path-traversal',
    severity: 'critical',
    matchesStatic: (id) => id.startsWith('PATH-'),
    references: ['https://cwe.mitre.org/data/definitions/22.html'],
    remediation:
      'Resolve the requested file against a fixed base directory and reject any path that resolves outside it. Do not build file paths from raw request input.',
  },
  xss: {
    id: 'DAST-105',
    name: 'Reflected XSS (confirmed at runtime)',
    category: 'xss',
    severity: 'high',
    matchesStatic: (id) => id.startsWith('XSS-') && id !== 'XSS-004',
    references: ['https://cwe.mitre.org/data/definitions/79.html'],
    remediation:
      'Escape request data for the HTML context where it is rendered, or use a template engine with auto-escaping. Add a Content-Security-Policy.',
  },
  'open-redirect': {
    id: 'DAST-011',
    name: 'Open redirect (confirmed at runtime)',
    category: 'xss',
    severity: 'medium',
    matchesStatic: (id) => id === 'XSS-004',
    references: ['https://cwe.mitre.org/data/definitions/601.html'],
    remediation:
      'Redirect only to relative paths or to an allowlist of hosts. Do not put a URL taken from the request into the Location header.',
  },
};

/** Oráculo que figura en la evidencia del hallazgo. */
type EvidenceOracle = DastEvidence['oracle'];

/** Corta el análisis de inyección por tiempo. */
class StopInjection extends Error {}
/** Agota el tope de peticiones de un endpoint. Solo corta ese endpoint. */
class EndpointCap extends Error {}

interface Sent {
  url: string;
  response: HttpResponse;
  payload: ConcretePayload;
}

interface EndpointRun {
  options: InjectionOptions;
  classes: InjectionClass[];
  delay: number;
  maxPerEndpoint: number;
  result: InjectionResult;
  attacked: Set<string>;
  endpoint: SurfaceEndpoint;
  key: string;
  sent: number;
  timeouts: number;
  reported: Set<InjectionClass>;
}

interface PointRun {
  run: EndpointRun;
  point: InjectionPoint;
  baseline: HttpResponse;
  /** Valor benigno de la petición base. */
  baselineValue: string;
  /** Valores benignos distintos del de la base: miden la variación natural de la página. */
  neutralValues: [string, string];
  neutrals?: { first: HttpResponse; second?: HttpResponse };
  neutralTried: boolean;
}

/** Nombres de los parámetros de path que aparecen en la plantilla del endpoint (`/users/:id` → id). */
function pathParamNames(template: string): string[] {
  return [...template.matchAll(PATH_PARAM)].map((match) => match[1]);
}

/** Codifica un valor para la URL. En path-traversal de query se dejan las barras: `../` tiene que llegar al servidor. */
function encodeValue(value: string, traversal: boolean): string {
  const encoded = encodeURIComponent(value);
  return traversal ? encoded.replace(/%2F/gi, '/') : encoded;
}

/**
 * Plantilla de path con un parámetro sustituido por `encodedValue` y los demás por valores de muestra (las
 * mismas reglas que concretize en surface.ts).
 */
function fillPath(template: string, name: string, encodedValue: string): string {
  const segments: string[] = [];
  for (const segment of template.split('/').slice(1)) {
    const filled = segment.replace(PARAM_TOKEN, (_token, token: string, modifier: string) => {
      if (token === name) return encodedValue;
      return modifier === '*' ? '' : encodeURIComponent(modifier === '+' ? 'x' : '1');
    });
    if (filled !== '') segments.push(filled);
  }
  return `/${segments.join('/')}`;
}

/**
 * URL de un intento. Path: se sustituye el `:name` de la plantilla, con el valor codificado entero (nada del payload
 * puede abrir segmentos, cambiar de host ni de puerto). Query: `?name=valor` (o `name[$ne]=valor`, con los corchetes
 * literales para que qs los parsee); solo ahí path-traversal deja las barras. Devuelve undefined si la URL no queda
 * en el origen del target: ese intento se descarta sin enviar nada (resolveEndpointUrl rechaza "." y "..").
 */
function attemptUrl(
  origin: string,
  endpoint: SurfaceEndpoint,
  point: InjectionPoint,
  value: string,
  bracket: string | undefined,
  traversal: boolean,
): string | undefined {
  if (point.param.in === 'path') {
    // En un segmento de path las barras se quedan codificadas (`..%2F..%2Fetc%2Fpasswd`): una `/` literal abriría
    // segmentos nuevos y `..` los colapsaría (resolveEndpointUrl lo descarta). El servidor decodifica el parámetro.
    return resolveEndpointUrl(origin, fillPath(endpoint.path, point.param.name, encodeValue(value, false)));
  }
  const base = resolveEndpointUrl(origin, endpoint.concretePath);
  if (base === undefined) return undefined;
  return `${base}?${encodeURIComponent(point.param.name)}${bracket ?? ''}=${encodeValue(value, traversal)}`;
}

/** Valor benigno aleatorio de una petición base o neutral. */
function benignValue(): string {
  return `bs${randomBytes(4).toString('hex')}`;
}

/** Payload concreto de la clase, en la posición `index`, con canario nuevo (uno por envío). */
function freshPayload(cls: InjectionClass, index: number, delay: number): ConcretePayload {
  return buildPayloads(cls, newCanary(), delay)[index];
}

/**
 * Envía una petición de inyección o de comprobación. Aplica el tope por endpoint y el tiempo. Un fallo de red se
 * registra y no decide nada; el presupuesto y las barandillas se propagan.
 */
async function transmit(
  run: EndpointRun,
  point: InjectionPoint,
  value: string,
  bracket: string | undefined,
  traversal: boolean,
  isPayload: boolean,
): Promise<{ url: string; response: HttpResponse } | undefined> {
  const { options, endpoint } = run;
  const url = attemptUrl(options.origin, endpoint, point, value, bracket, traversal);
  if (url === undefined) return undefined;
  if (options.deadlineReached()) throw new StopInjection();
  if (run.sent >= run.maxPerEndpoint) throw new EndpointCap();
  run.sent++;
  if (isPayload) run.attacked.add(run.key);
  let response: HttpResponse;
  try {
    response = await options.client.request(endpoint.method, url, { followRedirects: false });
  } catch (e) {
    if (e instanceof BudgetExceededError || e instanceof GuardError) throw e;
    logger.warn(`Inyección: petición fallida a ${run.key}`, e);
    return undefined;
  }
  if (response.timedOut || response.status === 0) {
    run.timeouts++;
    if (run.timeouts >= MAX_CONSECUTIVE_TIMEOUTS) throw new EndpointCap();
    return undefined;
  }
  run.timeouts = 0;
  return { url, response };
}

/** Envía un payload concreto. undefined si no se envió o no hubo respuesta. */
async function attack(
  state: PointRun,
  cls: InjectionClass,
  index: number,
  delay: number,
): Promise<Sent | undefined> {
  const payload = freshPayload(cls, index, delay);
  const traversal = cls === 'path-traversal';
  const sent = await transmit(state.run, state.point, payload.text, payload.bracket, traversal, true);
  if (sent === undefined) return undefined;
  const { run, point } = state;
  run.options.trace?.({
    canary: payload.canary,
    cls,
    endpoint: `${run.endpoint.method} ${run.endpoint.path}`,
    route: run.endpoint.route,
    param: point.param,
    method: run.endpoint.method,
    url: sent.url,
    payloadText: payload.text,
    response: sent.response,
  });
  return { ...sent, payload };
}

/**
 * Variación natural: dos valores benignos distintos del de la base, enviados una vez por punto (solo NoSQLi los
 * usa). Con tres muestras benignas, dos que coincidan por azar ya no fijan una tolerancia de cero.
 */
async function neutralsOf(state: PointRun): Promise<{ first: HttpResponse; second?: HttpResponse } | undefined> {
  if (!state.neutralTried) {
    state.neutralTried = true;
    const first = await transmit(state.run, state.point, state.neutralValues[0], undefined, false, false);
    if (first !== undefined) {
      const second = await transmit(state.run, state.point, state.neutralValues[1], undefined, false, false);
      state.neutrals = { first: first.response, ...(second !== undefined ? { second: second.response } : {}) };
    }
  }
  return state.neutrals;
}

/** Oráculo para un payload de reflejo, sobre la respuesta del ataque. */
function reflectionResult(cls: InjectionClass, input: OracleInput): OracleResult {
  if (cls === 'path-traversal') return signatureOracle(input);
  return reflectionOracle(input, cls === 'xss' ? 'xss' : 'echo');
}

/** Construye el Finding dinámico de (endpoint, clase): la evidencia es el intercambio que disparó. */
function makeFinding(
  state: PointRun,
  cls: InjectionClass,
  sent: Sent,
  result: OracleResult,
  oracle: EvidenceOracle,
): Finding {
  const { run, point } = state;
  const { options, endpoint } = run;
  const meta = CLASS_META[cls];
  const label = `${endpoint.method} ${endpoint.path}`;
  const hints = endpoint.route.staticFindings.filter((ref) => meta.matchesStatic(ref.ruleId));
  const hint =
    hints.length > 0
      ? ` Possible static origin: ${hints.map((ref) => `${ref.ruleId} ${ref.filePath}:${ref.line}`).join(', ')}.`
      : '';
  const observation: DastObservation = {
    endpoint: label,
    url: sent.url,
    method: endpoint.method,
    response: sent.response,
    route: endpoint.route,
    ...(options.artifactTarget !== undefined ? { artifactTarget: options.artifactTarget } : {}),
  };
  return dynamicFinding({
    rule: { id: meta.id, name: meta.name, category: meta.category, severity: meta.severity, once: false },
    confidence: result.confidence,
    endpoint: label,
    message: `Parameter "${point.param.name}" (${point.param.in}) of ${label}: ${result.detail}.${hint}`,
    remediation: meta.remediation,
    references: meta.references,
    codeSnippet: `${point.param.in} parameter "${point.param.name}"`,
    observation,
    knownSecrets: options.knownSecrets,
    payload: sent.payload.text,
    oracle,
  });
}

/** Retardo: dos confirmaciones del payload de delay y un control con delay 0 entre medias. */
async function timingFlow(state: PointRun, cls: InjectionClass, index: number): Promise<Finding | undefined> {
  const { run, baseline } = state;
  const first = await attack(state, cls, index, run.delay);
  if (first === undefined) return undefined;
  // Sin retardo en el primer intento no hay nada que confirmar: se ahorran dos peticiones.
  if (first.response.elapsedMs - baseline.elapsedMs < run.delay * 1000 * TIMING_DELAY_FRACTION) return undefined;
  const control = await attack(state, cls, index, 0);
  if (control === undefined) return undefined;
  const second = await attack(state, cls, index, run.delay);
  if (second === undefined) return undefined;

  const fastest = first.response.elapsedMs <= second.response.elapsedMs ? first : second;
  const result = timingOracle({
    baseline,
    attack: fastest.response,
    control: control.response,
    canary: fastest.payload.canary,
    payloadText: fastest.payload.text,
    delaySeconds: run.delay,
  });
  return result.detected ? makeFinding(state, cls, fastest, result, 'timing') : undefined;
}

/** NoSQLi: dos ataques con el mismo payload frente a la benigna y la neutral. Señal de error de Mongo como respaldo. */
async function diffFlow(state: PointRun, cls: InjectionClass, index: number): Promise<Finding | undefined> {
  const first = await attack(state, cls, index, state.run.delay);
  if (first === undefined) return undefined;
  const second = await attack(state, cls, index, state.run.delay);
  if (second === undefined) return undefined;
  const neutrals = await neutralsOf(state);
  if (neutrals === undefined) return undefined;

  const input: OracleInput = {
    baseline: state.baseline,
    attack: first.response,
    canary: first.payload.canary,
    payloadText: first.payload.text,
  };
  const diff = diffOracle({
    ...input,
    attack2: second.response,
    neutral: neutrals.first,
    ...(neutrals.second !== undefined ? { neutral2: neutrals.second } : {}),
    reflected: [state.baselineValue, ...state.neutralValues],
  });
  if (diff.detected) return makeFinding(state, cls, first, diff, 'diff');
  const mongo = sqlErrorOracle(input, 'mongo');
  return mongo.detected ? makeFinding(state, cls, first, mongo, 'sql-error') : undefined;
}

/** Oráculos de un solo ataque: error SQL, reflejo (XSS, cmdi, firma de path traversal) y redirect. */
async function singleFlow(state: PointRun, cls: InjectionClass, index: number): Promise<Finding | undefined> {
  const sent = await attack(state, cls, index, state.run.delay);
  if (sent === undefined) return undefined;
  const input: OracleInput = {
    baseline: state.baseline,
    attack: sent.response,
    canary: sent.payload.canary,
    payloadText: sent.payload.text,
  };
  switch (sent.payload.oracle) {
    case 'sql-error': {
      const result = sqlErrorOracle(input, 'sql');
      return result.detected ? makeFinding(state, cls, sent, result, 'sql-error') : undefined;
    }
    case 'reflection': {
      const result = reflectionResult(cls, input);
      return result.detected ? makeFinding(state, cls, sent, result, 'reflection') : undefined;
    }
    case 'redirect': {
      const result = redirectOracle(input);
      return result.detected ? makeFinding(state, cls, sent, result, 'redirect') : undefined;
    }
    default:
      return undefined;
  }
}

/** Ejecuta los payloads de una clase en orden; el primero que dispara decide la clase para este punto. */
async function probeClass(state: PointRun, cls: InjectionClass): Promise<Finding | undefined> {
  const count = buildPayloads(cls, newCanary(), state.run.delay).length;
  for (let index = 0; index < count; index++) {
    if (state.run.options.deadlineReached()) throw new StopInjection();
    // El oráculo es propio de la plantilla (no depende del canario), así que basta una muestra para elegir el flujo.
    const oracle = freshPayload(cls, index, state.run.delay).oracle;
    let finding: Finding | undefined;
    if (oracle === 'timing') {
      finding = await timingFlow(state, cls, index);
    } else if (oracle === 'diff') {
      finding = await diffFlow(state, cls, index);
    } else {
      finding = await singleFlow(state, cls, index);
    }
    if (finding !== undefined) return finding;
  }
  return undefined;
}

async function probeEndpoint(points: InjectionPoint[], shared: Omit<EndpointRun, 'endpoint' | 'key' | 'sent' | 'timeouts' | 'reported'>): Promise<void> {
  const endpoint = points[0].endpoint;
  const run: EndpointRun = {
    ...shared,
    endpoint,
    key: `${endpoint.method} ${endpoint.path}`,
    sent: 0,
    timeouts: 0,
    reported: new Set<InjectionClass>(),
  };
  try {
    for (const point of points) {
      // Si todas las clases ya tienen hallazgo en este endpoint, otro parámetro no aporta nada: ni siquiera la base.
      if (run.classes.every((cls) => run.reported.has(cls))) break;
      const benign = benignValue();
      const baseline = await transmit(run, point, benign, undefined, false, false);
      if (baseline === undefined) continue;
      const state: PointRun = {
        run,
        point,
        baseline: baseline.response,
        baselineValue: benign,
        neutralValues: [benignValue(), benignValue()],
        neutralTried: false,
      };
      for (const cls of run.classes) {
        if (run.reported.has(cls)) continue;
        // El operador `[$ne]` solo tiene sentido como clave de query: en un segmento de path no hay objeto que parsear.
        if (cls === 'nosqli' && point.param.in === 'path') continue;
        const finding = await probeClass(state, cls);
        if (finding !== undefined) {
          run.result.findings.push(finding);
          run.reported.add(cls);
        }
      }
    }
  } catch (e) {
    if (!(e instanceof EndpointCap)) throw e;
    logger.warn(`Inyección: ${run.key} deja de atacarse (tope de ${run.maxPerEndpoint} peticiones o sin respuesta); puede haber parámetros o clases sin probar`);
  }
}

/** Puntos atacables: solo GET/HEAD/OPTIONS, solo params de path o query, y el path del parámetro debe existir. */
function eligible(point: InjectionPoint, origin: string): boolean {
  const { endpoint, param } = point;
  if (!SAFE_METHODS.has(endpoint.method) || endpoint.mutating) return false;
  if (param.in === 'body') return false;
  if (resolveEndpointUrl(origin, endpoint.concretePath) === undefined) return false;
  if (param.in === 'path') return pathParamNames(endpoint.path).includes(param.name);
  return param.in === 'query';
}

/**
 * Inyección activa sobre los parámetros de path y query de los endpoints de solo lectura. Por cada punto: una
 * petición benigna y, por clase aplicable, los payloads con sus oráculos. Un solo hallazgo por (endpoint, clase).
 * Orden determinista: endpoints por path y método, params por nombre, clases en orden fijo.
 */
export async function runInjection(points: InjectionPoint[], opts: InjectionOptions): Promise<InjectionResult> {
  const delay = opts.delaySeconds ?? DEFAULT_DELAY_SECONDS;
  if (!Number.isInteger(delay) || delay < 1 || delay > MAX_DELAY_SECONDS) {
    throw new RangeError(`delaySeconds debe ser un entero entre 1 y ${MAX_DELAY_SECONDS}`);
  }
  const maxPerEndpoint = opts.maxPayloadsPerEndpoint ?? DEFAULT_MAX_PAYLOADS_PER_ENDPOINT;
  if (!Number.isInteger(maxPerEndpoint) || maxPerEndpoint < 1) {
    throw new RangeError('maxPayloadsPerEndpoint debe ser un entero positivo');
  }

  const classes = PAYLOAD_CLASSES.filter(
    (cls) => opts.rulesFilter === undefined || opts.rulesFilter.includes(CLASS_META[cls].id),
  );
  const result: InjectionResult = { findings: [], budgetExceeded: false, timedOut: false, attackedEndpoints: 0 };
  if (classes.length === 0) return result;

  const attackable = points
    .filter((point) => eligible(point, opts.origin))
    .sort((a, b) => {
      const ka = `${a.endpoint.path}\u0000${a.endpoint.method}`;
      const kb = `${b.endpoint.path}\u0000${b.endpoint.method}`;
      if (ka !== kb) return ka < kb ? -1 : 1;
      if (a.param.in !== b.param.in) return a.param.in < b.param.in ? -1 : 1;
      return a.param.name < b.param.name ? -1 : a.param.name > b.param.name ? 1 : 0;
    });

  const groups: InjectionPoint[][] = [];
  for (const point of attackable) {
    const last = groups[groups.length - 1];
    if (last && last[0].endpoint.method === point.endpoint.method && last[0].endpoint.path === point.endpoint.path) {
      last.push(point);
    } else {
      groups.push([point]);
    }
  }

  const attacked = new Set<string>();
  const shared = { options: opts, classes, delay, maxPerEndpoint, result, attacked };
  try {
    for (const group of groups) {
      if (opts.deadlineReached()) throw new StopInjection();
      await probeEndpoint(group, shared);
    }
  } catch (e) {
    if (e instanceof BudgetExceededError) {
      result.budgetExceeded = true;
    } else if (e instanceof StopInjection) {
      result.timedOut = true;
    } else {
      throw e;
    }
  }
  result.attackedEndpoints = attacked.size;
  return result;
}
