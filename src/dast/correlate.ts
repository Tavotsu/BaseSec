import type { Confidence, CorrelationKind, DastEvidence, Finding, RuleCategory } from '../rules/types';
import type { ExtractedRoute, RouteArtifact } from '../framework/routes/types';
import { toRootRelative } from '../framework/routes/common';

export interface CorrelationResult {
  /** Estáticos (algunos ya verificados, como copias) seguidos de los dinámicos no correlacionados. */
  findings: Finding[];
  stats: { verified: number; dynamicOnly: number };
}

/** Categoría de los hallazgos estáticos que explica cada inyección confirmada (§4.3, §7.8). */
const INJECTION_CATEGORY: Readonly<Record<string, RuleCategory>> = {
  'DAST-011': 'xss',
  'DAST-101': 'sql-injection',
  'DAST-102': 'nosql-injection',
  'DAST-103': 'command-injection',
  'DAST-104': 'path-traversal',
  'DAST-105': 'xss',
};

/**
 * Dentro de la categoría `xss` conviven reglas que un hit no puede confirmar: el artefacto lista TODOS los hallazgos de
 * los ficheros alcanzables (p. ej. XSS-002 "Missing Helmet" en app.ts). Un redirect abierto solo explica XSS-004 y un
 * XSS reflejado solo XSS-001; sin este filtro un DAST-105 marcaría como verificado un XSS-002 o un XSS-004.
 */
const INJECTION_RULES: Readonly<Record<string, (ruleId: string) => boolean>> = {
  'DAST-011': (ruleId) => ruleId === 'XSS-004',
  'DAST-105': (ruleId) => ruleId === 'XSS-001',
};

/**
 * Reglas estáticas hermanas de cada DAST-0xx (§4.3). DAST-001 y DAST-003 van 1:1 (cabeceras → helmet, CSP → CONF-001):
 * el plan agrupaba ambas por brevedad, pero con XSS-002 y CONF-001 presentes a la vez un mapeo agrupado deja 2
 * candidatos en cada regla y no enlaza ninguno.
 */
const SISTER_RULES: Readonly<Record<string, readonly string[]>> = {
  'DAST-001': ['XSS-002', 'FASTIFY-002', 'KOA-001'],
  'DAST-003': ['CONF-001'],
  'DAST-004': ['AUTH-003', 'FASTIFY-003', 'KOA-002'],
  'DAST-005': ['CONF-003'],
  'DAST-006': ['ERR-001'],
  'DAST-008': ['AUTH-001', 'NG-006'],
  'DAST-010': ['AUTH-004', 'FASTIFY-001'],
};

/** Estas hermanas se buscan primero en el fichero del handler del endpoint del hallazgo dinámico. */
const HANDLER_FIRST_SISTERS = new Set(['DAST-005', 'DAST-006', 'DAST-008']);

const RANK: Readonly<Record<Confidence, number>> = { low: 0, medium: 1, high: 2 };

interface StaticEntry {
  index: number;
  finding: Finding;
  /** Fichero relativo a la raíz del artefacto, con "/". */
  relPath: string;
}

interface Context {
  artifact: RouteArtifact;
  statics: StaticEntry[];
  /** ruleId + fichero relativo + línea → índice del estático. */
  byLocation: Map<string, number>;
}

interface Link {
  correlation: CorrelationKind;
  confidence: Confidence;
  endpoint?: string;
  evidence: DastEvidence;
}

/** Decisión sobre un dinámico: enlazar a uno o más estáticos, o listar sus orígenes posibles sin enlazar. */
type Decision =
  | { kind: 'link'; correlation: CorrelationKind; targets: Array<{ index: number; confidence: Confidence }> }
  | { kind: 'ambiguous'; origins: string[] };

/**
 * Enlaza hallazgos dinámicos confirmados con sus estáticos (plan §7.8). Un estático enlazado se sustituye en la salida
 * por una copia `verified: true` con la evidencia del dinámico. Los objetos de entrada nunca se mutan: pueden venir de
 * la caché de análisis.
 */
export function correlate(
  staticFindings: Finding[],
  dynamicFindings: Finding[],
  artifact: RouteArtifact,
): CorrelationResult {
  const ctx = buildContext(staticFindings, artifact);
  const links = new Map<number, Link>();
  const dynamicOnly: Finding[] = [];

  for (const dynamic of dynamicFindings) {
    const { evidence } = dynamic;
    const decision = evidence === undefined ? undefined : decide(dynamic, ctx);
    if (decision === undefined || evidence === undefined) {
      dynamicOnly.push(dynamic);
      continue;
    }
    if (decision.kind === 'ambiguous') {
      dynamicOnly.push(withOrigins(dynamic, decision.origins));
      continue;
    }
    for (const target of decision.targets) {
      // Varios dinámicos sobre el mismo estático: se clona una vez y gana la confianza mayor (la primera en empate).
      const current = links.get(target.index);
      if (current === undefined || RANK[target.confidence] > RANK[current.confidence]) {
        links.set(target.index, {
          correlation: decision.correlation,
          confidence: target.confidence,
          endpoint: dynamic.endpoint,
          evidence,
        });
      }
    }
  }

  const findings = ctx.statics.map(({ index, finding }) => {
    const link = links.get(index);
    return link === undefined ? finding : verifiedCopy(finding, link);
  });
  findings.push(...dynamicOnly);

  return { findings, stats: { verified: links.size, dynamicOnly: dynamicOnly.length } };
}

function buildContext(staticFindings: Finding[], artifact: RouteArtifact): Context {
  const statics: StaticEntry[] = [];
  const byLocation = new Map<string, number>();
  staticFindings.forEach((finding, index) => {
    const relPath = finding.filePath === '' ? '' : toRootRelative(artifact.target, finding.filePath);
    statics.push({ index, finding, relPath });
    if (relPath !== '') {
      const key = locationKey(finding.ruleId, relPath, finding.line);
      if (!byLocation.has(key)) byLocation.set(key, index);
    }
  });
  return { artifact, statics, byLocation };
}

function decide(dynamic: Finding, ctx: Context): Decision | undefined {
  const injection = INJECTION_CATEGORY[dynamic.ruleId];
  if (injection !== undefined) return decideInjection(dynamic, injection, ctx);
  return decideSister(dynamic, ctx);
}

/**
 * Inyección (DAST-1xx, DAST-011): candidatos = estáticos de la categoría en las rutas del endpoint (§7.8). Se usa el
 * nivel `handler` si hay alguno, si no `import-graph`. Varios candidatos en la MISMA línea (p. ej. SQLI-001 y
 * SQLI-003 sobre una misma query) no son orígenes competidores: describen el mismo sitio, así que se enlazan todos.
 * Con candidatos en líneas distintas no se adivina y el dinámico se queda.
 */
function decideInjection(dynamic: Finding, category: RuleCategory, ctx: Context): Decision | undefined {
  const candidates = new Map<number, 'handler' | 'import-graph'>();
  const ruleAllowed = INJECTION_RULES[dynamic.ruleId];
  for (const route of routesOf(dynamic, ctx.artifact)) {
    for (const ref of route.staticFindings) {
      if (ruleAllowed !== undefined && !ruleAllowed(ref.ruleId)) continue;
      const index = ctx.byLocation.get(locationKey(ref.ruleId, ref.filePath, ref.line));
      if (index === undefined || ctx.statics[index].finding.category !== category) continue;
      if (ref.via === 'handler' || candidates.get(index) !== 'handler') candidates.set(index, ref.via);
    }
  }

  const indexes = [...candidates.keys()].sort((a, b) => a - b);
  const handlers = indexes.filter((index) => candidates.get(index) === 'handler');
  const imports = indexes.filter((index) => candidates.get(index) === 'import-graph');
  const useHandlers = handlers.length > 0;
  const tier = useHandlers ? handlers : imports;

  if (tier.length > 0 && sameLocation(tier, ctx)) {
    const correlation: CorrelationKind = useHandlers ? 'handler' : 'import-graph';
    return {
      kind: 'link',
      correlation,
      targets: tier.map((index) => ({
        index,
        confidence: useHandlers ? 'high' : atLeastMedium(ctx.statics[index].finding.confidence),
      })),
    };
  }
  if (indexes.length >= 2) {
    return { kind: 'ambiguous', origins: indexes.map((index) => describe(ctx.statics[index])) };
  }
  return undefined;
}

/** Todos los estáticos de la lista están en el mismo fichero y línea. */
function sameLocation(indexes: number[], ctx: Context): boolean {
  const first = ctx.statics[indexes[0]].finding;
  return indexes.every((index) => {
    const finding = ctx.statics[index].finding;
    return finding.filePath === first.filePath && finding.line === first.line;
  });
}

/** `max(original, 'medium')` del enlace por import-graph (§7.8). */
function atLeastMedium(confidence: Confidence): Confidence {
  return RANK[confidence] > RANK.medium ? confidence : 'medium';
}

/**
 * Hermana estática (DAST-0xx): un único candidato del ruleId hermano enlaza. Para DAST-005/006/008 se prefiere el
 * fichero del handler del endpoint; si allí hay 2+, no se enlaza.
 */
function decideSister(dynamic: Finding, ctx: Context): Decision | undefined {
  const sisters = SISTER_RULES[dynamic.ruleId];
  if (sisters === undefined) return undefined;
  const project = ctx.statics.filter((entry) => sisters.includes(entry.finding.ruleId));

  if (HANDLER_FIRST_SISTERS.has(dynamic.ruleId)) {
    const handlerFiles = new Set(routesOf(dynamic, ctx.artifact).map((route) => route.filePath));
    const local = project.filter((entry) => handlerFiles.has(entry.relPath));
    if (local.length === 1) return runtimeProperty(local[0].index);
    if (local.length >= 2) return undefined;
  }
  return project.length === 1 ? runtimeProperty(project[0].index) : undefined;
}

function runtimeProperty(index: number): Decision {
  return { kind: 'link', correlation: 'runtime-property', targets: [{ index, confidence: 'high' }] };
}

/**
 * Rutas del artefacto con el método y el path del endpoint del dinámico ("GET /api/users/:id"). El runner ataca las
 * rutas `ALL` como GET (toSurfaceEndpoints), así que aquí también casan como GET. Sin endpoint de ruta (nivel target,
 * "GET /" que no está en el artefacto) devuelve [].
 */
function routesOf(dynamic: Finding, artifact: RouteArtifact): ExtractedRoute[] {
  const match = /^([A-Z]+) (\/\S*)$/.exec(dynamic.endpoint ?? '');
  if (match === null) return [];
  const [, method, routePath] = match;
  return artifact.routes.filter(
    (route) => (route.method === 'ALL' ? 'GET' : route.method) === method && route.path === routePath,
  );
}

function describe(entry: StaticEntry): string {
  return `${entry.finding.ruleId} ${entry.relPath}:${entry.finding.line}`;
}

/** Añade los orígenes posibles al mensaje, salvo que el motor de inyección ya los haya escrito. */
function withOrigins(dynamic: Finding, origins: string[]): Finding {
  if (/possible static origin/i.test(dynamic.message)) return dynamic;
  return { ...dynamic, message: `${dynamic.message} (possible static origins: ${origins.join(', ')})` };
}

function verifiedCopy(finding: Finding, link: Link): Finding {
  const copy: Finding = structuredClone(finding);
  copy.verified = true;
  copy.confidence = link.confidence;
  if (link.endpoint !== undefined) copy.endpoint = link.endpoint;
  copy.evidence = { ...structuredClone(link.evidence), correlation: link.correlation };
  return copy;
}

function locationKey(ruleId: string, relPath: string, line: number): string {
  return `${ruleId}\0${relPath}\0${line}`;
}
