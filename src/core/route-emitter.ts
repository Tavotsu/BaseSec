import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Finding, ParsedFile } from '../rules/types';
import { buildImportGraph } from './import-graph';
import { extractExpressRoutes } from '../framework/routes/express-routes';
import { extractNestRoutes } from '../framework/routes/nestjs-routes';
import { extractNextRoutes } from '../framework/routes/nextjs-routes';
import { toRootRelative } from '../framework/routes/common';
import type {
  ExtractedRoute,
  ExtractionContext,
  RawRoute,
  RouteArtifact,
  StaticFindingRef,
  UnresolvedRoute,
} from '../framework/routes/types';
import { getBaseSecDir } from '../utils/basesec-dir';
import { prepareDir } from '../dast/evidence';

const NO_EXTRACTOR_FRAMEWORKS = ['fastify', 'koa'];

export interface BuildRouteArtifactArgs {
  parsedFiles: ParsedFile[];
  frameworks: string[];
  root: string;
  findings: Finding[];
}

/**
 * Construye el artefacto de superficie de ataque (plan §5.2). Corre sobre `parsedFiles`
 * en el hilo principal; no depende de que las reglas se hayan ejecutado.
 */
export function buildRouteArtifact(args: BuildRouteArtifactArgs): RouteArtifact {
  const absRoot = path.resolve(args.root);
  const graph = buildImportGraph(args.parsedFiles);
  const ctx: ExtractionContext = { parsedFiles: args.parsedFiles, graph, root: absRoot };
  const frameworks = new Set(args.frameworks);

  const rawRoutes: RawRoute[] = [];
  const unresolved: UnresolvedRoute[] = [];

  if (frameworks.has('express')) {
    const result = extractExpressRoutes(ctx);
    rawRoutes.push(...result.routes);
    unresolved.push(...result.unresolved);
  }
  if (frameworks.has('nestjs')) {
    const result = extractNestRoutes(ctx);
    rawRoutes.push(...result.routes);
    unresolved.push(...result.unresolved);
  }
  if (frameworks.has('nextjs')) {
    const result = extractNextRoutes(ctx);
    rawRoutes.push(...result.routes);
    unresolved.push(...result.unresolved);
  }
  for (const fw of NO_EXTRACTOR_FRAMEWORKS) {
    if (frameworks.has(fw)) {
      unresolved.push({ filePath: '', line: 0, reason: `framework sin extractor de rutas: ${fw}` });
    }
  }

  const relCache = new Map<string, string>();
  const rel = (file: string): string => {
    let value = relCache.get(file);
    if (value === undefined) {
      value = toRootRelative(absRoot, file);
      relCache.set(file, value);
    }
    return value;
  };

  // Hallazgos indexados una vez por fichero (relativo), sin duplicados (ruleId, fichero, línea).
  const findingsByFile = new Map<string, FindingRef[]>();
  const seenFindings = new Set<string>();
  for (const f of args.findings) {
    if (f.filePath === '' || f.category === 'dependency-check') continue;
    const relPath = rel(f.filePath);
    const key = `${f.ruleId}\0${relPath}\0${f.line}`;
    if (seenFindings.has(key)) continue;
    seenFindings.add(key);
    const list = findingsByFile.get(relPath) ?? [];
    list.push({ ruleId: f.ruleId, filePath: relPath, line: f.line });
    findingsByFile.set(relPath, list);
  }

  // Muchas rutas comparten fichero de handler: el cierre de imports y sus hallazgos se calculan una vez.
  const reachCache = new Map<string, Reach>();
  const reachOf = (handlerFile: string): Reach => {
    let reach = reachCache.get(handlerFile);
    if (reach === undefined) {
      const files = graph
        .reachableFrom(path.resolve(absRoot, handlerFile))
        .map(rel)
        .sort(compareStrings);
      const inReach: FindingRef[] = [];
      for (const file of files) inReach.push(...(findingsByFile.get(file) ?? []));
      inReach.sort(compareFindingRefs);
      reach = { files, findings: inReach };
      reachCache.set(handlerFile, reach);
    }
    return reach;
  };

  const routes: ExtractedRoute[] = rawRoutes.map((raw) => {
    const reach = reachOf(raw.filePath);
    const staticFindings: StaticFindingRef[] = reach.findings.map((f) => ({
      ...f,
      via: f.filePath === raw.filePath && f.line >= raw.line && f.line <= raw.endLine ? 'handler' : 'import-graph',
    }));
    return { ...raw, reachableFiles: [...reach.files], staticFindings };
  });

  routes.sort((a, b) =>
    compareStrings(a.path, b.path) ||
    compareStrings(a.method, b.method) ||
    compareStrings(a.filePath, b.filePath) ||
    a.line - b.line,
  );
  unresolved.sort((a, b) =>
    compareStrings(a.filePath, b.filePath) || a.line - b.line || compareStrings(a.reason, b.reason),
  );

  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    target: absRoot,
    frameworks: [...frameworks].sort(compareStrings),
    routes,
    unresolved,
  };
}

interface FindingRef {
  ruleId: string;
  filePath: string;
  line: number;
}

interface Reach {
  files: string[];
  findings: FindingRef[];
}

function compareFindingRefs(a: FindingRef, b: FindingRef): number {
  return compareStrings(a.filePath, b.filePath) || a.line - b.line || compareStrings(a.ruleId, b.ruleId);
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Raíz del proyecto: el directorio más cercano con package.json, subiendo desde `startPath`.
 * Si no hay ninguno, el directorio de `startPath` (o su carpeta, si es un fichero).
 */
export function findProjectRoot(startPath: string): string {
  const abs = path.resolve(startPath);
  const start = isFile(abs) ? path.dirname(abs) : abs;

  let dir = start;
  for (;;) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return start;
    dir = parent;
  }
}

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

/** ~/.basesec/routes/<sha256(raíz)[0..12]>.json */
export function defaultArtifactPath(root: string): string {
  const hash = crypto.createHash('sha256').update(path.resolve(root)).digest('hex').slice(0, 12);
  return path.join(getBaseSecDir(), 'routes', `${hash}.json`);
}

/**
 * Escribe el artefacto de forma atómica: temporal exclusivo (O_EXCL, 0600, nombre aleatorio) en el
 * mismo directorio + rename. El rename sustituye lo que haya en `target` (también un symlink: no se
 * escribe a través de él). El directorio por defecto (`~/.basesec/routes`) se fuerza a 0700 aunque
 * ya existiera; el de un `--routes-out` explícito es del usuario y no se modifica. Si el fichero
 * queda dentro de la raíz, avisa por stderr.
 */
export function writeRouteArtifact(artifact: RouteArtifact, file?: string): string {
  const target = path.resolve(file ?? defaultArtifactPath(artifact.target));
  const dir = path.dirname(target);
  if (file === undefined) {
    prepareDir(getBaseSecDir(), dir);
  } else {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const tmp = path.join(dir, `.${path.basename(target)}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  try {
    fs.writeFileSync(tmp, JSON.stringify(artifact, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    fs.renameSync(tmp, target);
  } catch (error) {
    fs.rmSync(tmp, { force: true });
    throw error;
  }

  if (isInside(path.resolve(artifact.target), target)) {
    console.error('Note: the route artifact describes your whole API surface; add it to .gitignore.');
  }
  return target;
}

function isInside(root: string, file: string): boolean {
  const rel = path.relative(root, file);
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
}
