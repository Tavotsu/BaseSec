import * as fs from 'node:fs';
import * as path from 'node:path';
import type {
  ExtractedRoute,
  RouteArtifact,
  RouteParam,
  StaticFindingRef,
  UnresolvedRoute,
} from '../framework/routes/types';
import { logger } from '../utils/logger';

export class RouteArtifactError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RouteArtifactError';
  }
}

export interface LoadedSurface {
  artifact: RouteArtifact;
  source: 'artifact' | 'scan' | 'routes-file';
  stale: boolean;
}

export interface SurfaceEndpoint {
  method: string;
  path: string;
  concretePath: string;
  route: ExtractedRoute;
  mutating: boolean;
}

const MAX_ARTIFACT_BYTES = 20 * 1024 * 1024;
const READ_CHUNK_BYTES = 1024 * 1024;
const MAX_ROUTES = 50000;
const MAX_PATH_LENGTH = 2048;
const MAX_STALE_CHECKS = 2000;
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'ALL']);
const FRAMEWORKS = new Set(['express', 'nestjs', 'nextjs']);
const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/;
const PARAM_TOKEN = /:(\w+)([?+*]?)/g;

export function loadRouteArtifact(file: string): RouteArtifact {
  let text: string;
  try {
    text = readBounded(file);
  } catch (e) {
    if (e instanceof RouteArtifactError) throw e;
    throw new RouteArtifactError(`No se pudo leer el artefacto de rutas: ${file}`);
  }

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    // El mensaje de JSON.parse puede citar fragmentos del fichero: no se reenvía.
    throw new RouteArtifactError('El artefacto de rutas no es JSON válido');
  }
  return validateRouteArtifact(raw);
}

/**
 * Lee un fichero regular de como mucho MAX_ARTIFACT_BYTES. Se lee por descriptor y con tope, no por el
 * tamaño de stat: un fichero especial (/dev/zero, una FIFO) o uno que crece mientras se lee no agota la memoria.
 */
function readBounded(file: string): string {
  const fd = fs.openSync(file, 'r');
  try {
    if (!fs.fstatSync(fd).isFile()) throw new RouteArtifactError(`El artefacto de rutas no es un fichero regular: ${file}`);
    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const chunk = Buffer.alloc(READ_CHUNK_BYTES);
      const read = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (read === 0) break;
      total += read;
      if (total > MAX_ARTIFACT_BYTES) {
        throw new RouteArtifactError(`El artefacto de rutas supera ${MAX_ARTIFACT_BYTES} bytes`);
      }
      chunks.push(chunk.subarray(0, read));
    }
    return Buffer.concat(chunks, total).toString('utf-8');
  } finally {
    fs.closeSync(fd);
  }
}

function fail(where: string, reason: string): never {
  throw new RouteArtifactError(`Artefacto de rutas no válido: ${where} ${reason}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

/**
 * Ruta relativa al proyecto, con "/" como separador (así la emite 2a/2b): sin ruta absoluta, sin letra de
 * unidad, sin "\\" (separador de Windows), sin segmentos "..", sin NUL ni otros caracteres de control.
 */
function isSafeRelativePath(value: unknown): value is string {
  if (typeof value !== 'string' || value === '') return false;
  if (path.isAbsolute(value) || /^[A-Za-z]:/.test(value) || value.includes('\\')) return false;
  if (CONTROL_CHARS.test(value)) return false;
  return !value.split('/').includes('..');
}

/** Segmento "." o ".." escrito tal cual o con el punto codificado (%2e): new URL lo colapsaría y cambiaría el path. */
export function isDotSegment(segment: string): boolean {
  const decoded = segment.replace(/%2e/gi, '.');
  return decoded === '.' || decoded === '..';
}

function isRoutePath(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.startsWith('/') &&
    value.length <= MAX_PATH_LENGTH &&
    !value.includes('//') &&
    !value.includes('\\') &&
    !CONTROL_CHARS.test(value) &&
    !value.split('/').some(isDotSegment)
  );
}

function validateRoute(route: unknown, index: number): ExtractedRoute {
  const at = (field: string): string => `routes[${index}].${field}`;
  if (!isRecord(route)) fail(`routes[${index}]`, 'no es un objeto');
  if (typeof route.method !== 'string' || !METHODS.has(route.method)) {
    fail(at('method'), 'no es un método HTTP soportado');
  }
  if (!isRoutePath(route.path)) {
    fail(
      at('path'),
      'debe empezar por "/", no contener "//", "\\", segmentos "." o "..", ni caracteres de control, y tener 2048 caracteres como máximo',
    );
  }
  if (typeof route.framework !== 'string' || !FRAMEWORKS.has(route.framework)) {
    fail(at('framework'), 'debe ser express, nestjs o nextjs');
  }
  if (!isSafeRelativePath(route.filePath)) fail(at('filePath'), 'debe ser una ruta relativa sin ".."');
  if (!isInteger(route.line) || route.line < 1) fail(at('line'), 'debe ser un entero positivo');
  if (!isInteger(route.endLine) || route.endLine < 1) fail(at('endLine'), 'debe ser un entero positivo');
  if (route.endLine < route.line) fail(at('endLine'), 'es menor que line');
  if (route.hasAuth !== true && route.hasAuth !== false && route.hasAuth !== 'unknown') {
    fail(at('hasAuth'), 'debe ser true, false o "unknown"');
  }

  const rawParams = route.params;
  if (!Array.isArray(rawParams)) fail(at('params'), 'debe ser un array');
  const params = rawParams.map((param: unknown, p): RouteParam => {
    const where = `${at('params')}[${p}]`;
    if (!isRecord(param)) fail(where, 'no es un objeto');
    if (typeof param.name !== 'string' || param.name === '') fail(`${where}.name`, 'debe ser una cadena no vacía');
    if (param.in !== 'path' && param.in !== 'query' && param.in !== 'body') {
      fail(`${where}.in`, 'debe ser path, query o body');
    }
    if (param.type !== undefined && typeof param.type !== 'string') fail(`${where}.type`, 'debe ser una cadena');
    return param.type === undefined
      ? { name: param.name, in: param.in }
      : { name: param.name, in: param.in, type: param.type };
  });

  const rawReachable = route.reachableFiles;
  if (!Array.isArray(rawReachable)) fail(at('reachableFiles'), 'debe ser un array');
  const reachableFiles = rawReachable.map((file: unknown, f): string => {
    if (!isSafeRelativePath(file)) fail(`${at('reachableFiles')}[${f}]`, 'debe ser una ruta relativa sin ".."');
    return file;
  });

  const rawStatics = route.staticFindings;
  if (!Array.isArray(rawStatics)) fail(at('staticFindings'), 'debe ser un array');
  const staticFindings = rawStatics.map((finding: unknown, s): StaticFindingRef => {
    const where = `${at('staticFindings')}[${s}]`;
    if (!isRecord(finding)) fail(where, 'no es un objeto');
    if (typeof finding.ruleId !== 'string' || finding.ruleId === '') fail(`${where}.ruleId`, 'debe ser una cadena no vacía');
    if (!isSafeRelativePath(finding.filePath)) fail(`${where}.filePath`, 'debe ser una ruta relativa sin ".."');
    if (!isInteger(finding.line) || finding.line < 0) fail(`${where}.line`, 'debe ser un entero no negativo');
    if (finding.via !== 'handler' && finding.via !== 'import-graph') {
      fail(`${where}.via`, 'debe ser handler o import-graph');
    }
    return { ruleId: finding.ruleId, filePath: finding.filePath, line: finding.line, via: finding.via };
  });

  return {
    method: route.method,
    path: route.path,
    framework: route.framework as ExtractedRoute['framework'],
    filePath: route.filePath,
    line: route.line,
    endLine: route.endLine,
    hasAuth: route.hasAuth,
    params,
    reachableFiles,
    staticFindings,
  };
}

/**
 * Valida la forma completa del artefacto (plan §5.2). Cualquier entrada inválida lo invalida entero;
 * el mensaje indica el índice y el campo, nunca el valor. Devuelve una copia reconstruida solo con los campos
 * conocidos: las propiedades extra del JSON (incluida una propia "__proto__") no llegan al resto del código.
 */
export function validateRouteArtifact(raw: unknown): RouteArtifact {
  if (!isRecord(raw)) fail('raíz', 'no es un objeto');
  if (raw.version !== 1) throw new RouteArtifactError('versión de artefacto no soportada');
  if (typeof raw.generatedAt !== 'string' || Number.isNaN(Date.parse(raw.generatedAt))) {
    fail('generatedAt', 'debe ser una fecha ISO válida');
  }
  if (typeof raw.target !== 'string' || !path.isAbsolute(raw.target) || CONTROL_CHARS.test(raw.target)) {
    fail('target', 'debe ser una ruta absoluta sin caracteres de control');
  }
  if (!isStringArray(raw.frameworks)) fail('frameworks', 'debe ser un array de cadenas');

  const rawRoutes = raw.routes;
  if (!Array.isArray(rawRoutes)) fail('routes', 'debe ser un array');
  if (rawRoutes.length > MAX_ROUTES) fail('routes', `supera ${MAX_ROUTES} entradas`);
  const routes = rawRoutes.map((route: unknown, index) => validateRoute(route, index));

  const rawUnresolved = raw.unresolved;
  if (!Array.isArray(rawUnresolved)) fail('unresolved', 'debe ser un array');
  const unresolved = rawUnresolved.map((entry: unknown, index): UnresolvedRoute => {
    const where = `unresolved[${index}]`;
    if (!isRecord(entry)) fail(where, 'no es un objeto');
    if (typeof entry.filePath !== 'string' || (entry.filePath !== '' && !isSafeRelativePath(entry.filePath))) {
      fail(`${where}.filePath`, 'debe ser una ruta relativa sin ".."');
    }
    if (!isInteger(entry.line) || entry.line < 0) fail(`${where}.line`, 'debe ser un entero no negativo');
    if (typeof entry.reason !== 'string') fail(`${where}.reason`, 'debe ser una cadena');
    return { filePath: entry.filePath, line: entry.line, reason: entry.reason };
  });

  return {
    version: 1,
    generatedAt: raw.generatedAt,
    target: raw.target,
    frameworks: [...raw.frameworks],
    routes,
    unresolved,
  };
}

/**
 * true si algún fichero de una ruta cambió después de generar el artefacto, o ya no existe. Solo hace stat,
 * nunca lee contenido. `target` viene del artefacto (no confiable), así que cada fichero se resuelve con
 * realpath y solo se consulta si queda dentro de `target`: ni un filePath con "..", ni un symlink que
 * apunte fuera, hacen un stat de algo ajeno al proyecto (ese fichero se ignora).
 */
export function isArtifactStale(artifact: RouteArtifact): boolean {
  const generatedAt = Date.parse(artifact.generatedAt);
  let realTarget: string;
  try {
    realTarget = fs.realpathSync(artifact.target);
  } catch (e) {
    if (isMissing(e)) return true;
    logger.warn('No se pudo resolver el directorio del artefacto de rutas', e);
    return false;
  }
  const files = [...new Set(artifact.routes.map((route) => route.filePath))].slice(0, MAX_STALE_CHECKS);
  for (const file of files) {
    const abs = path.resolve(realTarget, file);
    if (!isInside(realTarget, abs)) continue;
    try {
      const real = fs.realpathSync(abs);
      if (!isInside(realTarget, real)) continue;
      if (fs.statSync(real).mtimeMs > generatedAt) return true;
    } catch (e) {
      if (isMissing(e)) return true;
      logger.warn(`No se pudo comprobar si ${file} es posterior al artefacto`, e);
    }
  }
  return false;
}

function isMissing(e: unknown): boolean {
  const code = (e as NodeJS.ErrnoException).code;
  return code === 'ENOENT' || code === 'ENOTDIR';
}

function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

/** Sustituye los parámetros por valores de muestra: :x y :x? → 1, :x+ → x, :x* → se elimina. */
function concretize(routePath: string): string {
  const segments: string[] = [];
  for (const segment of routePath.split('/').slice(1)) {
    const value = segment.replace(PARAM_TOKEN, (_token, _name: string, modifier: string) =>
      modifier === '*' ? '' : encodeURIComponent(modifier === '+' ? 'x' : '1'),
    );
    if (value !== '') segments.push(value);
  }
  return `/${segments.join('/')}`;
}

/** Endpoints únicos del artefacto por (método, path). ALL se trata como GET. Orden estable por (path, method). */
export function toSurfaceEndpoints(artifact: RouteArtifact): SurfaceEndpoint[] {
  const byKey = new Map<string, SurfaceEndpoint>();
  for (const route of artifact.routes) {
    const method = route.method === 'ALL' ? 'GET' : route.method;
    const key = `${method} ${route.path}`;
    if (byKey.has(key)) continue;
    byKey.set(key, {
      method,
      path: route.path,
      concretePath: concretize(route.path),
      route,
      mutating: MUTATING.has(method),
    });
  }
  return [...byKey.values()].sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : a.method < b.method ? -1 : a.method > b.method ? 1 : 0,
  );
}
