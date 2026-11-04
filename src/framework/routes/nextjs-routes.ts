import * as ts from 'typescript';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { visit } from '../../utils/ast-helpers';
import { logger } from '../../utils/logger';
import type { ExtractionContext, ExtractionResult, RawRoute, RouteParam, UnresolvedRoute } from './types';
import { ModuleIndex, localFunctionNode, type ModuleFile, type ResolvedExport } from './module-index';
import { classifyNextFile } from './nextjs-files';
import {
  endLineOf,
  extractPathParams,
  isAuthName,
  isPatternPath,
  joinRoutePaths,
  literalString,
  mergeParams,
  startLineOf,
  toRootRelative,
  unwrapExpression,
} from './common';
import { handlerAccessParams } from './express-routes';
import {
  HTTP_METHOD_NAMES,
  hasDefaultModifier,
  hasExportModifier,
  functionParams,
  isFunctionLike,
  isNewUrlOfReq,
  isReqCall,
  isReqProperty,
  isSearchParamsExpr,
  requestParamName,
  unwrapAwait,
} from './nextjs-access';

/**
 * Extractor de rutas de Next.js (plan §5.7). La ruta sale del sistema de ficheros: App Router
 * (`app/**\/route.*`) y Pages Router (`pages/api/**`). Los catch-all usan `:name+` y `:name*`,
 * que es notación propia de Next y válida en el artefacto; por eso no pasan por `isPatternPath`.
 */

const AUTH_CALL_NAMES = new Set([
  'auth',
  'getServerSession',
  'getSession',
  'getToken',
  'currentUser',
  'getAuth',
  'verifyToken',
  'requireAuth',
]);

const MIDDLEWARE_FILES = ['middleware.ts', 'middleware.js', 'src/middleware.ts', 'src/middleware.js'];
const CONFIG_FILES = ['next.config.js', 'next.config.mjs', 'next.config.cjs', 'next.config.ts'];
const CONFIG_FILE_LABEL = 'next.config.*';
const INTERCEPTION_SEGMENT = /\(\.{1,3}\)/;
const GROUP_SEGMENT = /^\([^()]*\)$/;
const CATCH_ALL_OPTIONAL_SEGMENT = /^\[\[\.\.\.([A-Za-z_]\w*)\]\]$/;
const CATCH_ALL_SEGMENT = /^\[\.\.\.([A-Za-z_]\w*)\]$/;
const DYNAMIC_SEGMENT = /^\[([A-Za-z_]\w*)\]$/;
const ESCAPED_UNDERSCORE = /%5F/gi;
const COMPARISON_OPERATORS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
]);

export function extractNextRoutes(ctx: ExtractionContext): ExtractionResult {
  const index = new ModuleIndex(ctx.parsedFiles, ctx.graph);
  const unresolved: UnresolvedRoute[] = [];
  const routes: RawRoute[] = [];
  const basePath = readBasePath(ctx.root, unresolved);
  const middleware = hasMiddleware(ctx);
  const files = [...ctx.parsedFiles].sort((a, b) => compare(path.resolve(a.filePath), path.resolve(b.filePath)));

  for (const parsed of files) {
    const rel = toRootRelative(ctx.root, parsed.filePath);
    if (isServerActionFile(parsed.sourceFile)) {
      unresolved.push({ filePath: rel, line: 1, reason: 'Server Actions de Next.js' });
    }

    const file = classifyNextFile(rel);
    if (file === null) continue;

    const mapped = segmentsToPieces(file.segments);
    if (mapped.kind === 'discard') continue;
    if (mapped.kind === 'unresolved') {
      unresolved.push({ filePath: rel, line: 1, reason: mapped.reason });
      continue;
    }

    const fullPath = joinRoutePaths(basePath, ...mapped.pieces);
    const mf = index.file(parsed.filePath);
    if (mf === undefined) continue;

    const emit = (method: string, handler: RouteHandler, handlerParams: RouteParam[]): void => {
      routes.push({
        method,
        path: fullPath,
        framework: 'nextjs',
        filePath: toRootRelative(ctx.root, handler.file),
        line: startLineOf(handler.node),
        endLine: endLineOf(handler.node),
        hasAuth: handlerAuth(handler, middleware),
        params: mergeParams(extractPathParams(fullPath), handlerParams),
      });
    };

    if (file.kind === 'app-route') {
      const handlers = appHandlers(mf, index);
      const explicit = new Set(handlers.map((h) => h.method));
      for (const handler of handlers) {
        const params = handler.fn !== undefined ? appParams(handler.fn) : [];
        emit(handler.method, handler, params);
        if (handler.method === 'GET' && !explicit.has('HEAD')) {
          emit('HEAD', handler, params);
        }
      }
    } else {
      const handler = pagesHandler(mf, index);
      if (handler === undefined) continue;
      const params = handler.fn !== undefined ? handlerAccessParams(handler.fn) : [];
      for (const method of pagesMethods(handler.fn)) {
        emit(method, handler, params);
      }
    }
  }

  return { routes, unresolved: dedupeUnresolved(unresolved) };
}

// ------------------------------------------------------------------ segmentos

type SegmentResult =
  | { kind: 'path'; pieces: string[] }
  | { kind: 'discard' }
  | { kind: 'unresolved'; reason: string };

/**
 * Segmentos de carpeta -> piezas de path (tabla de plan §5.7 / §2 del contrato). Un segmento
 * `_x` o `@x` descarta la ruta entera; `(.)x`, `(..)x` y `(...)x` (interceptación) quedan sin
 * resolver; los grupos `(x)` desaparecen; `%5F` es un guion bajo literal.
 */
export function segmentsToPieces(segments: string[]): SegmentResult {
  const pieces: string[] = [];
  for (const segment of segments) {
    if (segment.startsWith('_') || segment.startsWith('@')) return { kind: 'discard' };
    if (INTERCEPTION_SEGMENT.test(segment)) return { kind: 'unresolved', reason: 'ruta interceptada de Next.js' };
    if (GROUP_SEGMENT.test(segment)) continue;

    const optional = CATCH_ALL_OPTIONAL_SEGMENT.exec(segment);
    if (optional !== null) {
      pieces.push(`:${optional[1]}*`);
      continue;
    }
    const catchAll = CATCH_ALL_SEGMENT.exec(segment);
    if (catchAll !== null) {
      pieces.push(`:${catchAll[1]}+`);
      continue;
    }
    const dynamic = DYNAMIC_SEGMENT.exec(segment);
    if (dynamic !== null) {
      pieces.push(`:${dynamic[1]}`);
      continue;
    }

    const literal = segment.replace(ESCAPED_UNDERSCORE, '_');
    if (isPatternPath(literal) || literal.includes(':')) {
      return { kind: 'unresolved', reason: 'path con patrón' };
    }
    pieces.push(literal);
  }
  return { kind: 'path', pieces };
}

// ------------------------------------------------------------- basePath y config

/**
 * Lee `basePath` de next.config.* en la raíz (lo único que este extractor lee de disco; los
 * nombres son fijos, así que nunca sale de la raíz). El fichero se parsea y se buscan las
 * propiedades `basePath` y `rewrites`: un texto igual dentro de un comentario o de una cadena
 * no cuenta. Un basePath literal se antepone; uno no literal (`process.env.X`, una constante,
 * la forma abreviada `{ basePath }`) o los rewrites se listan como unresolved.
 */
function readBasePath(root: string, unresolved: UnresolvedRoute[]): string {
  for (const name of CONFIG_FILES) {
    const file = path.join(root, name);
    if (!fs.existsSync(file)) continue;

    let content: string;
    try {
      content = fs.readFileSync(file, 'utf-8');
    } catch (e) {
      logger.warn(`Could not read ${file}, Next.js routes are emitted without basePath`, e);
      return '';
    }

    const sf = ts.createSourceFile(file, content, ts.ScriptTarget.Latest, false);
    let prefix = '';
    let basePathSeen = false;
    let rewritesAt: number | undefined;
    visit(sf, (node) => {
      const key = configKey(node);
      if (key === 'basePath' && !basePathSeen) {
        basePathSeen = true;
        const value = ts.isPropertyAssignment(node) ? literalString(node.initializer) : undefined;
        if (value === '') return 'continue';
        if (value !== undefined && value.startsWith('/')) {
          prefix = value;
        } else {
          unresolved.push({
            filePath: CONFIG_FILE_LABEL,
            line: lineOfNode(sf, node),
            reason: 'basePath no literal',
          });
        }
      } else if (key === 'rewrites' && rewritesAt === undefined) {
        rewritesAt = lineOfNode(sf, node);
      }
      return 'continue';
    });
    if (rewritesAt !== undefined) {
      unresolved.push({
        filePath: CONFIG_FILE_LABEL,
        line: rewritesAt,
        reason: 'rewrites de next.config no interpretados',
      });
    }
    return prefix;
  }
  return '';
}

/** Nombre de la propiedad/método de un objeto de configuración (`basePath: …`, `basePath,`, `rewrites() {}`). */
function configKey(node: ts.Node): string | undefined {
  if (ts.isShorthandPropertyAssignment(node)) return node.name.text;
  if (ts.isPropertyAssignment(node) || ts.isMethodDeclaration(node)) {
    const name = node.name;
    return ts.isIdentifier(name) || ts.isStringLiteral(name) ? name.text : undefined;
  }
  return undefined;
}

function lineOfNode(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

function hasMiddleware(ctx: ExtractionContext): boolean {
  const known = new Set(ctx.parsedFiles.map((f) => path.resolve(f.filePath)));
  return MIDDLEWARE_FILES.some((rel) => {
    const abs = path.resolve(ctx.root, rel);
    return known.has(abs) || fs.existsSync(abs);
  });
}

function isServerActionFile(sf: ts.SourceFile): boolean {
  const first = sf.statements[0];
  return (
    first !== undefined &&
    ts.isExpressionStatement(first) &&
    ts.isStringLiteral(first.expression) &&
    first.expression.text === 'use server'
  );
}

// ---------------------------------------------------------------- handlers

interface RouteHandler {
  /** Fichero donde está el handler (puede no ser el de la ruta si viene de un import). */
  file: string;
  /** Rango del handler: la función, o la llamada si no se pudo resolver. */
  node: ts.Node;
  fn?: ts.Node;
  /** Callee de un wrapper de una sola llamada (`withAuth(handler)`). */
  wrapper?: string;
  /** Solo App Router: el método exportado. Pages lo calcula con `pagesMethods`. */
  method: string;
}

interface Resolved {
  file: string;
  fn: ts.Node;
}

function appHandlers(mf: ModuleFile, index: ModuleIndex): RouteHandler[] {
  const handlers: RouteHandler[] = [];
  for (const stmt of mf.sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && hasExportModifier(stmt) && stmt.name !== undefined && isHttpMethod(stmt.name.text)) {
      handlers.push({ method: stmt.name.text, file: mf.path, node: stmt, fn: stmt });
    } else if (ts.isVariableStatement(stmt) && hasExportModifier(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        if (ts.isObjectBindingPattern(decl.name)) {
          // `export const { GET, POST } = handlers` (Auth.js): el handler no se ve, se emite la
          // ruta con el rango de la declaración.
          for (const element of decl.name.elements) {
            if (ts.isIdentifier(element.name) && isHttpMethod(element.name.text) && !element.dotDotDotToken) {
              handlers.push({ method: element.name.text, file: mf.path, node: decl });
            }
          }
          continue;
        }
        if (!ts.isIdentifier(decl.name) || !isHttpMethod(decl.name.text) || decl.initializer === undefined) continue;
        handlers.push({ method: decl.name.text, ...valueHandler(mf, decl.initializer, index) });
      }
    } else if (ts.isExportDeclaration(stmt) && stmt.exportClause !== undefined && ts.isNamedExports(stmt.exportClause)) {
      const spec = stmt.moduleSpecifier !== undefined && ts.isStringLiteral(stmt.moduleSpecifier) ? stmt.moduleSpecifier.text : undefined;
      for (const element of stmt.exportClause.elements) {
        const exported = element.name.text;
        if (!isHttpMethod(exported)) continue;
        const local = (element.propertyName ?? element.name).text;
        const resolved = spec !== undefined ? fromModule(mf, spec, local, index) : resolveLocal(mf, local, index);
        handlers.push(
          resolved !== undefined
            ? { method: exported, file: resolved.file, node: resolved.fn, fn: resolved.fn }
            : { method: exported, file: mf.path, node: stmt },
        );
      }
    }
  }
  return handlers;
}

/** `export default …` de un route de Pages. Sin export default no hay ruta. */
function pagesHandler(mf: ModuleFile, index: ModuleIndex): RouteHandler | undefined {
  for (const stmt of mf.sf.statements) {
    if (ts.isExportAssignment(stmt) && !stmt.isExportEquals) {
      return { method: 'GET', ...valueHandler(mf, stmt.expression, index) };
    }
    if (ts.isFunctionDeclaration(stmt) && hasExportModifier(stmt) && hasDefaultModifier(stmt)) {
      return { method: 'GET', file: mf.path, node: stmt, fn: stmt };
    }
    if (ts.isExportDeclaration(stmt) && stmt.moduleSpecifier === undefined && stmt.exportClause !== undefined && ts.isNamedExports(stmt.exportClause)) {
      // `export { handler as default }`
      const element = stmt.exportClause.elements.find((e) => e.name.text === 'default');
      if (element === undefined) continue;
      const resolved = resolveLocal(mf, (element.propertyName ?? element.name).text, index);
      return resolved !== undefined
        ? { method: 'GET', file: resolved.file, node: resolved.fn, fn: resolved.fn }
        : { method: 'GET', file: mf.path, node: stmt };
    }
  }
  return undefined;
}

/** Handler a partir de su expresión: función, identificador, o un wrapper de una sola llamada. */
function valueHandler(
  mf: ModuleFile,
  input: ts.Expression,
  index: ModuleIndex,
): Omit<RouteHandler, 'method'> {
  const expr = unwrapExpression(input);
  if (isFunctionLike(expr)) {
    return { file: mf.path, node: expr, fn: expr };
  }

  if (ts.isCallExpression(expr) && expr.arguments.length === 1) {
    const inner = unwrapExpression(expr.arguments[0]);
    const resolved = innerHandler(mf, inner, index);
    const wrapper = expr.expression.getText(mf.sf);
    if (resolved !== undefined) {
      return { file: resolved.file, node: resolved.fn, fn: resolved.fn, wrapper };
    }
    return { file: mf.path, node: expr, wrapper };
  }

  const resolved = innerHandler(mf, expr, index);
  if (resolved !== undefined) {
    return { file: resolved.file, node: resolved.fn, fn: resolved.fn };
  }
  return { file: mf.path, node: expr };
}

function innerHandler(mf: ModuleFile, expr: ts.Expression, index: ModuleIndex): Resolved | undefined {
  if (isFunctionLike(expr)) return { file: mf.path, fn: expr };
  if (ts.isIdentifier(expr)) return resolveLocal(mf, expr.text, index);
  return undefined;
}

/** Función de nivel superior con ese nombre; si viene de un import relativo, se sigue el grafo. */
function resolveLocal(mf: ModuleFile, name: string, index: ModuleIndex): Resolved | undefined {
  const local = localFunctionNode(mf, name);
  if (local !== undefined) return { file: mf.path, fn: local };

  const binding = mf.imports.get(name);
  if (binding === undefined || !isRelativeSpec(binding.spec)) return undefined;
  return fromModule(mf, binding.spec, binding.imported, index);
}

function fromModule(mf: ModuleFile, spec: string, name: string, index: ModuleIndex): Resolved | undefined {
  if (!isRelativeSpec(spec)) return undefined;
  const target = index.target(mf, spec);
  if (target === undefined) return undefined;
  const resolved = index.resolveExport(target, name);
  return resolved === undefined || resolved.namespace ? undefined : functionOfExport(resolved);
}

function functionOfExport(resolved: ResolvedExport): Resolved | undefined {
  if (resolved.value !== undefined) {
    const value = ts.isExpression(resolved.value) ? unwrapExpression(resolved.value) : resolved.value;
    if (isFunctionLike(value) || ts.isFunctionDeclaration(value)) {
      return { file: resolved.file.path, fn: value };
    }
    return undefined;
  }
  if (resolved.local !== undefined) {
    const fn = localFunctionNode(resolved.file, resolved.local);
    return fn !== undefined ? { file: resolved.file.path, fn } : undefined;
  }
  return undefined;
}

function isRelativeSpec(spec: string): boolean {
  return spec.startsWith('./') || spec.startsWith('../');
}

function isHttpMethod(name: string): boolean {
  return (HTTP_METHOD_NAMES as readonly string[]).includes(name);
}

/**
 * Métodos de un handler de Pages: literales comparados con `req.method` (===, !==, ==, !=), en
 * `switch (req.method)` o en un array literal `[...].includes(req.method)`. Sin comparaciones,
 * solo GET.
 */
function pagesMethods(fn: ts.Node | undefined): string[] {
  const req = fn !== undefined ? requestParamName(fn) : undefined;
  if (fn === undefined || req === undefined) return ['GET'];

  const found: string[] = [];
  const add = (value: string | undefined): void => {
    if (value === undefined) return;
    const upper = value.toUpperCase();
    if (isHttpMethod(upper) && !found.includes(upper)) found.push(upper);
  };

  visit(fn, (node) => {
    if (ts.isBinaryExpression(node) && COMPARISON_OPERATORS.has(node.operatorToken.kind)) {
      if (isReqProperty(node.left, req, 'method')) add(literalString(node.right));
      else if (isReqProperty(node.right, req, 'method')) add(literalString(node.left));
    } else if (
      ts.isCallExpression(node) &&
      node.arguments.length === 1 &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === 'includes' &&
      isReqProperty(node.arguments[0], req, 'method')
    ) {
      // `['GET', 'POST'].includes(req.method)`: se cuentan todos los literales del array, también
      // en la forma negada (`!['GET','POST'].includes(...)`) porque lista los métodos soportados.
      const list = unwrapExpression(node.expression.expression);
      if (ts.isArrayLiteralExpression(list)) {
        for (const element of list.elements) add(literalString(element));
      }
    } else if (ts.isSwitchStatement(node) && isReqProperty(node.expression, req, 'method')) {
      for (const clause of node.caseBlock.clauses) {
        if (ts.isCaseClause(clause)) add(literalString(clause.expression));
      }
    }
    return 'continue';
  });

  return found.length > 0 ? found : ['GET'];
}

// ------------------------------------------------------------------ auth

/**
 * `true` si el handler (o el wrapper que lo envuelve) muestra auth. Si no, `'unknown'` cuando
 * existe middleware.ts (su matcher no se interpreta), y `false` en otro caso.
 */
function handlerAuth(handler: RouteHandler, middleware: boolean): boolean | 'unknown' {
  if (handler.wrapper !== undefined && isAuthName(handler.wrapper)) return true;

  let found = false;
  visit(handler.node, (node) => {
    if (found) return 'stop';
    if (ts.isCallExpression(node)) {
      const callee = unwrapExpression(node.expression);
      // Solo llamadas a un identificador: `store.getToken()` o `db.getSession()` son otra cosa.
      if (ts.isIdentifier(callee) && AUTH_CALL_NAMES.has(callee.text)) found = true;
    }
    return 'continue';
  });
  if (found) return true;
  return middleware ? 'unknown' : false;
}

// ---------------------------------------------------------- parámetros App

/**
 * Parámetros de un handler del App Router: query (`searchParams.get`), body (`await req.json()`,
 * `formData.get`) y path (`ctx.params`, desestructurado o no). Solo literales.
 */
function appParams(fn: ts.Node): RouteParam[] {
  const req = requestParamName(fn);
  if (req === undefined) return [];

  const second = functionParams(fn)[1];
  let ctxName: string | undefined;
  const paramsVars = new Set<string>();
  if (second !== undefined) {
    if (ts.isIdentifier(second.name)) {
      ctxName = second.name.text;
    } else if (ts.isObjectBindingPattern(second.name)) {
      for (const element of second.name.elements) {
        const local = ts.isIdentifier(element.name) ? element.name.text : undefined;
        if (local !== undefined && bindingKey(element) === 'params') paramsVars.add(local);
      }
    }
  }

  const isCtxParams = (expr: ts.Expression): boolean => {
    const node = unwrapAwait(expr);
    return (
      ts.isPropertyAccessExpression(node) &&
      node.name.text === 'params' &&
      ctxName !== undefined &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === ctxName
    );
  };

  const spVars = new Set<string>();
  const bodyVars = new Set<string>();
  const formVars = new Set<string>();

  visit(fn, (node) => {
    if (ts.isVariableDeclaration(node) && node.initializer !== undefined) {
      const init = node.initializer;
      if (ts.isIdentifier(node.name)) {
        const name = node.name.text;
        if (isCtxParams(init)) paramsVars.add(name);
        if (isSearchParamsExpr(init, req)) spVars.add(name);
        if (isReqCall(init, req, 'json')) bodyVars.add(name);
        if (isReqCall(init, req, 'formData')) formVars.add(name);
      } else if (ts.isObjectBindingPattern(node.name)) {
        const core = unwrapAwait(init);
        if (isNewUrlOfReq(core, req)) {
          for (const element of node.name.elements) {
            if (ts.isIdentifier(element.name) && bindingKey(element) === 'searchParams') spVars.add(element.name.text);
          }
        }
        const initId = unwrapExpression(init);
        if (ctxName !== undefined && ts.isIdentifier(initId) && initId.text === ctxName) {
          for (const element of node.name.elements) {
            if (ts.isIdentifier(element.name) && bindingKey(element) === 'params') paramsVars.add(element.name.text);
          }
        }
      }
    }
    return 'continue';
  });

  const found: RouteParam[] = [];
  const pushAccess = (input: ts.Expression, key: string): void => {
    if (isCtxParams(input)) {
      found.push({ name: key, in: 'path' });
      return;
    }
    // `(await params).id` cuando `params` salió de la desestructuración del segundo parámetro.
    const base = unwrapAwait(input);
    if (!ts.isIdentifier(base)) return;
    if (paramsVars.has(base.text)) found.push({ name: key, in: 'path' });
    else if (bodyVars.has(base.text)) found.push({ name: key, in: 'body' });
  };

  visit(fn, (node) => {
    if (ts.isPropertyAccessExpression(node)) {
      // `body.map(...)` o `body.hasOwnProperty(...)` es una llamada a un método, no un campo.
      const isCallee = ts.isCallExpression(node.parent) && node.parent.expression === node;
      if (!isCallee) pushAccess(node.expression, node.name.text);
    } else if (ts.isElementAccessExpression(node)) {
      const key = literalString(node.argumentExpression);
      if (key !== undefined) pushAccess(node.expression, key);
    } else if (ts.isCallExpression(node)) {
      const callee = unwrapExpression(node.expression);
      const key = node.arguments.length > 0 ? literalString(node.arguments[0]) : undefined;
      if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'get' && key !== undefined) {
        const recv = callee.expression;
        const recvName = ts.isIdentifier(recv) ? recv.text : undefined;
        if (isSearchParamsExpr(recv, req) || (recvName !== undefined && spVars.has(recvName))) {
          found.push({ name: key, in: 'query' });
        } else if ((recvName !== undefined && formVars.has(recvName)) || isReqCall(recv, req, 'formData')) {
          found.push({ name: key, in: 'body' });
        }
      }
    } else if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name) && node.initializer !== undefined) {
      const init = node.initializer;
      const initId = unwrapAwait(init);
      if (isReqCall(init, req, 'json')) pushBindingKeys(node.name, 'body', found);
      else if (isCtxParams(init) || (ts.isIdentifier(initId) && paramsVars.has(initId.text))) {
        pushBindingKeys(node.name, 'path', found);
      }
    }
    return 'continue';
  });

  return mergeParams(found);
}

function pushBindingKeys(pattern: ts.ObjectBindingPattern, location: RouteParam['in'], out: RouteParam[]): void {
  for (const element of pattern.elements) {
    if (element.dotDotDotToken) continue;
    const key = bindingKey(element);
    if (key !== undefined) out.push({ name: key, in: location });
  }
}

/** Clave de un elemento de desestructuración: `{ a }` -> a, `{ a: b }` -> a. */
function bindingKey(element: ts.BindingElement): string | undefined {
  const source = element.propertyName ?? element.name;
  return ts.isIdentifier(source) || ts.isStringLiteral(source) ? source.text : undefined;
}

// ------------------------------------------------------------------ utilidades

function dedupeUnresolved(list: UnresolvedRoute[]): UnresolvedRoute[] {
  const seen = new Set<string>();
  return list.filter((u) => {
    const key = `${u.filePath}\0${u.line}\0${u.reason}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
