import * as ts from 'typescript';
import * as path from 'node:path';
import { visit } from '../../utils/ast-helpers';
import type { ParsedFile } from '../../rules/types';
import type { ExtractionContext, ExtractionResult, RawRoute, RouteParam, UnresolvedRoute } from './types';
import {
  endLineOf,
  extractPathParams,
  isPatternPath,
  joinRoutePaths,
  literalPathValues,
  literalString,
  mergeParams,
  startLineOf,
  stripParamConstraints,
  toRootRelative,
} from './common';

const HTTP_DECORATORS: Record<string, string> = {
  Get: 'GET',
  Post: 'POST',
  Put: 'PUT',
  Patch: 'PATCH',
  Delete: 'DELETE',
  Head: 'HEAD',
  Options: 'OPTIONS',
  All: 'ALL',
};

const PARAM_DECORATORS: Record<string, RouteParam['in']> = {
  Param: 'path',
  Query: 'query',
  Body: 'body',
};

/** Decoradores que marcan una ruta como pública cuando hay un guard global. */
const PUBLIC_DECORATORS = ['Public', 'SkipAuth'];

/**
 * Extrae rutas de NestJS del AST: @Controller + @Get/@Post/…, prefijo global de
 * app.setGlobalPrefix, guards, decoradores de parámetros y DTOs de @Body()/@Query().
 */
export function extractNestRoutes(ctx: ExtractionContext): ExtractionResult {
  const root = ctx.root;
  const unresolved: UnresolvedRoute[] = [];
  const files = [...ctx.parsedFiles].sort((a, b) => compare(path.resolve(a.filePath), path.resolve(b.filePath)));

  const globalPrefix = findGlobalPrefix(files, root, unresolved);
  const hasGlobalGuard = detectGlobalGuard(files);
  const classesByName = indexClasses(files);

  const routes: RawRoute[] = [];

  for (const parsed of files) {
    visit(parsed.sourceFile, (node) => {
      if (ts.isClassDeclaration(node)) {
        collectController(node, parsed, {
          globalPrefix,
          hasGlobalGuard,
          classesByName,
          root,
          routes,
          unresolved,
        });
      }
      return 'continue';
    });
  }

  return { routes, unresolved: dedupeUnresolved(unresolved) };
}

function dedupeUnresolved(list: UnresolvedRoute[]): UnresolvedRoute[] {
  const seen = new Set<string>();
  return list.filter((u) => {
    const key = `${u.filePath}\0${u.line}\0${u.reason}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

interface GlobalPrefix {
  value: string;
  /** Rutas excluidas del prefijo (`exclude` de setGlobalPrefix); method undefined = cualquiera. */
  excluded: Array<{ path: string; method?: string }>;
}

interface CollectContext {
  globalPrefix: GlobalPrefix;
  hasGlobalGuard: boolean;
  classesByName: Map<string, ts.ClassDeclaration[]>;
  root: string;
  routes: RawRoute[];
  unresolved: UnresolvedRoute[];
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function decoratorsOf(node: ts.Node): ts.Decorator[] {
  return ts.canHaveDecorators(node) ? [...(ts.getDecorators(node) ?? [])] : [];
}

/** Nombre de un decorador: `@Get(...)` → 'Get', `@Foo` → 'Foo'. */
function decoratorName(dec: ts.Decorator): string | undefined {
  const expr = dec.expression;
  if (ts.isCallExpression(expr)) {
    return identifierName(expr.expression);
  }
  return identifierName(expr);
}

function identifierName(expr: ts.Expression): string | undefined {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
  return undefined;
}

function decoratorArgs(dec: ts.Decorator): readonly ts.Expression[] {
  return ts.isCallExpression(dec.expression) ? dec.expression.arguments : [];
}

function hasDecorator(node: ts.Node, names: readonly string[]): boolean {
  return decoratorsOf(node).some((dec) => {
    const name = decoratorName(dec);
    return name !== undefined && names.includes(name);
  });
}

/** Tipo simple que se muestra en el artefacto: solo string, number o boolean. */
function simpleType(node: ts.TypeNode | undefined): string | undefined {
  if (!node) return undefined;
  const text = node.getText(node.getSourceFile()).trim();
  return text === 'string' || text === 'number' || text === 'boolean' ? text : undefined;
}

function memberName(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return undefined;
}

/** Entradas literales de `exclude` en `setGlobalPrefix(prefix, { exclude: [...] })`. */
function excludedPaths(options: ts.Expression | undefined): GlobalPrefix['excluded'] {
  if (options === undefined || !ts.isObjectLiteralExpression(options)) return [];
  const prop = options.properties.find(
    (p): p is ts.PropertyAssignment => ts.isPropertyAssignment(p) && memberName(p.name) === 'exclude',
  );
  if (prop === undefined || !ts.isArrayLiteralExpression(prop.initializer)) return [];

  const excluded: GlobalPrefix['excluded'] = [];
  for (const element of prop.initializer.elements) {
    const direct = literalString(element);
    if (direct !== undefined) {
      excluded.push({ path: joinRoutePaths(direct) });
    } else if (ts.isObjectLiteralExpression(element)) {
      let excludedPath: string | undefined;
      let method: string | undefined;
      for (const p of element.properties) {
        if (!ts.isPropertyAssignment(p)) continue;
        const key = memberName(p.name);
        if (key === 'path') excludedPath = literalString(p.initializer);
        if (key === 'method') {
          const init = p.initializer;
          method = ts.isPropertyAccessExpression(init) ? init.name.text.toUpperCase() : undefined;
        }
      }
      if (excludedPath !== undefined) excluded.push({ path: joinRoutePaths(excludedPath), method });
    }
  }
  return excluded;
}

/** Prefijo global de `app.setGlobalPrefix('…')`. Un prefijo no literal se reporta. */
function findGlobalPrefix(files: ParsedFile[], root: string, unresolved: UnresolvedRoute[]): GlobalPrefix {
  const result: GlobalPrefix = { value: '', excluded: [] };
  let found = false;
  for (const parsed of files) {
    visit(parsed.sourceFile, (node) => {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'setGlobalPrefix' &&
        node.arguments.length >= 1
      ) {
        const value = literalString(node.arguments[0]);
        if (value !== undefined) {
          if (!found) {
            found = true;
            result.value = value;
            result.excluded = excludedPaths(node.arguments[1]);
          }
        } else {
          unresolved.push({
            filePath: toRootRelative(root, parsed.filePath),
            line: startLineOf(node),
            reason: 'prefijo global no literal',
          });
        }
      }
      return 'continue';
    });
  }
  return result;
}

/** Hay guard global si se llama a useGlobalGuards o hay un provider { provide: APP_GUARD }. */
function detectGlobalGuard(files: ParsedFile[]): boolean {
  let found = false;
  for (const parsed of files) {
    visit(parsed.sourceFile, (node) => {
      if (found) return 'stop';
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'useGlobalGuards'
      ) {
        found = true;
      } else if (
        ts.isPropertyAssignment(node) &&
        memberName(node.name) === 'provide' &&
        ts.isIdentifier(node.initializer) &&
        node.initializer.text === 'APP_GUARD'
      ) {
        found = true;
      }
      return 'continue';
    });
    if (found) break;
  }
  return found;
}

function indexClasses(files: ParsedFile[]): Map<string, ts.ClassDeclaration[]> {
  const byName = new Map<string, ts.ClassDeclaration[]>();
  for (const parsed of files) {
    visit(parsed.sourceFile, (node) => {
      if (ts.isClassDeclaration(node) && node.name) {
        const list = byName.get(node.name.text) ?? [];
        list.push(node);
        byName.set(node.name.text, list);
      }
      return 'continue';
    });
  }
  return byName;
}

/**
 * Prefijos de @Controller: literal, array, objeto { path }, o sin argumento (''). Devuelve
 * null si no es resoluble.
 */
function controllerPrefixes(dec: ts.Decorator): string[] | null {
  const args = decoratorArgs(dec);
  if (args.length === 0) return [''];
  const first = args[0];
  if (ts.isObjectLiteralExpression(first)) {
    const pathProp = first.properties.find(
      (p): p is ts.PropertyAssignment => ts.isPropertyAssignment(p) && memberName(p.name) === 'path',
    );
    return pathProp === undefined ? [''] : literalPathValues(pathProp.initializer);
  }
  return literalPathValues(first);
}

function collectController(node: ts.ClassDeclaration, parsed: ParsedFile, ctx: CollectContext): void {
  const classDecorators = decoratorsOf(node);
  const controller = classDecorators.find((dec) => decoratorName(dec) === 'Controller');
  if (controller === undefined) return;

  const prefixes = controllerPrefixes(controller)?.map(stripParamConstraints) ?? null;
  const classGuard = hasDecorator(node, ['UseGuards']);
  const classPublic = hasDecorator(node, PUBLIC_DECORATORS);
  const filePath = toRootRelative(ctx.root, parsed.filePath);

  for (const member of node.members) {
    if (!ts.isMethodDeclaration(member)) continue;
    const httpDec = decoratorsOf(member).find((dec) => {
      const name = decoratorName(dec);
      return name !== undefined && Object.hasOwn(HTTP_DECORATORS, name);
    });
    if (httpDec === undefined) continue;

    const httpName = decoratorName(httpDec) as string;
    const line = startLineOf(member);
    const endLine = endLineOf(member);

    if (prefixes === null) {
      ctx.unresolved.push({ filePath, line, reason: 'prefijo de controller no literal' });
      continue;
    }
    const rawMethodPaths = httpDecoratorPaths(httpDec);
    if (rawMethodPaths === null) {
      ctx.unresolved.push({ filePath, line, reason: 'path no literal' });
      continue;
    }
    const methodPaths = rawMethodPaths.map(stripParamConstraints);

    const methodGuard = classGuard || hasDecorator(member, ['UseGuards']);
    const publicRoute = classPublic || hasDecorator(member, PUBLIC_DECORATORS);
    const hasAuth: boolean | 'unknown' = methodGuard
      ? true
      : ctx.hasGlobalGuard
        ? (publicRoute ? false : 'unknown')
        : false;

    const handlerParams = methodParams(member, ctx.classesByName);

    for (const cp of prefixes) {
      for (const mp of methodPaths) {
        const method = HTTP_DECORATORS[httpName];
        const local = joinRoutePaths(cp, mp);
        if (isPatternPath(local)) {
          ctx.unresolved.push({ filePath, line, reason: 'path con patrón' });
          continue;
        }
        const skipPrefix = ctx.globalPrefix.excluded.some(
          (e) => e.path === local && (e.method === undefined || e.method === method || e.method === 'ALL'),
        );
        const full = skipPrefix ? local : joinRoutePaths(ctx.globalPrefix.value, local);
        ctx.routes.push({
          method,
          path: full,
          framework: 'nestjs',
          filePath,
          line,
          endLine,
          hasAuth,
          params: mergeParams(extractPathParams(full), handlerParams),
        });
      }
    }
  }
}

function httpDecoratorPaths(dec: ts.Decorator): string[] | null {
  const args = decoratorArgs(dec);
  if (args.length === 0) return [''];
  return literalPathValues(args[0]);
}

/** Parámetros de un método: @Param('x'), @Query('x'), @Body('x') y DTOs sin nombre. */
function methodParams(
  method: ts.MethodDeclaration,
  classesByName: Map<string, ts.ClassDeclaration[]>,
): RouteParam[] {
  const params: RouteParam[] = [];

  for (const parameter of method.parameters) {
    const type = simpleType(parameter.type);
    for (const dec of decoratorsOf(parameter)) {
      const name = decoratorName(dec);
      if (name === undefined || !Object.hasOwn(PARAM_DECORATORS, name)) continue;
      const location = PARAM_DECORATORS[name];
      const literal = literalString(decoratorArgs(dec)[0]);

      if (literal !== undefined) {
        params.push(type !== undefined ? { name: literal, in: location, type } : { name: literal, in: location });
        continue;
      }
      if (location !== 'path' && parameter.type && ts.isTypeReferenceNode(parameter.type)) {
        params.push(...dtoParams(parameter.type, location, classesByName));
      }
    }
  }

  return mergeParams(params);
}

/**
 * Propiedades de un DTO como parámetros. Solo si el nombre de la clase es único en el
 * proyecto; si no, no se añade nada (no se inventa).
 */
function dtoParams(
  typeRef: ts.TypeReferenceNode,
  location: RouteParam['in'],
  classesByName: Map<string, ts.ClassDeclaration[]>,
): RouteParam[] {
  const name = ts.isIdentifier(typeRef.typeName) ? typeRef.typeName.text : undefined;
  if (name === undefined) return [];
  const candidates = classesByName.get(name) ?? [];
  if (candidates.length !== 1) return [];

  const params: RouteParam[] = [];
  const visited = new Set<ts.ClassDeclaration>();
  let current: ts.ClassDeclaration | undefined = candidates[0];
  // Propiedades heredadas de `extends Base` (solo si la base es una clase única por nombre).
  while (current !== undefined && !visited.has(current)) {
    visited.add(current);
    for (const member of current.members) {
      if (!ts.isPropertyDeclaration(member)) continue;
      if (member.modifiers?.some((m) => m.kind === ts.SyntaxKind.StaticKeyword)) continue;
      const propName = memberName(member.name);
      if (propName === undefined) continue;
      const type = simpleType(member.type);
      params.push(type !== undefined ? { name: propName, in: location, type } : { name: propName, in: location });
    }
    current = baseClass(current, classesByName);
  }
  return params;
}

function baseClass(
  node: ts.ClassDeclaration,
  classesByName: Map<string, ts.ClassDeclaration[]>,
): ts.ClassDeclaration | undefined {
  const heritage = node.heritageClauses?.find((h) => h.token === ts.SyntaxKind.ExtendsKeyword);
  const base = heritage?.types[0]?.expression;
  if (base === undefined || !ts.isIdentifier(base)) return undefined;
  const candidates = classesByName.get(base.text) ?? [];
  return candidates.length === 1 ? candidates[0] : undefined;
}
