import * as ts from 'typescript';
import { visit } from '../../utils/ast-helpers';
import type { ExtractionContext, ExtractionResult, RawRoute, RouteParam, UnresolvedRoute } from './types';
import {
  ModuleIndex,
  type ModuleFile,
  type ResolvedExport,
  type TopDecl,
  isRequireCall,
  requireSpecifier,
  localFunctionNode,
} from './module-index';
import {
  endLineOf,
  extractPathParams,
  hasAuthMiddleware,
  isAuthName,
  isPatternPath,
  isRequestSection,
  joinRoutePaths,
  literalPathValues,
  literalString,
  mergeParams,
  startLineOf,
  stripParamConstraints,
  toRootRelative,
  unwrapExpression,
} from './common';

const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'all'];
const MAX_REF_DEPTH = 8;

type RoutingKind = 'root' | 'router';

interface AuthMark {
  file: string;
  pos: number;
}

interface DirectRoute {
  method: string;
  paths: string[];
  /** Fichero donde se declara la ruta (absoluto). */
  file: string;
  pos: number;
  /** Línea de la llamada de declaración (para `unresolved`). */
  declLine: number;
  handlerFile: string;
  line: number;
  endLine: number;
  inlineAuth: boolean;
  handlerParams: RouteParam[];
}

/** Un prefijo de montaje: `value` null = no se puede resolver a una URL concreta (`reason` dice por qué). */
interface PrefixEntry {
  value: string | null;
  reason: string;
}

const NON_LITERAL_PREFIX = 'prefijo de montaje no literal';
const PATTERN_PATH = 'path con patrón';
/** Nombres que, sin poder resolverse, se leen como prefijo y no como middleware. */
const PREFIX_LIKE_NAME = /prefix|base_?path|base_?url|mount_?path/i;

interface Mount {
  file: string;
  pos: number;
  line: number;
  prefixes: PrefixEntry[];
  /** Clave del objeto montado. */
  target: string;
  hasAuth: boolean;
}

interface RoutingObject {
  key: string;
  file: string;
  name: string;
  kind: RoutingKind;
  routes: DirectRoute[];
  mounts: Mount[];
  authMarks: AuthMark[];
}

interface HandlerRef {
  file: string;
  node: ts.Node;
  /** Función real del handler (ausente si no se resolvió y se usa la llamada). */
  fn?: ts.Node;
}

/**
 * Extrae rutas de Express del AST: objetos de enrutado, montajes con prefijos (cross-file
 * por el grafo de imports), handlers y parámetros. No modifica `express.ts`.
 */
export function extractExpressRoutes(ctx: ExtractionContext): ExtractionResult {
  return new ExpressExtractor(ctx).run();
}

class ExpressExtractor {
  private readonly index: ModuleIndex;
  private readonly objects = new Map<string, RoutingObject>();
  private readonly declared = new Map<string, Map<string, RoutingKind>>();
  private readonly unresolved: UnresolvedRoute[] = [];
  private readonly root: string;

  constructor(private readonly ctx: ExtractionContext) {
    this.index = new ModuleIndex(ctx.parsedFiles, ctx.graph);
    this.root = ctx.root;
  }

  run(): ExtractionResult {
    const files = this.index.allFiles();

    // Pasada 1: objetos declarados (const app = express(), const r = express.Router()).
    for (const file of files) {
      const kinds = new Map<string, RoutingKind>();
      this.declared.set(file.path, kinds);
      visit(file.sf, (node) => {
        if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
          const kind = this.factoryKind(file, node.initializer);
          if (kind !== undefined) {
            kinds.set(node.name.text, kind);
            this.ensureObject(file.path, node.name.text, kind);
          }
        }
        return 'continue';
      });
    }

    // Pasada 2: declaraciones de ruta y de montaje / auth.
    for (const file of files) {
      visit(file.sf, (node) => {
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
          const name = node.expression.name.text;
          if (name === 'use') {
            this.handleUse(file, node, node.expression.expression);
          } else if (HTTP_METHODS.includes(name)) {
            this.handleRoute(file, node, name);
          }
        }
        return 'continue';
      });
    }

    // Pasada 3: expansión desde las raíces; las rutas de routers no alcanzados se listan.
    const reached = new Set<string>();
    const routes: RawRoute[] = [];
    const sortedObjects = [...this.objects.values()].sort((a, b) => compareStrings(a.key, b.key));

    for (const obj of sortedObjects) {
      if (obj.kind === 'root') {
        this.expand(obj, '', '', false, [obj.key], reached, routes);
      }
    }

    for (const obj of sortedObjects) {
      if (obj.kind !== 'router' || reached.has(obj.key)) continue;
      for (const route of obj.routes) {
        this.unresolved.push({
          filePath: toRootRelative(this.root, route.file),
          line: route.declLine,
          reason: 'router sin montaje conocido',
        });
      }
    }

    return { routes: dedupeRoutes(routes), unresolved: dedupeUnresolved(this.unresolved) };
  }

  // ---------------------------------------------------------------- objetos

  private key(file: string, name: string): string {
    return `${file}#${name}`;
  }

  private ensureObject(file: string, name: string, kind: RoutingKind): string {
    const key = this.key(file, name);
    if (!this.objects.has(key)) {
      this.objects.set(key, { key, file, name, kind, routes: [], mounts: [], authMarks: [] });
    }
    return key;
  }

  /** Clasifica una expresión de creación: express(), express.Router(), Router(). */
  private factoryKind(file: ModuleFile, expr: ts.Expression): RoutingKind | undefined {
    if (!ts.isCallExpression(expr)) return undefined;
    const callee = expr.expression;

    if (ts.isIdentifier(callee)) {
      const binding = file.imports.get(callee.text);
      if (binding?.spec !== 'express') return undefined;
      if (binding.imported === 'Router') return 'router';
      if (binding.imported === 'default' || binding.imported === '*') return 'root';
      return undefined;
    }

    if (isRequireCall(callee) && requireSpecifier(callee) === 'express') {
      return 'root';
    }

    if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'Router' && this.isExpressModule(file, callee.expression)) {
      return 'router';
    }

    return undefined;
  }

  private isExpressModule(file: ModuleFile, expr: ts.Expression): boolean {
    if (ts.isIdentifier(expr)) {
      const binding = file.imports.get(expr.text);
      return binding?.spec === 'express' && (binding.imported === 'default' || binding.imported === '*');
    }
    return isRequireCall(expr) && requireSpecifier(expr) === 'express';
  }

  // ------------------------------------------------------ resolución de refs

  /** Clave del objeto de enrutado al que se refiere `expr`, o undefined. */
  private resolveRef(file: ModuleFile, expr: ts.Expression, depth = 0): string | undefined {
    if (depth > MAX_REF_DEPTH) return undefined;

    if (ts.isParenthesizedExpression(expr)) {
      return this.resolveRef(file, expr.expression, depth + 1);
    }
    if (ts.isIdentifier(expr)) {
      return this.resolveName(file, expr.text, depth + 1);
    }
    if (isRequireCall(expr)) {
      return this.resolveFromSpec(file, requireSpecifier(expr), 'default', depth + 1);
    }
    if (ts.isPropertyAccessExpression(expr)) {
      const base = expr.expression;
      if (isRequireCall(base)) {
        return this.resolveFromSpec(file, requireSpecifier(base), expr.name.text, depth + 1);
      }
      if (ts.isIdentifier(base) && !this.declared.get(file.path)?.has(base.text)) {
        const binding = file.imports.get(base.text);
        if (binding !== undefined && isRelative(binding.spec)) {
          return this.resolveFromSpec(file, binding.spec, expr.name.text, depth + 1);
        }
      }
    }
    return undefined;
  }

  private resolveName(file: ModuleFile, name: string, depth: number): string | undefined {
    if (depth > MAX_REF_DEPTH) return undefined;

    if (this.declared.get(file.path)?.has(name)) {
      return this.key(file.path, name);
    }

    const binding = file.imports.get(name);
    if (binding !== undefined && isRelative(binding.spec)) {
      const viaImport = this.resolveFromSpec(file, binding.spec, binding.imported, depth + 1);
      if (viaImport !== undefined) return viaImport;
    }

    const decl = file.topDecls.get(name);
    const isInstance = decl?.kind === 'value' && decl.init !== undefined && ts.isNewExpression(unwrapExpression(decl.init));
    if (isRoutingName(name) && !isInstance) {
      return this.ensureObject(file.path, name, name === 'app' ? 'root' : 'router');
    }
    return undefined;
  }

  private resolveFromSpec(file: ModuleFile, spec: string, exportName: string, depth: number): string | undefined {
    if (depth > MAX_REF_DEPTH || !isRelative(spec)) return undefined;
    const target = this.index.target(file, spec);
    if (target === undefined) return undefined;
    return this.resolveExportedRef(target, exportName, depth + 1);
  }

  private resolveExportedRef(target: ModuleFile, exportName: string, depth: number): string | undefined {
    if (depth > MAX_REF_DEPTH) return undefined;
    const resolved = this.index.resolveExport(target, exportName);
    if (resolved === undefined || resolved.namespace) return undefined;
    if (resolved.local !== undefined) {
      return this.resolveName(resolved.file, resolved.local, depth + 1);
    }
    return undefined;
  }

  // ---------------------------------------------------------- declaraciones

  private handleRoute(file: ModuleFile, call: ts.CallExpression, methodName: string): void {
    const chain = findRouteCall(call.expression as ts.PropertyAccessExpression);
    let objectExpr: ts.Expression;
    let pathNode: ts.Expression | undefined;
    let handlerNode: ts.Expression | undefined;
    let middleware: ts.Expression[];

    if (chain !== undefined) {
      // app.route('/x').get(mw…, handler)
      const routeCallee = chain.expression as ts.PropertyAccessExpression;
      objectExpr = routeCallee.expression;
      pathNode = chain.arguments[0];
      handlerNode = call.arguments[call.arguments.length - 1];
      middleware = call.arguments.slice(0, -1);
    } else {
      // app.get('/x', mw…, handler). Con un solo argumento es un getter de settings de Express.
      if (call.arguments.length < 2) return;
      objectExpr = (call.expression as ts.PropertyAccessExpression).expression;
      pathNode = call.arguments[0];
      handlerNode = call.arguments[call.arguments.length - 1];
      middleware = call.arguments.slice(1, -1);
    }

    const objKey = this.resolveRef(file, objectExpr);
    if (objKey === undefined || handlerNode === undefined) return;
    const obj = this.objects.get(objKey);
    if (obj === undefined) return;

    const declLine = startLineOf(call);
    const rawPaths = pathNode === undefined ? null : literalPathValues(pathNode);
    if (rawPaths === null) {
      this.unresolved.push({
        filePath: toRootRelative(this.root, file.path),
        line: declLine,
        reason: 'path no literal',
      });
      return;
    }
    // Patrones de Express (`*`, regex-strings): no son una URL concreta; se listan aparte.
    const paths: string[] = [];
    for (const raw of rawPaths) {
      const cleaned = stripParamConstraints(raw);
      if (isPatternPath(cleaned)) {
        this.unresolved.push({
          filePath: toRootRelative(this.root, file.path),
          line: declLine,
          reason: PATTERN_PATH,
        });
      } else {
        paths.push(cleaned);
      }
    }
    if (paths.length === 0) return;

    const handler = this.resolveHandler(file, handlerNode, call);
    obj.routes.push({
      method: methodName.toUpperCase(),
      paths,
      file: file.path,
      pos: call.getStart(file.sf),
      declLine,
      handlerFile: handler.file,
      line: startLineOf(handler.node),
      endLine: endLineOf(handler.node),
      inlineAuth: hasAuthMiddleware(middleware),
      handlerParams: handler.fn !== undefined ? handlerAccessParams(handler.fn) : [],
    });
  }

  private handleUse(file: ModuleFile, call: ts.CallExpression, receiverExpr: ts.Expression): void {
    const args = call.arguments;
    if (args.length === 0) return;

    const receiverKey = this.resolveRef(file, receiverExpr);
    if (receiverKey === undefined) return;
    const receiver = this.objects.get(receiverKey);
    if (receiver === undefined) return;

    const pos = call.getStart(file.sf);
    const shape = this.useShape(file, args);

    const middleware: ts.Expression[] = [...shape.middleware];
    const targets: string[] = [];
    for (const arg of shape.rest) {
      const key = this.resolveRef(file, arg);
      if (key !== undefined) targets.push(key);
      else middleware.push(arg);
    }

    if (targets.length > 0) {
      const hasAuth = hasAuthMiddleware(middleware);
      for (const target of targets) {
        receiver.mounts.push({
          file: file.path,
          pos,
          line: startLineOf(call),
          prefixes: shape.prefixes,
          target,
          hasAuth,
        });
      }
      return;
    }

    // use(authMw) sin prefijo: marca las rutas y montajes posteriores de este objeto.
    if (!shape.hasPrefix && hasAuthMiddleware(middleware)) {
      receiver.authMarks.push({ file: file.path, pos });
    }
  }

  /**
   * Forma de un `use(...)`: el prefijo (si lo hay), los argumentos que quedan y los que, siendo
   * el primero, resultaron ser middleware. El primer argumento es prefijo si es un literal (o array
   * de literales), o un identificador que resuelve a un `const` con literal. Un identificador que
   * resuelve a otra cosa o no resuelve es un middleware (`app.use(logger, router)`). Solo lo que
   * es claramente una cadena no literal (`process.env.X`, `base + '/x'`, regex) es un prefijo no
   * resoluble.
   */
  private useShape(
    file: ModuleFile,
    args: readonly ts.Expression[],
  ): { prefixes: PrefixEntry[]; hasPrefix: boolean; middleware: ts.Expression[]; rest: ts.Expression[] } {
    const noPrefix = { prefixes: [{ value: '', reason: '' }], hasPrefix: false, middleware: [], rest: [...args] };
    const first = unwrapExpression(args[0]);
    if (isFunctionLike(first) || this.resolveRef(file, first) !== undefined) return noPrefix;

    const nonLiteral = (): PrefixEntry[] => [{ value: null, reason: NON_LITERAL_PREFIX }];
    const fromValues = (values: string[]): PrefixEntry[] =>
      values.map((raw) => {
        const cleaned = stripParamConstraints(raw);
        return isPatternPath(cleaned)
          ? { value: null, reason: PATTERN_PATH }
          : { value: cleaned, reason: '' };
      });
    const asPrefix = (prefixes: PrefixEntry[]) => ({
      prefixes,
      hasPrefix: true,
      middleware: [],
      rest: args.slice(1),
    });
    const asMiddleware = () => ({
      prefixes: noPrefix.prefixes,
      hasPrefix: false,
      middleware: [args[0]],
      rest: args.slice(1),
    });

    const literal = literalPathValues(first);
    if (literal !== null) return asPrefix(fromValues(literal));

    if (ts.isIdentifier(first)) {
      const known = this.stringConstant(file, first.text);
      if (known === 'dynamic') return asPrefix(nonLiteral());
      if (known !== undefined && known !== 'other') return asPrefix(fromValues(known));
      if (known === undefined && PREFIX_LIKE_NAME.test(first.text) && !isAuthName(first.text)) {
        return asPrefix(nonLiteral());
      }
      return asMiddleware();
    }

    if (ts.isPropertyAccessExpression(first)) {
      const text = first.getText(file.sf);
      if (isAuthName(text)) return asMiddleware();
      if (isProcessEnv(first) || PREFIX_LIKE_NAME.test(first.name.text)) return asPrefix(nonLiteral());
      return asMiddleware();
    }

    if (isStringish(first) || ts.isArrayLiteralExpression(first) && first.elements.some(isStringLike)) {
      return asPrefix(nonLiteral());
    }
    return asMiddleware();
  }

  /**
   * Qué es el identificador `name` si es un `const` de nivel superior (o importado de un fichero
   * relativo): los valores literales, 'dynamic' (claramente una cadena, pero no literal), 'other'
   * (función, objeto, llamada…) o undefined si no se encuentra.
   */
  private stringConstant(file: ModuleFile, name: string): string[] | 'dynamic' | 'other' | undefined {
    const local = file.topDecls.get(name);
    if (local !== undefined && !file.imports.has(name)) return classifyDecl(local);

    const binding = file.imports.get(name);
    if (binding === undefined || !isRelative(binding.spec)) return undefined;
    const target = this.index.target(file, binding.spec);
    if (target === undefined || binding.imported === '*') return undefined;
    const resolved = this.index.resolveExport(target, binding.imported);
    if (resolved === undefined || resolved.namespace) return undefined;
    if (resolved.value !== undefined) {
      return ts.isExpression(resolved.value) ? classifyInit(resolved.value) : 'other';
    }
    const decl = resolved.local !== undefined ? resolved.file.topDecls.get(resolved.local) : undefined;
    return decl === undefined ? undefined : classifyDecl(decl);
  }

  /**
   * Resuelve el handler: función inline, función/const local, import de un fichero, `obj.method`
   * (objeto literal o instancia de clase, también importados), `fn.bind(x)` y wrappers de un solo
   * argumento (`asyncHandler(fn)`). Si no se resuelve, el rango es el de la llamada de la ruta.
   */
  private resolveHandler(file: ModuleFile, input: ts.Expression, call: ts.CallExpression, depth = 0): HandlerRef {
    const fallback: HandlerRef = { file: file.path, node: call };
    const expr = unwrapExpression(input);

    if (isFunctionLike(expr)) {
      return { file: file.path, node: expr, fn: expr };
    }

    if (ts.isCallExpression(expr) && depth < 2) {
      if (ts.isPropertyAccessExpression(expr.expression) && expr.expression.name.text === 'bind') {
        const bound = this.resolveHandler(file, expr.expression.expression, call, depth + 1);
        return bound.fn !== undefined ? bound : fallback;
      }
      if (expr.arguments.length === 1) {
        const inner = this.resolveHandler(file, expr.arguments[0], call, depth + 1);
        return inner.fn !== undefined ? inner : fallback;
      }
      return fallback;
    }

    if (ts.isIdentifier(expr)) {
      const local = localFunctionNode(file, expr.text);
      if (local !== undefined) return { file: file.path, node: local, fn: local };

      const binding = file.imports.get(expr.text);
      if (binding !== undefined && isRelative(binding.spec)) {
        const target = this.index.target(file, binding.spec);
        const resolved = target && this.index.resolveExport(target, binding.imported);
        const fn = resolved ? functionFromResolved(resolved) : undefined;
        if (resolved !== undefined && fn !== undefined) {
          return { file: resolved.file.path, node: fn, fn };
        }
      }
      return fallback;
    }

    if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.expression)) {
      const objName = expr.expression.text;
      const member = expr.name.text;

      const binding = file.imports.get(objName);
      if (binding?.imported === '*' && isRelative(binding.spec)) {
        const target = this.index.target(file, binding.spec);
        const resolved = target && this.index.resolveExport(target, member);
        const fn = resolved ? functionFromResolved(resolved) : undefined;
        return resolved !== undefined && fn !== undefined
          ? { file: resolved.file.path, node: fn, fn }
          : fallback;
      }

      const container = this.containerFor(file, objName);
      const method = container !== undefined ? findMember(container, member) : undefined;
      if (container !== undefined && method !== undefined) {
        return { file: container.file.path, node: method, fn: method };
      }
    }

    return fallback;
  }

  /** Objeto literal o clase a la que apunta `name`: declarada aquí, importada, o `new Clase()`. */
  private containerFor(file: ModuleFile, name: string): Container | undefined {
    const decl = file.topDecls.get(name);
    if (decl !== undefined && !file.imports.has(name)) return this.containerOfDecl(file, decl);

    const binding = file.imports.get(name);
    if (binding === undefined || !isRelative(binding.spec) || binding.imported === '*') return undefined;
    const target = this.index.target(file, binding.spec);
    const resolved = target && this.index.resolveExport(target, binding.imported);
    if (resolved === undefined || resolved.namespace) return undefined;
    if (resolved.value !== undefined) return this.containerOfValue(resolved.file, resolved.value);
    const topDecl = resolved.local !== undefined ? resolved.file.topDecls.get(resolved.local) : undefined;
    return topDecl === undefined ? undefined : this.containerOfDecl(resolved.file, topDecl);
  }

  private containerOfDecl(file: ModuleFile, decl: TopDecl): Container | undefined {
    if (decl.kind === 'class') return { file, node: decl.node };
    if (decl.kind === 'value' && decl.init !== undefined) return this.containerOfValue(file, decl.init);
    return undefined;
  }

  private containerOfValue(file: ModuleFile, value: ts.Node): Container | undefined {
    const node = ts.isExpression(value) ? unwrapExpression(value) : value;
    if (ts.isObjectLiteralExpression(node) || ts.isClassDeclaration(node)) return { file, node };
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
      return this.classNamed(file, node.expression.text);
    }
    return undefined;
  }

  /** Clase `name` declarada en `file` o importada de un fichero relativo. */
  private classNamed(file: ModuleFile, name: string): Container | undefined {
    const decl = file.topDecls.get(name);
    if (decl?.kind === 'class') return { file, node: decl.node };
    const binding = file.imports.get(name);
    if (binding === undefined || !isRelative(binding.spec) || binding.imported === '*') return undefined;
    const target = this.index.target(file, binding.spec);
    const resolved = target && this.index.resolveExport(target, binding.imported);
    if (resolved === undefined || resolved.namespace) return undefined;
    if (resolved.value !== undefined && ts.isClassDeclaration(resolved.value)) {
      return { file: resolved.file, node: resolved.value };
    }
    const topDecl = resolved.local !== undefined ? resolved.file.topDecls.get(resolved.local) : undefined;
    return topDecl?.kind === 'class' ? { file: resolved.file, node: topDecl.node } : undefined;
  }

  // -------------------------------------------------------------- expansión

  private authBefore(obj: RoutingObject, file: string, pos: number): boolean {
    return obj.authMarks.some((mark) => mark.file === file && mark.pos < pos);
  }

  private expand(
    obj: RoutingObject,
    prefix: string | null,
    reason: string,
    inheritedAuth: boolean,
    stack: string[],
    reached: Set<string>,
    out: RawRoute[],
  ): void {
    reached.add(obj.key);

    for (const route of [...obj.routes].sort(comparePositions)) {
      if (prefix === null) {
        this.unresolved.push({
          filePath: toRootRelative(this.root, route.file),
          line: route.declLine,
          reason,
        });
        continue;
      }
      for (const p of route.paths) {
        const full = joinRoutePaths(prefix, p);
        out.push({
          method: route.method,
          path: full,
          framework: 'express',
          filePath: toRootRelative(this.root, route.handlerFile),
          line: route.line,
          endLine: route.endLine,
          hasAuth: inheritedAuth || route.inlineAuth || this.authBefore(obj, route.file, route.pos),
          params: mergeParams(extractPathParams(full), route.handlerParams),
        });
      }
    }

    for (const mount of [...obj.mounts].sort(comparePositions)) {
      if (stack.includes(mount.target)) {
        this.unresolved.push({
          filePath: toRootRelative(this.root, mount.file),
          line: mount.line,
          reason: 'ciclo de montaje',
        });
        continue;
      }
      const child = this.objects.get(mount.target);
      if (child === undefined) continue;

      const inherited = inheritedAuth || mount.hasAuth || this.authBefore(obj, mount.file, mount.pos);
      const childStack = [...stack, mount.target];

      for (const entry of mount.prefixes) {
        if (prefix === null) {
          this.expand(child, null, reason, inherited, childStack, reached, out);
        } else if (entry.value === null) {
          this.expand(child, null, entry.reason, inherited, childStack, reached, out);
        } else {
          this.expand(child, joinRoutePaths(prefix, entry.value), '', inherited, childStack, reached, out);
        }
      }
    }
  }
}

// ------------------------------------------------------------------ helpers

function isRelative(spec: string): boolean {
  return spec.startsWith('./') || spec.startsWith('../');
}

function isRoutingName(name: string): boolean {
  return name === 'app' || name === 'router' || name.endsWith('Router');
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function comparePositions(a: { file: string; pos: number }, b: { file: string; pos: number }): number {
  return compareStrings(a.file, b.file) || a.pos - b.pos;
}

/** Si la expresión es `obj.METHOD` encadenado sobre `obj.route(path)`, devuelve la llamada `.route(...)`. */
function findRouteCall(callee: ts.PropertyAccessExpression): ts.CallExpression | undefined {
  let current: ts.Expression = callee.expression;
  while (ts.isCallExpression(current) && ts.isPropertyAccessExpression(current.expression)) {
    const name = current.expression.name.text;
    if (name === 'route') return current;
    if (!HTTP_METHODS.includes(name)) return undefined;
    current = current.expression.expression;
  }
  return undefined;
}

function isFunctionLike(node: ts.Node): node is ts.ArrowFunction | ts.FunctionExpression {
  return ts.isArrowFunction(node) || ts.isFunctionExpression(node);
}

/** `process.env.X` / `process.env['X']`. */
function isProcessEnv(node: ts.Expression): boolean {
  const base = ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node) ? node.expression : undefined;
  return (
    base !== undefined &&
    ts.isPropertyAccessExpression(base) &&
    ts.isIdentifier(base.expression) &&
    base.expression.text === 'process' &&
    base.name.text === 'env'
  );
}

function isStringLike(node: ts.Expression): boolean {
  const inner = unwrapExpression(node);
  return literalString(inner) !== undefined || ts.isRegularExpressionLiteral(inner) || isStringish(inner);
}

/**
 * Claramente una cadena (o regex) que no es un literal: plantilla con expresiones, `a + '/x'`,
 * `process.env.X`, `x || '/api'`, regex. Lo que no se pueda afirmar queda fuera.
 */
function isStringish(input: ts.Expression): boolean {
  const node = unwrapExpression(input);
  if (ts.isTemplateExpression(node) || ts.isRegularExpressionLiteral(node)) return true;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return true;
  if (isProcessEnv(node)) return true;
  if (ts.isBinaryExpression(node)) {
    const op = node.operatorToken.kind;
    if (op === ts.SyntaxKind.PlusToken) return isStringish(node.left) || isStringish(node.right);
    if (op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken) {
      return isStringish(node.left) || isStringish(node.right);
    }
    return false;
  }
  if (ts.isConditionalExpression(node)) return isStringish(node.whenTrue) && isStringish(node.whenFalse);
  return false;
}

function classifyInit(init: ts.Expression): string[] | 'dynamic' | 'other' {
  const literal = literalPathValues(init);
  if (literal !== null && !isFunctionLike(unwrapExpression(init))) return literal;
  return isStringLike(init) ? 'dynamic' : 'other';
}

function classifyDecl(decl: TopDecl): string[] | 'dynamic' | 'other' {
  return decl.kind === 'value' && decl.init !== undefined ? classifyInit(decl.init) : 'other';
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

function dedupeRoutes(list: RawRoute[]): RawRoute[] {
  const seen = new Set<string>();
  return list.filter((r) => {
    const key = [r.method, r.path, r.filePath, r.line, r.hasAuth].join('\0');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

interface Container {
  file: ModuleFile;
  node: ts.ObjectLiteralExpression | ts.ClassDeclaration;
}

function functionFromResolved(resolved: ResolvedExport): ts.Node | undefined {
  if (resolved.value !== undefined) {
    if (isFunctionLike(resolved.value) || ts.isFunctionDeclaration(resolved.value)) {
      return resolved.value;
    }
    return undefined;
  }
  if (resolved.local !== undefined) {
    return localFunctionNode(resolved.file, resolved.local);
  }
  return undefined;
}

function memberName(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNoSubstitutionTemplateLiteral(name)) {
    return name.text;
  }
  return undefined;
}

function findMember(container: Container, member: string): ts.Node | undefined {
  const { node, file } = container;
  if (ts.isClassDeclaration(node)) {
    for (const m of node.members) {
      if (ts.isMethodDeclaration(m) && memberName(m.name) === member) return m;
      if (
        ts.isPropertyDeclaration(m) &&
        memberName(m.name) === member &&
        m.initializer !== undefined &&
        isFunctionLike(unwrapExpression(m.initializer))
      ) {
        return unwrapExpression(m.initializer);
      }
    }
    return undefined;
  }
  for (const prop of node.properties) {
    if (ts.isMethodDeclaration(prop) && memberName(prop.name) === member) return prop;
    if (ts.isShorthandPropertyAssignment(prop) && prop.name.text === member) {
      return localFunctionNode(file, member);
    }
    if (ts.isPropertyAssignment(prop) && memberName(prop.name) === member) {
      const init = unwrapExpression(prop.initializer);
      if (isFunctionLike(init)) return init;
      if (ts.isIdentifier(init)) return localFunctionNode(file, init.text);
    }
  }
  return undefined;
}

function functionParameters(fn: ts.Node): readonly ts.ParameterDeclaration[] {
  if (
    ts.isArrowFunction(fn) ||
    ts.isFunctionExpression(fn) ||
    ts.isFunctionDeclaration(fn) ||
    ts.isMethodDeclaration(fn)
  ) {
    return fn.parameters;
  }
  return [];
}

/**
 * Parámetros query/body que el handler lee de su primer argumento (`req`, `request`…):
 * `req.query.X`, `req.query['X']`, `req.body.X` y desestructuración `const { a } = req.body`.
 */
export function handlerAccessParams(fn: ts.Node): RouteParam[] {
  const first = functionParameters(fn)[0];
  if (first === undefined || !ts.isIdentifier(first.name)) return [];
  const reqName = first.name.text;
  const found: RouteParam[] = [];

  visit(fn, (node) => {
    if (ts.isPropertyAccessExpression(node)) {
      const section = isRequestSection(node.expression, reqName);
      if (section !== undefined) {
        found.push({ name: node.name.text, in: section });
      }
    } else if (ts.isElementAccessExpression(node)) {
      const section = isRequestSection(node.expression, reqName);
      const key = literalString(node.argumentExpression);
      if (section !== undefined && key !== undefined) {
        found.push({ name: key, in: section });
      }
    } else if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name) && node.initializer) {
      const section = isRequestSection(node.initializer, reqName);
      if (section === undefined) return 'continue';
      for (const element of node.name.elements) {
        if (element.dotDotDotToken || !ts.isIdentifier(element.name)) continue;
        const source = element.propertyName ?? element.name;
        const key = ts.isIdentifier(source) || ts.isStringLiteral(source) ? source.text : undefined;
        if (key !== undefined) found.push({ name: key, in: section });
      }
    }
    return 'continue';
  });

  return mergeParams(found);
}
