import * as ts from 'typescript';
import type { TaintSourceInfo } from './types';
import { visit } from '../utils/ast-helpers';
import { nextRouteFileKindOfPath, type NextRouteFileKind } from '../framework/routes/nextjs-files';
import { unwrapExpression } from '../framework/routes/common';
import {
  HTTP_METHOD_NAMES,
  functionParams,
  hasDefaultModifier,
  hasExportModifier,
  isFunctionLike,
  isNewUrlOfReq,
  isReqCall,
  isSearchParamsExpr,
  nextHeaderImports,
  requestParamName,
  rootCallName,
  startsWithPath,
  unwrapAwait,
} from '../framework/routes/nextjs-access';

/**
 * Fuentes de taint del lado servidor en route handlers de Next.js (plan §5.7). Solo las llama
 * `findSources` cuando `nextjs` está detectado y el fichero es un route handler. Los nombres de
 * la request y del contexto son los reales del handler exportado, no nombres fijos.
 */
export function findNextServerSources(sourceFile: ts.SourceFile): TaintSourceInfo[] {
  const fileKind = nextRouteFileKindOfPath(sourceFile.fileName);
  if (fileKind === undefined) return [];

  const collector = createCollector(sourceFile);

  // cookies() y headers() cuentan solo si se importan de next/headers: como texto suelto
  // coincidirían con cualquier función con ese nombre.
  const headerLocals = nextHeaderImports(sourceFile);
  if (headerLocals.size > 0) {
    collectHeaderSources(sourceFile, headerLocals, collector);
  }

  for (const fn of exportedHandlers(sourceFile, fileKind)) {
    collectHandlerSources(fn, fileKind, sourceFile, headerLocals, collector);
  }

  return collector.list();
}

interface Collector {
  add(kind: string, expression: string, at: ts.Node, variableName?: string): void;
  list(): TaintSourceInfo[];
}

/** Acumula fuentes con posición 1-based; no repite (expresión, línea, columna). */
function createCollector(sourceFile: ts.SourceFile): Collector {
  const sources: TaintSourceInfo[] = [];
  const seen = new Set<string>();
  return {
    add(kind, expression, at, variableName) {
      const pos = sourceFile.getLineAndCharacterOfPosition(at.getStart(sourceFile));
      const line = pos.line + 1;
      const column = pos.character + 1;
      const key = `${expression}\0${line}\0${column}`;
      if (seen.has(key)) return;
      seen.add(key);
      sources.push(
        variableName === undefined
          ? { kind, expression, line, column }
          : { kind, expression, line, column, variableName },
      );
    },
    list: () => sources,
  };
}

function collectHeaderSources(
  sourceFile: ts.SourceFile,
  locals: Map<string, string>,
  collector: Collector,
): void {
  const headerKind = (expr: ts.Expression): string | undefined => {
    const root = rootCallName(expr);
    return root === undefined ? undefined : locals.get(root);
  };

  visit(sourceFile, (node) => {
    if (ts.isVariableDeclaration(node) && node.initializer !== undefined) {
      const kind = headerKind(node.initializer);
      if (kind !== undefined && ts.isIdentifier(node.name)) {
        collector.add(kind, node.initializer.getText(sourceFile), node, node.name.text);
      } else if (kind !== undefined && ts.isObjectBindingPattern(node.name)) {
        for (const element of node.name.elements) {
          if (ts.isIdentifier(element.name)) collector.add(kind, element.name.text, element, element.name.text);
        }
      }
    } else if (ts.isPropertyAccessExpression(node)) {
      const kind = headerKind(node.expression);
      if (kind !== undefined) collector.add(kind, node.getText(sourceFile), node);
    }
    return 'continue';
  });
}

function collectHandlerSources(
  fn: ts.Node,
  fileKind: NextRouteFileKind,
  sourceFile: ts.SourceFile,
  headerLocals: Map<string, string>,
  collector: Collector,
): void {
  const req = requestParamName(fn);
  if (req === undefined) return;
  const isApp = fileKind === 'app-route';

  // App Router: `(req, ctx)`, con ctx = identificador o `{ params }`.
  const second = isApp ? functionParams(fn)[1] : undefined;
  let ctxName: string | undefined;
  const paramsVars = new Set<string>();
  if (second !== undefined) {
    if (ts.isIdentifier(second.name)) {
      ctxName = second.name.text;
    } else if (ts.isObjectBindingPattern(second.name)) {
      for (const element of second.name.elements) {
        if (ts.isIdentifier(element.name) && bindingKey(element) === 'params') paramsVars.add(element.name.text);
      }
    }
  }

  const prefixes: Array<[string, string]> = isApp
    ? [
        [`${req}.nextUrl.searchParams`, 'next:searchParams'],
        [`${req}.headers`, 'next:headers'],
        [`${req}.cookies`, 'next:cookies'],
        [`${req}.url`, 'next:request.url'],
        ...(ctxName !== undefined ? [[`${ctxName}.params`, 'next:params'] as [string, string]] : []),
      ]
    : [
        [`${req}.query`, 'next:pages.query'],
        [`${req}.body`, 'next:pages.body'],
        [`${req}.headers`, 'next:headers'],
        [`${req}.cookies`, 'next:cookies'],
      ];

  const isCtxParams = (expr: ts.Expression): boolean =>
    ctxName !== undefined &&
    ts.isPropertyAccessExpression(expr) &&
    expr.name.text === 'params' &&
    ts.isIdentifier(expr.expression) &&
    expr.expression.text === ctxName;

  // Variables ya marcadas en este handler: `const x = body.name` hereda la fuente de `body`. Se
  // rellena en orden de código en un único recorrido, así que no hay ciclos posibles.
  const tainted = new Map<string, string>();

  /**
   * Tipo de fuente de una expresión, o undefined. Solo propagan las cadenas de acceso
   * (`body.name`, `sp.get('q')`), los alias (`const b = body`) y los operadores que devuelven
   * uno de sus operandos (`??`, `||`, `&&`, `+`, `?:`, plantillas). Una comparación o una
   * llamada a otra función (`Number(body.id)`, `sanitize(x)`) no hereda.
   */
  const kindOf = (input: ts.Expression): string | undefined => {
    const core = unwrapAwait(input);
    if (ts.isBinaryExpression(core)) {
      return PASSTHROUGH_OPERATORS.has(core.operatorToken.kind) ? kindOf(core.left) ?? kindOf(core.right) : undefined;
    }
    if (ts.isConditionalExpression(core)) return kindOf(core.whenTrue) ?? kindOf(core.whenFalse);
    if (ts.isTemplateExpression(core)) {
      for (const span of core.templateSpans) {
        const kind = kindOf(span.expression);
        if (kind !== undefined) return kind;
      }
      return undefined;
    }

    if (isApp) {
      if (isReqCall(core, req, 'json')) return 'next:request.json';
      if (isReqCall(core, req, 'formData')) return 'next:request.formData';
      if (isReqCall(core, req, 'text')) return 'next:request.text';
      if (isSearchParamsExpr(core, req)) return 'next:searchParams';
      if (isCtxParams(core)) return 'next:params';
    }
    if (ts.isIdentifier(core)) {
      if (paramsVars.has(core.text)) return 'next:params';
      return tainted.get(core.text);
    }
    if (!isAccessChain(core)) return undefined;

    const headerKind = headerKindOf(core, headerLocals);
    if (headerKind !== undefined) return headerKind;
    const root = accessRoot(core);
    if (root !== undefined && paramsVars.has(root)) return 'next:params';
    const text = core.getText(sourceFile);
    const fromPrefix = prefixes.find(([prefix]) => startsWithPath(text, prefix));
    if (fromPrefix !== undefined) return fromPrefix[1];
    for (const [name, kind] of tainted) {
      if (startsWithPath(text, name)) return kind;
    }
    return undefined;
  };

  const mark = (kind: string, expression: string, at: ts.Node, name: string): void => {
    collector.add(kind, expression, at, name);
    tainted.set(name, kind);
  };

  visit(fn, (node) => {
    if (ts.isVariableDeclaration(node) && node.initializer !== undefined) {
      const init = node.initializer;
      const kind = kindOf(init);
      if (ts.isIdentifier(node.name)) {
        if (kind !== undefined) mark(kind, init.getText(sourceFile), node, node.name.text);
      } else {
        const fromNewUrl = ts.isObjectBindingPattern(node.name) && isNewUrlOfReq(unwrapAwait(init), req);
        for (const target of bindingTargets(node.name)) {
          const elementKind =
            kind ??
            (fromNewUrl && target.depth === 0 && target.key === 'searchParams' ? 'next:searchParams' : undefined);
          if (elementKind !== undefined) mark(elementKind, target.id.text, target.at, target.id.text);
        }
      }
    } else if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left)
    ) {
      // `let q; q = req.nextUrl.searchParams.get('q')`
      const kind = kindOf(node.right);
      if (kind !== undefined) mark(kind, node.right.getText(sourceFile), node, node.left.text);
    } else if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const text = node.getText(sourceFile);
      const hit = prefixes.find(([prefix]) => startsWithPath(text, prefix));
      if (hit !== undefined) {
        collector.add(hit[1], text, node);
      } else {
        const base = unwrapAwait(node.expression);
        if (ts.isIdentifier(base) && (paramsVars.has(base.text) || tainted.get(base.text) === 'next:params')) {
          collector.add('next:params', text, node);
        }
      }
    }
    return 'continue';
  });
}

const PASSTHROUGH_OPERATORS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.QuestionQuestionToken,
  ts.SyntaxKind.BarBarToken,
  ts.SyntaxKind.AmpersandAmpersandToken,
  ts.SyntaxKind.PlusToken,
]);

function isAccessChain(expr: ts.Expression): boolean {
  return (
    ts.isPropertyAccessExpression(expr) ||
    ts.isElementAccessExpression(expr) ||
    ts.isCallExpression(expr)
  );
}

/** Identificador en la raíz de una cadena de accesos y llamadas (`params.id`, `sp.get('q')`). */
function accessRoot(expr: ts.Expression): string | undefined {
  let current: ts.Expression = expr;
  for (;;) {
    current = unwrapExpression(current);
    if (ts.isIdentifier(current)) return current.text;
    if (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) current = current.expression;
    else if (ts.isCallExpression(current)) current = current.expression;
    else if (ts.isAwaitExpression(current)) current = current.expression;
    else return undefined;
  }
}

function headerKindOf(expr: ts.Expression, locals: Map<string, string>): string | undefined {
  if (locals.size === 0) return undefined;
  const root = rootCallName(expr);
  return root === undefined ? undefined : locals.get(root);
}

interface BindingTarget {
  id: ts.Identifier;
  /** Nodo que fija la posición de la fuente. */
  at: ts.Node;
  /** Clave de la propiedad en el nivel superior; undefined en niveles anidados. */
  key: string | undefined;
  depth: number;
}

/** Identificadores que introduce un patrón de desestructuración, también anidados. */
function bindingTargets(name: ts.BindingName, depth = 0, out: BindingTarget[] = []): BindingTarget[] {
  if (ts.isIdentifier(name)) {
    out.push({ id: name, at: name, key: undefined, depth });
    return out;
  }
  for (const element of name.elements) {
    if (ts.isOmittedExpression(element)) continue;
    if (ts.isIdentifier(element.name)) {
      out.push({ id: element.name, at: element, key: depth === 0 ? bindingKey(element) : undefined, depth });
    } else {
      bindingTargets(element.name, depth + 1, out);
    }
  }
  return out;
}

/** Funciones de los métodos exportados (App) o del default export (Pages), del mismo fichero. */
function exportedHandlers(sourceFile: ts.SourceFile, fileKind: NextRouteFileKind): ts.Node[] {
  const handlers: ts.Node[] = [];
  for (const stmt of sourceFile.statements) {
    if (fileKind === 'app-route') {
      appHandlersOf(stmt, sourceFile, handlers);
    } else if (ts.isExportAssignment(stmt) && !stmt.isExportEquals) {
      addFunctionOf(stmt.expression, sourceFile, handlers);
    } else if (ts.isFunctionDeclaration(stmt) && hasExportModifier(stmt) && hasDefaultModifier(stmt)) {
      handlers.push(stmt);
    } else if (ts.isExportDeclaration(stmt) && stmt.moduleSpecifier === undefined && stmt.exportClause !== undefined && ts.isNamedExports(stmt.exportClause)) {
      // `export { handler as default }`
      for (const element of stmt.exportClause.elements) {
        if (element.name.text !== 'default') continue;
        const fn = sameFileFunction(sourceFile, (element.propertyName ?? element.name).text);
        if (fn !== undefined) handlers.push(fn);
      }
    }
  }
  return handlers;
}

function appHandlersOf(stmt: ts.Statement, sourceFile: ts.SourceFile, out: ts.Node[]): void {
  if (ts.isFunctionDeclaration(stmt) && hasExportModifier(stmt) && stmt.name !== undefined && isMethod(stmt.name.text)) {
    out.push(stmt);
  } else if (ts.isVariableStatement(stmt) && hasExportModifier(stmt)) {
    for (const decl of stmt.declarationList.declarations) {
      if (ts.isIdentifier(decl.name) && isMethod(decl.name.text) && decl.initializer !== undefined) {
        addFunctionOf(decl.initializer, sourceFile, out);
      }
    }
  } else if (ts.isExportDeclaration(stmt) && stmt.moduleSpecifier === undefined && stmt.exportClause !== undefined && ts.isNamedExports(stmt.exportClause)) {
    for (const element of stmt.exportClause.elements) {
      const local = (element.propertyName ?? element.name).text;
      if (isMethod(element.name.text)) {
        const fn = sameFileFunction(sourceFile, local);
        if (fn !== undefined) out.push(fn);
      }
    }
  }
}

/** Añade la función de una expresión: literal, identificador local o wrapper de una llamada. */
function addFunctionOf(input: ts.Expression, sourceFile: ts.SourceFile, out: ts.Node[]): void {
  const expr = unwrapExpression(input);
  if (isFunctionLike(expr)) {
    out.push(expr);
    return;
  }
  if (ts.isIdentifier(expr)) {
    const fn = sameFileFunction(sourceFile, expr.text);
    if (fn !== undefined) out.push(fn);
    return;
  }
  if (ts.isCallExpression(expr) && expr.arguments.length === 1) {
    addFunctionOf(expr.arguments[0], sourceFile, out);
  }
}

/** Declaración o const con función de nivel superior con ese nombre, en el mismo fichero. */
function sameFileFunction(sourceFile: ts.SourceFile, name: string): ts.Node | undefined {
  for (const stmt of sourceFile.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name?.text === name) return stmt;
    if (!ts.isVariableStatement(stmt)) continue;
    for (const decl of stmt.declarationList.declarations) {
      if (!ts.isIdentifier(decl.name) || decl.name.text !== name || decl.initializer === undefined) continue;
      const init = unwrapExpression(decl.initializer);
      if (isFunctionLike(init)) return init;
    }
  }
  return undefined;
}

function isMethod(name: string): boolean {
  return (HTTP_METHOD_NAMES as readonly string[]).includes(name);
}

function bindingKey(element: ts.BindingElement): string | undefined {
  const source = element.propertyName ?? element.name;
  return ts.isIdentifier(source) || ts.isStringLiteral(source) ? source.text : undefined;
}
