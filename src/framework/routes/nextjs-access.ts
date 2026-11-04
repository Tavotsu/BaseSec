import * as ts from 'typescript';
import { unwrapExpression } from './common';

export const HTTP_METHOD_NAMES = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;

/** Quita paréntesis, casts y `await` (`(await req.json())` -> `req.json()`). */
export function unwrapAwait(input: ts.Expression): ts.Expression {
  let current = unwrapExpression(input);
  while (ts.isAwaitExpression(current)) {
    current = unwrapExpression(current.expression);
  }
  return current;
}

export function isFunctionLike(node: ts.Node | undefined): node is ts.ArrowFunction | ts.FunctionExpression {
  return node !== undefined && (ts.isArrowFunction(node) || ts.isFunctionExpression(node));
}

export function hasExportModifier(node: ts.Node): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
}

export function hasDefaultModifier(node: ts.Node): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((m) => m.kind === ts.SyntaxKind.DefaultKeyword);
}

export function functionParams(fn: ts.Node): readonly ts.ParameterDeclaration[] {
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

/** Nombre real del primer parámetro del handler (la request), si es un identificador. */
export function requestParamName(fn: ts.Node): string | undefined {
  const first = functionParams(fn)[0];
  return first !== undefined && ts.isIdentifier(first.name) ? first.name.text : undefined;
}

/** `req.<prop>` donde `req` es el nombre del primer parámetro. */
export function isReqProperty(input: ts.Expression, req: string, prop: string): boolean {
  const node = unwrapExpression(input);
  return (
    ts.isPropertyAccessExpression(node) &&
    node.name.text === prop &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === req
  );
}

/** `new URL(req.url)`. */
export function isNewUrlOfReq(input: ts.Expression, req: string): boolean {
  const node = unwrapExpression(input);
  if (!ts.isNewExpression(node) || !ts.isIdentifier(node.expression) || node.expression.text !== 'URL') {
    return false;
  }
  const first = node.arguments?.[0];
  return first !== undefined && isReqProperty(first, req, 'url');
}

/** `req.nextUrl.searchParams` o `new URL(req.url).searchParams`. */
export function isSearchParamsExpr(input: ts.Expression, req: string): boolean {
  const node = unwrapExpression(input);
  if (!ts.isPropertyAccessExpression(node) || node.name.text !== 'searchParams') return false;
  const base = unwrapExpression(node.expression);
  return isReqProperty(base, req, 'nextUrl') || isNewUrlOfReq(base, req);
}

/** `await req.<method>()` o `req.<method>()` sin argumentos. */
export function isReqCall(input: ts.Expression, req: string, method: string): boolean {
  const node = unwrapAwait(input);
  return (
    ts.isCallExpression(node) &&
    node.arguments.length === 0 &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === method &&
    ts.isIdentifier(node.expression.expression) &&
    node.expression.expression.text === req
  );
}

/**
 * Nombre de la función llamada en la raíz de una cadena (`cookies()`, `cookies().get('x')`,
 * `await headers()`). Undefined si la raíz no es una llamada a un identificador.
 */
export function rootCallName(input: ts.Expression): string | undefined {
  let current: ts.Expression = unwrapAwait(input);
  for (;;) {
    if (ts.isCallExpression(current)) {
      if (ts.isIdentifier(current.expression)) return current.expression.text;
      current = unwrapExpression(current.expression);
    } else if (ts.isPropertyAccessExpression(current)) {
      current = unwrapExpression(current.expression);
    } else {
      return undefined;
    }
  }
}

/** Nombres locales de `cookies` y `headers` importados de `next/headers` (con alias). */
export function nextHeaderImports(sourceFile: ts.SourceFile): Map<string, 'next:cookies' | 'next:headers'> {
  const locals = new Map<string, 'next:cookies' | 'next:headers'>();
  for (const stmt of sourceFile.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
    if (stmt.moduleSpecifier.text !== 'next/headers') continue;
    const bindings = stmt.importClause?.namedBindings;
    if (bindings === undefined || !ts.isNamedImports(bindings)) continue;
    for (const element of bindings.elements) {
      const imported = (element.propertyName ?? element.name).text;
      if (imported === 'cookies') locals.set(element.name.text, 'next:cookies');
      if (imported === 'headers') locals.set(element.name.text, 'next:headers');
    }
  }
  return locals;
}

/** `text` es `prefix`, o empieza por `prefix.` o `prefix[`: acceso a la misma cadena. */
export function startsWithPath(text: string, prefix: string): boolean {
  return text === prefix || text.startsWith(prefix + '.') || text.startsWith(prefix + '[');
}
