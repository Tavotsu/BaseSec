import * as ts from 'typescript';
import * as path from 'node:path';
import { AUTH_MIDDLEWARE_NAMES } from '../express';
import type { RouteParam } from './types';

export const PATH_PARAM_REGEX = /:([A-Za-z_$][\w$]*)\??/g;

/** Ruta de fichero relativa a la raíz, con `/` como separador. */
export function toRootRelative(root: string, file: string): string {
  return path.relative(path.resolve(root), path.resolve(file)).split(path.sep).join('/');
}

/** Línea 1-based de inicio de un nodo. */
export function startLineOf(node: ts.Node): number {
  const sf = node.getSourceFile();
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

/** Línea 1-based de fin de un nodo. */
export function endLineOf(node: ts.Node): number {
  const sf = node.getSourceFile();
  return sf.getLineAndCharacterOfPosition(node.getEnd()).line + 1;
}

/** Quita paréntesis, `as`, `satisfies`, `!` y aserciones de tipo que no cambian el valor. */
export function unwrapExpression(node: ts.Expression): ts.Expression {
  let current = node;
  for (;;) {
    if (
      ts.isParenthesizedExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isTypeAssertionExpression(current)
    ) {
      current = current.expression;
    } else {
      return current;
    }
  }
}

/** Valor de un literal de cadena o de plantilla sin expresiones; undefined en otro caso. */
export function literalString(input: ts.Node | undefined): string | undefined {
  if (!input) return undefined;
  const node = ts.isExpression(input) ? unwrapExpression(input) : input;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    return node.text;
  }
  return undefined;
}

/**
 * Valores de un argumento de ruta: un literal da [valor]; un array de literales da
 * un valor por elemento; cualquier otra cosa da null (no resoluble).
 */
export function literalPathValues(input: ts.Node | undefined): string[] | null {
  if (input === undefined) return [''];
  const single = literalString(input);
  if (single !== undefined) return [single];
  const node = ts.isExpression(input) ? unwrapExpression(input) : input;
  if (ts.isArrayLiteralExpression(node)) {
    const values: string[] = [];
    for (const element of node.elements) {
      const value = literalString(element);
      if (value === undefined) return null;
      values.push(value);
    }
    return values;
  }
  return null;
}

const PARAM_CONSTRAINT_REGEX = /(:[A-Za-z_$][\w$]*)\(([^()]*)\)/g;
const OPTIONAL_PARAM_REGEX = /(:[A-Za-z_$][\w$]*)\?/g;
const PATTERN_CHARS_REGEX = /[*()+?{}[\]\\]/;

/** `/users/:id(\\d+)` -> `/users/:id`: quita la restricción regex de un parámetro con nombre. */
export function stripParamConstraints(routePath: string): string {
  return routePath.replace(PARAM_CONSTRAINT_REGEX, '$1');
}

/**
 * True si la ruta contiene sintaxis de patrón de Express (`*`, `(`, `)`, `+`, `{`, `[`, `\\`
 * o `?` fuera de `:param?`). Un patrón no es una URL concreta que se pueda atacar tal cual.
 * Llamar antes a `stripParamConstraints`.
 */
export function isPatternPath(routePath: string): boolean {
  return PATTERN_CHARS_REGEX.test(routePath.replace(OPTIONAL_PARAM_REGEX, '$1'));
}

/**
 * Normaliza una ruta HTTP: '/' inicial, sin '//' repetidos, sin '/' final salvo la raíz.
 */
export function normalizeRoutePath(raw: string): string {
  const collapsed = ('/' + raw).replace(/\/{2,}/g, '/');
  if (collapsed.length > 1 && collapsed.endsWith('/')) {
    return collapsed.slice(0, -1);
  }
  return collapsed;
}

/** Concatena segmentos de ruta y los normaliza. */
export function joinRoutePaths(...segments: string[]): string {
  return normalizeRoutePath(segments.filter((s) => s !== '').join('/'));
}

/** Parámetros de path (`:name` y `:name?`) de una ruta final. */
export function extractPathParams(routePath: string): RouteParam[] {
  const params: RouteParam[] = [];
  for (const match of routePath.matchAll(PATH_PARAM_REGEX)) {
    params.push({ name: match[1], in: 'path' });
  }
  return params;
}

/** Añade parámetros sin duplicar (name + in), conservando el orden de aparición. */
export function mergeParams(...lists: RouteParam[][]): RouteParam[] {
  const merged: RouteParam[] = [];
  const seen = new Set<string>();
  for (const list of lists) {
    for (const param of list) {
      const key = `${param.in}:${param.name}`;
      if (!seen.has(key)) {
        seen.add(key);
        merged.push(param);
      }
    }
  }
  return merged;
}

/** Heurística de nombre de auth, la misma lista que express.ts (sin distinguir mayúsculas). */
export function isAuthName(text: string): boolean {
  const lower = text.toLowerCase();
  return AUTH_MIDDLEWARE_NAMES.some((name) => lower.includes(name.toLowerCase()));
}

/**
 * Texto de un middleware para la heurística de auth: identificador, acceso a propiedad
 * o callee de una llamada. Las funciones inline no cuentan.
 */
export function middlewareNames(node: ts.Expression): string[] {
  if (ts.isArrayLiteralExpression(node)) {
    return node.elements.flatMap((element) =>
      ts.isExpression(element) ? middlewareNames(element) : [],
    );
  }
  if (ts.isIdentifier(node)) return [node.text];
  if (ts.isPropertyAccessExpression(node)) return [node.getText(node.getSourceFile())];
  if (ts.isCallExpression(node)) return [node.expression.getText(node.getSourceFile())];
  return [];
}

export function hasAuthMiddleware(args: readonly ts.Expression[]): boolean {
  return args.some((arg) => middlewareNames(arg).some(isAuthName));
}

/** Acceso `obj.query` / `obj.body` (y `obj['query']` no se considera aquí). */
export function isRequestSection(input: ts.Expression, reqName: string): 'query' | 'body' | undefined {
  const node = unwrapExpression(input);
  if (
    ts.isPropertyAccessExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === reqName &&
    (node.name.text === 'query' || node.name.text === 'body')
  ) {
    return node.name.text;
  }
  return undefined;
}
