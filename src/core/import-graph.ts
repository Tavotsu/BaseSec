import * as ts from 'typescript';
import * as path from 'node:path';
import type { ParsedFile } from '../rules/types';

export interface ImportGraph {
  /** Ficheros importados directamente desde `file` (rutas absolutas), en orden de aparición. */
  importsOf(file: string): string[];
  /** Cierre transitivo desde `file` (lo incluye). `maxDepth` limita la profundidad (default 6). */
  reachableFrom(file: string, maxDepth?: number): string[];
  /** Resuelve un especificador relativo desde `fromFile` a un fichero conocido, o undefined. */
  resolve(fromFile: string, specifier: string): string | undefined;
}

const DEFAULT_MAX_DEPTH = 6;
const EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts'];
const JS_EXTENSIONS = ['.js', '.jsx', '.mjs', '.cjs'];
const TS_ALTERNATES = ['.ts', '.tsx', '.mts', '.cts'];
const INDEX_FILES = ['index.ts', 'index.tsx', 'index.js', 'index.jsx', 'index.mjs', 'index.cjs'];

/**
 * Grafo de imports relativos entre ficheros ya parseados (plan §5.5).
 * Es una sobreaproximación de "qué código puede ejecutar este fichero": no es taint
 * entre ficheros. Los paquetes y los alias de tsconfig se ignoran.
 */
export function buildImportGraph(parsedFiles: ParsedFile[]): ImportGraph {
  const known = new Set<string>();
  for (const file of parsedFiles) {
    known.add(path.resolve(file.filePath));
  }

  const edges = new Map<string, string[]>();
  for (const file of parsedFiles) {
    const abs = path.resolve(file.filePath);
    const targets: string[] = [];
    const seen = new Set<string>();
    for (const specifier of collectRelativeSpecifiers(file.sourceFile)) {
      const target = resolveSpecifier(abs, specifier, known);
      if (target !== undefined && !seen.has(target)) {
        seen.add(target);
        targets.push(target);
      }
    }
    edges.set(abs, targets);
  }

  return {
    importsOf(file: string): string[] {
      return [...(edges.get(path.resolve(file)) ?? [])];
    },

    reachableFrom(file: string, maxDepth: number = DEFAULT_MAX_DEPTH): string[] {
      const start = path.resolve(file);
      const depth = new Map<string, number>([[start, 0]]);
      const queue: string[] = [start];
      for (let i = 0; i < queue.length; i++) {
        const current = queue[i];
        const currentDepth = depth.get(current) ?? 0;
        for (const next of edges.get(current) ?? []) {
          if (currentDepth + 1 > maxDepth) continue;
          if (!depth.has(next)) {
            depth.set(next, currentDepth + 1);
            queue.push(next);
          }
        }
      }
      return [...depth.keys()].sort();
    },

    resolve(fromFile: string, specifier: string): string | undefined {
      return resolveSpecifier(path.resolve(fromFile), specifier, known);
    },
  };
}

function isRelativeSpecifier(specifier: string): boolean {
  return specifier.startsWith('./') || specifier.startsWith('../');
}

function resolveSpecifier(
  fromAbs: string,
  specifier: string,
  known: Set<string>,
): string | undefined {
  if (!isRelativeSpecifier(specifier)) return undefined;

  const base = path.resolve(path.dirname(fromAbs), specifier);
  const candidates: string[] = [base];

  for (const ext of EXTENSIONS) {
    candidates.push(base + ext);
  }

  if (JS_EXTENSIONS.includes(path.extname(base))) {
    const stripped = base.slice(0, -path.extname(base).length);
    for (const ext of TS_ALTERNATES) {
      candidates.push(stripped + ext);
    }
  }

  for (const indexFile of INDEX_FILES) {
    candidates.push(path.join(base, indexFile));
  }

  for (const candidate of candidates) {
    if (known.has(candidate)) return candidate;
  }
  return undefined;
}

/**
 * Especificadores relativos literales de: import/export ... from, import '…',
 * require('…') e import('…'). Ignora especificadores bare y no literales.
 */
function collectRelativeSpecifiers(sourceFile: ts.SourceFile): string[] {
  const specifiers: string[] = [];

  const visit = (node: ts.Node): void => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      specifiers.push(node.moduleSpecifier.text);
    } else if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference) &&
      ts.isStringLiteral(node.moduleReference.expression)
    ) {
      // import x = require('./y')
      specifiers.push(node.moduleReference.expression.text);
    } else if (ts.isCallExpression(node) && node.arguments.length === 1) {
      const arg = node.arguments[0];
      const isRequire = ts.isIdentifier(node.expression) && node.expression.text === 'require';
      const isDynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      if ((isRequire || isDynamicImport) && ts.isStringLiteralLike(arg)) {
        specifiers.push(arg.text);
      }
    }
    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  return specifiers.filter(isRelativeSpecifier);
}
