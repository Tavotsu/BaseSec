import * as ts from 'typescript';
import * as path from 'node:path';
import { visit } from '../utils/ast-helpers';

const FRONTEND_EXTENSIONS = new Set(['.tsx', '.jsx', '.vue', '.svelte']);

export function isFrontendFile(filePath: string): boolean {
  return FRONTEND_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

export function hasJsx(sourceFile: ts.SourceFile): boolean {
  let found = false;
  visit(sourceFile, (node) => {
    if (
      ts.isJsxElement(node) ||
      ts.isJsxSelfClosingElement(node) ||
      ts.isJsxFragment(node)
    ) {
      found = true;
      return 'stop';
    }
    return 'continue';
  });
  return found;
}

export function isStaticLiteral(node: ts.Node): boolean {
  return (
    ts.isStringLiteral(node) ||
    ts.isNoSubstitutionTemplateLiteral(node) ||
    ts.isNumericLiteral(node) ||
    node.kind === ts.SyntaxKind.TrueKeyword ||
    node.kind === ts.SyntaxKind.FalseKeyword ||
    node.kind === ts.SyntaxKind.NullKeyword
  );
}

// Template rules (v-html, {@html}, [innerHTML]) scan raw text rather than a template
// AST — sfc-extractor keeps ParsedFile.content raw for exactly this. Maps a match
// index back to a 1-based line/column, matching getLineAndColumn's convention.
export function lineAtIndex(content: string, index: number): { line: number; column: number } {
  let line = 1;
  let lastNewline = -1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === '\n') {
      line++;
      lastNewline = i;
    }
  }
  return { line, column: index - lastNewline };
}

// ponytail: these primitives cover every current rule gate; add per-framework
// component/SFC detectors (isReactComponent, isVueSfc, ...) when a rule needs them.
