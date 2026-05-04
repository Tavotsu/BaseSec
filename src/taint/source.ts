import * as ts from 'typescript';
import type { TaintSourceInfo, SourceDefinition } from './types';
import { visit } from '../utils/ast-helpers';
import { TAINT_SOURCES } from '../utils/patterns';

const SOURCE_DEFINITIONS: SourceDefinition[] = [
  { pattern: 'req.body', framework: 'express' },
  { pattern: 'req.params', framework: 'express' },
  { pattern: 'req.query', framework: 'express' },
  { pattern: 'req.headers', framework: 'express' },
  { pattern: 'req.cookies', framework: 'express' },
  { pattern: 'req.files', framework: 'express' },
  { pattern: 'process.argv', framework: '*' },
];

const NESTJS_DECORATOR_SOURCES: SourceDefinition[] = [
  { pattern: '@Body()', framework: 'nestjs' },
  { pattern: '@Param()', framework: 'nestjs' },
  { pattern: '@Query()', framework: 'nestjs' },
  { pattern: '@Headers()', framework: 'nestjs' },
  { pattern: '@Req()', framework: 'nestjs' },
];

export function findSources(
  sourceFile: ts.SourceFile,
  content: string,
  frameworks: string[],
): TaintSourceInfo[] {
  const sources: TaintSourceInfo[] = [];
  const allDefs = [...SOURCE_DEFINITIONS, ...NESTJS_DECORATOR_SOURCES];

  visit(sourceFile, (node) => {
    if (ts.isPropertyAccessExpression(node)) {
      const text = node.getText(sourceFile);
      for (const def of allDefs) {
        if (def.framework !== '*' && !frameworks.includes(def.framework)) {
          continue;
        }
        if (text === def.pattern || text.startsWith(def.pattern + '.')) {
          const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
          sources.push({
            kind: def.pattern,
            expression: text,
            line: pos.line + 1,
            column: pos.character + 1,
          });
        }
      }
    }

    if (ts.isVariableDeclaration(node) && node.initializer) {
      const varName = ts.isIdentifier(node.name) ? node.name.text : undefined;
      const initText = node.initializer.getText(sourceFile);

      if (!ts.isObjectBindingPattern(node.name) && isTaintExpression(initText, allDefs, frameworks)) {
        const varName = ts.isIdentifier(node.name) ? node.name.text : undefined;
        const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
        const kind = detectSourceKind(initText, allDefs, frameworks);
        sources.push({
          kind,
          expression: initText,
          line: pos.line + 1,
          column: pos.character + 1,
          variableName: varName,
        });
      }
    }

    if (ts.isObjectBindingPattern(node) && node.parent) {
      const bindingPattern = node.parent;
      if (ts.isVariableDeclaration(bindingPattern) && bindingPattern.initializer) {
        const initText = bindingPattern.initializer.getText(sourceFile);
        if (isTaintExpression(initText, allDefs, frameworks)) {
          for (const element of node.elements) {
            if (ts.isIdentifier(element.name)) {
              const pos = sourceFile.getLineAndCharacterOfPosition(element.getStart(sourceFile));
              sources.push({
                kind: detectSourceKind(initText, allDefs, frameworks),
                expression: element.name.text,
                line: pos.line + 1,
                column: pos.character + 1,
                variableName: element.name.text,
              });
            }
          }
        }
      }
    }

    return 'continue';
  });

  return sources;
}

function isTaintExpression(
  text: string,
  defs: SourceDefinition[],
  frameworks: string[],
): boolean {
  for (const def of defs) {
    if (def.framework !== '*' && !frameworks.includes(def.framework)) {
      continue;
    }
    if (text === def.pattern || text.startsWith(def.pattern + '.') || text.startsWith(def.pattern + '[')) {
      return true;
    }
  }
  return false;
}

function detectSourceKind(
  text: string,
  defs: SourceDefinition[],
  frameworks: string[],
): string {
  for (const def of defs) {
    if (def.framework !== '*' && !frameworks.includes(def.framework)) {
      continue;
    }
    if (text.startsWith(def.pattern)) {
      return def.pattern;
    }
  }
  return 'unknown';
}

export { SOURCE_DEFINITIONS, NESTJS_DECORATOR_SOURCES };