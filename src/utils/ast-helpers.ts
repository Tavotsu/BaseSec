import * as ts from 'typescript';

export type VisitResult = 'skip' | 'continue' | 'stop';

export function visit(
  node: ts.Node,
  callback: (node: ts.Node) => VisitResult,
): void {
  const result = callback(node);
  if (result === 'stop') return;
  if (result === 'skip') {
    return;
  }
  ts.forEachChild(node, (child) => visit(child, callback));
}

export function findNodes(
  root: ts.Node,
  kind: ts.SyntaxKind,
): ts.Node[] {
  const results: ts.Node[] = [];
  visit(root, (node) => {
    if (node.kind === kind) {
      results.push(node);
    }
    return 'continue';
  });
  return results;
}

export function findCallExpressions(
  sourceFile: ts.SourceFile,
  identifier: string,
): ts.CallExpression[] {
  const results: ts.CallExpression[] = [];
  visit(sourceFile, (node) => {
    if (ts.isCallExpression(node)) {
      const expr = node.expression;
      if (
        ts.isIdentifier(expr) && expr.text === identifier
      ) {
        results.push(node);
      } else if (
        ts.isPropertyAccessExpression(expr) &&
        expr.name.text === identifier
      ) {
        results.push(node);
      }
    }
    return 'continue';
  });
  return results;
}

export function getAncestorOfKind(
  node: ts.Node,
  kind: ts.SyntaxKind,
): ts.Node | undefined {
  let current = node.parent;
  while (current) {
    if (current.kind === kind) return current;
    current = current.parent;
  }
  return undefined;
}

export function getNodeText(sourceFile: ts.SourceFile, node: ts.Node): string {
  return node.getText(sourceFile);
}

export function getLineAndColumn(
  sourceFile: ts.SourceFile,
  node: ts.Node,
): { line: number; column: number } {
  const start = node.getStart(sourceFile);
  const { line, character } =
    sourceFile.getLineAndCharacterOfPosition(start);
  return { line: line + 1, column: character + 1 };
}

export function getCodeSnippet(
  sourceText: string,
  line: number,
): string {
  const lines = sourceText.split('\n');
  const idx = line - 1;
  if (idx < 0 || idx >= lines.length) return '';
  return lines[idx].trim();
}