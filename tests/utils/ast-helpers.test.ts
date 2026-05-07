import { describe, it, expect } from 'vitest';
import { visit, findNodes, findCallExpressions, getAncestorOfKind, getCodeSnippet, getLineAndColumn } from '../../src/utils/ast-helpers';
import * as ts from 'typescript';

function createSourceFile(code: string): ts.SourceFile {
  return ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
}

describe('visit', () => {
  it('visits all nodes in order', () => {
    const code = 'const x = 1 + 2;';
    const sourceFile = createSourceFile(code);
    const nodes: ts.SyntaxKind[] = [];
    visit(sourceFile, (node) => {
      nodes.push(node.kind);
      return 'continue';
    });
    expect(nodes.length).toBeGreaterThan(0);
    expect(nodes).toContain(ts.SyntaxKind.VariableDeclaration);
    expect(nodes).toContain(ts.SyntaxKind.BinaryExpression);
  });

  it('stops descent on "stop" but siblings continue', () => {
    const code = 'const x = 1; const y = 2;';
    const sourceFile = createSourceFile(code);
    let foundFirst = false;
    let foundSecond = false;
    visit(sourceFile, (node) => {
      if (ts.isNumericLiteral(node)) {
        if (!foundFirst) {
          foundFirst = true;
          return 'stop';
        }
        foundSecond = true;
      }
      return 'continue';
    });
    expect(foundFirst).toBe(true);
    expect(foundSecond).toBe(true);
  });

  it('skips children on "skip"', () => {
    const code = 'const obj = { a: 1, b: 2 };';
    const sourceFile = createSourceFile(code);
    const nodes: ts.SyntaxKind[] = [];
    visit(sourceFile, (node) => {
      nodes.push(node.kind);
      if (node.kind === ts.SyntaxKind.ObjectLiteralExpression) {
        return 'skip';
      }
      return 'continue';
    });
    expect(nodes).toContain(ts.SyntaxKind.ObjectLiteralExpression);
    expect(nodes).not.toContain(ts.SyntaxKind.PropertyAssignment);
  });
});

describe('findNodes', () => {
  it('finds all nodes of a specific kind', () => {
    const code = 'const x = 1; const y = 2;';
    const sourceFile = createSourceFile(code);
    const decls = findNodes(sourceFile, ts.SyntaxKind.VariableDeclaration);
    expect(decls.length).toBe(2);
  });

  it('returns empty array when no nodes found', () => {
    const code = 'const x = 1;';
    const sourceFile = createSourceFile(code);
    const classes = findNodes(sourceFile, ts.SyntaxKind.ClassDeclaration);
    expect(classes).toEqual([]);
  });
});

describe('findCallExpressions', () => {
  it('finds function calls by identifier', () => {
    const code = 'eval("1+2");';
    const sourceFile = createSourceFile(code);
    const calls = findCallExpressions(sourceFile, 'eval');
    expect(calls.length).toBe(1);
  });

  it('finds method calls by name', () => {
    const code = 'app.get("/users", handler);';
    const sourceFile = createSourceFile(code);
    const calls = findCallExpressions(sourceFile, 'get');
    expect(calls.length).toBe(1);
  });

  it('returns empty when no matches', () => {
    const code = 'const x = 1 + 2;';
    const sourceFile = createSourceFile(code);
    const calls = findCallExpressions(sourceFile, 'eval');
    expect(calls).toEqual([]);
  });

  it('finds multiple occurrences', () => {
    const code = 'eval("a"); eval("b");';
    const sourceFile = createSourceFile(code);
    const calls = findCallExpressions(sourceFile, 'eval');
    expect(calls.length).toBe(2);
  });
});

describe('getAncestorOfKind', () => {
  it('finds parent of specific kind', () => {
    const code = 'const x = 1 + 2;';
    const sourceFile = createSourceFile(code);
    let binaryExpr: ts.Node | undefined;
    visit(sourceFile, (node) => {
      if (ts.isBinaryExpression(node)) {
        binaryExpr = node;
        return 'stop';
      }
      return 'continue';
    });
    expect(binaryExpr).toBeDefined();
    const parent = getAncestorOfKind(binaryExpr!, ts.SyntaxKind.VariableDeclaration);
    expect(parent).toBeDefined();
    expect(parent!.kind).toBe(ts.SyntaxKind.VariableDeclaration);
  });

  it('returns undefined when no ancestor of kind', () => {
    const code = 'const x = 1;';
    const sourceFile = createSourceFile(code);
    let numLiteral: ts.Node | undefined;
    visit(sourceFile, (node) => {
      if (ts.isNumericLiteral(node)) {
        numLiteral = node;
        return 'stop';
      }
      return 'continue';
    });
    const classAncestor = getAncestorOfKind(numLiteral!, ts.SyntaxKind.ClassDeclaration);
    expect(classAncestor).toBeUndefined();
  });
});

describe('getLineAndColumn', () => {
  it('returns correct line and column', () => {
    const code = 'const x = 1;\nconst y = 2;';
    const sourceFile = createSourceFile(code);
    const decls = findNodes(sourceFile, ts.SyntaxKind.VariableDeclaration);
    const secondDecl = decls[1];
    const lc = getLineAndColumn(sourceFile, secondDecl);
    expect(lc.line).toBe(2);
    expect(lc.column).toBeGreaterThanOrEqual(1);
  });
});

describe('getCodeSnippet', () => {
  it('returns code for valid line number', () => {
    const code = 'line one\nline two\nline three';
    expect(getCodeSnippet(code, 2)).toBe('line two');
  });

  it('returns empty string for line 0', () => {
    const code = 'line one\nline two';
    expect(getCodeSnippet(code, 0)).toBe('');
  });

  it('returns empty string for line beyond file', () => {
    const code = 'line one';
    expect(getCodeSnippet(code, 10)).toBe('');
  });

  it('trims whitespace from snippet', () => {
    const code = '  const x = 1;  ';
    expect(getCodeSnippet(code, 1)).toBe('const x = 1;');
  });
});