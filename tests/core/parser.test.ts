import { describe, it, expect } from 'vitest';
import * as ts from 'typescript';
import { Parser } from '../../src/core/parser';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

function hasJsxElement(sourceFile: ts.SourceFile): boolean {
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) {
      found = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);
  return found;
}

describe('Parser', () => {
  let tmpDir: string;

  function createFile(name: string, content: string): string {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-parser-'));
    const filePath = path.join(tmpDir, name);
    fs.writeFileSync(filePath, content);
    return filePath;
  }

  function cleanup() {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  it('parses TypeScript files to AST SourceFile', () => {
    const filePath = createFile('app.ts', 'const x: number = 1;');
    const parser = new Parser();
    const result = parser.parseFile(filePath);

    expect('sourceFile' in result).toBe(true);
    if ('sourceFile' in result) {
      expect(result.filePath).toBe(filePath);
      expect(result.size).toBeGreaterThan(0);
      expect(result.content).toBe('const x: number = 1;');
    }
    cleanup();
  });

  it('parses JavaScript files with JS ScriptKind', () => {
    const filePath = createFile('app.js', 'var x = 1;');
    const parser = new Parser();
    const result = parser.parseFile(filePath);

    expect('sourceFile' in result).toBe(true);
    cleanup();
  });

  it('parses JSX files', () => {
    const filePath = createFile('component.jsx', 'const X = () => <div/>;');
    const parser = new Parser();
    const result = parser.parseFile(filePath);

    expect('sourceFile' in result).toBe(true);
    cleanup();
  });

  it('parses JSX in .tsx files as JSX (ScriptKind.TSX)', () => {
    const parser = new Parser();
    const result = parser.parseContent('/virtual/component.tsx', 'const X = () => <div className="a">hi</div>;');

    expect('sourceFile' in result).toBe(true);
    if ('sourceFile' in result) {
      expect(hasJsxElement(result.sourceFile)).toBe(true);
    }
  });

  it('does not parse the same content as JSX in a .ts file', () => {
    const parser = new Parser();
    const result = parser.parseContent('/virtual/component.ts', 'const X = () => <div className="a">hi</div>;');

    expect('sourceFile' in result).toBe(true);
    if ('sourceFile' in result) {
      expect(hasJsxElement(result.sourceFile)).toBe(false);
    }
  });

  it('returns ParseError for non-existent files', () => {
    const parser = new Parser();
    const result = parser.parseFile('/nonexistent/file.ts');

    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error).toBeTruthy();
    }
  });

  it('returns ParseError for files without extensions', () => {
    const parser = new Parser();
    const result = parser.parseFile('/some/path/Makefile');

    expect('error' in result).toBe(true);
  });

  it('parseFiles filters out errored files', () => {
    const validPath = createFile('valid.ts', 'const x = 1;');
    const parser = new Parser();
    const results = parser.parseFiles([validPath, '/nonexistent/file.ts']);

    expect(results.length).toBe(1);
    expect(results[0].filePath).toBe(validPath);
    cleanup();
  });
});