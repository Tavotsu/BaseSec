import { describe, it, expect } from 'vitest';
import { findSources } from '../../src/taint/source';
import { findSinks } from '../../src/taint/sink';
import * as ts from 'typescript';

function parseCode(code: string, fileName = 'test.ts'): ts.SourceFile {
  return ts.createSourceFile(fileName, code, ts.ScriptTarget.Latest, true);
}

describe('Taint Source Detection', () => {
  it('detects req.body as taint source', () => {
    const code = `const name = req.body.name;`;
    const sourceFile = parseCode(code);
    const sources = findSources(sourceFile, code, ['express']);
    expect(sources.length).toBeGreaterThanOrEqual(1);
    expect(sources.some(s => s.expression.includes('req.body'))).toBe(true);
  });

  it('detects req.params as taint source', () => {
    const code = `const id = req.params.id;`;
    const sourceFile = parseCode(code);
    const sources = findSources(sourceFile, code, ['express']);
    expect(sources.some(s => s.expression.includes('req.params'))).toBe(true);
  });

  it('detects req.query as taint source', () => {
    const code = `const search = req.query.search;`;
    const sourceFile = parseCode(code);
    const sources = findSources(sourceFile, code, ['express']);
    expect(sources.some(s => s.expression.includes('req.query'))).toBe(true);
  });

  it('detects process.argv as taint source', () => {
    const code = `const arg = process.argv[2];`;
    const sourceFile = parseCode(code);
    const sources = findSources(sourceFile, code, []);
    expect(sources.some(s => s.expression.includes('process.argv'))).toBe(true);
  });
});

describe('Taint Sink Detection', () => {
  it('detects eval() as sink', () => {
    const code = `eval(userInput);`;
    const sourceFile = parseCode(code);
    const sinks = findSinks(sourceFile);
    expect(sinks.some(s => s.functionName === 'eval')).toBe(true);
  });

  it('detects exec() as sink', () => {
    const code = `exec(\`ping \${host}\`);`;
    const sourceFile = parseCode(code);
    const sinks = findSinks(sourceFile);
    expect(sinks.some(s => s.functionName === 'exec')).toBe(true);
  });

  it('detects res.send() as sink', () => {
    const code = `res.send(data);`;
    const sourceFile = parseCode(code);
    const sinks = findSinks(sourceFile);
    expect(sinks.some(s => s.functionName === 'res.send')).toBe(true);
  });
});