import { describe, it, expect } from 'vitest';
import { analyzeFile, isExpressionTainted, isExpressionSanitized, getTaintSourcesForExpression } from '../../src/taint/engine';
import type { TaintGraph } from '../../src/rules/types';
import * as ts from 'typescript';

function createParsedFile(code: string): { sourceFile: ts.SourceFile; filePath: string; content: string } {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { sourceFile, filePath: 'test.ts', content: code };
}

describe('analyzeFile', () => {
  it('detects taint sources from req.body', () => {
    const parsedFile = createParsedFile('const name = req.body.name;');
    const graph = analyzeFile(parsedFile, ['express'], []);
    expect(graph.sources.length).toBeGreaterThanOrEqual(1);
    expect(graph.sources.some(s => s.expression.includes('req.body'))).toBe(true);
  });

  it('detects taint sources from req.query', () => {
    const parsedFile = createParsedFile('const id = req.query.id;');
    const graph = analyzeFile(parsedFile, ['express'], []);
    expect(graph.sources.length).toBeGreaterThanOrEqual(1);
  });

  it('detects flows from source to sink', () => {
    const code = 'const name = req.body.name;\neval(name);';
    const parsedFile = createParsedFile(code);
    const graph = analyzeFile(parsedFile, ['express'], []);
    expect(graph.flows.length).toBeGreaterThanOrEqual(1);
  });

  it('marks sanitized variables in taintMap', () => {
    const code = 'const raw = req.body.input;\nconst safe = escapeHtml(raw);';
    const parsedFile = createParsedFile(code);
    const graph = analyzeFile(parsedFile, ['express'], ['escapeHtml']);
    const safeEntry = graph.taintMap.get('safe');
    if (safeEntry) {
      expect(safeEntry.isSanitized).toBe(true);
    }
  });

  it('deduplicates flows', () => {
    const code = 'const input = req.body.input;\nconst output = input;\neval(output);';
    const parsedFile = createParsedFile(code);
    const graph = analyzeFile(parsedFile, ['express'], []);
    const uniqueKeys = new Set(graph.flows.map(f => `${f.source.expression}\x00${f.sink.functionName}\x00${f.sink.line}`));
    expect(graph.flows.length).toBe(uniqueKeys.size);
  });

  it('handles empty file', () => {
    const parsedFile = createParsedFile('');
    const graph = analyzeFile(parsedFile, ['express'], []);
    expect(graph.sources).toHaveLength(0);
    expect(graph.sinks).toHaveLength(0);
    expect(graph.flows).toHaveLength(0);
  });

  it('handles file with no taint sources or sinks', () => {
    const parsedFile = createParsedFile('const x = 1;\nconst y = x + 2;');
    const graph = analyzeFile(parsedFile, ['express'], []);
    expect(graph.sources).toHaveLength(0);
    expect(graph.sinks).toHaveLength(0);
  });

  it('detects process.argv as taint source', () => {
    const parsedFile = createParsedFile('const arg = process.argv[2];');
    const graph = analyzeFile(parsedFile, [], []);
    expect(graph.sources.length).toBeGreaterThanOrEqual(1);
  });

  it('respects frameworks filter', () => {
    const parsedFile = createParsedFile('const name = req.body.name;');
    const graphNoExpress = analyzeFile(parsedFile, [], []);
    expect(graphNoExpress.sources.some(s => s.kind === 'body')).toBe(false);
  });
});

describe('isExpressionTainted', () => {
  it('returns false for undefined graph', () => {
    expect(isExpressionTainted(undefined, 'req.body.name')).toBe(false);
  });

  it('returns false for empty expression', () => {
    const graph: TaintGraph = { filePath: 'test.ts', taintMap: new Map(), sources: [], sinks: [], flows: [] };
    expect(isExpressionTainted(graph, '')).toBe(false);
  });

  it('returns true when expression matches source directly', () => {
    const graph: TaintGraph = {
      filePath: 'test.ts',
      taintMap: new Map(),
      sources: [{ expression: 'req.body.name', kind: 'body', line: 1 }],
      sinks: [],
      flows: [],
    };
    expect(isExpressionTainted(graph, 'req.body.name')).toBe(true);
  });

  it('returns true when expression starts with source kind', () => {
    const graph: TaintGraph = {
      filePath: 'test.ts',
      taintMap: new Map(),
      sources: [{ expression: 'req.body.name', kind: 'body', line: 1 }],
      sinks: [],
      flows: [],
    };
    expect(isExpressionTainted(graph, 'body.name')).toBe(true);
  });

  it('returns true from unsanitized flow', () => {
    const graph: TaintGraph = {
      filePath: 'test.ts',
      taintMap: new Map(),
      sources: [],
      sinks: [],
      flows: [{ source: { expression: 'req.query.id', kind: 'query', line: 1 }, sink: { functionName: 'eval', line: 2 }, path: [], isSanitized: false, sanitizersApplied: [] }],
    };
    expect(isExpressionTainted(graph, 'req.query.id')).toBe(true);
  });

  it('skips sanitized flows', () => {
    const graph: TaintGraph = {
      filePath: 'test.ts',
      taintMap: new Map(),
      sources: [],
      sinks: [],
      flows: [{ source: { expression: 'req.query.id', kind: 'query', line: 1 }, sink: { functionName: 'eval', line: 2 }, path: [], isSanitized: true, sanitizersApplied: ['escapeHtml'] }],
    };
    expect(isExpressionTainted(graph, 'req.query.id')).toBe(false);
  });

  it('returns true from taintMap entry', () => {
    const taintMap = new Map();
    taintMap.set('username', { isSanitized: false, sources: [{ expression: 'req.body.username', kind: 'body', line: 1 }], sanitizers: [] });
    const graph: TaintGraph = {
      filePath: 'test.ts',
      taintMap,
      sources: [],
      sinks: [],
      flows: [],
    };
    expect(isExpressionTainted(graph, 'username')).toBe(true);
    expect(isExpressionTainted(graph, 'username.login')).toBe(true);
    expect(isExpressionTainted(graph, 'username[0]')).toBe(true);
  });

  it('skips sanitized taintMap entries', () => {
    const taintMap = new Map();
    taintMap.set('safeName', { isSanitized: true, sources: [{ expression: 'req.body.name', kind: 'body', line: 1 }], sanitizers: ['escapeHtml'] });
    const graph: TaintGraph = {
      filePath: 'test.ts',
      taintMap,
      sources: [],
      sinks: [],
      flows: [],
    };
    expect(isExpressionTainted(graph, 'safeName')).toBe(false);
  });
});

describe('isExpressionSanitized', () => {
  it('returns false for undefined graph', () => {
    expect(isExpressionSanitized(undefined, 'input')).toBe(false);
  });

  it('returns false for empty expression', () => {
    const graph: TaintGraph = { filePath: 'test.ts', taintMap: new Map(), sources: [], sinks: [], flows: [] };
    expect(isExpressionSanitized(graph, '')).toBe(false);
  });

  it('returns true for sanitized taintMap entry', () => {
    const taintMap = new Map();
    taintMap.set('cleanInput', { isSanitized: true, sources: [{ expression: 'req.body.input', kind: 'body', line: 1 }], sanitizers: ['escapeHtml'] });
    const graph: TaintGraph = {
      filePath: 'test.ts',
      taintMap,
      sources: [],
      sinks: [],
      flows: [],
    };
    expect(isExpressionSanitized(graph, 'cleanInput')).toBe(true);
  });

  it('returns false when taintMap entry is not sanitized', () => {
    const taintMap = new Map();
    taintMap.set('dirtyInput', { isSanitized: false, sources: [{ expression: 'req.body.input', kind: 'body', line: 1 }], sanitizers: [] });
    const graph: TaintGraph = {
      filePath: 'test.ts',
      taintMap,
      sources: [],
      sinks: [],
      flows: [],
    };
    expect(isExpressionSanitized(graph, 'dirtyInput')).toBe(false);
  });

  it('returns false when unsanitized flow exists for same expression', () => {
    const taintMap = new Map();
    taintMap.set('input', { isSanitized: true, sources: [{ expression: 'req.body.input', kind: 'body', line: 1 }], sanitizers: ['escapeHtml'] });
    const graph: TaintGraph = {
      filePath: 'test.ts',
      taintMap,
      sources: [],
      sinks: [],
      flows: [{ source: { expression: 'input', kind: 'body', line: 1 }, sink: { functionName: 'eval', line: 2 }, path: [], isSanitized: false, sanitizersApplied: [] }],
    };
    expect(isExpressionSanitized(graph, 'input')).toBe(false);
  });
});

describe('getTaintSourcesForExpression', () => {
  it('finds matching source expressions', () => {
    const graph: TaintGraph = {
      filePath: 'test.ts',
      taintMap: new Map(),
      sources: [{ expression: 'req.body.name', kind: 'body', line: 1 }],
      sinks: [],
      flows: [],
    };
    const result = getTaintSourcesForExpression(graph, 'req.body.name');
    expect(result.length).toBeGreaterThanOrEqual(1);
    expect(result[0].expression).toBe('req.body.name');
  });

  it('finds sources from taintMap', () => {
    const taintMap = new Map();
    taintMap.set('username', { isSanitized: false, sources: [{ expression: 'req.body.username', kind: 'body', line: 1 }], sanitizers: [] });
    const graph: TaintGraph = {
      filePath: 'test.ts',
      taintMap,
      sources: [],
      sinks: [],
      flows: [],
    };
    const result = getTaintSourcesForExpression(graph, 'username');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });

  it('returns empty array when no matches', () => {
    const graph: TaintGraph = { filePath: 'test.ts', taintMap: new Map(), sources: [], sinks: [], flows: [] };
    const result = getTaintSourcesForExpression(graph, 'safeVariable');
    expect(result).toEqual([]);
  });
});