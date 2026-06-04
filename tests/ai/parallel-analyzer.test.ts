import { describe, it, expect, vi } from 'vitest';
import { detectSuspiciousFiles, analyzeSuspiciousFiles } from '../../src/ai/parallel-analyzer';
import type { Finding, ParsedFile, TaintGraph } from '../../src/rules/types';
import type { LlmProvider } from '../../src/ai/providers/types';
import * as ts from 'typescript';

function makeSourceFile(): ts.SourceFile {
  return ts.createSourceFile('test.ts', '', ts.ScriptTarget.Latest, true);
}

function makeParsedFile(filePath: string, content = ''): ParsedFile {
  return { filePath, sourceFile: makeSourceFile(), content, size: content.length };
}

function makeTaintGraph(filePath: string, hasFlows = true): TaintGraph {
  return {
    filePath,
    taintMap: new Map(),
    sources: [],
    sinks: [],
    flows: hasFlows
      ? [{
          source: { expression: 'req.body', kind: 'http-request', line: 1, column: 1 },
          sink: { category: 'sql-injection', functionName: 'db.query', line: 5, column: 1 },
          path: [],
          isSanitized: false,
          sanitizersApplied: [],
        }]
      : [],
  };
}

function makeFinding(filePath: string): Finding {
  return {
    ruleId: 'SQLI-001', ruleName: 'SQL Injection', category: 'sql-injection', severity: 'high',
    filePath, line: 1, column: 1, endLine: 1, endColumn: 1, message: '', codeSnippet: '',
    remediation: '', references: [], confidence: 'high',
  };
}

describe('detectSuspiciousFiles', () => {
  it('returns files with taint flows but no existing findings', () => {
    const files = [makeParsedFile('/src/a.ts'), makeParsedFile('/src/b.ts')];
    const graphs = new Map([
      ['/src/a.ts', makeTaintGraph('/src/a.ts', true)],
      ['/src/b.ts', makeTaintGraph('/src/b.ts', false)],
    ]);
    const findings = [makeFinding('/src/a.ts')];

    const result = detectSuspiciousFiles(files, graphs, findings);
    expect(result).toHaveLength(0);
  });

  it('includes file with flows and no findings', () => {
    const files = [makeParsedFile('/src/c.ts')];
    const graphs = new Map([['/src/c.ts', makeTaintGraph('/src/c.ts', true)]]);
    const result = detectSuspiciousFiles(files, graphs, []);
    expect(result).toHaveLength(1);
    expect(result[0].filePath).toBe('/src/c.ts');
  });

  it('excludes file without taint graph', () => {
    const files = [makeParsedFile('/src/d.ts')];
    const result = detectSuspiciousFiles(files, new Map(), []);
    expect(result).toHaveLength(0);
  });
});

describe('analyzeSuspiciousFiles', () => {
  it('returns AI findings from provider response', async () => {
    const file = makeParsedFile('/src/e.ts', 'const x = req.body;');
    const graphs = new Map([['/src/e.ts', makeTaintGraph('/src/e.ts')]]);
    const provider: LlmProvider = {
      name: 'mock',
      call: vi.fn().mockResolvedValue(JSON.stringify([
        { line: 3, severity: 'high', category: 'xss', message: 'XSS risk', remediation: 'Escape', confidence: 'medium' },
      ])),
      validateConnection: vi.fn().mockResolvedValue(true),
    };

    const result = await analyzeSuspiciousFiles([file], graphs, provider, { contextLevel: 'minimal' });
    expect(result).toHaveLength(1);
    expect(result[0].aiGenerated).toBe(true);
    expect(result[0].severity).toBe('high');
  });

  it('returns empty on provider error', async () => {
    const file = makeParsedFile('/src/f.ts', '');
    const graphs = new Map([['/src/f.ts', makeTaintGraph('/src/f.ts')]]);
    const provider: LlmProvider = {
      name: 'mock',
      call: vi.fn().mockRejectedValue(new Error('Timeout')),
      validateConnection: vi.fn().mockResolvedValue(false),
    };
    const result = await analyzeSuspiciousFiles([file], graphs, provider, { contextLevel: 'minimal' });
    expect(result).toHaveLength(0);
  });

  it('returns empty on empty LLM response', async () => {
    const file = makeParsedFile('/src/g.ts', '');
    const graphs = new Map([['/src/g.ts', makeTaintGraph('/src/g.ts')]]);
    const provider: LlmProvider = {
      name: 'mock',
      call: vi.fn().mockResolvedValue('[]'),
      validateConnection: vi.fn().mockResolvedValue(true),
    };
    const result = await analyzeSuspiciousFiles([file], graphs, provider, { contextLevel: 'minimal' });
    expect(result).toHaveLength(0);
  });
});
