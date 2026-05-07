import { describe, it, expect } from 'vitest';
import { Pipeline } from '../../src/core/pipeline';
import { createSourceFile } from '../helpers';
import type { ParsedFile, secbaseConfig } from '../../src/rules/types';
import { resolveConfidence, isExpressionTainted, isExpressionSanitized } from '../../src/taint/integration';
import { analyzeFile } from '../../src/taint/engine';
import type { TaintGraph } from '../../src/taint/rules/types';

function makeParsedFile(code: string, filePath = 'test.ts'): ParsedFile {
  return {
    filePath,
    sourceFile: createSourceFile(code, filePath),
    content: code,
    size: code.length,
  };
}

describe('Taint Integration - resolveConfidence', () => {
  it('returns default confidence when taintGraph is undefined', () => {
    expect(resolveConfidence(undefined, 'req.body.name', 'high')).toBe('high');
    expect(resolveConfidence(undefined, 'req.body.name', 'medium')).toBe('medium');
    expect(resolveConfidence(undefined, 'req.body.name', 'low')).toBe('low');
  });

  it('returns "high" when expression is tainted', () => {
    const code = `const name = req.body.name;`;
    const parsedFile = makeParsedFile(code);
    const graph = analyzeFile(parsedFile, ['express'], []);
    const confidence = resolveConfidence(graph, 'name', 'low');
    expect(confidence).toBe('high');
  });

  it('returns "low" when expression is sanitized', () => {
    const code = `const safeName = escapeHtml(req.body.name);`;
    const parsedFile = makeParsedFile(code);
    const graph = analyzeFile(parsedFile, ['express'], []);
    const confidence = resolveConfidence(graph, 'safeName', 'high');
    expect(confidence).toBe('low');
  });

  it('returns "medium" when expression is neither tainted nor sanitized', () => {
    const code = `const x = getUserInput();`;
    const parsedFile = makeParsedFile(code);
    const graph = analyzeFile(parsedFile, [], []);
    const confidence = resolveConfidence(graph, 'x', 'medium');
    expect(confidence).toBe('medium');
  });
});

describe('Taint Integration - isExpressionTainted', () => {
  it('returns true for direct taint source', () => {
    const code = `const data = req.body;`;
    const parsedFile = makeParsedFile(code);
    const graph = analyzeFile(parsedFile, ['express'], []);
    expect(isExpressionTainted(graph, 'data')).toBe(true);
  });

  it('returns true for property access of taint source', () => {
    const code = `const name = req.body.name;`;
    const parsedFile = makeParsedFile(code);
    const graph = analyzeFile(parsedFile, ['express'], []);
    expect(isExpressionTainted(graph, 'name')).toBe(true);
  });

  it('returns false for non-tainted expression', () => {
    const code = `const x = 42;`;
    const parsedFile = makeParsedFile(code);
    const graph = analyzeFile(parsedFile, [], []);
    expect(isExpressionTainted(graph, 'x')).toBe(false);
  });

  it('returns false when graph is undefined', () => {
    expect(isExpressionTainted(undefined, 'req.body')).toBe(false);
  });
});

describe('Taint Integration - isExpressionSanitized', () => {
  it('returns true when expression was sanitized', () => {
    const code = `const safeData = escapeHtml(req.body.input);`;
    const parsedFile = makeParsedFile(code);
    const graph = analyzeFile(parsedFile, ['express'], []);
    expect(isExpressionSanitized(graph, 'safeData')).toBe(true);
  });

  it('returns false for non-sanitized expression', () => {
    const code = `const data = req.body.input;`;
    const parsedFile = makeParsedFile(code);
    const graph = analyzeFile(parsedFile, ['express'], []);
    expect(isExpressionSanitized(graph, 'data')).toBe(false);
  });

  it('returns false when graph is undefined', () => {
    expect(isExpressionSanitized(undefined, 'safeData')).toBe(false);
  });
});

describe('Taint Integration - Custom Sanitizers', () => {
  it('recognizes custom sanitizer from config', () => {
    const code = `const safe = myCustomSanitizer(req.body.input);`;
    const parsedFile = makeParsedFile(code);
    const graph = analyzeFile(parsedFile, ['express'], ['myCustomSanitizer']);
    expect(isExpressionSanitized(graph, 'safe')).toBe(true);
  });

  it('does not recognize unknown sanitizer', () => {
    const code = `const unsafe = unknownFunction(req.body.input);`;
    const parsedFile = makeParsedFile(code);
    const graph = analyzeFile(parsedFile, ['express'], []);
    expect(isExpressionSanitized(graph, 'unsafe')).toBe(false);
  });
});

describe('Taint Integration - Pipeline with Taint', () => {
  it('produces findings when scanning code with taint sources', async () => {
    const pipeline = new Pipeline();
    const code = `
      import express from 'express';
      const app = express();
      app.post('/cmd', (req, res) => {
        exec('ping ' + req.body.host);
      });
    `;
    const os = await import('node:os');
    const path = await import('node:path');
    const fs = await import('node:fs');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secbase-taint-'));
    const tmpFile = path.join(tmpDir, 'test.ts');
    fs.writeFileSync(tmpFile, code);

    try {
      const result = await pipeline.run(tmpDir, {
        format: 'terminal',
        severity: 'low',
        ignore: ['**/.git/**', '**/node_modules/**'],
        taintAnalysis: true,
        noTaint: false,
      });

      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.stats.filesScanned).toBeGreaterThanOrEqual(1);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('produces findings without taint analysis (--no-taint)', async () => {
    const pipeline = new Pipeline();
    const code = `
      import express from 'express';
      const app = express();
      app.post('/cmd', (req, res) => {
        exec('ping ' + req.body.host);
      });
    `;
    const os = await import('node:os');
    const path = await import('node:path');
    const fs = await import('node:fs');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secbase-taint-'));
    const tmpFile = path.join(tmpDir, 'test.ts');
    fs.writeFileSync(tmpFile, code);

    try {
      const result = await pipeline.run(tmpDir, {
        format: 'terminal',
        severity: 'low',
        ignore: ['**/.git/**', '**/node_modules/**'],
        noTaint: true,
      });

      expect(result.findings.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});