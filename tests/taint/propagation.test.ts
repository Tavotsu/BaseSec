import { describe, it, expect } from 'vitest';
import { TaintPropagation } from '../../src/taint/propagation';
import * as ts from 'typescript';

function parseAndAnalyze(code: string, customSanitizers: string[] = []): Map<string, import('../../src/taint/types').TaintInfo> {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  const propagation = new TaintPropagation(sourceFile, code, customSanitizers);
  return propagation.analyze();
}

describe('TaintPropagation', () => {
  it('tracks variable declaration from taint source', () => {
    const code = `const name = req.body.name;`;
    const taintMap = parseAndAnalyze(code);
    expect(taintMap.has('name')).toBe(true);
    expect(taintMap.get('name')!.isSanitized).toBe(false);
  });

  it('tracks assignment from taint source', () => {
    const code = `let x; x = req.query.id;`;
    const taintMap = parseAndAnalyze(code);
    expect(taintMap.has('x')).toBe(true);
  });

  it('tracks template literal taint', () => {
    const code = 'const query = `SELECT * FROM users WHERE id = ${req.params.id}`;';
    const taintMap = parseAndAnalyze(code);
    expect(taintMap.has('query')).toBe(true);
  });

  it('tracks string concatenation taint', () => {
    const code = 'const query = "SELECT * FROM users WHERE id = " + req.params.id;';
    const taintMap = parseAndAnalyze(code);
    expect(taintMap.has('query')).toBe(true);
  });

  it('marks variable as sanitized with escapeHtml', () => {
    const code = 'const safe = escapeHtml(req.body.name);';
    const taintMap = parseAndAnalyze(code);
    expect(taintMap.has('safe')).toBe(true);
    expect(taintMap.get('safe')!.isSanitized).toBe(true);
    expect(taintMap.get('safe')!.sanitizers).toContain('escapeHtml');
  });

  it('marks variable as sanitized with encodeURIComponent', () => {
    const code = 'const safe = encodeURIComponent(req.query.url);';
    const taintMap = parseAndAnalyze(code);
    expect(taintMap.has('safe')).toBe(true);
    expect(taintMap.get('safe')!.isSanitized).toBe(true);
  });

  it('recognizes custom sanitizers', () => {
    const code = 'const safe = mySanitizer(req.body.input);';
    const taintMap = parseAndAnalyze(code, ['mySanitizer']);
    expect(taintMap.has('safe')).toBe(true);
    expect(taintMap.get('safe')!.isSanitized).toBe(true);
  });

  it('tracks taint through object destructuring', () => {
    const code = 'const { name, email } = req.body;';
    const taintMap = parseAndAnalyze(code);
    expect(taintMap.has('name')).toBe(true);
    expect(taintMap.has('email')).toBe(true);
  });

  it('tracks taint through spread operator', () => {
    const code = 'const data = { ...req.body, extra: "safe" };';
    const taintMap = parseAndAnalyze(code);
    expect(taintMap.has('data')).toBe(true);
  });

  it('does not taint safe variable assignments', () => {
    const code = 'const safe = "hello world";';
    const taintMap = parseAndAnalyze(code);
    expect(taintMap.has('safe')).toBe(false);
  });

  it('resolvesToTainted returns false for safe variables', () => {
    const code = 'const safe = "hello"; const x = safe;';
    const taintMap = parseAndAnalyze(code);
    expect(taintMap.has('x')).toBe(false);
  });
});