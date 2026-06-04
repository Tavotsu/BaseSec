import { describe, it, expect } from 'vitest';
import { prepareContext, redactForLlm, formatDryRun } from '../../src/ai/privacy';
import type { Finding } from '../../src/rules/types';

const baseFinding: Finding = {
  ruleId: 'SQLI-001',
  ruleName: 'SQL Injection',
  category: 'sql-injection',
  severity: 'high',
  filePath: '/project/src/db.ts',
  line: 10,
  column: 1,
  endLine: 10,
  endColumn: 50,
  message: 'Potential SQL injection',
  codeSnippet: 'db.query(`SELECT * FROM users WHERE id = ${req.body.id}`)',
  remediation: 'Use parameterized queries',
  references: [],
  confidence: 'high',
};

const fileContent = Array.from({ length: 30 }, (_, i) => `line ${i + 1}`).join('\n');

describe('prepareContext', () => {
  it('minimal returns only codeSnippet', () => {
    const result = prepareContext(baseFinding, fileContent, 'minimal');
    expect(result).toBe(baseFinding.codeSnippet);
  });

  it('file returns full content', () => {
    const result = prepareContext(baseFinding, fileContent, 'file');
    expect(result).toBe(fileContent);
  });

  it('context returns ±10 lines around finding.line', () => {
    const result = prepareContext({ ...baseFinding, line: 15 }, fileContent, 'context');
    const lines = result.split('\n');
    expect(lines.length).toBeLessThanOrEqual(21);
  });
});

describe('redactForLlm', () => {
  it('replaces long base64-like strings', () => {
    const code = 'const token = "abcdefghijklmnopqrstuvwxyz1234567890";';
    const result = redactForLlm(code);
    expect(result).toContain('**************');
  });

  it('replaces file paths', () => {
    const code = 'const p = "/home/user/project/secret.ts";';
    const result = redactForLlm(code);
    expect(result).toContain('[REDACTED_PATH]');
  });

  it('leaves short strings alone', () => {
    const code = 'const x = "hello";';
    const result = redactForLlm(code);
    expect(result).toBe(code);
  });
});

describe('formatDryRun', () => {
  it('includes DRY RUN header', () => {
    const result = formatDryRun([baseFinding], 'minimal');
    expect(result).toContain('[DRY RUN]');
  });

  it('includes finding ruleId', () => {
    const result = formatDryRun([baseFinding], 'minimal');
    expect(result).toContain('SQLI-001');
  });

  it('handles empty findings array', () => {
    const result = formatDryRun([], 'minimal');
    expect(result).toContain('[DRY RUN]');
  });
});
