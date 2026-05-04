import { describe, it, expect } from 'vitest';
import { getFormatter } from '../../src/report/formatter';
import type { ScanResult } from '../../src/rules/types';

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    findings: [],
    stats: {
      filesScanned: 10,
      filesSkipped: 2,
      rulesRun: 30,
      frameworks: ['express'],
    },
    duration: 1200,
    ...overrides,
  };
}

function makeFinding(overrides: Record<string, unknown> = {}) {
  return {
    ruleId: 'TEST-001',
    ruleName: 'Test Rule',
    category: 'sql-injection' as const,
    severity: 'high' as const,
    filePath: 'src/app.ts',
    line: 23,
    column: 7,
    endLine: 23,
    endColumn: 65,
    message: 'Test finding message',
    codeSnippet: 'const query = "SELECT * FROM users WHERE id = " + req.params.id;',
    remediation: 'Use parameterized queries.',
    references: ['https://owasp.org'],
    confidence: 'high' as const,
    ...overrides,
  };
}

describe('Terminal Formatter', () => {
  it('produces output for findings', () => {
    const formatter = getFormatter('terminal');
    const result = makeScanResult({
      findings: [makeFinding()],
    });
    const output = formatter.format(result, './src');
    expect(output).toContain('TEST-001');
    expect(output).toContain('Test Rule');
    expect(output).toContain('src/app.ts');
  });

  it('shows no vulnerabilities message for empty findings', () => {
    const formatter = getFormatter('terminal');
    const result = makeScanResult();
    const output = formatter.format(result, './src');
    expect(output).toContain('No vulnerabilities found');
  });
});

describe('JSON Formatter', () => {
  it('produces valid JSON output', () => {
    const formatter = getFormatter('json');
    const result = makeScanResult({
      findings: [makeFinding()],
    });
    const output = formatter.format(result, './src');
    const parsed = JSON.parse(output);
    expect(parsed.version).toBe('0.1.0');
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].ruleId).toBe('TEST-001');
  });
});

describe('SARIF Formatter', () => {
  it('produces valid SARIF output', () => {
    const formatter = getFormatter('sarif');
    const result = makeScanResult({
      findings: [makeFinding()],
    });
    const output = formatter.format(result, './src');
    const parsed = JSON.parse(output);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.runs[0].results).toHaveLength(1);
  });
});

describe('Markdown Formatter', () => {
  it('produces markdown output', () => {
    const formatter = getFormatter('markdown');
    const result = makeScanResult({
      findings: [makeFinding()],
    });
    const output = formatter.format(result, './src');
    expect(output).toContain('TEST-001');
    expect(output).toContain('Test Rule');
    expect(output).toContain('```');
  });
});

describe('HTML Formatter', () => {
  it('produces HTML output', () => {
    const formatter = getFormatter('html');
    const result = makeScanResult({
      findings: [makeFinding()],
    });
    const output = formatter.format(result, './src');
    expect(output).toContain('<!DOCTYPE html>');
    expect(output).toContain('TEST-001');
    expect(output).toContain('Test Rule');
  });

  it('produces HTML output with empty findings', () => {
    const formatter = getFormatter('html');
    const result = makeScanResult();
    const output = formatter.format(result, './src');
    expect(output).toContain('No vulnerabilities found');
  });
});