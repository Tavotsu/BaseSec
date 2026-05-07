import { describe, it, expect } from 'vitest';
import { MarkdownFormatter } from '../../src/report/markdown';
import type { ScanResult, Finding, Severity } from '../../src/rules/types';

function createFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'SQLI-001',
    ruleName: 'SQL Injection',
    category: 'sql-injection',
    severity: 'critical' as Severity,
    confidence: 'high',
    filePath: 'db.ts',
    line: 10,
    column: 5,
    endLine: 10,
    endColumn: 30,
    message: 'Potential SQL injection via string concatenation',
    codeSnippet: 'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
    remediation: 'Use parameterized queries',
    references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
    ...overrides,
  };
}

function createScanResult(findings: Finding[] = []): ScanResult {
  return {
    findings,
    stats: {
      filesScanned: 8,
      filesSkipped: 1,
      rulesRun: 30,
      duration: 350,
      frameworks: ['express'],
    },
    duration: 350,
  };
}

describe('MarkdownFormatter', () => {
  it('produces markdown with title', () => {
    const formatter = new MarkdownFormatter();
    const result = createScanResult([createFinding()]);
    const output = formatter.format(result, '/app');
    expect(output).toContain('# basesec Security Report');
  });

  it('includes severity counts', () => {
    const formatter = new MarkdownFormatter();
    const findings: Finding[] = [
      createFinding({ severity: 'critical', ruleId: 'A-001' }),
      createFinding({ severity: 'high', ruleId: 'A-002' }),
      createFinding({ severity: 'low', ruleId: 'A-003' }),
    ];
    const result = createScanResult(findings);
    const output = formatter.format(result, '/app');
    expect(output).toContain('CRITICAL');
    expect(output).toContain('HIGH');
    expect(output).toContain('LOW');
  });

  it('includes finding details', () => {
    const formatter = new MarkdownFormatter();
    const result = createScanResult([createFinding()]);
    const output = formatter.format(result, '/app');
    expect(output).toContain('SQLI-001');
    expect(output).toContain('SQL Injection');
    expect(output).toContain('Potential SQL injection');
    expect(output).toContain('parameterized queries');
  });

  it('escapes markdown special characters in code', () => {
    const formatter = new MarkdownFormatter();
    const result = createScanResult([
      createFinding({
        codeSnippet: '```javascript\nconsole.log("hello")\n```',
        message: 'Test finding',
      }),
    ]);
    const output = formatter.format(result, '/app');
    expect(output).toContain('\\`\\`\\`');
  });

  it('handles empty findings', () => {
    const formatter = new MarkdownFormatter();
    const result = createScanResult([]);
    const output = formatter.format(result, '/app');
    expect(output).toContain('No vulnerabilities found');
  });

  it('includes framework detection', () => {
    const formatter = new MarkdownFormatter();
    const result = createScanResult([createFinding()]);
    const output = formatter.format(result, '/app');
    expect(output).toContain('express');
  });

  it('includes references when present', () => {
    const formatter = new MarkdownFormatter();
    const result = createScanResult([createFinding()]);
    const output = formatter.format(result, '/app');
    expect(output).toContain('owasp.org');
  });

  it('handles findings without references', () => {
    const formatter = new MarkdownFormatter();
    const result = createScanResult([
      createFinding({ references: [] }),
    ]);
    const output = formatter.format(result, '/app');
    expect(output).toContain('SQLI-001');
  });

  it('handles maximum-severity-first grouping', () => {
    const formatter = new MarkdownFormatter();
    const findings: Finding[] = [
      createFinding({ severity: 'low', ruleId: 'LOW-001' }),
      createFinding({ severity: 'critical', ruleId: 'CRIT-001' }),
    ];
    const result = createScanResult(findings);
    const output = formatter.format(result, '/app');
    const critIdx = output.indexOf('CRIT-001');
    const lowIdx = output.indexOf('LOW-001');
    expect(critIdx).toBeLessThan(lowIdx);
  });
});