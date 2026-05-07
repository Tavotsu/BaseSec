import { describe, it, expect } from 'vitest';
import { HtmlFormatter } from '../../src/report/html';
import type { ScanResult, Finding, Severity } from '../../src/rules/types';

function createFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'XSS-001',
    ruleName: 'XSS via res.send',
    category: 'xss',
    severity: 'high' as Severity,
    confidence: 'high',
    filePath: 'app.ts',
    line: 10,
    column: 5,
    endLine: 10,
    endColumn: 20,
    message: 'Potential XSS vulnerability',
    codeSnippet: 'res.send(userInput)',
    remediation: 'Sanitize input before sending',
    references: ['https://owasp.org/www-community/attacks/xss/'],
    ...overrides,
  };
}

function createScanResult(findings: Finding[] = []): ScanResult {
  return {
    findings,
    stats: {
      filesScanned: 5,
      filesSkipped: 1,
      rulesRun: 30,
      duration: 250,
      frameworks: ['express'],
    },
    duration: 250,
  };
}

describe('HtmlFormatter', () => {
  it('produces valid HTML with DOCTYPE', () => {
    const formatter = new HtmlFormatter();
    const result = createScanResult([createFinding()]);
    const output = formatter.format(result, '/app');
    expect(output.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(output).toContain('<html');
    expect(output).toContain('</html>');
  });

  it('includes finding details in output', () => {
    const formatter = new HtmlFormatter();
    const result = createScanResult([createFinding()]);
    const output = formatter.format(result, '/app');
    expect(output).toContain('XSS-001');
    expect(output).toContain('XSS via res.send');
    expect(output).toContain('Potential XSS vulnerability');
    expect(output).toContain('res.send(userInput)');
    expect(output).toContain('Sanitize input before sending');
  });

  it('escapes HTML in findings', () => {
    const formatter = new HtmlFormatter();
    const result = createScanResult([
      createFinding({
        message: '<script>alert("xss")</script>',
        codeSnippet: 'res.send("<b>bold</b>")',
        filePath: 'app"<script>.ts',
      }),
    ]);
    const output = formatter.format(result, '/app');
    expect(output).not.toContain('<script>alert');
    expect(output).toContain('&lt;script&gt;');
  });

  it('shows severity stats', () => {
    const formatter = new HtmlFormatter();
    const findings: Finding[] = [
      createFinding({ severity: 'critical', ruleId: 'A-001' }),
      createFinding({ severity: 'high', ruleId: 'A-002' }),
      createFinding({ severity: 'medium', ruleId: 'A-003' }),
    ];
    const result = createScanResult(findings);
    const output = formatter.format(result, '/app');
    expect(output).toContain('CRITICAL');
    expect(output).toContain('HIGH');
    expect(output).toContain('MEDIUM');
  });

  it('shows empty message when no findings', () => {
    const formatter = new HtmlFormatter();
    const result = createScanResult([]);
    const output = formatter.format(result, '/app');
    expect(output).toContain('No vulnerabilities found');
  });

  it('shows framework detection', () => {
    const formatter = new HtmlFormatter();
    const result = createScanResult([]);
    const output = formatter.format(result, '/app');
    expect(output).toContain('express');
  });

  it('shows "No frameworks detected" when no frameworks', () => {
    const formatter = new HtmlFormatter();
    const result: ScanResult = {
      findings: [],
      stats: {
        filesScanned: 5,
        filesSkipped: 1,
        rulesRun: 30,
        duration: 250,
        frameworks: [],
      },
      duration: 250,
    };
    const output = formatter.format(result, '/app');
    expect(output).toContain('No frameworks detected');
  });

  it('sorts findings by severity', () => {
    const formatter = new HtmlFormatter();
    const findings: Finding[] = [
      createFinding({ severity: 'low', ruleId: 'LOW-001' }),
      createFinding({ severity: 'critical', ruleId: 'CRIT-001' }),
      createFinding({ severity: 'medium', ruleId: 'MED-001' }),
    ];
    const result = createScanResult(findings);
    const output = formatter.format(result, '/app');
    const critIdx = output.indexOf('CRIT-001');
    const medIdx = output.indexOf('MED-001');
    const lowIdx = output.indexOf('LOW-001');
    expect(critIdx).toBeLessThan(medIdx);
    expect(medIdx).toBeLessThan(lowIdx);
  });

  it('handles unicode in output', () => {
    const formatter = new HtmlFormatter();
    const result = createScanResult([
      createFinding({
        message: 'Inyección SQL 中文',
        category: 'sql-injection',
      }),
    ]);
    const output = formatter.format(result, '/app');
    expect(output).toContain('Inyección SQL 中文');
  });

  it('includes references when present', () => {
    const formatter = new HtmlFormatter();
    const result = createScanResult([createFinding()]);
    const output = formatter.format(result, '/app');
    expect(output).toContain('References');
    expect(output).toContain('owasp.org');
  });

  it('hides references section when empty', () => {
    const formatter = new HtmlFormatter();
    const result = createScanResult([
      createFinding({ references: [] }),
    ]);
    const output = formatter.format(result, '/app');
    expect(output).not.toContain('References');
  });
});