import { describe, it, expect } from 'vitest';
import { SarifFormatter } from '../../src/report/sarif';
import type { ScanResult, Finding, Severity } from '../../src/rules/types';

function createFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'SQLI-001',
    ruleName: 'SQL Injection',
    category: 'sql-injection',
    severity: 'critical' as Severity,
    confidence: 'high',
    filePath: 'test.ts',
    line: 10,
    column: 5,
    endLine: 10,
    endColumn: 30,
    message: 'Potential SQL injection',
    codeSnippet: 'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
    remediation: 'Use parameterized queries',
    references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
    ...overrides,
  };
}

function createScanResult(findings: Finding[] = [], overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    findings,
    stats: {
      filesScanned: 10,
      filesSkipped: 2,
      rulesRun: 30,
      duration: 500,
      frameworks: ['express'],
    },
    duration: 500,
    ...overrides,
  };
}

describe('SarifFormatter', () => {
  it('produces valid SARIF JSON', () => {
    const formatter = new SarifFormatter();
    const result = createScanResult([createFinding()]);
    const output = formatter.format(result, '/app');
    const sarif = JSON.parse(output);

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('basesec');
  });

  it('maps severities correctly', () => {
    const formatter = new SarifFormatter();
    const findings: Finding[] = [
      createFinding({ severity: 'critical', ruleId: 'A-001' }),
      createFinding({ severity: 'high', ruleId: 'A-002' }),
      createFinding({ severity: 'medium', ruleId: 'A-003' }),
      createFinding({ severity: 'low', ruleId: 'A-004' }),
      createFinding({ severity: 'info', ruleId: 'A-005' }),
    ];
    const result = createScanResult(findings);
    const output = formatter.format(result, '/app');
    const sarif = JSON.parse(output);

    const levels = sarif.runs[0].results.map((r: any) => r.level);
    expect(levels).toContain('error');
    expect(levels).toContain('warning');
    expect(levels).toContain('note');
  });

  it('ensures line and column are at least 1', () => {
    const formatter = new SarifFormatter();
    const findings: Finding[] = [
      createFinding({ line: 0, column: 0 }),
    ];
    const result = createScanResult(findings);
    const output = formatter.format(result, '/app');
    const sarif = JSON.parse(output);

    const region = sarif.runs[0].results[0].locations[0].physicalLocation.region;
    expect(region.startLine).toBeGreaterThanOrEqual(1);
    expect(region.startColumn).toBeGreaterThanOrEqual(1);
  });

  it('includes endLine only when greater than startLine', () => {
    const formatter = new SarifFormatter();
    const findingsSameLine: Finding[] = [
      createFinding({ line: 5, endLine: 5 }),
    ];
    const findingsMultiLine: Finding[] = [
      createFinding({ line: 5, endLine: 10 }),
    ];

    const result1 = createScanResult(findingsSameLine);
    const output1 = formatter.format(result1, '/app');
    const sarif1 = JSON.parse(output1);
    expect(sarif1.runs[0].results[0].locations[0].physicalLocation.region.endLine).toBeUndefined();

    const result2 = createScanResult(findingsMultiLine);
    const output2 = formatter.format(result2, '/app');
    const sarif2 = JSON.parse(output2);
    expect(sarif2.runs[0].results[0].locations[0].physicalLocation.region.endLine).toBe(10);
  });

  it('deduplicates rules in SARIF output', () => {
    const formatter = new SarifFormatter();
    const findings: Finding[] = [
      createFinding({ ruleId: 'SQLI-001' }),
      createFinding({ ruleId: 'SQLI-001' }),
      createFinding({ ruleId: 'XSS-001' }),
    ];
    const result = createScanResult(findings);
    const output = formatter.format(result, '/app');
    const sarif = JSON.parse(output);

    expect(sarif.runs[0].tool.driver.rules).toHaveLength(2);
  });

  it('handles empty findings', () => {
    const formatter = new SarifFormatter();
    const result = createScanResult([]);
    const output = formatter.format(result, '/app');
    const sarif = JSON.parse(output);

    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });

  it('handles findings with unicode characters', () => {
    const formatter = new SarifFormatter();
    const findings: Finding[] = [
      createFinding({
        message: 'Peligro: inyección SQL en español 中文 日本語',
        filePath: 'fïlë-wïth-ünïcödé.ts',
      }),
    ];
    const result = createScanResult(findings);
    const output = formatter.format(result, '/app');
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('defaults to warning for unknown severity', () => {
    const formatter = new SarifFormatter();
    const findings: Finding[] = [
      createFinding({ severity: 'unknown' as any }),
    ];
    const result = createScanResult(findings);
    const output = formatter.format(result, '/app');
    const sarif = JSON.parse(output);
    expect(sarif.runs[0].results[0].level).toBe('warning');
  });
});