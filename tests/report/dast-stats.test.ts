import { describe, it, expect } from 'vitest';
import { getFormatter } from '../../src/report/formatter';
import type { DastStats, Finding, ScanResult } from '../../src/rules/types';

const DAST_STATS: DastStats = {
  target: 'http://127.0.0.1:3000',
  mode: 'no-source',
  routesSource: 'none',
  routesStale: false,
  readOnly: true,
  agent: false,
  endpoints: { total: 1, analyzed: 1, skippedMutating: 0, unresolved: 0 },
  requests: 7,
};

const DYNAMIC_FINDING: Finding = {
  ruleId: 'DAST-007',
  ruleName: 'Server banner leakage',
  category: 'misconfiguration',
  severity: 'low',
  filePath: '',
  line: 0,
  column: 0,
  endLine: 0,
  endColumn: 0,
  message: 'Response discloses the framework.',
  codeSnippet: 'x-powered-by: Express',
  remediation: 'Remove X-Powered-By.',
  references: [],
  confidence: 'high',
  source: 'dynamic',
  verified: true,
  endpoint: 'http://127.0.0.1:3000',
};

function result(stats: Partial<ScanResult['stats']>, findings: Finding[] = [DYNAMIC_FINDING]): ScanResult {
  return {
    findings,
    duration: 120,
    stats: { filesScanned: 0, filesSkipped: 0, rulesRun: 7, frameworks: [], ...stats },
  };
}

describe('DAST stats in the terminal formatter', () => {
  it('shows the DAST header and no file counters', () => {
    const output = getFormatter('terminal').format(result({ dast: DAST_STATS }), 'http://127.0.0.1:3000');
    expect(output).toContain('mode: no-source');
    expect(output).toContain('7 requests');
    expect(output).toContain('No source code: only headers, cookies and errors');
    expect(output).not.toContain('Files:');
  });

  it('prints the incomplete reason when the analysis was cut', () => {
    const output = getFormatter('terminal').format(
      result({ dast: { ...DAST_STATS, incomplete: 'budget' } }),
      'http://127.0.0.1:3000',
    );
    expect(output).toContain('Incomplete analysis: budget');
  });

  it('says that no runtime issues is not the same as secure when there are no findings', () => {
    const output = getFormatter('terminal').format(result({ dast: DAST_STATS }, []), 'http://127.0.0.1:3000');
    expect(output).toContain('No issues confirmed at runtime (this is not the same as "secure").');
    expect(output).not.toContain('No vulnerabilities found.');
  });

  it('keeps the classic output without stats.dast', () => {
    const output = getFormatter('terminal').format(result({ filesScanned: 4 }, []), '.');
    expect(output).toContain('Files: 4 | Skipped: 0');
    expect(output).toContain('No vulnerabilities found.');
    expect(output).not.toContain('mode:');
  });
});

describe('DAST stats in the structured formatters', () => {
  it('JSON includes stats.dast only when it exists', () => {
    const withDast = JSON.parse(getFormatter('json').format(result({ dast: DAST_STATS }), 'x'));
    expect(withDast.stats.dast).toEqual(DAST_STATS);

    const without = JSON.parse(getFormatter('json').format(result({}), 'x'));
    expect(without.stats).not.toHaveProperty('dast');
  });

  it('SARIF puts stats.dast under runs[0].properties only when it exists', () => {
    const withDast = JSON.parse(getFormatter('sarif').format(result({ dast: DAST_STATS }), 'x'));
    expect(withDast.runs[0].properties.dast).toEqual(DAST_STATS);

    const without = JSON.parse(getFormatter('sarif').format(result({}), 'x'));
    expect(without.runs[0]).not.toHaveProperty('properties');
  });

  it('HTML shows a DAST block and hides file counters', () => {
    const withDast = getFormatter('html').format(result({ dast: DAST_STATS }), 'http://127.0.0.1:3000');
    expect(withDast).toContain('<h3>DAST</h3>');
    expect(withDast).toContain('Mode: <strong>no-source</strong>');
    expect(withDast).not.toContain('Files scanned');

    const without = getFormatter('html').format(result({}, []), 'x');
    expect(without).not.toContain('<h3>DAST</h3>');
    expect(without).toContain('Files scanned');
  });

  it('Markdown shows the DAST mode line instead of file counters', () => {
    const withDast = getFormatter('markdown').format(result({ dast: DAST_STATS }), 'http://127.0.0.1:3000');
    expect(withDast).toContain('**Mode:** no-source');
    expect(withDast).not.toContain('Files Scanned');

    const without = getFormatter('markdown').format(result({}, []), 'x');
    expect(without).toContain('Files Scanned');
    expect(without).not.toContain('**Mode:**');
  });
});
