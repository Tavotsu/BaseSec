import { describe, it, expect } from 'vitest';
import { getFormatter } from '../../src/report/formatter';
import type { Finding, ScanResult } from '../../src/rules/types';

const SAST_FINDING: Finding = {
  ruleId: 'SQLI-001',
  ruleName: 'SQL String Concatenation',
  category: 'sql-injection',
  severity: 'critical',
  filePath: 'src/app.ts',
  line: 10,
  column: 3,
  endLine: 10,
  endColumn: 40,
  message: 'Concatenated SQL query',
  codeSnippet: 'db.query("SELECT * FROM users WHERE id = " + id)',
  remediation: 'Use parameterized queries.',
  references: ['https://cwe.mitre.org/data/definitions/89.html'],
  confidence: 'high',
};

const ENDPOINT_FINDING: Finding = {
  ruleId: 'DAST-006',
  ruleName: 'Stack trace exposed',
  category: 'error-handling',
  severity: 'high',
  filePath: '/app/routes/users.ts',
  line: 10,
  column: 1,
  endLine: 20,
  endColumn: 1,
  message: 'Server responded HTTP 500 with a stack trace exposing internal file paths.',
  codeSnippet: 'at Object.<anonymous> (/srv/app/routes/users.js:10:5)',
  remediation: 'Do not return error stacks to clients.',
  references: ['https://cwe.mitre.org/data/definitions/209.html'],
  confidence: 'high',
  source: 'dynamic',
  verified: true,
  endpoint: 'GET /api/users/:id',
};

const RESULT: ScanResult = {
  findings: [SAST_FINDING, ENDPOINT_FINDING],
  stats: {
    filesScanned: 0,
    filesSkipped: 0,
    rulesRun: 8,
    frameworks: [],
    dast: {
      target: 'http://127.0.0.1:3000',
      mode: 'full',
      routesSource: 'routes-file',
      routesStale: false,
      readOnly: true,
      agent: false,
      endpoints: { total: 2, analyzed: 2, skippedMutating: 0, unresolved: 0 },
      requests: 4,
    },
  },
  duration: 500,
};

const ONLY_SAST: ScanResult = { ...RESULT, findings: [SAST_FINDING], stats: { ...RESULT.stats, dast: undefined } };

describe('endpoint location of a dynamic finding with a handler file', () => {
  it('shows File and then Endpoint in the terminal', () => {
    const output = getFormatter('terminal').format(RESULT, './src');
    const file = output.indexOf('File: /app/routes/users.ts:10');
    const endpoint = output.indexOf('Endpoint: GET /api/users/:id');

    expect(file).toBeGreaterThan(-1);
    expect(endpoint).toBeGreaterThan(file);
  });

  it('shows **File:** and then **Endpoint:** in Markdown', () => {
    const markdown = getFormatter('markdown').format(RESULT, './src');
    const file = markdown.indexOf('**File:** `/app/routes/users.ts:10`');
    const endpoint = markdown.indexOf('**Endpoint:** `GET /api/users/:id`');

    expect(file).toBeGreaterThan(-1);
    expect(endpoint).toBeGreaterThan(file);
  });

  it('adds an Endpoint row after the File row in HTML', () => {
    const html = getFormatter('html').format(RESULT, './src');
    expect(html).toContain('<strong>File:</strong></td><td><code>/app/routes/users.ts:10:1</code></td></tr>');
    expect(html).toContain('<strong>Endpoint:</strong></td><td><code>GET /api/users/:id</code></td></tr>');
    expect(html.indexOf('<strong>Endpoint:</strong>')).toBeGreaterThan(html.indexOf('<strong>File:</strong>'));
  });
});

describe('a static finding without endpoint', () => {
  it('keeps the File line and shows no Endpoint in the terminal', () => {
    const output = getFormatter('terminal').format(ONLY_SAST, './src');
    expect(output).toContain('    File: src/app.ts:10');
    expect(output).not.toContain('Endpoint');
  });

  it('keeps the File line and shows no Endpoint in Markdown and HTML', () => {
    expect(getFormatter('markdown').format(ONLY_SAST, './src')).toContain('**File:** `src/app.ts:10`');
    expect(getFormatter('markdown').format(ONLY_SAST, './src')).not.toContain('**Endpoint:**');
    expect(getFormatter('html').format(ONLY_SAST, './src')).not.toContain('Endpoint:');
  });
});
