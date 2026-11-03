import { describe, it, expect } from 'vitest';
import { getFormatter } from '../../src/report/formatter';
import type { Finding, ScanResult } from '../../src/rules/types';

const STATIC_FINDING: Finding = {
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

const DYNAMIC_FINDING: Finding = {
  ruleId: 'DAST-001',
  ruleName: 'Missing security headers',
  category: 'misconfiguration',
  severity: 'medium',
  filePath: '',
  line: 0,
  column: 0,
  endLine: 0,
  endColumn: 0,
  message: 'HTML response is missing security headers: Referrer-Policy.',
  codeSnippet: 'content-type: text/html',
  remediation: 'Add Referrer-Policy.',
  references: ['https://cwe.mitre.org/data/definitions/693.html'],
  confidence: 'high',
  source: 'dynamic',
  verified: true,
  endpoint: 'http://localhost:3000',
  evidence: {
    request: 'GET http://localhost:3000/<script>alert(1)</script>',
    response: 'HTTP 200\ncontent-type: text/html',
    payload: '',
    oracle: 'header',
  },
};

const RESULT: ScanResult = {
  findings: [STATIC_FINDING, DYNAMIC_FINDING],
  stats: { filesScanned: 4, filesSkipped: 0, rulesRun: 9, frameworks: ['express'] },
  duration: 800,
};

describe('DAST output in SARIF', () => {
  const sarif = JSON.parse(getFormatter('sarif').format(RESULT, '/app'));
  const [staticResult, dynamicResult] = sarif.runs[0].results;

  it('keeps physicalLocation for the static finding', () => {
    expect(staticResult.locations[0].physicalLocation.artifactLocation.uri).toBe('src/app.ts');
    expect(staticResult.properties).toBeUndefined();
  });

  it('uses logicalLocations and no physicalLocation for the target-level finding', () => {
    expect(dynamicResult.locations[0].physicalLocation).toBeUndefined();
    expect(dynamicResult.locations[0].logicalLocations).toEqual([
      { fullyQualifiedName: 'http://localhost:3000', kind: 'resource' },
    ]);
  });

  it('marks the dynamic finding as verified with its endpoint', () => {
    expect(dynamicResult.properties.verified).toBe(true);
    expect(dynamicResult.properties.endpoint).toBe('http://localhost:3000');
  });
});

describe('DAST output in terminal', () => {
  const output = getFormatter('terminal').format(RESULT, './src');

  it('shows the endpoint and the verified marker for the dynamic finding', () => {
    expect(output).toContain('Endpoint: http://localhost:3000');
    expect(output).toContain('VERIFIED');
  });

  it('keeps the file location for the static finding', () => {
    expect(output).toContain('File: src/app.ts:10');
  });
});

describe('DAST output in HTML', () => {
  const html = getFormatter('html').format(RESULT, './src');

  it('escapes evidence values taken from the server', () => {
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).not.toContain('<script>alert(1)</script>');
  });

  it('shows the endpoint and the verified badge', () => {
    expect(html).toContain('http://localhost:3000');
    expect(html).toContain('Verified (runtime)');
  });
});

describe('DAST output in Markdown', () => {
  const markdown = getFormatter('markdown').format(RESULT, './src');

  it('uses Endpoint for the target-level finding and File for the static one', () => {
    expect(markdown).toContain('**Endpoint:** `http://localhost:3000`');
    expect(markdown).toContain('**File:** `src/app.ts:10`');
  });

  it('marks the dynamic finding as verified and includes its evidence', () => {
    expect(markdown).toContain('**Verified:** runtime');
    expect(markdown).toContain('**Evidence:**');
  });
});

describe('hostile server data in reports', () => {
  const XSS = '<img src=x onerror=alert(1)>';
  const hostile: ScanResult = {
    ...RESULT,
    findings: [
      {
        ...DYNAMIC_FINDING,
        endpoint: `GET /${XSS}`,
        codeSnippet: `x-powered-by: ${XSS}`,
        evidence: {
          request: `GET http://localhost:3000/${XSS}`,
          response: `HTTP 200\nx-evil: ${XSS}\nx-fence: \`\`\`\n# injected heading`,
          payload: '',
          oracle: 'header',
        },
      },
    ],
  };

  it('escapes the endpoint and all evidence in HTML', () => {
    const html = getFormatter('html').format(hostile, './src');
    expect(html).not.toContain(XSS);
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('cannot break out of the evidence fence in Markdown', () => {
    const markdown = getFormatter('markdown').format(hostile, './src');
    const start = markdown.indexOf('```http');
    const end = markdown.indexOf('\n```\n', start + 7);
    const block = markdown.slice(start + 7, end);
    expect(block).toContain('x-fence:');
    expect(block).not.toMatch(/(^|[^\\])```/);
  });

  it('does not let a backtick in the endpoint close the Markdown code span', () => {
    const result: ScanResult = { ...RESULT, findings: [{ ...DYNAMIC_FINDING, endpoint: 'GET /a`b' }] };
    expect(getFormatter('markdown').format(result, './src')).toContain('**Endpoint:** `GET /a\'b`');
  });
});

describe('findings without the new fields keep their previous output', () => {
  it('emits no dynamic markers for a static finding in any format', () => {
    const only: ScanResult = { ...RESULT, findings: [STATIC_FINDING] };
    expect(getFormatter('terminal').format(only, './src')).not.toMatch(/Endpoint|VERIFIED/);
    expect(getFormatter('html').format(only, './src')).not.toMatch(/Endpoint|Verified|<details/);
    expect(getFormatter('markdown').format(only, './src')).not.toMatch(/Endpoint|Verified|Evidence/);
    const sarif = JSON.parse(getFormatter('sarif').format(only, '/app'));
    expect(sarif.runs[0].results[0].properties).toBeUndefined();
    expect(sarif.runs[0].results[0].locations[0].logicalLocations).toBeUndefined();
  });
});
