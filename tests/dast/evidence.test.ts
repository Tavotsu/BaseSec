import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createEvidenceWriter } from '../../src/dast/evidence';
import type { DastObservation } from '../../src/dast/types';
import type { Finding } from '../../src/rules/types';

const KNOWN_SECRET = 'sekret-known-value-42';
const COOKIE_VALUE = 'cookievalue987654';

let baseDir: string;

function observation(): DastObservation {
  return {
    endpoint: 'GET /',
    url: 'http://127.0.0.1:3000/',
    method: 'GET',
    requestHeaders: { 'x-custom-auth': KNOWN_SECRET, Accept: 'text/html' },
    response: {
      status: 200,
      headers: {
        'content-type': 'text/html',
        'set-cookie': [`sid=${COOKIE_VALUE}; Path=/`],
      },
      body: `<html>\u001b[31mred\u001b[0m token=${KNOWN_SECRET}</html>`,
      contentEncoding: null,
      bodyDecoded: true,
      url: 'http://127.0.0.1:3000/',
      redirects: [],
      timedOut: false,
      elapsedMs: 3,
    },
  };
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'DAST-005',
    ruleName: 'Insecure cookie flags',
    category: 'misconfiguration',
    severity: 'high',
    filePath: '',
    line: 0,
    column: 0,
    endLine: 0,
    endColumn: 0,
    message: 'Cookie without flags',
    codeSnippet: 'set-cookie: sid=[REDACTED]; Path=/',
    remediation: 'Set HttpOnly.',
    references: [],
    confidence: 'high',
    source: 'dynamic',
    verified: true,
    endpoint: 'http://127.0.0.1:3000',
    evidence: {
      request: 'GET http://127.0.0.1:3000/',
      response: 'HTTP 200',
      payload: '',
      oracle: 'header',
    },
    ...overrides,
  };
}

function readAll(dir: string): string[] {
  return fs.readdirSync(dir).flatMap((entry) => {
    const full = path.join(dir, entry);
    return fs.statSync(full).isDirectory() ? readAll(full) : [full];
  });
}

describe('createEvidenceWriter', () => {
  beforeEach(() => {
    baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-evidence-'));
  });

  afterEach(() => {
    fs.rmSync(baseDir, { recursive: true, force: true });
  });

  it('does not create the directory when nothing is written', () => {
    const writer = createEvidenceWriter(baseDir);
    expect(fs.readdirSync(baseDir)).toEqual([]);
    expect(writer.dir.startsWith(baseDir)).toBe(true);
    expect(fs.existsSync(writer.dir)).toBe(false);
  });

  it('creates the directory with mode 0700 and the file with mode 0600', () => {
    const writer = createEvidenceWriter(baseDir);
    const filePath = writer.write(finding(), observation(), [KNOWN_SECRET]);

    expect(filePath).toBeDefined();
    if (process.platform !== 'win32') {
      expect(fs.statSync(writer.dir).mode & 0o777).toBe(0o700);
      expect(fs.statSync(filePath!).mode & 0o777).toBe(0o600);
    }
  });

  it('names the file after the rule and never overwrites an existing one', () => {
    const writer = createEvidenceWriter(baseDir);
    const first = writer.write(finding(), observation(), [KNOWN_SECRET]);
    const second = writer.write(finding(), observation(), [KNOWN_SECRET]);

    expect(first).toBeDefined();
    expect(second).toBeDefined();
    expect(first).not.toBe(second);
    expect(path.basename(first!)).toMatch(/^DAST-005-[0-9a-f]{8}\.http$/);
    expect(path.basename(second!)).toMatch(/^DAST-005-[0-9a-f]{8}-2\.http$/);
    expect(fs.readdirSync(writer.dir)).toHaveLength(2);
  });

  it('redacts cookies and known secrets and removes control characters', () => {
    const writer = createEvidenceWriter(baseDir);
    const filePath = writer.write(finding(), observation(), [KNOWN_SECRET]);
    const content = fs.readFileSync(filePath!, 'utf-8');

    expect(content).toContain('GET http://127.0.0.1:3000/ HTTP/1.1');
    expect(content).toContain('HTTP/1.1 200');
    expect(content).not.toContain(COOKIE_VALUE);
    expect(content).not.toContain(KNOWN_SECRET);
    expect(content).not.toContain('\u001b');
    expect(content).toContain('sid=[REDACTED]');
  });

  it('keeps no secret in any file written to the directory', () => {
    const writer = createEvidenceWriter(baseDir);
    writer.write(finding(), observation(), [KNOWN_SECRET]);
    for (const file of readAll(writer.dir)) {
      const content = fs.readFileSync(file, 'utf-8');
      expect(content).not.toContain(COOKIE_VALUE);
      expect(content).not.toContain(KNOWN_SECRET);
    }
  });
});

describe('createEvidenceWriter hardening', () => {
  beforeEach(() => {
    baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-evidence-'));
  });

  afterEach(() => {
    fs.rmSync(baseDir, { recursive: true, force: true });
  });

  it.skipIf(process.platform === 'win32')('tightens an existing directory with lax permissions to 0700', () => {
    const writer = createEvidenceWriter(baseDir);
    fs.mkdirSync(writer.dir, { mode: 0o755 });
    fs.chmodSync(writer.dir, 0o755);

    const filePath = writer.write(finding(), observation(), [KNOWN_SECRET]);

    expect(filePath).toBeDefined();
    expect(fs.statSync(writer.dir).mode & 0o777).toBe(0o700);
  });

  it.skipIf(process.platform === 'win32')('does not write through a symlink planted as the evidence directory', () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-evidence-outside-'));
    try {
      const writer = createEvidenceWriter(baseDir);
      fs.symlinkSync(outside, writer.dir);

      expect(writer.write(finding(), observation(), [KNOWN_SECRET])).toBeUndefined();
      expect(fs.readdirSync(outside)).toEqual([]);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  it.skipIf(process.platform === 'win32')('does not write through a symlink planted as the evidence file', () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-evidence-outside-'));
    try {
      const writer = createEvidenceWriter(baseDir);
      const first = writer.write(finding(), observation(), [KNOWN_SECRET]);
      const target = path.join(outside, 'victim.txt');
      fs.writeFileSync(target, 'ORIGINAL');
      fs.rmSync(first!);
      fs.symlinkSync(target, first!);

      const second = writer.write(finding(), observation(), [KNOWN_SECRET]);

      expect(second).toBeDefined();
      expect(second).not.toBe(first);
      expect(fs.readFileSync(target, 'utf-8')).toBe('ORIGINAL');
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  it('resolves a relative base directory to an absolute path', () => {
    const relative = path.relative(process.cwd(), baseDir);
    const writer = createEvidenceWriter(relative);
    expect(path.isAbsolute(writer.dir)).toBe(true);
    expect(writer.dir.startsWith(baseDir)).toBe(true);
  });

  it('hides a user header value entirely, even under a harmless name, and masks it in the body', () => {
    const secret = 'abcdefghij-user-secret';
    const obs = observation();
    obs.requestHeaders = { 'x-tenant': secret, Origin: 'https://bs-1234.invalid' };
    obs.response.body = `echo ${secret}`;
    const writer = createEvidenceWriter(baseDir);
    const content = fs.readFileSync(writer.write(finding(), obs, [secret])!, 'utf-8');

    expect(content).not.toContain(secret);
    expect(content).not.toContain('abcdef');
    expect(content).toContain('Origin: https://bs-1234.invalid');
  });
});
