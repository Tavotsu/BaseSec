import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, afterEach } from 'vitest';
import { DastConfigError, expandEnvHeaders, parseHeaderFlag } from '../../src/dast/config';
import { loadConfig } from '../../src/config/loader';

const ENV = { API_TOKEN: 'tok-123456', SECOND: 'second-value', EMPTY: '' } as NodeJS.ProcessEnv;

describe('expandEnvHeaders', () => {
  it('replaces a whole value with a simple $env: reference', () => {
    expect(expandEnvHeaders({ 'X-Api-Key': '$env:API_TOKEN' }, ENV)).toEqual({ 'X-Api-Key': 'tok-123456' });
  });

  it('replaces several references in one value', () => {
    expect(expandEnvHeaders({ 'X-Pair': '$env:API_TOKEN/$env:SECOND' }, ENV)).toEqual({
      'X-Pair': 'tok-123456/second-value',
    });
  });

  it('replaces a reference inside a longer value', () => {
    expect(expandEnvHeaders({ Authorization: 'Bearer $env:API_TOKEN' }, ENV)).toEqual({
      Authorization: 'Bearer tok-123456',
    });
  });

  it('leaves values without references untouched', () => {
    expect(expandEnvHeaders({ Accept: 'application/json' }, ENV)).toEqual({ Accept: 'application/json' });
  });

  it('throws naming the variable, never the value, when it does not exist', () => {
    let caught: unknown;
    try {
      expandEnvHeaders({ Authorization: 'Bearer $env:MISSING_TOKEN_VAR' }, ENV);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(DastConfigError);
    const message = (caught as Error).message;
    expect(message).toContain('MISSING_TOKEN_VAR');
    expect(message).not.toContain('tok-123456');
    expect(message).not.toContain('$env:MISSING_TOKEN_VAR');
  });

  it('throws when the variable is empty', () => {
    expect(() => expandEnvHeaders({ Authorization: '$env:EMPTY' }, ENV)).toThrow(DastConfigError);
    expect(() => expandEnvHeaders({ Authorization: '$env:EMPTY' }, ENV)).toThrow(/EMPTY/);
  });

  it('rejects a header name that is not an HTTP token', () => {
    expect(() => expandEnvHeaders({ 'bad name': 'x' }, ENV)).toThrow(DastConfigError);
  });

  it('rejects a value that would inject a header line', () => {
    expect(() => expandEnvHeaders({ 'X-A': 'a\r\nX-Injected: b' }, ENV)).toThrow(DastConfigError);
  });
});

describe('parseHeaderFlag', () => {
  it('parses "Name: value" and trims both sides', () => {
    expect(parseHeaderFlag('Authorization:   Bearer abc  ')).toEqual(['Authorization', 'Bearer abc']);
  });

  it('keeps colons that belong to the value', () => {
    expect(parseHeaderFlag('X-Time: 10:30')).toEqual(['X-Time', '10:30']);
  });

  it('rejects a value without a colon', () => {
    expect(() => parseHeaderFlag('Authorization Bearer abc')).toThrow(DastConfigError);
  });

  it('rejects an invalid header name', () => {
    expect(() => parseHeaderFlag('bad name: value')).toThrow(DastConfigError);
  });

  it('rejects a value with CR or LF', () => {
    expect(() => parseHeaderFlag('X-A: one\r\nX-B: two')).toThrow(DastConfigError);
    expect(() => parseHeaderFlag('X-A: one\nX-B: two')).toThrow(DastConfigError);
  });

  it('does not echo the raw value in the error message', () => {
    try {
      parseHeaderFlag('sk-secret-value-without-colon');
      expect.unreachable('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(DastConfigError);
      expect((e as Error).message).not.toContain('sk-secret-value-without-colon');
    }
  });
});

describe('dast section of the config file', () => {
  const tmpDirs: string[] = [];

  afterEach(() => {
    for (const dir of tmpDirs.splice(0)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('copies only fields of the right type and ignores the rest', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-dast-cfg-'));
    tmpDirs.push(dir);
    const file = path.join(dir, 'config.json');
    fs.writeFileSync(
      file,
      JSON.stringify({
        dast: {
          target: 'http://127.0.0.1:3000',
          health: '/health',
          allowRemote: 'yes',
          rps: 10,
          concurrency: -1,
          maxRequests: '5000',
          timeout: 60,
          requestTimeout: 0,
          evidence: false,
          evidenceDir: '/tmp/evidence',
          rules: ['DAST-001', 42],
          headers: { Authorization: 'Bearer $env:API_TOKEN', Bad: 1 },
          unknownField: true,
        },
      }),
    );

    const config = loadConfig(file, dir);

    expect(config.dast).toEqual({
      target: 'http://127.0.0.1:3000',
      health: '/health',
      rps: 10,
      timeout: 60,
      evidence: false,
      evidenceDir: '/tmp/evidence',
      headers: { Authorization: 'Bearer $env:API_TOKEN' },
    });
  });
});

describe('header injection hardening', () => {
  it('rejects a CR/LF that appears only after $env: expansion', () => {
    const env = { INJECTED: 'good\r\nX-Evil: 1', LATIN: 'café', WIDE: 'snow☃man' } as NodeJS.ProcessEnv;
    expect(() => expandEnvHeaders({ 'X-Token': '$env:INJECTED' }, env)).toThrow(DastConfigError);
    expect(() => expandEnvHeaders({ 'X-Token': '$env:WIDE' }, env)).toThrow(DastConfigError);
    expect(expandEnvHeaders({ 'X-Token': '$env:LATIN' }, env)).toEqual({ 'X-Token': 'café' });
  });

  it('never puts the expanded value in the error of a rejected header', () => {
    const env = { INJECTED: 'SUPERSECRET\r\nX-Evil: 1' } as NodeJS.ProcessEnv;
    try {
      expandEnvHeaders({ 'X-Token': '$env:INJECTED' }, env);
      expect.unreachable();
    } catch (e) {
      expect((e as Error).message).not.toContain('SUPERSECRET');
    }
  });

  it('rejects control characters and CR/LF in config header names and values', () => {
    expect(() => expandEnvHeaders({ 'X-A\r\nB': 'v' }, ENV)).toThrow(DastConfigError);
    expect(() => expandEnvHeaders({ 'X-A': 'v\nw' }, ENV)).toThrow(DastConfigError);
    expect(() => expandEnvHeaders({ 'X-A': 'v\u0000w' }, ENV)).toThrow(DastConfigError);
  });

  it('parseHeaderFlag rejects CR/LF in the name and the value', () => {
    expect(() => parseHeaderFlag('X-A\r\nEvil: v')).toThrow(DastConfigError);
    expect(() => parseHeaderFlag('X-A: v\r\nEvil: 1')).toThrow(DastConfigError);
  });
});

describe('dast.publicRoutes and dast.probeRateLimit', () => {
  const tmpDirs: string[] = [];
  afterEach(() => {
    for (const dir of tmpDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  it('keeps only string patterns and a boolean probe flag', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-dast-cfg-'));
    tmpDirs.push(dir);
    const file = path.join(dir, 'config.json');
    fs.writeFileSync(
      file,
      JSON.stringify({
        dast: {
          publicRoutes: ['/api/*/status', 42, '/docs'],
          probeRateLimit: true,
        },
      }),
    );

    const config = loadConfig(file, dir);

    expect(config.dast).toEqual({ publicRoutes: ['/api/*/status', '/docs'], probeRateLimit: true });
  });

  it('ignores a non-array publicRoutes and a non-boolean probeRateLimit', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-dast-cfg-'));
    tmpDirs.push(dir);
    const file = path.join(dir, 'config.json');
    fs.writeFileSync(file, JSON.stringify({ dast: { publicRoutes: '/docs', probeRateLimit: 'yes' } }));

    const config = loadConfig(file, dir);

    expect(config.dast).toEqual({});
  });
});
