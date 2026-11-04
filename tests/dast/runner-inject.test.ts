import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFile } from 'node:child_process';
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createVulnerableApp } from '../fixtures/vulnerable-app/server.mjs';
import { runDast } from '../../src/dast/runner';
import type { LoadedSurface } from '../../src/dast/surface';
import type { ExtractedRoute, RouteArtifact, RouteParam } from '../../src/framework/routes/types';

const APP_ROOT = path.join(os.tmpdir(), 'basesec-runner-inject-app');
const TOKEN = 'SECRETTOKEN123';

const app = createVulnerableApp();
let origin: string;

beforeAll(async () => {
  origin = await app.start();
});

afterAll(async () => {
  await app.stop();
});

beforeEach(() => {
  app.requests.length = 0;
  app.reset();
});

function route(method: string, routePath: string, params: RouteParam[]): ExtractedRoute {
  return {
    method,
    path: routePath,
    framework: 'express',
    filePath: `src${routePath.replace(/[^a-z]/gi, '_')}.ts`,
    line: 1,
    endLine: 5,
    hasAuth: false,
    params,
    reachableFiles: [],
    staticFindings: [],
  };
}

function surfaceOf(routes: ExtractedRoute[]): LoadedSurface {
  const artifact: RouteArtifact = {
    version: 1,
    generatedAt: '2026-08-02T10:00:00.000Z',
    target: APP_ROOT,
    frameworks: ['express'],
    routes,
    unresolved: [],
  };
  return { artifact, source: 'routes-file', stale: false };
}

const VULNERABLE_ROUTES: ExtractedRoute[] = [
  route('GET', '/users', [{ name: 'id', in: 'query' }]),
  route('GET', '/search', [{ name: 'q', in: 'query' }]),
  route('GET', '/safe', [{ name: 'q', in: 'query' }]),
  route('GET', '/file', [{ name: 'name', in: 'query' }]),
  route('GET', '/go', [{ name: 'url', in: 'query' }]),
  route('GET', '/items', [{ name: 'role', in: 'query' }]),
];

describe('runDast injection over a surface', () => {
  it('finds SQLi, XSS, path traversal, NoSQLi and open redirect in the fixture', async () => {
    const result = await runDast({
      url: origin,
      surface: surfaceOf(VULNERABLE_ROUTES),
      evidence: false,
      injectionDelaySeconds: 1,
    });
    const injected = result.findings.filter((f) => /^DAST-(1\d\d|011)$/.test(f.ruleId));
    const ids = new Set(injected.map((f) => `${f.ruleId} ${f.endpoint}`));

    expect(ids).toContain('DAST-101 GET /users');
    expect(ids).toContain('DAST-105 GET /search');
    expect(ids).toContain('DAST-104 GET /file');
    expect(ids).toContain('DAST-011 GET /go');
    expect(ids).toContain('DAST-102 GET /items');
    expect(injected.some((f) => f.endpoint === 'GET /safe')).toBe(false);
    expect(result.stats.dast?.endpoints.attacked).toBeGreaterThan(0);
    expect(result.stats.dast?.incomplete).toBeUndefined();
  }, 60000);

  it('sends no payload at all in no-source mode (only the root and the healthcheck)', async () => {
    const result = await runDast({ url: origin, evidence: false, injectionDelaySeconds: 1 });

    expect(result.stats.dast?.mode).toBe('no-source');
    expect(app.requests.length).toBeGreaterThan(0);
    expect(app.requests.every((request) => request === 'GET /')).toBe(true);
    expect(result.findings.some((f) => /^DAST-(1\d\d|011)$/.test(f.ruleId))).toBe(false);
  });

  it('with --rules DAST-105 attacks only the XSS check', async () => {
    const result = await runDast({
      url: origin,
      surface: surfaceOf(VULNERABLE_ROUTES),
      rules: ['DAST-105'],
      evidence: false,
      injectionDelaySeconds: 1,
    });

    expect(result.findings.map((f) => f.ruleId)).toEqual(['DAST-105']);
    // La clase XSS corre en todos los endpoints con parámetros; ninguna otra clase envía payloads.
    expect(app.requests.some((r) => r.includes('onerror'))).toBe(true);
    expect(app.requests.some((r) => r.includes('passwd') || r.includes('win.ini'))).toBe(false);
    expect(app.requests.some((r) => r.includes('example.net'))).toBe(false);
    expect(app.requests.some((r) => /sleep/i.test(r))).toBe(false);
  });

  it('accepts injection rule IDs in --rules without calling them unknown', async () => {
    await expect(
      runDast({ url: origin, surface: surfaceOf(VULNERABLE_ROUTES), rules: ['DAST-101'], evidence: false }),
    ).resolves.toBeDefined();
  });

  it('marks the analysis incomplete when the request budget runs out during injection', async () => {
    const result = await runDast({
      url: origin,
      surface: surfaceOf(VULNERABLE_ROUTES),
      maxRequests: 8,
      evidence: false,
      injectionDelaySeconds: 1,
    });

    expect(result.stats.dast?.incomplete).toBe('budget');
    expect(result.stats.dast?.requests).toBeLessThanOrEqual(8);
  });
});

describe('runDast injection evidence', () => {
  let evidenceBase: string;

  beforeAll(() => {
    evidenceBase = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-inject-evidence-'));
  });

  afterAll(() => {
    fs.rmSync(evidenceBase, { recursive: true, force: true });
  });

  it('writes the payload and oracle into the evidence and never the known secrets', async () => {
    const result = await runDast({
      url: origin,
      surface: surfaceOf([route('GET', '/users', [{ name: 'id', in: 'query' }])]),
      headers: { Authorization: `Bearer ${TOKEN}` },
      evidenceDir: evidenceBase,
      rules: ['DAST-101'],
      injectionDelaySeconds: 1,
    });
    const finding = result.findings.find((f) => f.ruleId === 'DAST-101');

    expect(finding).toBeDefined();
    expect(finding?.evidence?.payload).toContain("'");
    expect(finding?.evidence?.oracle).toBe('sql-error');
    expect(JSON.stringify(finding)).not.toContain(TOKEN);

    const file = finding?.evidence?.file;
    expect(file).toBeDefined();
    const content = fs.readFileSync(file as string, 'utf-8');
    expect(content).toContain('# payload (sql-error):');
    expect(content).toContain('/users?id=');
    expect(content).not.toContain(TOKEN);
    expect(content).toMatch(/authorization: \[REDACTED\]/i);
  });
});

describe('runDast injection: secrets, delay cap and clean shutdown', () => {
  let evidenceBase: string;

  beforeAll(() => {
    evidenceBase = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-inject-leak-'));
  });

  afterAll(() => {
    fs.rmSync(evidenceBase, { recursive: true, force: true });
  });

  it('does not carry a known secret into the evidence when the server reflects the payload and the auth header', async () => {
    const result = await runDast({
      url: origin,
      surface: surfaceOf([route('GET', '/reflect', [{ name: 'q', in: 'query' }])]),
      headers: { Authorization: `Bearer ${TOKEN}`, 'X-Custom': 'topsecretvalue99' },
      evidenceDir: evidenceBase,
      rules: ['DAST-105'],
    });
    const finding = result.findings.find((f) => f.ruleId === 'DAST-105');

    expect(finding).toBeDefined();
    expect(finding?.evidence?.payload).toMatch(/BS[0-9a-f]{8}/);
    expect(JSON.stringify(result)).not.toContain(TOKEN);
    expect(JSON.stringify(result)).not.toContain('topsecretvalue99');

    const content = fs.readFileSync(finding?.evidence?.file as string, 'utf-8');
    expect(content).toContain('# payload (reflection):');
    // La respuesta SÍ reflejó el payload y la cabecera: el canario se conserva y el secreto no.
    expect(content).toMatch(/<img src=x onerror=alert\(BS[0-9a-f]{8}\)/);
    expect(content).toContain('auth: ');
    expect(content).not.toContain(TOKEN);
    expect(content).not.toContain('topsecretvalue99');
    expect(content).toMatch(/authorization: \[REDACTED\]/i);
    expect(content).toMatch(/x-custom: \[REDACTED\]/i);
  });

  it('tops the delay at 2 seconds even when injectionDelaySeconds is huge', async () => {
    const result = await runDast({
      url: origin,
      surface: surfaceOf([route('GET', '/ping', [{ name: 'host', in: 'query' }])]),
      rules: ['DAST-103'],
      evidence: false,
      injectionDelaySeconds: 9999,
    });

    const sleeps = app.requests.flatMap((request) =>
      [...decodeURIComponent(request).matchAll(/sleep[( ](\d+)/gi)].map((match) => Number(match[1])),
    );
    expect(sleeps.length).toBeGreaterThan(0);
    expect(Math.max(...sleeps)).toBe(2);
    expect(result.findings.some((f) => f.ruleId === 'DAST-103')).toBe(true);
  }, 60000);

  it('lets a process with a slow server and a tiny budget exit by itself (no timer or socket left alive)', async () => {
    const script = path.join(__dirname, '..', 'fixtures', 'vulnerable-app', 'stress-run.ts');
    const started = Date.now();
    const output = await new Promise<string>((resolve, reject) => {
      execFile(
        process.execPath,
        ['--import', 'tsx', script],
        { cwd: path.join(__dirname, '..', '..'), timeout: 40000 },
        (error, stdout) => (error ? reject(error) : resolve(stdout)),
      );
    });
    const summary = JSON.parse(output.trim().split('\n').pop() as string) as { incomplete?: string; requests?: number };

    expect(summary.incomplete).toBe('budget');
    expect(summary.requests).toBeLessThanOrEqual(2);
    expect(Date.now() - started).toBeLessThan(30000);
  }, 60000);
});
