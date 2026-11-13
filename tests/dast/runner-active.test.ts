import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { createVulnerableApp } from '../fixtures/vulnerable-app/server.mjs';
import { runDast } from '../../src/dast/runner';
import type { LoadedSurface } from '../../src/dast/surface';
import type { ExtractedRoute, RouteArtifact } from '../../src/framework/routes/types';

const APP_ROOT = path.join(os.tmpdir(), 'basesec-runner-active-app');
const TOKEN = 'SECRETTOKEN123';

const app = createVulnerableApp();
let origin: string;
let evidenceRoot: string;

beforeAll(async () => {
  origin = await app.start();
});

afterAll(async () => {
  await app.stop();
});

beforeEach(() => {
  app.requests.length = 0;
  app.reset();
  evidenceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-runner-active-evidence-'));
});

afterEach(() => {
  fs.rmSync(evidenceRoot, { recursive: true, force: true });
});

function route(method: string, routePath: string, overrides: Partial<ExtractedRoute> = {}): ExtractedRoute {
  return {
    method,
    path: routePath,
    framework: 'express',
    filePath: `src${routePath.replace(/[^a-z]/gi, '_')}.ts`,
    line: 1,
    endLine: 5,
    hasAuth: false,
    params: [],
    reachableFiles: [],
    staticFindings: [],
    ...overrides,
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

const SURFACE = surfaceOf([
  route('GET', '/admin'),
  route('GET', '/admin/guarded'),
  route('GET', '/profile'),
  route('GET', '/login'),
]);

describe('runDast with a surface runs DAST-008 and DAST-010', () => {
  it('the default run reports DAST-008 on /admin over the fixture', async () => {
    const result = await runDast({ url: origin, surface: SURFACE, evidence: false });
    const endpoints = result.findings.filter((finding) => finding.ruleId === 'DAST-008').map((finding) => finding.endpoint);
    expect(endpoints).toContain('GET /admin');
    expect(endpoints).not.toContain('GET /admin/guarded');
    expect(endpoints).not.toContain('GET /profile');
  });

  it('--rules DAST-008 runs only that check', async () => {
    const result = await runDast({ url: origin, surface: SURFACE, rules: ['DAST-008'], evidence: false });
    const ruleIds = new Set(result.findings.map((finding) => finding.ruleId));
    expect([...ruleIds]).toEqual(['DAST-008']);
    expect(result.stats.rulesRun).toBe(1);
  });

  it('--probe-rate-limit activates DAST-010 on the login route of the surface', async () => {
    const result = await runDast({
      url: origin,
      surface: SURFACE,
      rules: ['DAST-010'],
      probeRateLimit: true,
      evidence: false,
    });
    const findings = result.findings.filter((finding) => finding.ruleId === 'DAST-010');
    expect(findings).toHaveLength(1);
    expect(findings[0].endpoint).toBe('GET /login');
    expect(app.requests.filter((request) => request === 'GET /login')).toHaveLength(31);
  });

  it('the probe stays off by default even with a surface', async () => {
    const result = await runDast({ url: origin, surface: SURFACE, rules: ['DAST-010'], evidence: false });
    expect(result.findings.filter((finding) => finding.ruleId === 'DAST-010')).toHaveLength(0);
    expect(app.requests.filter((request) => request === 'GET /login')).toHaveLength(1);
  });

  it('the evidence of DAST-008 never carries the user credential', async () => {
    const result = await runDast({
      url: origin,
      surface: surfaceOf([route('GET', '/admin')]),
      headers: { Authorization: `Bearer ${TOKEN}` },
      rules: ['DAST-008'],
      evidenceDir: evidenceRoot,
    });
    const finding = result.findings.find((item) => item.ruleId === 'DAST-008');
    expect(finding?.evidence?.file).toBeDefined();
    const content = fs.readFileSync(finding!.evidence!.file!, 'utf-8');
    expect(content).not.toContain(TOKEN);
    expect(content).toContain(`GET ${origin}/admin HTTP/1.1`);
    expect(content).toContain('HTTP/1.1 200');
  });
});
