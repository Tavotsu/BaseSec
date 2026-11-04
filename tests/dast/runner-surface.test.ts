import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import type { AddressInfo } from 'node:net';
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { resolveEndpointUrl, runDast } from '../../src/dast/runner';
import type { LoadedSurface } from '../../src/dast/surface';
import type { ExtractedRoute, RouteArtifact } from '../../src/framework/routes/types';

const APP_ROOT = path.join(os.tmpdir(), 'basesec-surface-app');
const STACK_BODY = [
  'TypeError: boom',
  '    at Object.<anonymous> (/srv/app/src/b.js:10:5)',
  '    at Module._compile (node:internal/modules/cjs/loader:1554:14)',
].join('\n');

let server: http.Server;
let origin: string;
let requests: string[] = [];

function respond(req: http.IncomingMessage, res: http.ServerResponse): void {
  const url = req.url ?? '/';
  requests.push(`${req.method} ${url}`);
  if (url === '/a') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'set-cookie': 'sid=abc123; Path=/' });
    res.end('<html><body>a</body></html>');
    return;
  }
  if (url === '/b/1') {
    res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(STACK_BODY);
    return;
  }
  if (url === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end('<html><body>home</body></html>');
    return;
  }
  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('not found');
}

beforeAll(async () => {
  server = http.createServer(respond);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  requests = [];
});

function route(overrides: Partial<ExtractedRoute>): ExtractedRoute {
  return {
    method: 'GET',
    path: '/a',
    framework: 'express',
    filePath: 'src/a.ts',
    line: 1,
    endLine: 5,
    hasAuth: false,
    params: [],
    reachableFiles: [],
    staticFindings: [],
    ...overrides,
  };
}

function surfaceOf(routes: ExtractedRoute[], unresolved: RouteArtifact['unresolved'] = []): LoadedSurface {
  return {
    artifact: {
      version: 1,
      generatedAt: '2026-08-02T10:00:00.000Z',
      target: APP_ROOT,
      frameworks: ['express'],
      routes,
      unresolved,
    },
    source: 'routes-file',
    stale: false,
  };
}

const ROUTES: ExtractedRoute[] = [
  route({ method: 'GET', path: '/a', filePath: 'src/a.ts', line: 1, endLine: 5 }),
  route({ method: 'GET', path: '/b/:id', filePath: 'src/b.ts', line: 10, endLine: 20 }),
  route({ method: 'POST', path: '/c', filePath: 'src/c.ts', line: 3, endLine: 4 }),
];

describe('runDast with a route surface', () => {
  it('requests the read-only endpoints with concrete paths and never the mutating one', async () => {
    const result = await runDast({ url: origin, surface: surfaceOf(ROUTES), evidence: false });

    expect(requests).toContain('GET /a');
    expect(requests).toContain('GET /b/1');
    expect(requests.some((r) => r.endsWith(' /c'))).toBe(false);
    expect(result.stats.dast).toMatchObject({
      mode: 'full',
      routesSource: 'routes-file',
      routesStale: false,
      endpoints: { total: 3, analyzed: 2, skippedMutating: 1, unresolved: 0 },
    });
  });

  it('reports a 500 stack trace on an endpoint at the handler location', async () => {
    const result = await runDast({ url: origin, surface: surfaceOf(ROUTES), evidence: false });
    const finding = result.findings.find((f) => f.ruleId === 'DAST-006');

    expect(finding).toBeDefined();
    expect(finding?.filePath).toBe(path.join(APP_ROOT, 'src/b.ts'));
    expect(finding?.line).toBe(10);
    expect(finding?.endLine).toBe(20);
    expect(finding?.endpoint).toBe('GET /b/:id');
  });

  it('reports cookies without flags on the endpoint that set them', async () => {
    const result = await runDast({ url: origin, surface: surfaceOf(ROUTES), evidence: false });
    const cookie = result.findings.find((f) => f.ruleId === 'DAST-005' && f.endpoint === 'GET /a');

    expect(cookie).toBeDefined();
    expect(cookie?.filePath).toBe(path.join(APP_ROOT, 'src/a.ts'));
    expect(cookie?.codeSnippet).toBe('set-cookie: sid=[REDACTED]; Path=/');
  });

  it('counts the progress of endpoint requests in the total', async () => {
    const events: Array<{ done: number; total: number }> = [];
    await runDast({
      url: origin,
      surface: surfaceOf(ROUTES),
      evidence: false,
      onProgress: (event) => events.push({ done: event.done, total: event.total }),
    });

    // 1 target (/), 2 read-only endpoints, 7 DAST rules and the DAST-008 check (Fase 4: con superficie, DAST-008 ocupa una ranura).
    expect(events.at(-1)).toEqual({ done: 11, total: 11 });
  });

  it('keeps the findings of the observed endpoints when the budget runs out', async () => {
    const result = await runDast({ url: origin, surface: surfaceOf(ROUTES), evidence: false, maxRequests: 2 });

    expect(result.stats.dast?.incomplete).toBe('budget');
    expect(requests).not.toContain('GET /b/1');
    expect(result.findings.some((f) => f.ruleId === 'DAST-005' && f.endpoint === 'GET /a')).toBe(true);
  });

  it('keeps the normal no-source mode when no surface is given', async () => {
    const result = await runDast({ url: origin, evidence: false });
    expect(result.stats.dast?.mode).toBe('no-source');
    expect(requests.length).toBeGreaterThan(0);
    expect(requests.every((r) => r === 'GET /')).toBe(true);
  });
});

describe('resolveEndpointUrl', () => {
  it('resolves a concrete path on the target origin', () => {
    expect(resolveEndpointUrl(origin, '/b/1')).toBe(`${origin}/b/1`);
  });

  it.each(['/a/../b', '/a/%2e%2e/b', '/%2E/x', 'b', '/\\evil.example', '\t//evil.example'])(
    'discards the path %j that new URL would rewrite',
    (concrete) => {
      expect(resolveEndpointUrl(origin, concrete)).toBeUndefined();
    },
  );

  it.each(['/%2F%2Fevil.example', '/..%2Fx', '/@evil.example', '/a:b'])('keeps %s on the target origin', (concrete) => {
    expect(resolveEndpointUrl(origin, concrete)?.startsWith(`${origin}/`)).toBe(true);
  });

  it('discards paths that leave the target origin', () => {
    expect(resolveEndpointUrl(origin, '//evil.example/x')).toBeUndefined();
    expect(resolveEndpointUrl(origin, 'http://evil.example/x')).toBeUndefined();
  });
});

describe('runDast with a surface: target-level rules and the root endpoint', () => {
  let apiServer: http.Server;
  let apiOrigin: string;
  let apiRequests: string[] = [];

  beforeAll(async () => {
    apiServer = http.createServer((req, res) => {
      const url = req.url ?? '/';
      apiRequests.push(`${req.method} ${url}`);
      if (url === '/') {
        res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'sid=abc123; Path=/' });
        res.end('{}');
      } else if (url === '/page') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end('<html><body>page</body></html>');
      } else if (url === '/gone') {
        res.writeHead(404, { 'content-type': 'text/html; charset=utf-8' });
        res.end('<html><body>Cannot GET /gone</body></html>');
      } else {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end('{}');
      }
    });
    await new Promise<void>((resolve) => apiServer.listen(0, '127.0.0.1', resolve));
    apiOrigin = `http://127.0.0.1:${(apiServer.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    apiServer.closeAllConnections();
    await new Promise<void>((resolve) => apiServer.close(() => resolve()));
  });

  beforeEach(() => {
    apiRequests = [];
  });

  it('finds a missing CSP on an HTML endpoint that is not / (the root is JSON), without a handler location', async () => {
    const surface = surfaceOf([route({ path: '/page', filePath: 'src/page.ts' })]);
    const result = await runDast({ url: apiOrigin, surface, evidence: false });

    const csp = result.findings.find((f) => f.ruleId === 'DAST-003');
    expect(csp).toBeDefined();
    expect(csp?.endpoint).toBe('GET /page');
    expect(csp?.filePath).toBe('');
    expect(result.findings.some((f) => f.ruleId === 'DAST-001' && f.endpoint === 'GET /page')).toBe(true);
  });

  it('does not report HTML error pages (4xx) of an endpoint as target-level findings', async () => {
    const surface = surfaceOf([route({ path: '/gone', filePath: 'src/gone.ts' })]);
    const result = await runDast({ url: apiOrigin, surface, evidence: false });

    expect(result.findings.some((f) => f.ruleId === 'DAST-001' || f.ruleId === 'DAST-003')).toBe(false);
  });

  it('does not request / twice and gives its observation the handler of GET /', async () => {
    const surface = surfaceOf([route({ path: '/', filePath: 'src/index.ts', line: 7, endLine: 12 })]);
    // Solo DAST-005: DAST-004 hace su propia petición a / con un Origin.
    const result = await runDast({ url: apiOrigin, surface, rules: ['DAST-005'], evidence: false });

    expect(apiRequests.filter((r) => r === 'GET /')).toHaveLength(1);
    const cookie = result.findings.find((f) => f.ruleId === 'DAST-005');
    expect(cookie?.endpoint).toBe('GET /');
    expect(cookie?.filePath).toBe(path.join(APP_ROOT, 'src/index.ts'));
    expect(cookie?.line).toBe(7);
    expect(result.stats.dast?.endpoints).toMatchObject({ total: 1, analyzed: 1 });
  });

  it('does not request the healthcheck twice either', async () => {
    const surface = surfaceOf([route({ path: '/page' })]);
    await runDast({ url: apiOrigin, health: '/page', surface, evidence: false });

    expect(apiRequests.filter((r) => r === 'GET /page')).toHaveLength(1);
  });

  it('drops endpoints with dot segments and counts them as unresolved', async () => {
    const unsafe = surfaceOf([route({ path: '/a/%2e%2e/page' })]);
    const result = await runDast({ url: apiOrigin, surface: unsafe, rules: ['DAST-005'], evidence: false });

    expect(apiRequests).toEqual(['GET /']);
    expect(result.stats.dast?.endpoints).toMatchObject({ total: 1, analyzed: 0, unresolved: 1 });
  });
});

describe('runDast budget without a surface', () => {
  it('keeps inspecting what was observed when the budget runs out on the healthcheck', async () => {
    const result = await runDast({ url: origin, health: '/a', maxRequests: 1, evidence: false });

    expect(result.stats.dast?.incomplete).toBe('budget');
    expect(requests).toEqual(['GET /']);
    expect(result.stats.rulesRun).toBeGreaterThan(0);
  });
});
