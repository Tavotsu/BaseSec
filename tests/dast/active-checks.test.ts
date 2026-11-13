import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createVulnerableApp } from '../fixtures/vulnerable-app/server.mjs';
import { runDast } from '../../src/dast/runner';
import { isPublicRoute, isSensitivePath, pickRateLimitTarget } from '../../src/dast/active-checks';
import type { LoadedSurface } from '../../src/dast/surface';
import type { ExtractedRoute, RouteArtifact, RouteParam } from '../../src/framework/routes/types';

const APP_ROOT = path.join(os.tmpdir(), 'basesec-active-app');
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

function route(method: string, routePath: string, overrides: Partial<ExtractedRoute> = {}): ExtractedRoute {
  const params: RouteParam[] = [];
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

const AUTH_ROUTES: ExtractedRoute[] = [
  route('GET', '/admin'),
  route('GET', '/admin/guarded'),
  route('GET', '/profile'),
  route('GET', '/users/:id', { params: [{ name: 'id', in: 'path' }] }),
];

function ruleFindings<T extends { ruleId: string }>(findings: T[], ruleId: string): T[] {
  return findings.filter((finding) => finding.ruleId === ruleId);
}

describe('isSensitivePath', () => {
  it.each([
    ['/admin', true],
    ['/api/Internal/status', true],
    ['/debug/vars', true],
    ['/metrics', true],
    ['/account', true],
    ['/user-settings', true],
    ['/dashboard', true],
    ['/private/notes', true],
    ['/secret', true],
    ['/config', true],
    ['/users/:userId', true],
    ['/orders/:id', true],
    ['/accounts/:accountId', true],
    ['/teams/:uid', true],
    ['/users/:anything', true],
    ['/api/v1/users/:id/posts', true],
    ['/users/:id(\\d+)', true],
    ['/getAdminUsers', true],
    ['/admin-panel', true],
    ['/configs', true],
    // Catálogos públicos con :id: no son datos de un usuario.
    ['/products/:id', false],
    ['/items/:id', false],
    ['/posts/:id/comments', false],
    ['/:id', false],
    // Palabras completas, no subcadenas.
    ['/international/rates', false],
    ['/accounting', false],
    ['/configurator', false],
    // Colecciones sin parámetro: decisión conservadora, no sensibles por sí solas.
    ['/users', false],
    ['/profile', false],
    ['/products/:slug', false],
    ['/search', false],
  ])('%s → %s', (routePath, expected) => {
    expect(isSensitivePath(routePath)).toBe(expected);
  });
});

describe('isPublicRoute', () => {
  it('excludes the conventional public paths and health variants', () => {
    for (const routePath of ['/', '/login', '/logout', '/register', '/signup', '/health', '/healthz', '/status', '/ready', '/live', '/ping', '/favicon.ico', '/healthcheck']) {
      expect(isPublicRoute(routePath, []), routePath).toBe(true);
    }
    expect(isPublicRoute('/admin', [])).toBe(false);
  });

  it('ignores case and a trailing slash, covers login pages under a sensitive prefix, and not look-alikes', () => {
    expect(isPublicRoute('/LOGIN/', [])).toBe(true);
    expect(isPublicRoute('/admin/login', [])).toBe(true);
    expect(isPublicRoute('/health/db', [])).toBe(true);
    expect(isPublicRoute('/healthcare/records/:id', [])).toBe(false);
    expect(isPublicRoute('/metrics', [])).toBe(false);
  });

  it('matches dast.publicRoutes segment by segment, with * as one segment', () => {
    expect(isPublicRoute('/admin', ['/admin'])).toBe(true);
    expect(isPublicRoute('/api/v1/status', ['/api/*/status'])).toBe(true);
    expect(isPublicRoute('/api/v1/v2/status', ['/api/*/status'])).toBe(false);
    expect(isPublicRoute('/API/Admin', ['/api/admin'])).toBe(true);
    expect(isPublicRoute('/admin/guarded', ['/admin'])).toBe(false);
  });
});

describe('DAST-008 over the fixture', () => {
  it('reports the sensitive route that answers 2xx without credentials, and nothing else', async () => {
    const result = await runDast({
      url: origin,
      surface: surfaceOf(AUTH_ROUTES),
      rules: ['DAST-008'],
      evidence: false,
    });
    const findings = ruleFindings(result.findings, 'DAST-008');
    expect(findings.map((finding) => finding.endpoint).sort()).toEqual(['GET /admin', 'GET /users/:id']);
    for (const finding of findings) {
      expect(finding.severity).toBe('medium');
      expect(finding.confidence).toBe('low');
      expect(finding.source).toBe('dynamic');
      expect(finding.message).toContain('sensitive route is reachable without authentication (static analysis found no auth guard)');
      expect(finding.references).toContain('https://cwe.mitre.org/data/definitions/306.html');
    }
    const admin = findings.find((finding) => finding.endpoint === 'GET /admin');
    expect(admin?.filePath).toBe(path.join(APP_ROOT, 'src_admin.ts'));
    expect(admin?.line).toBe(1);
  });

  it('a 401 without credentials is not a finding (control)', async () => {
    const result = await runDast({
      url: origin,
      surface: surfaceOf([route('GET', '/admin/guarded')]),
      rules: ['DAST-008'],
      evidence: false,
    });
    expect(ruleFindings(result.findings, 'DAST-008')).toHaveLength(0);
  });

  it('an admin route with hasAuth "unknown" or true is never a candidate', async () => {
    const result = await runDast({
      url: origin,
      surface: surfaceOf([route('GET', '/admin', { hasAuth: 'unknown' }), route('GET', '/users/:id', { hasAuth: true })]),
      rules: ['DAST-008'],
      evidence: false,
    });
    expect(ruleFindings(result.findings, 'DAST-008')).toHaveLength(0);
    // Solo la observación de superficie: la comprobación sin auth no se lanza para estas rutas.
    expect(app.requests.filter((request) => request === 'GET /admin')).toHaveLength(1);
  });

  it('a route listed in dast.publicRoutes is not reported', async () => {
    const result = await runDast({
      url: origin,
      surface: surfaceOf(AUTH_ROUTES),
      rules: ['DAST-008'],
      publicRoutes: ['/admin', '/users/*'],
      evidence: false,
    });
    expect(ruleFindings(result.findings, 'DAST-008')).toHaveLength(0);
  });

  it('reuses the endpoint observation when the user sent no credentials (one request total)', async () => {
    await runDast({ url: origin, surface: surfaceOf([route('GET', '/admin')]), rules: ['DAST-008'], evidence: false });
    expect(app.requests.filter((request) => request === 'GET /admin')).toHaveLength(1);
  });

  it('with a user Authorization header, the check repeats the request without it and still detects /admin', async () => {
    const result = await runDast({
      url: origin,
      surface: surfaceOf(AUTH_ROUTES),
      headers: { Authorization: `Bearer ${TOKEN}` },
      rules: ['DAST-008'],
      evidence: false,
    });
    const endpoints = ruleFindings(result.findings, 'DAST-008').map((finding) => finding.endpoint);
    expect(endpoints).toContain('GET /admin');
    // /admin/guarded solo responde 200 con credenciales: la comprobación sin ellas recibe 401 y no reporta.
    expect(endpoints).not.toContain('GET /admin/guarded');
    expect(app.requests.filter((request) => request === 'GET /admin')).toHaveLength(2);
  });

  it('does not run without a surface (no source, no routes)', async () => {
    const result = await runDast({ url: origin, rules: ['DAST-008'], evidence: false });
    expect(ruleFindings(result.findings, 'DAST-008')).toHaveLength(0);
    expect(result.stats.rulesRun).toBe(0);
  });
});

describe('DAST-010 over the fixture', () => {
  it('does not run without --probe-rate-limit: no burst at all', async () => {
    const result = await runDast({ url: origin, health: '/burst', evidence: false });
    expect(ruleFindings(result.findings, 'DAST-010')).toHaveLength(0);
    expect(app.requests.filter((request) => request === 'GET /burst')).toHaveLength(1);
  });

  it('with the probe, a burst of 30 requests on an endpoint without rate limiting is a finding', async () => {
    const result = await runDast({ url: origin, health: '/burst', probeRateLimit: true, evidence: false });
    const findings = ruleFindings(result.findings, 'DAST-010');
    expect(findings).toHaveLength(1);
    expect(findings[0].endpoint).toBe('GET /burst');
    expect(findings[0].message).toBe('No rate limiting observed on GET /burst after 30 rapid requests.');
    expect(findings[0].severity).toBe('low');
    expect(findings[0].confidence).toBe('low');
    expect(findings[0].filePath).toBe('');
    // 1 de la observación base + 30 de la ráfaga.
    expect(app.requests.filter((request) => request === 'GET /burst')).toHaveLength(31);
  });

  it('a 429 and rate-limit headers on the target mean the check is silent (control)', async () => {
    const result = await runDast({ url: origin, health: '/limited', probeRateLimit: true, evidence: false });
    expect(ruleFindings(result.findings, 'DAST-010')).toHaveLength(0);
    expect(result.stats.dast?.incomplete).toBeUndefined();
  });

  it('a target that already answers an error is not probed', async () => {
    const result = await runDast({ url: origin, health: '/missing-page', probeRateLimit: true, evidence: false });
    expect(ruleFindings(result.findings, 'DAST-010')).toHaveLength(0);
    expect(app.requests.filter((request) => request === 'GET /missing-page')).toHaveLength(1);
  });

  it('a budget that runs out in the middle of the burst reports nothing and marks the analysis incomplete', async () => {
    const result = await runDast({
      url: origin,
      health: '/burst',
      probeRateLimit: true,
      maxRequests: 10,
      evidence: false,
    });
    expect(ruleFindings(result.findings, 'DAST-010')).toHaveLength(0);
    expect(result.stats.dast?.incomplete).toBe('budget');
  });

  it('--rules DAST-010 without the probe enabled does not burst', async () => {
    const result = await runDast({ url: origin, health: '/burst', rules: ['DAST-010'], evidence: false });
    expect(ruleFindings(result.findings, 'DAST-010')).toHaveLength(0);
    expect(app.requests.filter((request) => request === 'GET /burst')).toHaveLength(1);
  });

  it('uses the first login-like GET of the surface as the target and places the finding on its handler', async () => {
    const surface = surfaceOf([route('GET', '/login'), route('GET', '/burst')]);
    const result = await runDast({
      url: origin,
      surface,
      rules: ['DAST-010'],
      probeRateLimit: true,
      evidence: false,
    });
    const findings = ruleFindings(result.findings, 'DAST-010');
    expect(findings).toHaveLength(1);
    expect(findings[0].endpoint).toBe('GET /login');
    expect(findings[0].filePath).toBe(path.join(APP_ROOT, 'src_login.ts'));
    expect(app.requests.filter((request) => request === 'GET /login')).toHaveLength(31);
  });
});

describe('DAST-008 precision against false positives', () => {
  let server: http.Server;
  let local: string;
  const seen: string[] = [];

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      const url = req.url ?? '/';
      seen.push(`${req.method} ${url}`);
      if (url === '/') {
        res.writeHead(200, { 'content-type': 'text/plain' }).end('root');
      } else if (url === '/admin/redirected') {
        res.writeHead(302, { location: '/signin-page' }).end();
      } else if (url === '/signin-page') {
        res.writeHead(200, { 'content-type': 'text/html' }).end('<form><input type="password" name="p"></form>');
      } else if (url === '/admin/wall') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end('<html><form action="/x"><input name=u><INPUT TYPE=password name=p></form></html>');
      } else if (url === '/admin/basic') {
        res.writeHead(200, { 'www-authenticate': 'Basic realm="x"' }).end('please');
      } else if (url === '/admin/data') {
        res.writeHead(200, { 'content-type': 'text/html' }).end('<html><p>secret panel</p></html>');
      } else if (url === '/orders/1') {
        res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
      } else if (url === '/products/1') {
        res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
      } else {
        res.writeHead(404).end('nf');
      }
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    local = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  beforeEach(() => {
    seen.length = 0;
  });

  async function auth008(routes: ExtractedRoute[], headers?: Record<string, string>) {
    const result = await runDast({ url: local, surface: surfaceOf(routes), rules: ['DAST-008'], headers, evidence: false });
    return ruleFindings(result.findings, 'DAST-008').map((finding) => finding.endpoint);
  }

  it('an endpoint that redirects to a login page answering 200 is not reachable (also when its observation is reused)', async () => {
    expect(await auth008([route('GET', '/admin/redirected')])).toEqual([]);
  });

  it('a 200 login form or a WWW-Authenticate challenge is not a finding, a real admin page is', async () => {
    expect(await auth008([route('GET', '/admin/wall'), route('GET', '/admin/basic')])).toEqual([]);
    expect(await auth008([route('GET', '/admin/data')])).toEqual(['GET /admin/data']);
  });

  it(':id counts only for user-owned resources: /orders/:id yes, /products/:id no', async () => {
    const endpoints = await auth008([
      route('GET', '/orders/:id', { params: [{ name: 'id', in: 'path' }] }),
      route('GET', '/products/:id', { params: [{ name: 'id', in: 'path' }] }),
    ]);
    expect(endpoints).toEqual(['GET /orders/:id']);
  });

  it('OPTIONS routes are not candidates (preflight answers 2xx by design)', async () => {
    expect(await auth008([route('OPTIONS', '/admin/data')])).toEqual([]);
    // Solo la observación de superficie; la confirmación sin credenciales no se envía.
    expect(seen.filter((request) => request.startsWith('OPTIONS'))).toHaveLength(1);
  });

  it('with a user credential the unauthenticated request carries none of it', async () => {
    const seenHeaders: Array<string | undefined> = [];
    const spy = http.createServer((req, res) => {
      seenHeaders.push(req.headers.authorization ?? (req.headers['x-session-id'] as string | undefined));
      res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
    });
    await new Promise<void>((resolve) => spy.listen(0, '127.0.0.1', resolve));
    try {
      const url = `http://127.0.0.1:${(spy.address() as AddressInfo).port}`;
      await runDast({
        url,
        surface: surfaceOf([route('GET', '/admin/data')]),
        rules: ['DAST-008'],
        headers: { Authorization: 'Bearer TOP', 'X-Session-Id': 'abc' },
        evidence: false,
      });
      // `/` y la observación del endpoint llevan credenciales; la confirmación (última) no.
      expect(seenHeaders.at(-1)).toBeUndefined();
      expect(seenHeaders.filter((value) => value === undefined)).toHaveLength(1);
    } finally {
      spy.closeAllConnections();
      await new Promise<void>((resolve) => spy.close(() => resolve()));
    }
  });
});

describe('DAST-010 precision', () => {
  let server: http.Server;
  let local: string;
  const hits = new Map<string, number>();

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      const url = req.url ?? '/';
      const count = (hits.get(url) ?? 0) + 1;
      hits.set(url, count);
      if (url === '/ietf') {
        res.writeHead(200, { RateLimit: 'limit=10, remaining=9', 'content-type': 'text/plain' }).end('ok');
      } else if (url === '/xrate') {
        res.writeHead(200, { 'X-Rate-Limit-Limit': '10' }).end('ok');
      } else if (url === '/waf') {
        // 1 base + 4 de la ráfaga bien; después el WAF bloquea con 403 (sin 429 ni cabeceras).
        if (count > 5) res.writeHead(403).end('blocked');
        else res.writeHead(200).end('ok');
      } else if (url === '/plain' || url === '/') {
        res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
      } else {
        res.writeHead(404).end('nf');
      }
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    local = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  beforeEach(() => hits.clear());

  async function probe(health: string, routes?: ExtractedRoute[]) {
    const result = await runDast({
      url: local,
      health,
      surface: routes ? surfaceOf(routes) : undefined,
      rules: ['DAST-010'],
      probeRateLimit: true,
      evidence: false,
    });
    return ruleFindings(result.findings, 'DAST-010');
  }

  it('the IETF RateLimit header and X-Rate-Limit-* count as rate limiting', async () => {
    expect(await probe('/ietf')).toHaveLength(0);
    expect(await probe('/xrate')).toHaveLength(0);
    expect(await probe('/plain')).toHaveLength(1);
  });

  it('a 403 in the middle of the burst is inconclusive, not "no rate limit"', async () => {
    expect(await probe('/waf')).toHaveLength(0);
  });

  it('the burst goes to the login-like route, not to a route that merely contains "auth" (authors)', async () => {
    const findings = await probe('/plain', [route('GET', '/authors'), route('GET', '/plain')]);
    expect(findings.map((finding) => finding.endpoint)).toEqual(['GET /plain']);
    // /authors solo recibe la observación de superficie, no la ráfaga.
    expect(hits.get('/authors')).toBe(1);
  });

  it('pickRateLimitTarget prefers a word-level login match and falls back to the healthcheck', () => {
    const observation = (url: string, status = 200) => ({
      endpoint: `GET ${new URL(url).pathname}`,
      url,
      method: 'GET',
      response: { status, headers: {}, body: '', contentEncoding: 'identity', bodyDecoded: true, url, redirects: [], timedOut: false, elapsedMs: 1 },
    });
    const root = 'http://h.test/';
    const health = 'http://h.test/healthz';
    const target = (path: string) => ({ endpoint: { method: 'GET', path, concretePath: path, route: route('GET', path), mutating: false }, url: `http://h.test${path}` });
    const observations = [observation(root), observation(health), observation('http://h.test/api/login'), observation('http://h.test/authors')];
    expect(pickRateLimitTarget([target('/authors'), target('/api/login')], observations, health, root)?.url).toBe('http://h.test/api/login');
    expect(pickRateLimitTarget([target('/authors')], observations, health, root)?.url).toBe(health);
    expect(pickRateLimitTarget([target('/api/login')], [observation(root), observation(health), observation('http://h.test/api/login', 500)], health, root)).toBeUndefined();
  });
});
