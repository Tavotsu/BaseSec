import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createVulnerableApp } from '../fixtures/vulnerable-app/server.mjs';
import { runInjection } from '../../src/dast/inject';
import type { InjectionPoint, InjectionResult } from '../../src/dast/inject';
import { HttpClient } from '../../src/dast/http';
import { Guard } from '../../src/dast/guard';
import { findForbiddenFragment } from '../../src/dast/payloads';
import { toSurfaceEndpoints } from '../../src/dast/surface';
import type { ExtractedRoute, RouteArtifact, RouteParam } from '../../src/framework/routes/types';

const APP_ROOT = path.join(os.tmpdir(), 'basesec-inject-app');
const DELAY_SECONDS = 1;

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

function route(overrides: Partial<ExtractedRoute>): ExtractedRoute {
  return {
    method: 'GET',
    path: '/',
    framework: 'express',
    filePath: 'src/app.ts',
    line: 1,
    endLine: 5,
    hasAuth: false,
    params: [],
    reachableFiles: [],
    staticFindings: [],
    ...overrides,
  };
}

function query(name: string): RouteParam {
  return { name, in: 'query' };
}

function makeClient(maxRequests = 5000): HttpClient {
  return new HttpClient({ guard: new Guard(), rps: 500, concurrency: 5, maxRequests, requestTimeout: 10000 });
}

/** Puntos de inyección de un conjunto de rutas, como los construye el runner. */
function pointsOf(routes: ExtractedRoute[]): InjectionPoint[] {
  const artifact: RouteArtifact = {
    version: 1,
    generatedAt: '2026-08-02T10:00:00.000Z',
    target: APP_ROOT,
    frameworks: ['express'],
    routes,
    unresolved: [],
  };
  return toSurfaceEndpoints(artifact).flatMap((endpoint) =>
    endpoint.route.params.map((param) => ({ endpoint, param })),
  );
}

async function inject(
  routes: ExtractedRoute[],
  extra: { client?: HttpClient; maxPayloadsPerEndpoint?: number; rulesFilter?: string[] } = {},
): Promise<InjectionResult> {
  return runInjection(pointsOf(routes), {
    client: extra.client ?? makeClient(),
    origin,
    artifactTarget: APP_ROOT,
    knownSecrets: [],
    delaySeconds: DELAY_SECONDS,
    rulesFilter: extra.rulesFilter,
    maxPayloadsPerEndpoint: extra.maxPayloadsPerEndpoint,
    deadlineReached: () => false,
  });
}

describe('runInjection against the vulnerable fixture', () => {
  it('reports SQL injection on a query parameter, naming it and the oracle', async () => {
    const result = await inject([route({ method: 'GET', path: '/users', params: [query('id')] })]);
    const finding = result.findings.find((f) => f.ruleId === 'DAST-101');

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.category).toBe('sql-injection');
    expect(finding?.verified).toBe(true);
    expect(finding?.source).toBe('dynamic');
    expect(finding?.message).toContain('"id"');
    expect(finding?.message).toContain('query');
    expect(finding?.endpoint).toBe('GET /users');
    expect(finding?.evidence?.oracle).toBe('sql-error');
    expect(finding?.evidence?.payload).toContain("'");
    expect(finding?.filePath).toBe(path.join(APP_ROOT, 'src/app.ts'));
  });

  it('reports SQL injection on a path parameter', async () => {
    const result = await inject([route({ method: 'GET', path: '/users/:id', params: [{ name: 'id', in: 'path' }] })]);
    const finding = result.findings.find((f) => f.ruleId === 'DAST-101');

    expect(finding).toBeDefined();
    expect(finding?.message).toContain('"id" (path)');
    expect(finding?.endpoint).toBe('GET /users/:id');
  });

  it('reports one finding per (endpoint, class), even when the same point is probed twice', async () => {
    const routes = [route({ method: 'GET', path: '/users', params: [query('id')] })];
    const points = [...pointsOf(routes), ...pointsOf(routes)];
    const result = await runInjection(points, {
      client: makeClient(),
      origin,
      knownSecrets: [],
      delaySeconds: DELAY_SECONDS,
      deadlineReached: () => false,
    });
    expect(result.findings.filter((f) => f.ruleId === 'DAST-101')).toHaveLength(1);
  });

  it('reports reflected XSS on /search with the q parameter', async () => {
    const result = await inject([route({ method: 'GET', path: '/search', params: [query('q')] })]);
    const finding = result.findings.find((f) => f.ruleId === 'DAST-105');

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.message).toContain('"q"');
    expect(finding?.evidence?.oracle).toBe('reflection');
  });

  it('reports path traversal on /file with the name parameter', async () => {
    const result = await inject([route({ method: 'GET', path: '/file', params: [query('name')] })]);
    const finding = result.findings.find((f) => f.ruleId === 'DAST-104');

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.message).toContain('"name"');
  });

  it('reports open redirect on /go as DAST-011 with a medium confidence', async () => {
    const result = await inject([route({ method: 'GET', path: '/go', params: [query('url')] })]);
    const finding = result.findings.find((f) => f.ruleId === 'DAST-011');

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
    expect(finding?.category).toBe('xss');
    expect(finding?.confidence).toBe('medium');
    expect(finding?.evidence?.oracle).toBe('redirect');
  });

  it('reports NoSQL injection on /items through the bracket operator', async () => {
    const result = await inject([route({ method: 'GET', path: '/items', params: [query('role')] })]);
    const finding = result.findings.find((f) => f.ruleId === 'DAST-102');

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.confidence).toBe('low');
    expect(finding?.evidence?.oracle).toBe('diff');
    expect(app.requests.some((r) => r.includes('role%5B%24ne%5D') || r.includes('role[$ne]'))).toBe(true);
  });

  it('reports a timing-confirmed command injection on /ping (medium confidence, timing oracle)', async () => {
    const result = await inject([route({ method: 'GET', path: '/ping', params: [query('host')] })]);
    const finding = result.findings.find((f) => f.ruleId === 'DAST-103' || f.ruleId === 'DAST-101');

    expect(finding).toBeDefined();
    expect(finding?.evidence?.oracle).toBe('timing');
    expect(finding?.confidence).toBe('medium');
  }, 60000);

  it('never reports /safe (escaped reflection) as XSS', async () => {
    const result = await inject([route({ method: 'GET', path: '/safe', params: [query('q')] })]);
    expect(result.findings.some((f) => f.ruleId === 'DAST-105')).toBe(false);
    expect(result.findings).toHaveLength(0);
  });

  it('never reports /slow (always slow) as timing injection', async () => {
    const result = await inject([route({ method: 'GET', path: '/slow', params: [query('x')] })]);
    expect(result.findings).toHaveLength(0);
  }, 90000);

  it('keeps the message and evidence on the payload that fired, with no secret in it', async () => {
    const result = await inject([route({ method: 'GET', path: '/go', params: [query('url')] })]);
    const finding = result.findings.find((f) => f.ruleId === 'DAST-011');
    expect(finding?.evidence?.payload).toMatch(/bs-BS[0-9a-f]{8}\.example\.net/);
    expect(finding?.evidence?.request).toContain('/go?url=');
  });
});

describe('runInjection limits and guards', () => {
  it('respects maxPayloadsPerEndpoint, counting the benign request too', async () => {
    const result = await inject([route({ method: 'GET', path: '/users', params: [query('id')] })], {
      maxPayloadsPerEndpoint: 3,
    });
    expect(app.requests.filter((r) => r.startsWith('GET /users')).length).toBeLessThanOrEqual(3);
    expect(result.attackedEndpoints).toBe(1);
  });

  it('stops with budgetExceeded and keeps what it found when the budget runs out', async () => {
    // Presupuesto 2: la benigna y el primer payload de SQLi. El hallazgo ya encontrado se conserva.
    const result = await inject([route({ method: 'GET', path: '/users', params: [query('id')] })], {
      client: makeClient(2),
    });

    expect(result.budgetExceeded).toBe(true);
    expect(result.findings.some((f) => f.ruleId === 'DAST-101')).toBe(true);
    expect(app.requests.length).toBeLessThanOrEqual(2);
  });

  it('reports BudgetExceededError through the result instead of throwing it', async () => {
    await expect(inject([route({ method: 'GET', path: '/users', params: [query('id')] })], { client: makeClient(1) }))
      .resolves.toMatchObject({ budgetExceeded: true });
  });

  it('sends only non-destructive payloads (every request URL passes the policy)', async () => {
    await inject([
      route({ method: 'GET', path: '/users', params: [query('id')] }),
      route({ method: 'GET', path: '/search', params: [query('q')] }),
      route({ method: 'GET', path: '/file', params: [query('name')] }),
      route({ method: 'GET', path: '/go', params: [query('url')] }),
      route({ method: 'GET', path: '/items', params: [query('role')] }),
    ]);

    expect(app.requests.length).toBeGreaterThan(0);
    for (const request of app.requests) {
      const decoded = decodeURIComponent(request);
      expect(findForbiddenFragment(decoded), request).toBeUndefined();
    }
  });

  it('never injects into mutating endpoints or body parameters', async () => {
    const result = await inject([
      route({ method: 'POST', path: '/users', params: [query('id')] }),
      route({ method: 'GET', path: '/search', params: [{ name: 'q', in: 'body' }] }),
    ]);

    expect(result.findings).toHaveLength(0);
    expect(result.attackedEndpoints).toBe(0);
    expect(app.requests).toHaveLength(0);
  });

  it('rejects a delay above 2 seconds', async () => {
    await expect(
      runInjection(pointsOf([route({ method: 'GET', path: '/users', params: [query('id')] })]), {
        client: makeClient(),
        origin,
        knownSecrets: [],
        delaySeconds: 3,
        deadlineReached: () => false,
      }),
    ).rejects.toThrow(RangeError);
  });

  it('attacks only the rules named in the filter', async () => {
    const result = await inject([route({ method: 'GET', path: '/search', params: [query('q')] })], {
      rulesFilter: ['DAST-105'],
    });
    expect(result.findings.map((f) => f.ruleId)).toEqual(['DAST-105']);
  });

  it('sends nothing when the filter names no injection rule', async () => {
    const result = await inject([route({ method: 'GET', path: '/search', params: [query('q')] })], { rulesFilter: [] });
    expect(result.findings).toHaveLength(0);
    expect(app.requests).toHaveLength(0);
  });
});

/** Cliente que anota cada petición que recibiría la red: método, URL y opciones. */
function spyClient(max = 5000): { client: HttpClient; calls: Array<{ method: string; url: string; followRedirects: boolean | undefined }>; statuses: number[] } {
  const inner = makeClient(max);
  const calls: Array<{ method: string; url: string; followRedirects: boolean | undefined }> = [];
  const statuses: number[] = [];
  const client = Object.create(inner) as HttpClient;
  client.request = async (method, url, opts = {}) => {
    calls.push({ method, url, followRedirects: opts.followRedirects });
    const response = await inner.request(method, url, opts);
    statuses.push(response.status);
    return response;
  };
  return { client, calls, statuses };
}

describe('SSRF: every injection request stays on the target origin', () => {
  const ROUTES = [
    route({ method: 'GET', path: '/users/:id', params: [{ name: 'id', in: 'path' }] }),
    route({ method: 'GET', path: '/go', params: [query('url')] }),
    route({ method: 'GET', path: '/go/:url', params: [{ name: 'url', in: 'path' }] }),
    route({ method: 'GET', path: '/file', params: [query('name')] }),
    route({ method: 'GET', path: '/files/:name', params: [{ name: 'name', in: 'path' }] }),
    route({ method: 'GET', path: '/search', params: [query('q')] }),
  ];

  it('sends every request (path-traversal and open-redirect included) to the origin, GET only, never following redirects', async () => {
    const { client, calls, statuses } = spyClient();
    await inject(ROUTES, { client });

    expect(calls.length).toBeGreaterThan(20);
    for (const call of calls) {
      const url = new URL(call.url);
      expect(url.origin, call.url).toBe(origin);
      expect(call.method).toBe('GET');
      expect(call.followRedirects, call.url).toBe(false);
      expect(url.username + url.password, call.url).toBe('');
      expect(call.url.startsWith(`${origin}/`), call.url).toBe(true);
    }
    // El 302 del open redirect llega como 302: nadie lo siguió.
    expect(statuses).toContain(302);
  });

  it('keeps a path-parameter payload inside its own segment (nothing can add segments, a host or a port)', async () => {
    const { client, calls } = spyClient();
    await inject(ROUTES.slice(0, 1), { client });

    const attacks = calls.filter((call) => new URL(call.url).pathname.includes('%2F') || new URL(call.url).pathname.includes('%5C'));
    expect(attacks.length).toBeGreaterThan(0);
    for (const call of calls) {
      const url = new URL(call.url);
      expect(url.pathname.split('/'), call.url).toHaveLength(3);
      expect(url.pathname.split('/')[1]).toBe('users');
      expect(url.search).toBe('');
      expect(url.hash).toBe('');
    }
    // El servidor recibe el valor en un solo segmento: el traversal llega como ..%2F..%2F, nunca como ../
    expect(app.requests.some((r) => r.includes('/users/..%2F..%2F..%2F..%2Fetc%2Fpasswd'))).toBe(true);
    expect(app.requests.some((r) => r.includes('/../'))).toBe(false);
    expect(app.requests.every((r) => r.startsWith('GET /users/'))).toBe(true);
  });

  it('puts the open-redirect payload in the parameter value while the request still goes to the target', async () => {
    const { client, calls } = spyClient();
    await inject(ROUTES.slice(1, 2), { client });

    const external = calls.filter((call) => decodeURIComponent(call.url).includes('example.net'));
    expect(external.length).toBeGreaterThan(0);
    for (const call of external) {
      expect(new URL(call.url).host).toBe(new URL(origin).host);
      expect(new URL(call.url).pathname).toBe('/go');
      expect(call.url).toMatch(/\?url=(?:https%3A%2F%2F|%2F%2F)bs-BS[0-9a-f]{8}\.example\.net$/);
    }
  });

  it('never sends anything for an endpoint whose path would leave the origin', async () => {
    const hostile = route({ method: 'GET', path: '//evil.example.com/:id', params: [{ name: 'id', in: 'path' }] });
    const points = pointsOf([route({ method: 'GET', path: '/users/:id', params: [{ name: 'id', in: 'path' }] })]).map((point) => ({
      ...point,
      endpoint: { ...point.endpoint, path: hostile.path, concretePath: '//evil.example.com/1' },
    }));
    const { client, calls } = spyClient();
    const result = await runInjection(points, { client, origin, knownSecrets: [], delaySeconds: DELAY_SECONDS, deadlineReached: () => false });

    expect(calls).toHaveLength(0);
    expect(app.requests).toHaveLength(0);
    expect(result.attackedEndpoints).toBe(0);
  });

  it('records on the server only paths that begin with a single slash (no absolute-form targets, no protocol-relative paths)', async () => {
    await inject(ROUTES);
    expect(app.requests.length).toBeGreaterThan(20);
    for (const request of app.requests) {
      const target = request.split(' ')[1];
      expect(target.startsWith('/') && !target.startsWith('//'), request).toBe(true);
    }
  });
});

describe('one finding per (endpoint, class) and the parameter that fired', () => {
  it('names the second parameter when the first one is not vulnerable', async () => {
    const result = await inject([route({ method: 'GET', path: '/pair', params: [query('b'), query('a')] })], {
      rulesFilter: ['DAST-101'],
    });
    const findings = result.findings.filter((f) => f.ruleId === 'DAST-101');
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('"b"');
    expect(findings[0].message).not.toContain('"a"');
    expect(findings[0].codeSnippet).toContain('"b"');
    expect(findings[0].evidence?.request).toContain('/pair?b=');
  });

  it('reports a single finding, naming the first parameter in name order, when two parameters are vulnerable', async () => {
    const result = await inject([route({ method: 'GET', path: '/dual', params: [query('b'), query('a')] })], {
      rulesFilter: ['DAST-101'],
    });
    expect(result.findings.filter((f) => f.ruleId === 'DAST-101')).toHaveLength(1);
    expect(result.findings[0].message).toContain('"a"');
    expect(result.findings[0].evidence?.request).toContain('/dual?a=');
    // No se gasta presupuesto en la segunda: tras el hallazgo, el parámetro b no se ataca para esta clase (ni se pide su base).
    expect(app.requests.some((r) => r.startsWith('GET /dual?b='))).toBe(false);
  });
});

describe('oracle controls: endpoints that look suspicious but are not injectable', () => {
  const controls: Array<{ path: string; param: string; why: string }> = [
    { path: '/json', param: 'q', why: 'reflects raw but as application/json' },
    { path: '/attr', param: 'q', why: 'reflects escaped inside an attribute' },
    { path: '/sanitize', param: 'q', why: 'strips shell and markup characters' },
    { path: '/help', param: 'q', why: 'baseline already shows an SQL error phrase' },
    { path: '/docs', param: 'name', why: 'baseline already contains root:x:0:0:' },
    { path: '/vary', param: 'x', why: 'body length changes on every request' },
    { path: '/crash', param: 'role', why: 'fails with 500 when the operator object arrives' },
    { path: '/login', param: 'next', why: 'redirects to a third-party login carrying the value' },
  ];

  it.each(controls)('reports nothing on $path ($why)', async ({ path: routePath, param }) => {
    const result = await inject([route({ method: 'GET', path: routePath, params: [query(param)] })]);
    expect(result.findings.map((f) => f.ruleId)).toEqual([]);
    expect(app.requests.length).toBeGreaterThan(5);
  });

  it('does not report a single slow measurement: the reconfirmation and the control must agree', async () => {
    const result = await inject([route({ method: 'GET', path: '/flaky', params: [query('x')] })]);
    expect(result.findings).toHaveLength(0);
    // La primera medición lenta SÍ se confirmó (control + segundo envío), y fue la confirmación la que la descartó.
    expect(app.requests.filter((r) => /SLEEP\(|SLEEP%28/i.test(decodeURIComponent(r))).length).toBeGreaterThanOrEqual(3);
  }, 60000);

  it('does not send NoSQL operators to a path parameter (there is no object to parse)', async () => {
    await inject([route({ method: 'GET', path: '/users/:id', params: [{ name: 'id', in: 'path' }] })]);
    expect(app.requests.some((r) => r.includes('%5B%24ne%5D') || r.includes('[$ne]') || r.includes('%5B%24gt%5D'))).toBe(false);
  });
});

describe('time and budget limits', () => {
  it('stops without a request when the deadline has already passed', async () => {
    const result = await runInjection(pointsOf([route({ method: 'GET', path: '/users', params: [query('id')] })]), {
      client: makeClient(),
      origin,
      knownSecrets: [],
      delaySeconds: DELAY_SECONDS,
      deadlineReached: () => true,
    });
    expect(result.timedOut).toBe(true);
    expect(result.findings).toHaveLength(0);
    expect(app.requests).toHaveLength(0);
  });

  it('cuts between endpoints at the deadline and keeps what it already found', async () => {
    // /search va antes que /users (orden por path). Pasada su inyección de XSS (baseline + payload), vence el tiempo.
    const result = await runInjection(
      pointsOf([
        route({ method: 'GET', path: '/users', params: [query('id')] }),
        route({ method: 'GET', path: '/search', params: [query('q')] }),
      ]),
      {
        client: makeClient(),
        origin,
        knownSecrets: [],
        delaySeconds: DELAY_SECONDS,
        rulesFilter: ['DAST-105'],
        deadlineReached: () => app.requests.filter((r) => r.startsWith('GET /search')).length >= 2,
      },
    );
    expect(result.timedOut).toBe(true);
    expect(result.findings.map((f) => `${f.ruleId} ${f.endpoint}`)).toEqual(['DAST-105 GET /search']);
    expect(app.requests.some((r) => r.startsWith('GET /users'))).toBe(false);
  });

  it('cuts between classes at the deadline', async () => {
    // Con el deadline vencido tras la petición base, no se envía ningún payload de ninguna clase.
    const result = await runInjection(pointsOf([route({ method: 'GET', path: '/users', params: [query('id')] })]), {
      client: makeClient(),
      origin,
      knownSecrets: [],
      delaySeconds: DELAY_SECONDS,
      deadlineReached: () => app.requests.length >= 1,
    });
    expect(result.timedOut).toBe(true);
    expect(app.requests).toHaveLength(1);
  });

  it('gives up on an endpoint that stops answering after three timeouts in a row', async () => {
    const client = new HttpClient({ guard: new Guard(), rps: 500, concurrency: 5, maxRequests: 5000, requestTimeout: 300 });
    const result = await inject([route({ method: 'GET', path: '/ping', params: [query('host')] })], { client });

    // La base y los payloads sin delay responden; los de delay (1 s) superan los 300 ms. Los dos de SQLi no cortan (los
    // separa la clase NoSQL, que responde), pero los tres de cmdi seguidos sí: nada de lo que viene después se envía.
    const decoded = app.requests.map((r) => decodeURIComponent(r));
    expect(decoded.filter((r) => /sleep/i.test(r))).toHaveLength(5);
    expect(decoded.some((r) => r.includes('echo') || r.includes('passwd') || r.includes('example.net'))).toBe(false);
    expect(result.findings).toHaveLength(0);
    expect(result.budgetExceeded).toBe(false);
  });

  it('never exceeds maxPayloadsPerEndpoint across the parameters of an endpoint', async () => {
    await inject([route({ method: 'GET', path: '/dual', params: [query('a'), query('b'), query('c')] })], {
      maxPayloadsPerEndpoint: 7,
      rulesFilter: ['DAST-105'],
    });
    expect(app.requests.length).toBeLessThanOrEqual(7);
    expect(app.requests.length).toBeGreaterThan(0);
  });
});

describe('payload policy on the wire', () => {
  it('sends no destructive payload to any endpoint, in any of the encodings it travels in', async () => {
    const wide = [
      route({ method: 'GET', path: '/users', params: [query('id')] }),
      route({ method: 'GET', path: '/users/:id', params: [{ name: 'id', in: 'path' }] }),
      route({ method: 'GET', path: '/search', params: [query('q')] }),
      route({ method: 'GET', path: '/file', params: [query('name')] }),
      route({ method: 'GET', path: '/go', params: [query('url')] }),
      route({ method: 'GET', path: '/items', params: [query('role')] }),
      route({ method: 'GET', path: '/ping', params: [query('host')] }),
    ];
    await inject(wide);

    expect(app.requests.length).toBeGreaterThan(50);
    const seenSleeps: number[] = [];
    for (const request of app.requests) {
      const target = request.split(' ')[1];
      expect(findForbiddenFragment(target), request).toBeUndefined();
      expect(findForbiddenFragment(decodeURIComponent(target)), request).toBeUndefined();
      for (const match of decodeURIComponent(target).matchAll(/sleep[( ](\d+)/gi)) seenSleeps.push(Number(match[1]));
    }
    expect(Math.max(...seenSleeps)).toBeLessThanOrEqual(1);
  }, 60000);
});
