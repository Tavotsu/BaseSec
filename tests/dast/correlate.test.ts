import { describe, it, expect } from 'vitest';
import { correlate } from '../../src/dast/correlate';
import type { ExtractedRoute, RouteArtifact, StaticFindingRef } from '../../src/framework/routes/types';
import type { Confidence, DastEvidence, Finding, RuleCategory } from '../../src/rules/types';

const ROOT = '/proj';

function staticFinding(ruleId: string, category: RuleCategory, file: string, line: number, confidence: Confidence = 'high'): Finding {
  return {
    ruleId,
    ruleName: `${ruleId} name`,
    category,
    severity: 'high',
    filePath: `${ROOT}/${file}`,
    line,
    column: 1,
    endLine: line,
    endColumn: 10,
    message: `static ${ruleId}`,
    codeSnippet: 'code',
    remediation: 'fix it',
    references: [],
    confidence,
  };
}

function evidenceOf(request: string, payload = ''): DastEvidence {
  return { request, response: 'HTTP 500', payload, oracle: payload === '' ? 'header' : 'sql-error' };
}

function dynamicFinding(ruleId: string, category: RuleCategory, endpoint: string, request: string, payload = ''): Finding {
  return {
    ruleId,
    ruleName: `${ruleId} name`,
    category,
    severity: 'critical',
    filePath: '',
    line: 0,
    column: 0,
    endLine: 0,
    endColumn: 0,
    message: `runtime ${ruleId}`,
    codeSnippet: 'header',
    remediation: 'fix it',
    references: [],
    confidence: 'high',
    source: 'dynamic',
    verified: true,
    endpoint,
    evidence: evidenceOf(request, payload),
  };
}

function route(method: string, path: string, file: string, refs: StaticFindingRef[]): ExtractedRoute {
  return {
    method,
    path,
    framework: 'express',
    filePath: file,
    line: 5,
    endLine: 9,
    hasAuth: false,
    params: [{ name: 'id', in: 'path' }],
    reachableFiles: [file],
    staticFindings: refs,
  };
}

function artifact(routes: ExtractedRoute[]): RouteArtifact {
  return { version: 1, generatedAt: '2026-01-01T00:00:00.000Z', target: ROOT, frameworks: ['express'], routes, unresolved: [] };
}

describe('correlate: inyección (DAST-1xx)', () => {
  it('enlaza con el único candidato handler: verified, confidence high, sin DAST-101 aparte', () => {
    const sqli = staticFinding('SQLI-001', 'sql-injection', 'src/routes.js', 6);
    const art = artifact([route('GET', '/users/:id', 'src/routes.js', [{ ruleId: 'SQLI-001', filePath: 'src/routes.js', line: 6, via: 'handler' }])]);
    const dyn = dynamicFinding('DAST-101', 'sql-injection', 'GET /users/:id', 'GET http://x/users/1', "1'");

    const result = correlate([sqli], [dyn], art);

    expect(result.findings).toHaveLength(1);
    const [out] = result.findings;
    expect(out.ruleId).toBe('SQLI-001');
    expect(out.verified).toBe(true);
    expect(out.confidence).toBe('high');
    expect(out.evidence?.correlation).toBe('handler');
    expect(out.evidence?.payload).toBe("1'");
    expect(out.endpoint).toBe('GET /users/:id');
    expect(result.stats).toEqual({ verified: 1, dynamicOnly: 0 });
  });

  it('sin handler y con un único import-graph: confidence max(original, medium)', () => {
    const low = staticFinding('SQLI-001', 'sql-injection', 'src/db.js', 3, 'low');
    const high = staticFinding('SQLI-002', 'sql-injection', 'src/db2.js', 3, 'high');
    const art = artifact([
      route('GET', '/users/:id', 'src/routes.js', [{ ruleId: 'SQLI-001', filePath: 'src/db.js', line: 3, via: 'import-graph' }]),
      route('GET', '/orders/:id', 'src/orders.js', [{ ruleId: 'SQLI-002', filePath: 'src/db2.js', line: 3, via: 'import-graph' }]),
    ]);
    const dynLow = dynamicFinding('DAST-101', 'sql-injection', 'GET /users/:id', 'GET http://x/users/1', "'");
    const dynHigh = dynamicFinding('DAST-101', 'sql-injection', 'GET /orders/:id', 'GET http://x/orders/1', "'");

    const result = correlate([low, high], [dynLow, dynHigh], art);

    expect(result.findings.map((f) => [f.ruleId, f.confidence, f.evidence?.correlation])).toEqual([
      ['SQLI-001', 'medium', 'import-graph'],
      ['SQLI-002', 'high', 'import-graph'],
    ]);
  });

  it('dos candidatos: no se enlaza, el dinámico queda con los orígenes posibles', () => {
    const a = staticFinding('SQLI-001', 'sql-injection', 'src/a.js', 4);
    const b = staticFinding('SQLI-002', 'sql-injection', 'src/b.js', 8);
    const art = artifact([
      route('GET', '/users/:id', 'src/routes.js', [
        { ruleId: 'SQLI-001', filePath: 'src/a.js', line: 4, via: 'handler' },
        { ruleId: 'SQLI-002', filePath: 'src/b.js', line: 8, via: 'handler' },
      ]),
    ]);
    const dyn = dynamicFinding('DAST-101', 'sql-injection', 'GET /users/:id', 'GET http://x/users/1', "'");

    const result = correlate([a, b], [dyn], art);

    expect(result.findings).toHaveLength(3);
    expect(result.findings[0].verified).toBeUndefined();
    expect(result.findings[1].verified).toBeUndefined();
    const runtime = result.findings[2];
    expect(runtime.ruleId).toBe('DAST-101');
    expect(runtime.source).toBe('dynamic');
    expect(runtime.message).toContain('possible static origins: SQLI-001 src/a.js:4, SQLI-002 src/b.js:8');
    expect(result.stats).toEqual({ verified: 0, dynamicOnly: 1 });
  });

  it('dos candidatos en la misma línea (SQLI-001 y SQLI-003 sobre una query): ambos se enlazan', () => {
    const concat = staticFinding('SQLI-001', 'sql-injection', 'src/app.js', 8);
    const raw = staticFinding('SQLI-003', 'sql-injection', 'src/app.js', 8);
    const art = artifact([
      route('GET', '/users/:id', 'src/app.js', [
        { ruleId: 'SQLI-001', filePath: 'src/app.js', line: 8, via: 'handler' },
        { ruleId: 'SQLI-003', filePath: 'src/app.js', line: 8, via: 'handler' },
      ]),
    ]);
    const dyn = dynamicFinding('DAST-101', 'sql-injection', 'GET /users/:id', 'GET http://x/users/1', "'");

    const result = correlate([concat, raw], [dyn], art);

    expect(result.findings.map((f) => [f.ruleId, f.verified, f.evidence?.correlation])).toEqual([
      ['SQLI-001', true, 'handler'],
      ['SQLI-003', true, 'handler'],
    ]);
    expect(result.stats).toEqual({ verified: 2, dynamicOnly: 0 });
  });

  it('cero candidatos: el dinámico se emite tal cual', () => {
    const other = staticFinding('XSS-001', 'xss', 'src/routes.js', 6);
    const art = artifact([route('GET', '/users/:id', 'src/routes.js', [{ ruleId: 'XSS-001', filePath: 'src/routes.js', line: 6, via: 'handler' }])]);
    const dyn = dynamicFinding('DAST-101', 'sql-injection', 'GET /users/:id', 'GET http://x/users/1', "'");

    const result = correlate([other], [dyn], art);

    expect(result.findings).toHaveLength(2);
    expect(result.findings[0]).toBe(other);
    expect(result.findings[1]).toBe(dyn);
    expect(result.stats).toEqual({ verified: 0, dynamicOnly: 1 });
  });
});

describe('correlate: hermanas estáticas (DAST-0xx)', () => {
  it('DAST-005 enlaza con CONF-003 en el fichero del handler: runtime-property, high', () => {
    const conf = staticFinding('CONF-003', 'misconfiguration', 'src/routes.js', 7, 'medium');
    const art = artifact([route('GET', '/login', 'src/routes.js', [])]);
    const dyn = dynamicFinding('DAST-005', 'misconfiguration', 'GET /login', 'GET http://x/login');

    const result = correlate([conf], [dyn], art);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe('CONF-003');
    expect(result.findings[0].verified).toBe(true);
    expect(result.findings[0].confidence).toBe('high');
    expect(result.findings[0].evidence?.correlation).toBe('runtime-property');
  });

  // Antes el test usaba DAST-003; con el mapeo 1:1 (DAST-003 → CONF-001) esa regla ya no busca XSS-002, así que se pasa a DAST-001.
  it('DAST-001 sin endpoint de ruta busca la hermana en todo el proyecto (single candidate)', () => {
    const helmet = staticFinding('XSS-002', 'xss', 'src/server.js', 2);
    const art = artifact([]);
    const dyn = dynamicFinding('DAST-001', 'xss', 'http://x', 'GET http://x/');

    const result = correlate([helmet], [dyn], art);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe('XSS-002');
    expect(result.findings[0].evidence?.correlation).toBe('runtime-property');
  });

  it('dos hermanas posibles: el dinámico se queda', () => {
    const a = staticFinding('CONF-001', 'misconfiguration', 'src/a.js', 1);
    const b = staticFinding('CONF-001', 'misconfiguration', 'src/b.js', 1);
    const dyn = dynamicFinding('DAST-003', 'misconfiguration', 'http://x', 'GET http://x/');

    const result = correlate([a, b], [dyn], artifact([]));

    expect(result.findings).toHaveLength(3);
    expect(result.findings[2]).toBe(dyn);
    expect(result.stats).toEqual({ verified: 0, dynamicOnly: 1 });
  });

  it('DAST-001 con helmet y CSP ausentes a la vez: enlaza XSS-002 y no toca CONF-001', () => {
    const helmet = staticFinding('XSS-002', 'xss', 'src/app.js', 1);
    const csp = staticFinding('CONF-001', 'misconfiguration', 'src/app.js', 1);
    const dyn = dynamicFinding('DAST-001', 'xss', 'GET /', 'GET http://x/');

    const result = correlate([helmet, csp], [dyn], artifact([]));

    expect(result.findings.map((f) => [f.ruleId, f.verified, f.confidence, f.evidence?.correlation])).toEqual([
      ['XSS-002', true, 'high', 'runtime-property'],
      ['CONF-001', undefined, 'high', undefined],
    ]);
    expect(result.stats).toEqual({ verified: 1, dynamicOnly: 0 });
  });

  it('DAST-003 con helmet y CSP ausentes a la vez: enlaza CONF-001 y no toca XSS-002', () => {
    const helmet = staticFinding('XSS-002', 'xss', 'src/app.js', 1);
    const csp = staticFinding('CONF-001', 'misconfiguration', 'src/app.js', 1);
    const dyn = dynamicFinding('DAST-003', 'misconfiguration', 'GET /', 'GET http://x/');

    const result = correlate([helmet, csp], [dyn], artifact([]));

    expect(result.findings.map((f) => [f.ruleId, f.verified, f.confidence, f.evidence?.correlation])).toEqual([
      ['XSS-002', undefined, 'high', undefined],
      ['CONF-001', true, 'high', 'runtime-property'],
    ]);
    expect(result.stats).toEqual({ verified: 1, dynamicOnly: 0 });
  });

  it('DAST-001 y DAST-003 juntos: verifican XSS-002 y CONF-001 respectivamente, sin dinámicos sueltos', () => {
    const helmet = staticFinding('XSS-002', 'xss', 'src/app.js', 1);
    const csp = staticFinding('CONF-001', 'misconfiguration', 'src/app.js', 1);
    const headers = dynamicFinding('DAST-001', 'xss', 'GET /', 'GET http://x/');
    const policy = dynamicFinding('DAST-003', 'misconfiguration', 'GET /', 'GET http://x/');

    const result = correlate([helmet, csp], [headers, policy], artifact([]));

    expect(result.findings.map((f) => [f.ruleId, f.verified, f.evidence?.correlation])).toEqual([
      ['XSS-002', true, 'runtime-property'],
      ['CONF-001', true, 'runtime-property'],
    ]);
    expect(result.stats).toEqual({ verified: 2, dynamicOnly: 0 });
  });
});

describe('correlate: inmutabilidad y determinismo', () => {
  it('no muta el estático original (puede venir de caché)', () => {
    const sqli = staticFinding('SQLI-001', 'sql-injection', 'src/routes.js', 6);
    const snapshot = structuredClone(sqli);
    const art = artifact([route('GET', '/users/:id', 'src/routes.js', [{ ruleId: 'SQLI-001', filePath: 'src/routes.js', line: 6, via: 'handler' }])]);
    const dyn = dynamicFinding('DAST-101', 'sql-injection', 'GET /users/:id', 'GET http://x/users/1', "'");

    const result = correlate([sqli], [dyn], art);

    expect(sqli).toEqual(snapshot);
    expect(sqli.verified).toBeUndefined();
    expect(sqli.evidence).toBeUndefined();
    expect(result.findings[0]).not.toBe(sqli);
    expect(result.findings[0].verified).toBe(true);
  });

  it('dos dinámicos sobre el mismo estático: un solo clon, gana la confianza mayor', () => {
    const sqli = staticFinding('SQLI-001', 'sql-injection', 'src/db.js', 3, 'low');
    const art = artifact([
      route('GET', '/users/:id', 'src/routes.js', [{ ruleId: 'SQLI-001', filePath: 'src/db.js', line: 3, via: 'import-graph' }]),
      route('GET', '/admin/:id', 'src/admin.js', [{ ruleId: 'SQLI-001', filePath: 'src/db.js', line: 3, via: 'handler' }]),
    ]);
    const viaImport = dynamicFinding('DAST-101', 'sql-injection', 'GET /users/:id', 'GET http://x/users/1', "'");
    const viaHandler = dynamicFinding('DAST-101', 'sql-injection', 'GET /admin/:id', 'GET http://x/admin/1', "' OR 1=1");

    const result = correlate([sqli], [viaImport, viaHandler], art);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].confidence).toBe('high');
    expect(result.findings[0].evidence?.correlation).toBe('handler');
    expect(result.findings[0].evidence?.request).toBe('GET http://x/admin/1');
    expect(result.stats).toEqual({ verified: 1, dynamicOnly: 0 });
  });

  it('mantiene el orden de los estáticos y añade los dinámicos no correlacionados al final, en orden', () => {
    const a = staticFinding('XSS-001', 'xss', 'src/a.js', 1);
    const b = staticFinding('SQLI-001', 'sql-injection', 'src/routes.js', 6);
    const c = staticFinding('CMDI-001', 'command-injection', 'src/c.js', 2);
    const art = artifact([route('GET', '/users/:id', 'src/routes.js', [{ ruleId: 'SQLI-001', filePath: 'src/routes.js', line: 6, via: 'handler' }])]);
    const first = dynamicFinding('DAST-103', 'command-injection', 'GET /users/:id', 'GET http://x/users/1', 'a;sleep');
    const second = dynamicFinding('DAST-101', 'sql-injection', 'GET /users/:id', 'GET http://x/users/2', "'");

    const result = correlate([a, b, c], [first, second], art);

    expect(result.findings.map((f) => f.ruleId)).toEqual(['XSS-001', 'SQLI-001', 'CMDI-001', 'DAST-103']);
    expect(result.findings[3]).toBe(first);
  });
});

describe('correlate: revisión de enlace (no verificar lo que no corresponde)', () => {
  const ref = (ruleId: string, file: string, line: number, via: 'handler' | 'import-graph' = 'handler'): StaticFindingRef => ({ ruleId, filePath: file, line, via });

  it('dos SQLi en líneas distintas (mismo fichero): no se verifica ninguno y el dinámico se queda', () => {
    const a = staticFinding('SQLI-001', 'sql-injection', 'src/app.js', 8);
    const b = staticFinding('SQLI-002', 'sql-injection', 'src/app.js', 12);
    const art = artifact([route('GET', '/users/:id', 'src/app.js', [ref('SQLI-001', 'src/app.js', 8), ref('SQLI-002', 'src/app.js', 12)])]);
    const dyn = dynamicFinding('DAST-101', 'sql-injection', 'GET /users/:id', 'GET http://x/users/1', "'");

    const result = correlate([a, b], [dyn], art);

    expect(result.findings.filter((f) => f.verified === true && f.source !== 'dynamic')).toHaveLength(0);
    expect(result.findings[2].ruleId).toBe('DAST-101');
    expect(result.findings[2].message).toContain('SQLI-001 src/app.js:8, SQLI-002 src/app.js:12');
    expect(result.stats).toEqual({ verified: 0, dynamicOnly: 1 });
  });

  it('dos SQLi en la misma línea: se verifican ambos, y una tercera en otra línea de import-graph no los frena', () => {
    const a = staticFinding('SQLI-001', 'sql-injection', 'src/app.js', 8);
    const b = staticFinding('SQLI-003', 'sql-injection', 'src/app.js', 8);
    const far = staticFinding('SQLI-002', 'sql-injection', 'src/db.js', 3);
    const art = artifact([
      route('GET', '/users/:id', 'src/app.js', [ref('SQLI-001', 'src/app.js', 8), ref('SQLI-003', 'src/app.js', 8), ref('SQLI-002', 'src/db.js', 3, 'import-graph')]),
    ]);
    const dyn = dynamicFinding('DAST-101', 'sql-injection', 'GET /users/:id', 'GET http://x/users/1', "'");

    const result = correlate([a, b, far], [dyn], art);

    expect(result.findings.map((f) => [f.ruleId, f.verified])).toEqual([
      ['SQLI-001', true],
      ['SQLI-003', true],
      ['SQLI-002', undefined],
    ]);
    expect(result.stats).toEqual({ verified: 2, dynamicOnly: 0 });
  });

  it('no verifica un estático de otra categoría en la misma línea', () => {
    const cmd = staticFinding('CMDI-001', 'command-injection', 'src/app.js', 8);
    const sqli = staticFinding('SQLI-001', 'sql-injection', 'src/app.js', 8);
    const art = artifact([route('GET', '/users/:id', 'src/app.js', [ref('CMDI-001', 'src/app.js', 8), ref('SQLI-001', 'src/app.js', 8)])]);
    const dyn = dynamicFinding('DAST-101', 'sql-injection', 'GET /users/:id', 'GET http://x/users/1', "'");

    const result = correlate([cmd, sqli], [dyn], art);

    expect(result.findings.map((f) => [f.ruleId, f.verified])).toEqual([
      ['CMDI-001', undefined],
      ['SQLI-001', true],
    ]);
  });

  it('un endpoint no verifica el estático de otra ruta ni de otro método', () => {
    const sqli = staticFinding('SQLI-001', 'sql-injection', 'src/a.js', 4);
    const art = artifact([
      route('GET', '/a/:id', 'src/a.js', [ref('SQLI-001', 'src/a.js', 4)]),
      route('GET', '/b/:id', 'src/b.js', []),
      route('POST', '/a/:id', 'src/c.js', []),
    ]);
    const onB = dynamicFinding('DAST-101', 'sql-injection', 'GET /b/:id', 'GET http://x/b/1', "'");
    const onPost = dynamicFinding('DAST-101', 'sql-injection', 'POST /a/:id', 'POST http://x/a/1', "'");

    const result = correlate([sqli], [onB, onPost], art);

    expect(result.findings[0]).toBe(sqli);
    expect(result.findings.slice(1)).toEqual([onB, onPost]);
    expect(result.stats).toEqual({ verified: 0, dynamicOnly: 2 });
  });

  it('un endpoint que no casa ninguna ruta (nivel target) no lanza: inyección queda dinámica', () => {
    const sqli = staticFinding('SQLI-001', 'sql-injection', 'src/a.js', 4);
    const art = artifact([route('GET', '/a/:id', 'src/a.js', [ref('SQLI-001', 'src/a.js', 4)])]);
    const dyn = dynamicFinding('DAST-101', 'sql-injection', 'GET /', 'GET http://x/', "'");
    const noEndpoint = { ...dynamicFinding('DAST-101', 'sql-injection', 'x', 'GET http://x/', "'"), endpoint: undefined };

    expect(() => correlate([sqli], [dyn, noEndpoint], art)).not.toThrow();
    const result = correlate([sqli], [dyn, noEndpoint], art);
    expect(result.findings).toHaveLength(3);
    expect(result.stats).toEqual({ verified: 0, dynamicOnly: 2 });
  });

  it('una ruta ALL se ataca como GET y su estático se enlaza', () => {
    const sqli = staticFinding('SQLI-001', 'sql-injection', 'src/a.js', 4);
    const art = artifact([route('ALL', '/a/:id', 'src/a.js', [ref('SQLI-001', 'src/a.js', 4)])]);
    const dyn = dynamicFinding('DAST-101', 'sql-injection', 'GET /a/:id', 'GET http://x/a/1', "'");

    const result = correlate([sqli], [dyn], art);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].verified).toBe(true);
  });

  it('DAST-105 solo enlaza XSS-001: ni XSS-002 (helmet) ni XSS-004 (redirect) de ficheros alcanzables', () => {
    const helmet = staticFinding('XSS-002', 'xss', 'src/app.js', 1);
    const redirect = staticFinding('XSS-004', 'xss', 'src/routes.js', 9);
    const art = artifact([route('GET', '/q', 'src/routes.js', [ref('XSS-002', 'src/app.js', 1, 'import-graph'), ref('XSS-004', 'src/routes.js', 9)])]);
    const dyn = dynamicFinding('DAST-105', 'xss', 'GET /q', 'GET http://x/q?x=1', '<s>');

    const result = correlate([helmet, redirect], [dyn], art);

    expect(result.findings.map((f) => [f.ruleId, f.verified])).toEqual([
      ['XSS-002', undefined],
      ['XSS-004', undefined],
      ['DAST-105', true],
    ]);
    expect(result.findings[2].source).toBe('dynamic');

    const reflected = staticFinding('XSS-001', 'xss', 'src/routes.js', 7);
    const withReflected = artifact([route('GET', '/q', 'src/routes.js', [ref('XSS-001', 'src/routes.js', 7), ref('XSS-004', 'src/routes.js', 9)])]);
    const linked = correlate([reflected, redirect], [dyn], withReflected);
    expect(linked.findings.map((f) => [f.ruleId, f.verified])).toEqual([
      ['XSS-001', true],
      ['XSS-004', undefined],
    ]);
  });

  it('DAST-011 (open redirect) usa el algoritmo de inyección: enlaza XSS-004 del endpoint, no XSS-001 ni la tabla de hermanas', () => {
    const reflected = staticFinding('XSS-001', 'xss', 'src/routes.js', 7);
    const redirect = staticFinding('XSS-004', 'xss', 'src/routes.js', 9);
    const art = artifact([route('GET', '/go', 'src/routes.js', [ref('XSS-001', 'src/routes.js', 7), ref('XSS-004', 'src/routes.js', 9)])]);
    const dyn = dynamicFinding('DAST-011', 'xss', 'GET /go', 'GET http://x/go?next=http://evil', 'http://evil');

    const result = correlate([reflected, redirect], [dyn], art);

    expect(result.findings.map((f) => [f.ruleId, f.verified, f.evidence?.correlation])).toEqual([
      ['XSS-001', undefined, undefined],
      ['XSS-004', true, 'handler'],
    ]);

    // Un XSS-004 de otro endpoint no se enlaza por ser el único del proyecto (no hay tabla de hermanas para DAST-011).
    const other = correlate([redirect], [dynamicFinding('DAST-011', 'xss', 'GET /else', 'GET http://x/else', 'http://evil')], artifact([route('GET', '/else', 'src/e.js', [])]));
    expect(other.findings[0]).toBe(redirect);
    expect(other.stats).toEqual({ verified: 0, dynamicOnly: 1 });
  });

  it('hermanas de nivel proyecto (CSP/helmet) enlazan sin depender del endpoint, también con "GET /" fuera del artefacto', () => {
    const helmet = staticFinding('XSS-002', 'xss', 'src/server.js', 2);
    const art = artifact([route('GET', '/users/:id', 'src/routes.js', [])]);
    const dyn = dynamicFinding('DAST-001', 'xss', 'GET /', 'GET http://x/');

    const result = correlate([helmet], [dyn], art);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe('XSS-002');
    expect(result.findings[0].evidence?.correlation).toBe('runtime-property');
  });

  it('DAST-005/006/008 prefieren la hermana del fichero del handler del endpoint', () => {
    const here = staticFinding('ERR-001', 'error-handling', 'src/routes.js', 7);
    const elsewhere = staticFinding('ERR-001', 'error-handling', 'src/other.js', 3);
    const art = artifact([route('GET', '/boom', 'src/routes.js', [])]);
    const dyn = dynamicFinding('DAST-006', 'error-handling', 'GET /boom', 'GET http://x/boom');

    const result = correlate([elsewhere, here], [dyn], art);

    expect(result.findings.map((f) => [f.filePath, f.verified])).toEqual([
      [`${ROOT}/src/other.js`, undefined],
      [`${ROOT}/src/routes.js`, true],
    ]);
    // Sin esa preferencia hay dos candidatos y no se adivina.
    const unmatched = correlate([elsewhere, here], [dynamicFinding('DAST-006', 'error-handling', 'GET /nope', 'GET http://x/nope')], art);
    expect(unmatched.stats).toEqual({ verified: 0, dynamicOnly: 1 });
  });

  it('un dinámico que enlaza no se emite aparte; uno que no enlaza sí (DAST-002 sin hermana)', () => {
    const conf = staticFinding('CONF-003', 'misconfiguration', 'src/routes.js', 7);
    const art = artifact([route('GET', '/login', 'src/routes.js', [])]);
    const linked = dynamicFinding('DAST-005', 'misconfiguration', 'GET /login', 'GET http://x/login');
    const free = dynamicFinding('DAST-002', 'misconfiguration', 'GET /', 'GET http://x/');

    const result = correlate([conf], [linked, free], art);

    expect(result.findings.map((f) => f.ruleId)).toEqual(['CONF-003', 'DAST-002']);
    expect(result.stats).toEqual({ verified: 1, dynamicOnly: 1 });
  });

  it('el clon es profundo: tocar sus sub-objetos no altera el estático ni el dinámico', () => {
    const sqli = staticFinding('SQLI-001', 'sql-injection', 'src/a.js', 4);
    sqli.references = ['https://cwe.mitre.org/data/definitions/89.html'];
    const art = artifact([route('GET', '/a/:id', 'src/a.js', [ref('SQLI-001', 'src/a.js', 4)])]);
    const dyn = dynamicFinding('DAST-101', 'sql-injection', 'GET /a/:id', 'GET http://x/a/1', "'");
    const evidenceSnapshot = structuredClone(dyn.evidence);

    const [out] = correlate([sqli], [dyn], art).findings;
    out.references.push('mutated');
    if (out.evidence) out.evidence.request = 'mutated';

    expect(out).not.toBe(sqli);
    expect(out.references).not.toBe(sqli.references);
    expect(sqli.references).toEqual(['https://cwe.mitre.org/data/definitions/89.html']);
    expect(sqli.evidence).toBeUndefined();
    expect(dyn.evidence).toEqual(evidenceSnapshot);
  });
});
