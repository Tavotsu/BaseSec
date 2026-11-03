import { describe, it, expect } from 'vitest';
import { ALL_DAST_RULES } from '../../src/dast/rules';
import { DAST001, DAST002, DAST003, DAST007 } from '../../src/dast/rules/headers';
import { DAST004 } from '../../src/dast/rules/cors';
import { DAST005 } from '../../src/dast/rules/cookies';
import { DAST006 } from '../../src/dast/rules/errors';
import type { DastObservation, DastProbeContext, DastRule, DastTarget, HttpRequestOptions, HttpResponse } from '../../src/dast/types';
import { BudgetExceededError } from '../../src/dast/types';
import type { HttpClient } from '../../src/dast/http';
import type { Finding } from '../../src/rules/types';
import { dynamicFinding } from '../../src/dast/probe';

const HTTP_TARGET: DastTarget = { origin: 'http://localhost:3000', https: false };
const HTTPS_TARGET: DastTarget = { origin: 'https://app.example.test', https: true };
const HTML = { 'content-type': 'text/html; charset=utf-8' };
const SECURE_HTML = {
  'content-type': 'text/html',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
};

function res(overrides: Partial<HttpResponse> = {}): HttpResponse {
  return {
    status: 200,
    headers: {},
    body: '',
    contentEncoding: null,
    bodyDecoded: true,
    url: 'http://localhost:3000/',
    redirects: [],
    timedOut: false,
    elapsedMs: 5,
    ...overrides,
  };
}

function obs(response: Partial<HttpResponse> = {}, endpoint = 'GET /', url = 'http://localhost:3000/'): DastObservation {
  return { endpoint, url, method: 'GET', response: res(response) };
}

type Client = Pick<HttpClient, 'request'>;

const unusedClient: Client = {
  request: async () => {
    throw new Error('network must not be used by this rule');
  },
};

function ctx(
  observations: DastObservation[],
  options: { target?: DastTarget; client?: Client; knownSecrets?: string[] } = {},
): DastProbeContext {
  return {
    target: options.target ?? HTTP_TARGET,
    observations,
    client: options.client ?? unusedClient,
    knownSecrets: options.knownSecrets ?? [],
  };
}

async function run(rule: DastRule, context: DastProbeContext): Promise<Finding[]> {
  return rule.probe(context);
}

interface Call {
  method: string;
  url: string;
  opts?: HttpRequestOptions;
}

function fakeClient(handler: (call: Call) => HttpResponse | Promise<HttpResponse>): { client: Client; calls: Call[] } {
  const calls: Call[] = [];
  const client: Client = {
    request: async (method, url, opts) => {
      const call: Call = { method, url, opts };
      calls.push(call);
      return handler(call);
    },
  };
  return { client, calls };
}

describe('DAST-001 missing security headers', () => {
  it('reports one finding listing all missing headers on an HTML response', async () => {
    const findings = await run(DAST001, ctx([obs({ headers: HTML })]));
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('X-Content-Type-Options');
    expect(findings[0].message).toContain('X-Frame-Options');
    expect(findings[0].message).toContain('Referrer-Policy');
    expect(findings[0].endpoint).toBe('http://localhost:3000');
  });

  it('reports nothing when all headers are present', async () => {
    expect(await run(DAST001, ctx([obs({ headers: SECURE_HTML })]))).toHaveLength(0);
  });

  it('accepts CSP frame-ancestors in place of X-Frame-Options', async () => {
    const headers = {
      'content-type': 'text/html',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    };
    expect(await run(DAST001, ctx([obs({ headers })]))).toHaveLength(0);
  });

  it('treats a nosniff value other than nosniff as missing', async () => {
    const findings = await run(DAST001, ctx([obs({ headers: { ...SECURE_HTML, 'x-content-type-options': 'sniff' } })]));
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('X-Content-Type-Options');
  });

  it('ignores JSON responses', async () => {
    expect(await run(DAST001, ctx([obs({ headers: { 'content-type': 'application/json' } })]))).toHaveLength(0);
  });
});

describe('DAST-002 missing HSTS', () => {
  it('reports HTTPS without HSTS', async () => {
    const findings = await run(DAST002, ctx([obs({ headers: {} })], { target: HTTPS_TARGET }));
    expect(findings).toHaveLength(1);
  });

  it('never reports plain HTTP targets', async () => {
    expect(await run(DAST002, ctx([obs({ headers: {} })], { target: HTTP_TARGET }))).toHaveLength(0);
  });

  it('reports max-age=0', async () => {
    const findings = await run(
      DAST002,
      ctx([obs({ headers: { 'strict-transport-security': 'max-age=0' } })], { target: HTTPS_TARGET }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('max-age=0');
  });

  it('accepts a positive max-age', async () => {
    const findings = await run(
      DAST002,
      ctx([obs({ headers: { 'strict-transport-security': 'max-age=31536000; includeSubDomains' } })], { target: HTTPS_TARGET }),
    );
    expect(findings).toHaveLength(0);
  });
});

describe('DAST-003 missing or weak CSP', () => {
  it('reports an HTML response without CSP', async () => {
    const findings = await run(DAST003, ctx([obs({ headers: HTML })]));
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('no Content-Security-Policy');
  });

  it("reports script-src with 'unsafe-inline'", async () => {
    const findings = await run(
      DAST003,
      ctx([obs({ headers: { ...HTML, 'content-security-policy': "script-src 'self' 'unsafe-inline'" } })]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain("'unsafe-inline'");
  });

  it('accepts default-src self when script-src is absent', async () => {
    expect(
      await run(DAST003, ctx([obs({ headers: { ...HTML, 'content-security-policy': "default-src 'self'" } })])),
    ).toHaveLength(0);
  });

  it('does not treat a subdomain wildcard as the bare * token', async () => {
    expect(
      await run(
        DAST003,
        ctx([obs({ headers: { ...HTML, 'content-security-policy': 'script-src https://*.cdn.com' } })]),
      ),
    ).toHaveLength(0);
  });

  it('treats a report-only policy as no policy, with the missing-CSP message', async () => {
    const findings = await run(
      DAST003,
      ctx([obs({ headers: { ...HTML, 'content-security-policy-report-only': "default-src 'self'" } })]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('no Content-Security-Policy');
  });

  it('uses a different message for missing and weak policies', async () => {
    const missing = await run(DAST003, ctx([obs({ headers: HTML })]));
    const weak = await run(
      DAST003,
      ctx([obs({ headers: { ...HTML, 'content-security-policy': "script-src 'unsafe-eval'" } })]),
    );
    expect(missing[0].message).not.toEqual(weak[0].message);
  });
});

describe('DAST-004 permissive CORS at runtime', () => {
  const ORIGIN_RE = /^https:\/\/bs-[0-9a-f]{8}\.invalid$/;

  function corsClient(headersFor: (origin: string) => Record<string, string>): { client: Client; calls: Call[] } {
    return fakeClient((call) => {
      const origin = String(call.opts?.headers?.Origin ?? '');
      return res({ url: call.url, headers: headersFor(origin) });
    });
  }

  it('reports a reflected Origin with credentials as high', async () => {
    const { client } = corsClient((origin) => ({
      'access-control-allow-origin': origin,
      'access-control-allow-credentials': 'true',
    }));
    const findings = await run(DAST004, ctx([], { client }));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
  });

  it('reports a null origin with credentials as high', async () => {
    const { client } = corsClient(() => ({
      'access-control-allow-origin': 'null',
      'access-control-allow-credentials': 'true',
    }));
    const findings = await run(DAST004, ctx([], { client }));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
  });

  it('reports * with credentials as medium', async () => {
    const { client } = corsClient(() => ({
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    }));
    const findings = await run(DAST004, ctx([], { client }));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('medium');
  });

  it('reports nothing when the Origin is reflected without credentials', async () => {
    const { client } = corsClient((origin) => ({ 'access-control-allow-origin': origin }));
    expect(await run(DAST004, ctx([], { client }))).toHaveLength(0);
  });

  it('sends one GET with a random Origin under the .invalid TLD', async () => {
    const { client, calls } = corsClient(() => ({}));
    await run(DAST004, ctx([], { client }));
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe('GET');
    expect(calls[0].url).toBe('http://localhost:3000/');
    expect(String(calls[0].opts?.headers?.Origin)).toMatch(ORIGIN_RE);
  });

  it('propagates BudgetExceededError from the client', async () => {
    const client: Client = {
      request: async () => {
        throw new BudgetExceededError(5);
      },
    };
    await expect(run(DAST004, ctx([], { client }))).rejects.toBeInstanceOf(BudgetExceededError);
  });

  it('swallows other client errors and reports nothing', async () => {
    const client: Client = {
      request: async () => {
        throw new Error('ECONNREFUSED');
      },
    };
    expect(await run(DAST004, ctx([], { client }))).toHaveLength(0);
  });
});

describe('DAST-005 insecure cookie flags', () => {
  it('reports a cookie without flags, with the name and not the value', async () => {
    const findings = await run(
      DAST005,
      ctx([obs({ headers: { 'set-cookie': 'sid=VALUE-s3cr3t-42; Path=/' } })]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('sid');
    expect(findings[0].message).not.toContain('VALUE-s3cr3t-42');
    expect(JSON.stringify(findings[0])).not.toContain('VALUE-s3cr3t-42');
  });

  it('accepts HttpOnly and SameSite on HTTP', async () => {
    const findings = await run(
      DAST005,
      ctx([obs({ headers: { 'set-cookie': 'sid=abc; Path=/; HttpOnly; SameSite=Lax' } })]),
    );
    expect(findings).toHaveLength(0);
  });

  it('reports a missing Secure flag over HTTPS', async () => {
    const findings = await run(
      DAST005,
      ctx([obs({ headers: { 'set-cookie': 'sid=abc; Path=/; HttpOnly; SameSite=Lax' } })], { target: HTTPS_TARGET }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('Secure');
  });

  it('ignores deletion cookies (Max-Age=0)', async () => {
    const findings = await run(
      DAST005,
      ctx([obs({ headers: { 'set-cookie': 'sid=; Max-Age=0; Path=/' } })]),
    );
    expect(findings).toHaveLength(0);
  });

  it('emits one finding per observation', async () => {
    const bad = { headers: { 'set-cookie': 'sid=abc; Path=/' } };
    const findings = await run(
      DAST005,
      ctx([obs(bad, 'GET /', 'http://localhost:3000/'), obs(bad, 'GET /health', 'http://localhost:3000/health')]),
    );
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.endpoint)).toEqual(['GET /', 'GET /health']);
  });
});

describe('DAST-006 stack trace exposed', () => {
  const STACK = [
    'Error: boom',
    '    at Object.<anonymous> (/app/src/x.js:10:5)',
    '    at Module._compile (node:internal/modules/cjs/loader:1234:14)',
  ].join('\n');

  it('reports a 500 whose body contains a Node stack', async () => {
    const findings = await run(DAST006, ctx([obs({ status: 500, body: STACK, headers: {} })]));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].codeSnippet).toContain('at Object.<anonymous>');
  });

  it('ignores a 200 with a stack', async () => {
    expect(await run(DAST006, ctx([obs({ status: 200, body: STACK })]))).toHaveLength(0);
  });

  it('does not report an absolute path without stack formatting', async () => {
    expect(await run(DAST006, ctx([obs({ status: 500, body: 'failed reading /var/www/data' })]))).toHaveLength(0);
  });

  it('ignores bodies that were not decoded', async () => {
    expect(await run(DAST006, ctx([obs({ status: 500, body: STACK, bodyDecoded: false })]))).toHaveLength(0);
  });
});

describe('DAST-007 server banner leakage', () => {
  it('reports X-Powered-By', async () => {
    const findings = await run(DAST007, ctx([obs({ headers: { 'x-powered-by': 'Express' } })]));
    expect(findings).toHaveLength(1);
    expect(findings[0].codeSnippet).toBe('x-powered-by: Express');
  });

  it('reports a Server header with a version', async () => {
    const findings = await run(DAST007, ctx([obs({ headers: { server: 'nginx/1.25.3' } })]));
    expect(findings).toHaveLength(1);
  });

  it('ignores a Server header without a version', async () => {
    expect(await run(DAST007, ctx([obs({ headers: { server: 'nginx' } })]))).toHaveLength(0);
  });
});

describe('shared rule contract', () => {
  it('ignores timed-out observations (status 0) in every rule', async () => {
    const timedOut = obs({
      status: 0,
      timedOut: true,
      bodyDecoded: false,
      headers: {
        'content-type': 'text/html',
        'set-cookie': 'sid=abc',
        'x-powered-by': 'Express',
        'access-control-allow-origin': '*',
        'access-control-allow-credentials': 'true',
      },
    });
    const reflecting: Client = {
      request: async () => res({ status: 0, timedOut: true, headers: { 'access-control-allow-credentials': 'true', 'access-control-allow-origin': '*' } }),
    };
    for (const rule of ALL_DAST_RULES) {
      const findings = await run(rule, ctx([timedOut], { target: HTTPS_TARGET, client: reflecting }));
      expect(findings, rule.id).toHaveLength(0);
    }
  });

  it('exposes seven rules with unique, well-formed IDs in order', () => {
    expect(ALL_DAST_RULES).toHaveLength(7);
    const ids = ALL_DAST_RULES.map((rule) => rule.id);
    expect(new Set(ids).size).toBe(7);
    for (const id of ids) {
      expect(id).toMatch(/^[A-Z]+-\d{3}$/);
    }
    expect(ids).toEqual(['DAST-001', 'DAST-002', 'DAST-003', 'DAST-004', 'DAST-005', 'DAST-006', 'DAST-007']);
  });

  it('keeps cookie values and known secrets out of evidence and code snippets', async () => {
    const SECRET = 'MYTOKENVALUE999';
    const findings = await run(
      DAST005,
      ctx(
        [obs({ headers: { 'set-cookie': 'sess=COOKIEVAL9876; Path=/', 'x-debug': `token ${SECRET}` } })],
        { knownSecrets: [SECRET] },
      ),
    );
    expect(findings).toHaveLength(1);
    const serialized = JSON.stringify([findings[0].evidence, findings[0].codeSnippet]);
    expect(serialized).not.toContain('COOKIEVAL9876');
    expect(serialized).not.toContain(SECRET);
  });
});

describe('review hardening: DAST-001/002/003/007 precision', () => {
  it('DAST-001 accepts NoSniff in any case', async () => {
    const headers = { ...SECURE_HTML, 'x-content-type-options': 'NoSniff' };
    expect(await run(DAST001, ctx([obs({ headers })]))).toHaveLength(0);
  });

  it('DAST-003 reports a CSP with neither script-src nor default-src as not restricting scripts', async () => {
    const findings = await run(
      DAST003,
      ctx([obs({ headers: { ...HTML, 'content-security-policy': "img-src 'self'; frame-ancestors 'none'" } })]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('does not restrict scripts');
  });

  it('DAST-003 parses directive names case-insensitively', async () => {
    const weak = await run(
      DAST003,
      ctx([obs({ headers: { ...HTML, 'content-security-policy': "SCRIPT-SRC 'self' 'UNSAFE-INLINE'" } })]),
    );
    expect(weak).toHaveLength(1);
    const ok = await run(
      DAST003,
      ctx([obs({ headers: { ...HTML, 'content-security-policy': "Script-Src 'self'" } })]),
    );
    expect(ok).toHaveLength(0);
  });

  it("DAST-003 does not flag 'unsafe-inline' when a nonce or hash is present, but still flags unsafe-eval", async () => {
    const nonce = { ...HTML, 'content-security-policy': "script-src 'self' 'nonce-abc123' 'unsafe-inline'" };
    expect(await run(DAST003, ctx([obs({ headers: nonce })]))).toHaveLength(0);
    const hash = { ...HTML, 'content-security-policy': "script-src 'sha256-AAAA=' 'unsafe-inline'" };
    expect(await run(DAST003, ctx([obs({ headers: hash })]))).toHaveLength(0);
    const evalToo = { ...HTML, 'content-security-policy': "script-src 'nonce-abc' 'unsafe-inline' 'unsafe-eval'" };
    expect(await run(DAST003, ctx([obs({ headers: evalToo })]))).toHaveLength(1);
  });

  it('DAST-003 treats repeated headers as independent policies: weak only if none restricts scripts', async () => {
    const strict = "default-src 'self'";
    const weak = "script-src 'unsafe-inline'";
    const bothArray = { ...HTML, 'content-security-policy': [weak, strict] };
    expect(await run(DAST003, ctx([obs({ headers: bothArray })]))).toHaveLength(0);
    const onlyWeak = { ...HTML, 'content-security-policy': [weak, "img-src 'self'"] };
    expect(await run(DAST003, ctx([obs({ headers: onlyWeak })]))).toHaveLength(1);
  });

  it('DAST-003 treats comma-separated policies in one header as independent policies', async () => {
    const mixed = { ...HTML, 'content-security-policy': "script-src 'unsafe-inline', script-src 'self'" };
    expect(await run(DAST003, ctx([obs({ headers: mixed })]))).toHaveLength(0);
    const allWeak = { ...HTML, 'content-security-policy': "script-src 'unsafe-inline', img-src 'self'" };
    expect(await run(DAST003, ctx([obs({ headers: allWeak })]))).toHaveLength(1);
  });

  it('DAST-001 sees frame-ancestors in any of several policies', async () => {
    const headers = {
      ...SECURE_HTML,
      'x-frame-options': undefined as unknown as string,
      'content-security-policy': ["default-src 'self'", "frame-ancestors 'none'"],
    };
    delete (headers as Record<string, unknown>)['x-frame-options'];
    expect(await run(DAST001, ctx([obs({ headers })]))).toHaveLength(0);
  });

  it('DAST-002 accepts a quoted/spaced max-age and HSTS in any case', async () => {
    const headers = { 'strict-transport-security': 'Max-Age = 31536000; includeSubDomains' };
    expect(await run(DAST002, ctx([obs({ headers })], { target: HTTPS_TARGET }))).toHaveLength(0);
  });

  it('DAST-007 does not report vendor names without a version, and reports Apache/2.4', async () => {
    expect(await run(DAST007, ctx([obs({ headers: { server: 'cloudflare' } })]))).toHaveLength(0);
    expect(await run(DAST007, ctx([obs({ headers: { server: 'Apache/2.4' } })]))).toHaveLength(1);
    expect(await run(DAST007, ctx([obs({ headers: { 'x-powered-by': '' } })]))).toHaveLength(0);
  });

  it('DAST-007 sanitises hostile header values embedded in the message', async () => {
    const findings = await run(
      DAST007,
      ctx([obs({ headers: { 'x-powered-by': '<img src=x onerror=alert(1)>`[x](javascript:1)' } })]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].message).not.toMatch(/[<>`[\]]/);
  });
});

describe('review hardening: DAST-005 cookie parsing', () => {
  it('accepts flags in any case and with spaces around =', async () => {
    const cookie = 'sid=v; path=/; httponly; Secure; SameSite = Lax';
    expect(await run(DAST005, ctx([obs({ headers: { 'set-cookie': cookie } })], { target: HTTPS_TARGET }))).toHaveLength(0);
  });

  it('ignores cookies expiring in the past and reports ones expiring in the future', async () => {
    const past = 'sid=v; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
    expect(await run(DAST005, ctx([obs({ headers: { 'set-cookie': past } })]))).toHaveLength(0);
    const future = 'sid=v; Expires=Fri, 01 Jan 2100 00:00:00 GMT';
    expect(await run(DAST005, ctx([obs({ headers: { 'set-cookie': future } })]))).toHaveLength(1);
  });

  it('lets a positive Max-Age win over a past Expires (RFC 6265)', async () => {
    const cookie = 'sid=v; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
    expect(await run(DAST005, ctx([obs({ headers: { 'set-cookie': cookie } })]))).toHaveLength(1);
  });
});

describe('review hardening: DAST-006 stack detection', () => {
  it('ignores prose that starts with "at" inside an HTML 500 page', async () => {
    const body = '<html><body><h1>Error</h1>\n  at 5pm the server in /var/www:1:2 restarts\n  at the end of /var/log\n</body></html>';
    expect(await run(DAST006, ctx([obs({ status: 500, body })]))).toHaveLength(0);
  });

  it('does not accept a bare node_modules/ mention as a stack', async () => {
    const body = 'at the root of node_modules/ there is nothing';
    expect(await run(DAST006, ctx([obs({ status: 500, body })]))).toHaveLength(0);
  });

  it('detects the Express default handler format (<br> and &nbsp; on one line)', async () => {
    const body = '<pre>Error: boom<br> &nbsp; &nbsp;at handler (/app/src/x.js:10:5)<br> &nbsp; &nbsp;at next (/app/node_modules/express/lib/router/layer.js:95:5)</pre>';
    expect(await run(DAST006, ctx([obs({ status: 500, body })]))).toHaveLength(1);
  });

  it('detects stacks embedded in JSON with literal \\n', async () => {
    const body = JSON.stringify({ error: 'boom', stack: 'Error: boom\n    at handler (/app/src/x.js:10:5)\n    at next (/app/y.js:1:1)' });
    expect(await run(DAST006, ctx([obs({ status: 500, body })]))).toHaveLength(1);
  });

  it('detects a bare-location frame and a Windows path', async () => {
    expect(await run(DAST006, ctx([obs({ status: 500, body: 'Error\n    at /app/x.js:1:2' })]))).toHaveLength(1);
    expect(await run(DAST006, ctx([obs({ status: 500, body: 'Error\n    at f (C:\\app\\x.js:1:2)' })]))).toHaveLength(1);
  });

  it('runs in linear time on hostile bodies', async () => {
    const hostile = `at ${'/:1'.repeat(300)}\n`.repeat(2000) + 'x'.repeat(300000);
    const start = Date.now();
    await run(DAST006, ctx([obs({ status: 500, body: hostile })]));
    expect(Date.now() - start).toBeLessThan(1500);
  });
});

describe('review hardening: DAST-004 comparison', () => {
  const credentials = { 'access-control-allow-credentials': 'TRUE' };

  it('does not report when ACAO merely contains the sent Origin', async () => {
    const { client } = fakeClient((call) => {
      const origin = (call.opts?.headers as Record<string, string>).Origin;
      return res({ headers: { ...credentials, 'access-control-allow-origin': `${origin}.evil.test` } });
    });
    expect(await run(DAST004, ctx([], { client }))).toHaveLength(0);
  });

  it('reports a reflected Origin with credentials in any case', async () => {
    const { client } = fakeClient((call) => {
      const origin = (call.opts?.headers as Record<string, string>).Origin;
      return res({ headers: { ...credentials, 'access-control-allow-origin': origin } });
    });
    const findings = await run(DAST004, ctx([], { client }));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
  });
});

describe('review hardening: evidence never leaks secrets', () => {
  const COOKIE_VAL = 'CKVAL_7f3a9c1d';
  const COOKIE_VAL2 = 'CKVAL_second_55aa';
  const AUTH_VAL = 'AUTHVAL_8e2b4d6f';
  const SECRET = 'KNOWNSECRET_1a2b3c4d5e';

  function everyText(findings: Finding[]): string {
    return JSON.stringify(findings.map((f) => [f.evidence, f.codeSnippet, f.message, f.endpoint]));
  }

  it('keeps cookie, authorization and known-secret values out of every rule output', async () => {
    const headers = {
      ...HTML,
      'set-cookie': [`sid=${COOKIE_VAL}; Path=/`, `other=${COOKIE_VAL2}`],
      cookie: `sid=${COOKIE_VAL}`,
      authorization: `Basic ${AUTH_VAL}`,
      'x-powered-by': `Express ${SECRET}`,
      server: `nginx/1.2 ${SECRET}`,
      'x-custom': `${SECRET}`,
      'access-control-allow-credentials': 'true',
      'access-control-allow-origin': '*',
    };
    const observation = obs({ status: 500, headers, body: `Error\n    at f (/app/x.js:1:2)\n${SECRET}` });
    const { client } = fakeClient(() => res({ headers }));
    const context = ctx([observation], { target: HTTPS_TARGET, client, knownSecrets: [SECRET] });
    const findings: Finding[] = [];
    for (const rule of ALL_DAST_RULES) findings.push(...(await run(rule, context)));
    expect(findings.length).toBeGreaterThanOrEqual(5);
    const text = everyText(findings);
    for (const secret of [COOKIE_VAL, COOKIE_VAL2, AUTH_VAL, SECRET]) {
      expect(text).not.toContain(secret);
    }
  });
});

describe('terminal control characters in dynamic findings', () => {
  const CONTROL_RE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/;
  const SINGLE_LINE_RE = /[\u0000-\u0008\u000A-\u001F\u007F-\u009F]/;
  const SNIPPET = '\u001b[2J\u001b]0;pwned\u0007at foo (/app/x.js:1:1)';
  const ENDPOINT = 'GET /\u001b[1mx';
  const MESSAGE = '\u001b[31mred\u001b[0m';

  function controlFinding() {
    return dynamicFinding({
      rule: DAST006,
      confidence: 'high',
      endpoint: ENDPOINT,
      message: MESSAGE,
      remediation: 'fix it',
      references: [],
      codeSnippet: SNIPPET,
      observation: obs({ status: 500, headers: HTML, body: 'Error\n    at f (/app/x.js:1:2)' }),
      knownSecrets: [],
    });
  }

  it('removes ESC, BEL and other control characters from every free-text field', () => {
    const finding = controlFinding();
    const fields = [finding.codeSnippet, finding.message, finding.endpoint, finding.evidence.request, finding.evidence.response];
    for (const text of fields) {
      expect(text).not.toContain('\u001b');
      expect(text).not.toContain('\u0007');
      expect(text).not.toMatch(CONTROL_RE);
    }
  });

  it('keeps the readable text', () => {
    const finding = controlFinding();
    expect(finding.message).toContain('red');
    expect(finding.codeSnippet).toContain('at foo (/app/x.js:1:1)');
    expect(finding.endpoint).toContain('x');
  });

  it('keeps newlines in multi-line evidence but not in codeSnippet or endpoint', () => {
    const finding = controlFinding();
    expect(finding.codeSnippet).not.toContain('\n');
    expect(finding.endpoint).not.toContain('\n');
    expect(finding.codeSnippet).not.toMatch(SINGLE_LINE_RE);
    expect(finding.evidence.response).toContain('\n');
    expect(finding.evidence.response).toContain('HTTP 500');
  });

  it('strips control characters from a DAST-006 hostile body end to end', async () => {
    // El ESC va dentro del frame (nombre de función), no al inicio de línea: el detector de DAST-006
    // exige que la línea empiece por "at", así que un ESC inicial no produce hallazgo.
    const body = 'Error\n    at Object.<anonymous>\u001b[2J (/app/src/x.js:10:5)\n';
    const findings = await run(DAST006, ctx([obs({ status: 500, headers: HTML, body, bodyDecoded: true })]));
    expect(findings).toHaveLength(1);
    expect(findings[0].codeSnippet).not.toContain('\u001b');
    expect(findings[0].codeSnippet).toContain('at Object.<anonymous>');
  });
});
