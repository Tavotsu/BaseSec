import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import type { AddressInfo } from 'node:net';
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { runDast, DastTargetUnreachableError } from '../../src/dast/runner';
import { DastConfigError } from '../../src/dast/config';
import { GuardError } from '../../src/dast/types';

let server: http.Server;
let origin: string;
let hits = 0;

function route(req: http.IncomingMessage, res: http.ServerResponse): void {
  hits++;
  if ((req.url ?? '').startsWith('/health')) {
    res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    return;
  }
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'x-powered-by': 'Express',
    'set-cookie': 'sid=abc123; Path=/',
  });
  res.end('<html><body>hello</body></html>');
}

beforeAll(async () => {
  server = http.createServer(route);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  hits = 0;
});

describe('runDast', () => {
  it('reports the header, cookie and banner findings of an HTML response', async () => {
    const result = await runDast({ url: origin, evidence: false });
    const ids = new Set(result.findings.map((f) => f.ruleId));

    expect(ids).toContain('DAST-001');
    expect(ids).toContain('DAST-003');
    expect(ids).toContain('DAST-005');
    expect(ids).toContain('DAST-007');
    expect(result.stats.dast?.mode).toBe('no-source');
    expect(result.stats.dast?.requests).toBeGreaterThanOrEqual(2);
    expect(result.stats.dast?.incomplete).toBeUndefined();
    expect(result.stats.filesScanned).toBe(0);
    expect(result.stats.rulesRun).toBe(7);
  });

  it('observes the healthcheck as a second endpoint', async () => {
    const result = await runDast({ url: origin, health: '/health', evidence: false });
    expect(result.stats.dast?.endpoints).toEqual({ total: 2, analyzed: 2, skippedMutating: 0, unresolved: 0 });
    expect(hits).toBeGreaterThanOrEqual(2);
  });

  it('runs only the selected rules', async () => {
    const result = await runDast({ url: origin, rules: ['DAST-007'], evidence: false });
    expect(result.findings.length).toBeGreaterThan(0);
    expect(new Set(result.findings.map((f) => f.ruleId))).toEqual(new Set(['DAST-007']));
    expect(result.stats.rulesRun).toBe(1);
  });

  it('rejects unknown rule IDs before sending any request', async () => {
    await expect(runDast({ url: origin, rules: ['NOPE-001'], evidence: false })).rejects.toThrow(DastConfigError);
    expect(hits).toBe(0);
  });

  it('rejects a healthcheck path that is an absolute URL', async () => {
    await expect(runDast({ url: origin, health: 'http://evil.example/x', evidence: false })).rejects.toThrow(
      DastConfigError,
    );
    expect(hits).toBe(0);
  });

  it('stops at the request budget, keeps the findings and marks the analysis incomplete', async () => {
    const result = await runDast({ url: origin, maxRequests: 1, evidence: false });
    expect(result.stats.dast?.incomplete).toBe('budget');
    expect(result.findings.length).toBeGreaterThan(0);
    expect(hits).toBeLessThanOrEqual(1);
  });

  it('throws DastTargetUnreachableError when the port is closed', async () => {
    const closed = http.createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const port = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));

    await expect(runDast({ url: `http://127.0.0.1:${port}`, evidence: false })).rejects.toThrow(
      DastTargetUnreachableError,
    );
  });

  it('blocks a public host without allowRemote and sends no request to it', async () => {
    const error = await runDast({
      url: 'http://probe.example.test:9/',
      resolver: async () => ['203.0.113.10'],
      evidence: false,
    }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(GuardError);
    expect((error as GuardError).code).toBe('remote-blocked');
    expect(hits).toBe(0);
  });

  it('rejects a missing $env: header variable before sending any request', async () => {
    await expect(
      runDast({
        url: origin,
        headers: { Authorization: 'Bearer $env:BASESEC_RUNNER_TEST_MISSING_VAR' },
        evidence: false,
      }),
    ).rejects.toThrow(DastConfigError);
    expect(hits).toBe(0);
  });

  it('rejects a non-positive rps', async () => {
    await expect(runDast({ url: origin, rps: 0, evidence: false })).rejects.toThrow(DastConfigError);
    expect(hits).toBe(0);
  });
});

describe('runDast endpoint count', () => {
  let hanging: http.Server;
  let hangingOrigin: string;
  const sockets = new Set<import('node:net').Socket>();

  beforeAll(async () => {
    hanging = http.createServer((req, res) => {
      // /hang nunca responde: la petición agota el requestTimeout.
      if ((req.url ?? '').startsWith('/hang')) return;
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end('<html><body>ok</body></html>');
    });
    hanging.on('connection', (socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
    });
    await new Promise<void>((resolve) => hanging.listen(0, '127.0.0.1', resolve));
    hangingOrigin = `http://127.0.0.1:${(hanging.address() as AddressInfo).port}`;
  });

  afterEach(() => {
    for (const socket of sockets) socket.destroy();
    sockets.clear();
  });

  afterAll(async () => {
    hanging.closeAllConnections();
    await new Promise<void>((resolve) => hanging.close(() => resolve()));
  });

  it('counts as analyzed only the endpoints that answered', async () => {
    const result = await runDast({
      url: hangingOrigin,
      health: '/hang',
      requestTimeout: 200,
      evidence: false,
    });
    expect(result.stats.dast?.endpoints).toEqual({ total: 2, analyzed: 1, skippedMutating: 0, unresolved: 0 });
  }, 15000);
});

describe('runDast evidence', () => {
  let evidenceBase: string;

  beforeEach(() => {
    evidenceBase = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-runner-evidence-'));
  });

  afterEach(() => {
    fs.rmSync(evidenceBase, { recursive: true, force: true });
  });

  it('writes one evidence file per finding and links it from the finding', async () => {
    const result = await runDast({ url: origin, evidenceDir: evidenceBase });

    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.evidence?.file).toBeDefined();
      expect(fs.existsSync(finding.evidence!.file!)).toBe(true);
      expect(finding.evidence!.file!.startsWith(evidenceBase)).toBe(true);
    }
    expect(result.stats.dast?.evidenceDir).toBeDefined();
  });

  it('writes no evidence and creates no directory with evidence: false', async () => {
    const target = path.join(evidenceBase, 'not-created');
    const result = await runDast({ url: origin, evidence: false, evidenceDir: target });

    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.evidence?.file).toBeUndefined();
    }
    expect(fs.existsSync(target)).toBe(false);
    expect(result.stats.dast?.evidenceDir).toBeUndefined();
  });
});

describe('runDast review hardening', () => {
  let echo: http.Server;
  let echoOrigin: string;
  let echoHits = 0;
  let slowRoot = false;
  let slowTimers: NodeJS.Timeout[] = [];
  let tmp: string;

  beforeAll(async () => {
    echo = http.createServer((req, res) => {
      echoHits++;
      if (slowRoot && req.url === '/') {
        slowTimers.push(setTimeout(() => res.writeHead(200).end('slow'), 1100));
        return;
      }
      // Refleja el Origin con credenciales (DAST-004) y devuelve en el body y en una cabecera inocua las cabeceras recibidas.
      const origin = String(req.headers.origin ?? '');
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'access-control-allow-origin': origin,
        'access-control-allow-credentials': 'true',
        'x-echo-custom': String(req.headers['x-custom-id'] ?? ''),
        'set-cookie': 'sid=abc123; Path=/',
      });
      res.end(`<html>${JSON.stringify(req.headers)}</html>`);
    });
    await new Promise<void>((resolve) => echo.listen(0, '127.0.0.1', resolve));
    echoOrigin = `http://127.0.0.1:${(echo.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    for (const timer of slowTimers) clearTimeout(timer);
    echo.closeAllConnections();
    await new Promise<void>((resolve) => echo.close(() => resolve()));
  });

  beforeEach(() => {
    echoHits = 0;
    slowRoot = false;
    slowTimers = [];
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-runner-review-'));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('attaches to DAST-004 the extra request that carried the Origin header, not the GET /', async () => {
    const result = await runDast({ url: echoOrigin, rules: ['DAST-004', 'DAST-005'], evidenceDir: tmp });
    const cors = result.findings.find((f) => f.ruleId === 'DAST-004');
    const cookie = result.findings.find((f) => f.ruleId === 'DAST-005');

    expect(cors?.evidence?.file).toBeDefined();
    expect(cookie?.evidence?.file).toBeDefined();
    const corsText = fs.readFileSync(cors!.evidence!.file!, 'utf-8');
    const cookieText = fs.readFileSync(cookie!.evidence!.file!, 'utf-8');
    expect(corsText).toMatch(/^Origin: https:\/\/bs-[0-9a-f]+\.invalid$/m);
    expect(cookieText).not.toMatch(/^Origin:/m);
  });

  it('gives every finding the evidence of its own endpoint when two responses are identical', async () => {
    const result = await runDast({ url: echoOrigin, health: '/other', rules: ['DAST-005'], evidenceDir: tmp });
    const findings = result.findings.filter((f) => f.ruleId === 'DAST-005');

    expect(findings.length).toBe(2);
    const requestLines = findings.map((f) => fs.readFileSync(f.evidence!.file!, 'utf-8').split('\n')[1]);
    expect(new Set(requestLines).size).toBe(2);
    expect(requestLines.some((line) => line.endsWith('/other HTTP/1.1'))).toBe(true);
  });

  it('never leaks user header values into findings, evidence files or stats', async () => {
    const BEARER = 'zq9-bearer-UNIQUE-7c1f2e';
    const CUSTOM = 'zq9-custom-UNIQUE-91ab33';
    process.env.BASESEC_RUNNER_REVIEW_TOKEN = BEARER;
    try {
      const result = await runDast({
        url: `http://someuser:zq9-pass-UNIQUE@${echoOrigin.slice('http://'.length)}`,
        headers: {
          Authorization: 'Bearer $env:BASESEC_RUNNER_REVIEW_TOKEN',
          'X-Custom-Id': CUSTOM,
          'X-Api-Key': 'zq9-apikey-UNIQUE-55d0',
        },
        evidenceDir: tmp,
      });
      const files = fs
        .readdirSync(tmp, { recursive: true, encoding: 'utf-8' })
        .map((entry) => path.join(tmp, entry))
        .filter((entry) => fs.statSync(entry).isFile());
      const all = [JSON.stringify(result), ...files.map((file) => fs.readFileSync(file, 'utf-8'))].join('\n');

      expect(files.length).toBeGreaterThan(0);
      for (const secret of [BEARER, CUSTOM, 'zq9-apikey-UNIQUE', 'zq9-pass-UNIQUE', 'zq9-custom', 'zq9-bearer']) {
        expect(all).not.toContain(secret);
      }
      expect(result.stats.dast?.target).toBe(echoOrigin);
    } finally {
      delete process.env.BASESEC_RUNNER_REVIEW_TOKEN;
    }
  });

  it.each(['//evil.example', '/\\evil.example', '\\\\evil.example', 'http://x', 'evil.example/x', ''])(
    'rejects the healthcheck path %j before any request',
    async (health) => {
      await expect(runDast({ url: echoOrigin, health, evidence: false })).rejects.toThrow(DastConfigError);
      expect(echoHits).toBe(0);
    },
  );

  it('stops at the global timeout with incomplete = timeout', async () => {
    slowRoot = true;
    const result = await runDast({ url: echoOrigin, health: '/health', timeout: 1, evidence: false });

    expect(result.stats.dast?.incomplete).toBe('timeout');
    expect(result.stats.rulesRun).toBe(0);
    expect(echoHits).toBe(1);
  }, 15000);

  it('propagates a guard failure raised in the middle of the run instead of reporting the target as unreachable', async () => {
    let calls = 0;
    const resolver = async (): Promise<string[]> => (++calls === 1 ? ['127.0.0.1'] : ['203.0.113.10']);
    const error = await runDast({ url: 'http://rebind.example.test:9/', resolver, evidence: false }).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(GuardError);
    expect(echoHits).toBe(0);
  });
});
