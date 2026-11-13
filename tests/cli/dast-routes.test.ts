import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import type { AddressInfo } from 'node:net';
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import { runDastCommand } from '../../src/cli/commands/dast';
import { writeRouteArtifact } from '../../src/core/route-emitter';
import type { RouteArtifact } from '../../src/framework/routes/types';

const FIXTURE = path.resolve('tests/fixtures/express-src');

let server: http.Server;
let url: string;
let hits = 0;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    hits++;
    if ((req.url ?? '') === '/api/users/1') {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end('TypeError: boom\n    at Object.<anonymous> (/srv/app/routes/users.js:10:5)\n');
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

let workDir: string;
let previousHome: string | undefined;
let previousCwd: string;

beforeEach(() => {
  hits = 0;
  // Dentro del cwd: un informe fuera de él pediría confirmación interactiva (emitReport).
  workDir = fs.mkdtempSync(path.join(process.cwd(), 'basesec-dast-routes-'));
  previousHome = process.env.HOME;
  previousCwd = process.cwd();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
  process.chdir(previousCwd);
  if (previousHome === undefined) delete process.env.HOME;
  else process.env.HOME = previousHome;
  fs.rmSync(workDir, { recursive: true, force: true });
});

function baseOptions(overrides: Record<string, unknown> = {}): Parameters<typeof runDastCommand>[1] {
  return { quiet: true, evidenceDir: path.join(workDir, 'evidence'), ...overrides } as Parameters<typeof runDastCommand>[1];
}

function artifactFile(overrides: Record<string, unknown> = {}): string {
  const artifact = {
    version: 1,
    generatedAt: new Date().toISOString(),
    target: workDir,
    frameworks: ['express'],
    routes: [
      {
        method: 'GET',
        path: '/api/users/:id',
        framework: 'express',
        filePath: 'routes/users.ts',
        line: 3,
        endLine: 9,
        hasAuth: false,
        params: [{ name: 'id', in: 'path' }],
        reachableFiles: [],
        staticFindings: [],
      },
    ],
    unresolved: [],
    ...overrides,
  };
  const file = path.join(workDir, 'routes.json');
  fs.writeFileSync(file, JSON.stringify(artifact));
  return file;
}

function readReport(file: string): { stats: { dast: { routesSource: string; mode: string } }; findings: Array<{ ruleId: string; filePath: string; endpoint?: string }> } {
  return JSON.parse(fs.readFileSync(file, 'utf-8'));
}

describe('basesec dast --routes', () => {
  it('uses a valid artifact: exit 0 and routesSource routes-file', async () => {
    const output = path.join(workDir, 'report.json');
    const code = await runDastCommand(url, baseOptions({ routes: artifactFile(), format: 'json', output }));

    expect(code).toBe(0);
    const report = readReport(output);
    expect(report.stats.dast.routesSource).toBe('routes-file');
    expect(report.stats.dast.mode).toBe('full');
    expect(hits).toBeGreaterThan(0);
  });

  it('exits 3 without sending any request when the artifact is invalid', async () => {
    const file = path.join(workDir, 'bad.json');
    fs.writeFileSync(file, JSON.stringify({ version: 2 }));

    expect(await runDastCommand(url, baseOptions({ routes: file }))).toBe(3);
    expect(hits).toBe(0);
  });

  it('exits 3 when the artifact file does not exist', async () => {
    expect(await runDastCommand(url, baseOptions({ routes: path.join(workDir, 'missing.json') }))).toBe(3);
    expect(hits).toBe(0);
  });

  it('exits 3 when --routes and --scan are given together', async () => {
    expect(await runDastCommand(url, baseOptions({ routes: artifactFile(), scan: FIXTURE }))).toBe(3);
    expect(hits).toBe(0);
  });

  it('reports the endpoint finding at the handler location', async () => {
    const output = path.join(workDir, 'handler.json');
    await runDastCommand(url, baseOptions({ routes: artifactFile(), format: 'json', output }));

    const finding = readReport(output).findings.find((f) => f.ruleId === 'DAST-006');
    expect(finding?.endpoint).toBe('GET /api/users/:id');
    expect(finding?.filePath).toBe(path.join(workDir, 'routes/users.ts'));
  });
});

describe('basesec dast --scan', () => {
  it('derives the surface in memory: routesSource scan, and writes nothing to HOME', async () => {
    process.env.HOME = path.join(workDir, 'home');
    fs.mkdirSync(process.env.HOME, { recursive: true });
    const output = path.join(workDir, 'scan.json');

    const code = await runDastCommand(url, baseOptions({ scan: FIXTURE, format: 'json', output }));

    expect(code).toBe(0);
    expect(readReport(output).stats.dast.routesSource).toBe('scan');
    expect(fs.existsSync(path.join(process.env.HOME, '.basesec'))).toBe(false);
  });

  it('exits 3 when the scan path does not exist, with a clear message and no request', async () => {
    expect(await runDastCommand(url, baseOptions({ scan: path.join(workDir, 'nope') }))).toBe(3);
    expect(hits).toBe(0);
    const stderr = vi.mocked(console.error).mock.calls.flat().join('\n');
    expect(stderr).toMatch(/--scan path does not exist/);
  });

  it('writes no cache, report or artifact anywhere: HOME and the working tree stay untouched', async () => {
    const home = path.join(workDir, 'home');
    fs.mkdirSync(home, { recursive: true });
    process.env.HOME = home;
    const before = fs.readdirSync(workDir).sort();

    const code = await runDastCommand(url, baseOptions({ scan: FIXTURE, evidence: false }));

    expect(code).toBe(0);
    expect(fs.readdirSync(home)).toEqual([]);
    expect(fs.readdirSync(workDir).sort()).toEqual(before);
  });
});

describe('basesec dast default artifact', () => {
  function setupProjectWithArtifact(): string {
    const home = path.join(workDir, 'home');
    const root = path.join(workDir, 'project');
    fs.mkdirSync(home, { recursive: true });
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"project"}\n');
    process.env.HOME = home;
    process.chdir(root);
    return fs.realpathSync(root);
  }

  it('loads the artifact saved for the project root: routesSource artifact', async () => {
    const root = setupProjectWithArtifact();
    const artifact: RouteArtifact = {
      version: 1,
      generatedAt: new Date().toISOString(),
      target: root,
      frameworks: ['express'],
      routes: [],
      unresolved: [],
    };
    writeRouteArtifact(artifact);
    const output = path.join(root, 'default.json');

    const code = await runDastCommand(url, baseOptions({ format: 'json', output }));

    expect(code).toBe(0);
    expect(readReport(output).stats.dast.routesSource).toBe('artifact');
  });

  it('looks the artifact up from the project root computed from a subdirectory of the cwd', async () => {
    const root = setupProjectWithArtifact();
    writeRouteArtifact({
      version: 1,
      generatedAt: new Date().toISOString(),
      target: root,
      frameworks: [],
      routes: [],
      unresolved: [],
    });
    const nested = path.join(root, 'src', 'deep');
    fs.mkdirSync(nested, { recursive: true });
    process.chdir(nested);
    const output = path.join(nested, 'nested.json');

    expect(await runDastCommand(url, baseOptions({ format: 'json', output }))).toBe(0);
    expect(readReport(output).stats.dast.routesSource).toBe('artifact');
  });

  it('prints notices and the invalid-artifact warning on stderr, never on stdout', async () => {
    const root = setupProjectWithArtifact();
    const saved = writeRouteArtifact({
      version: 1,
      generatedAt: new Date().toISOString(),
      target: root,
      frameworks: [],
      routes: [],
      unresolved: [],
    });
    fs.writeFileSync(saved, '{ not json');

    await runDastCommand(url, baseOptions({ quiet: false }));

    const stderr = vi.mocked(console.error).mock.calls.flat().join('\n');
    const stdout = vi.mocked(console.log).mock.calls.flat().join('\n');
    expect(stderr).toMatch(/Saved route artifact ignored/);
    expect(stdout).not.toMatch(/Saved route artifact ignored|no routes to attack/);
  });

  it('falls back to no-source mode when the saved artifact is invalid', async () => {
    const root = setupProjectWithArtifact();
    const saved = writeRouteArtifact({
      version: 1,
      generatedAt: new Date().toISOString(),
      target: root,
      frameworks: [],
      routes: [],
      unresolved: [],
    });
    fs.writeFileSync(saved, JSON.stringify({ version: 9 }));
    const output = path.join(root, 'invalid-default.json');

    const code = await runDastCommand(url, baseOptions({ format: 'json', output }));

    expect(code).toBe(0);
    expect(readReport(output).stats.dast.routesSource).toBe('none');
  });
});