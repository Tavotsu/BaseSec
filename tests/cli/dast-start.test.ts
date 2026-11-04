import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import type { AddressInfo } from 'node:net';
import { buildSync } from 'esbuild';
import { afterAll, beforeAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { runDastCommand } from '../../src/cli/commands/dast';
import type { DastCliOptions } from '../../src/cli/commands/dast';

/*
 * --start: la app arranca con NODE_OPTIONS=--require <agent>, el análisis corre y, al terminar o ante Ctrl-C, el grupo
 * entero (incluido el nieto que lanza la app) desaparece. El agente se compila con esbuild a un temporal.
 */

const FIXTURES = path.join(process.cwd(), 'tests/fixtures/agent-start');
let tmp: string;
let bundle: string;
let fakeHome: string;
let previousHome: string | undefined;
const previousEnv: Record<string, string | undefined> = {};

function setEnv(values: Record<string, string>): void {
  for (const [key, value] of Object.entries(values)) {
    previousEnv[key] = process.env[key];
    process.env[key] = value;
  }
}

function restoreEnv(): void {
  for (const [key, value] of Object.entries(previousEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  for (const key of Object.keys(previousEnv)) delete previousEnv[key];
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      server.close(() => resolve(port));
    });
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

async function eventually(check: () => boolean, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return true;
    await delay(50);
  }
  return check();
}

/** Artefacto de rutas mínimo. `target` es la raíz del código (debe existir), no la URL del servidor. */
function writeRoutes(): string {
  const file = path.join(tmp, `routes-${crypto.randomBytes(3).toString('hex')}.json`);
  fs.writeFileSync(
    file,
    JSON.stringify({
      version: 1,
      generatedAt: new Date().toISOString(),
      target: tmp,
      frameworks: ['express'],
      unresolved: [],
      routes: [
        { method: 'GET', path: '/', framework: 'express', filePath: 'app.mjs', line: 1, endLine: 1, hasAuth: false, params: [], reachableFiles: [], staticFindings: [] },
      ],
    }),
  );
  return file;
}

function baseOptions(overrides: Partial<DastCliOptions>): DastCliOptions {
  return {
    format: 'json',
    quiet: true,
    noColor: true,
    evidence: false,
    rules: 'DAST-103',
    agentBundle: bundle,
    ...overrides,
  };
}

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-dast-start-'));
  bundle = path.join(tmp, 'agent.cjs');
  buildSync({
    entryPoints: [path.join(process.cwd(), 'src/dast/agent/index.ts')],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'node22',
    outfile: bundle,
    logLevel: 'silent',
  });
});

afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

beforeEach(() => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'log').mockImplementation(() => {});
  fakeHome = fs.mkdtempSync(path.join(tmp, 'home-'));
  previousHome = process.env.HOME;
  process.env.HOME = fakeHome;
});

afterEach(() => {
  vi.restoreAllMocks();
  restoreEnv();
  if (previousHome === undefined) delete process.env.HOME;
  else process.env.HOME = previousHome;
});

describe('dast --start', () => {
  it('runs the app with the agent injected, analyzes it and leaves no process behind', async () => {
    const out = fs.mkdtempSync(path.join(tmp, 'out-'));
    const port = await freePort();
    setEnv({ BS_TEST_OUT: out, BS_TEST_PORT: String(port) });

    const code = await runDastCommand(
      `http://127.0.0.1:${port}`,
      baseOptions({
        start: `node "${path.join(FIXTURES, 'server.mjs')}"`,
        startTimeout: 20,
        routes: writeRoutes(),
      }),
    );
    expect(code).toBe(0);

    const env = JSON.parse(fs.readFileSync(path.join(out, 'env.json'), 'utf8')) as { NODE_OPTIONS: string; agentDir: string };
    expect(env.NODE_OPTIONS).toContain(`--require "${bundle}"`);
    expect(env.agentDir).not.toBe('');

    const grandchild = Number(fs.readFileSync(path.join(out, 'grandchild.pid'), 'utf8'));
    expect(await eventually(() => !alive(grandchild), 3000)).toBe(true);
    expect(fs.existsSync(env.agentDir)).toBe(false);
  }, 60000);

  it('exits 2 and tears the app down when it never answers', async () => {
    const out = fs.mkdtempSync(path.join(tmp, 'never-'));
    const port = await freePort();
    setEnv({ BS_TEST_OUT: out });
    const code = await runDastCommand(
      `http://127.0.0.1:${port}`,
      baseOptions({
        start: `node -e "require('fs').writeFileSync(process.env.BS_TEST_OUT + '/app.pid', String(process.pid)); setInterval(() => {}, 1000)"`,
        startTimeout: 2,
        routes: writeRoutes(),
      }),
    );
    expect(code).toBe(2);
    // El teardown de un arranque fallido no deja el proceso vivo.
    const pid = Number(fs.readFileSync(path.join(out, 'app.pid'), 'utf8'));
    expect(await eventually(() => !alive(pid), 3000)).toBe(true);
  }, 30000);

  it('rejects inconsistent agent flags with exit 3 before sending anything', async () => {
    const url = 'http://127.0.0.1:9';
    expect(await runDastCommand(url, baseOptions({ startTimeout: 5 }))).toBe(3);
    expect(await runDastCommand(url, baseOptions({ agentDir: tmp }))).toBe(3);
    expect(await runDastCommand(url, baseOptions({ agent: true, start: 'node -e 0', agentDir: tmp }))).toBe(3);
  });

  it.each([
    ['SIGINT', 130],
    ['SIGTERM', 143],
  ] as const)('tears the whole group down on %s while BaseSec is running', async (signal, expectedCode) => {
    const out = fs.mkdtempSync(path.join(tmp, 'sigint-'));
    const port = await freePort();
    const args = {
      url: `http://127.0.0.1:${port}`,
      options: baseOptions({
        start: `node "${path.join(FIXTURES, 'server.mjs')}"`,
        startTimeout: 30,
        routes: writeRoutes(),
        agentBundle: bundle,
      }),
    };
    const runner = spawn(process.execPath, ['--import', 'tsx', path.join(FIXTURES, 'run-dast.ts')], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        BS_RUN_ARGS: JSON.stringify(args),
        BS_TEST_OUT: out,
        BS_TEST_PORT: String(port),
        HOME: fakeHome,
      },
      stdio: 'ignore',
    });
    const exited = new Promise<number | null>((resolve) => runner.once('exit', (code) => resolve(code)));

    const pidFile = path.join(out, 'grandchild.pid');
    expect(await eventually(() => fs.existsSync(pidFile), 30000)).toBe(true);
    const grandchild = Number(fs.readFileSync(pidFile, 'utf8'));

    runner.kill(signal);
    expect(await exited).toBe(expectedCode);
    expect(await eventually(() => !alive(grandchild), 3000)).toBe(true);
  }, 90000);
});
