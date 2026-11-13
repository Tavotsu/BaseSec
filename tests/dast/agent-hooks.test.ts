import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { promisify } from 'node:util';
import * as cp from 'node:child_process';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { installHooks } from '../../src/dast/agent/hooks';
import { startAgentServer } from '../../src/dast/agent/channel';
import type { SinkEvent } from '../../src/dast/agent/channel';

// Los parches van sobre el módulo real: se guardan los originales y se restauran en afterEach.
const load = createRequire(import.meta.url);
const realCp = load('node:child_process') as typeof cp;
const realFs = load('node:fs') as typeof fs;
const realNodeModule = load('node:module') as { syncBuiltinESMExports(): void };
const CHILD_KEYS = ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync'] as const;
const FS_KEYS = ['readFile', 'readFileSync', 'createReadStream', 'open', 'writeFile', 'unlink'] as const;
const realFsPromises = load('node:fs/promises') as typeof import('node:fs/promises');
const realVm = load('node:vm') as typeof import('node:vm');
const PROMISES_KEYS = ['readFile', 'open', 'writeFile', 'unlink'] as const;
const originals = {
  child: Object.fromEntries(CHILD_KEYS.map((key) => [key, realCp[key]])),
  fs: Object.fromEntries(FS_KEYS.map((key) => [key, realFs[key]])),
  promises: Object.fromEntries(PROMISES_KEYS.map((key) => [key, realFsPromises[key]])),
  runInNewContext: realVm.runInNewContext,
};

function restore(): void {
  for (const key of CHILD_KEYS) (realCp as unknown as Record<string, unknown>)[key] = originals.child[key];
  for (const key of FS_KEYS) (realFs as unknown as Record<string, unknown>)[key] = originals.fs[key];
  for (const key of PROMISES_KEYS) (realFsPromises as unknown as Record<string, unknown>)[key] = originals.promises[key];
  realVm.runInNewContext = originals.runInNewContext;
  realNodeModule.syncBuiltinESMExports();
}

let tmp: string;
let previousRoot: string | undefined;
let previousPrepare: typeof Error.prepareStackTrace;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-hooks-'));
  previousRoot = process.env.BASESEC_AGENT_ROOT;
  previousPrepare = Error.prepareStackTrace;
});

afterEach(() => {
  restore();
  Error.prepareStackTrace = previousPrepare;
  if (previousRoot === undefined) delete process.env.BASESEC_AGENT_ROOT;
  else process.env.BASESEC_AGENT_ROOT = previousRoot;
  fs.rmSync(tmp, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe('agent hooks', () => {
  it('reports execSync with a canary and returns the original output', () => {
    const report = vi.fn();
    installHooks(report);
    // Import nombrado: la app ve el parche gracias a syncBuiltinESMExports.
    const output = realCp.execSync('echo BS12345678').toString();
    expect(output).toBe('BS12345678\n');
    expect(report).toHaveBeenCalledTimes(1);
    const event = report.mock.calls[0][0] as SinkEvent;
    expect(event.canary).toBe('BS12345678');
    expect(event.sink).toBe('child_process.execSync');
    expect(event.snippet).toContain('BS12345678');
    expect(event.snippet.length).toBeLessThanOrEqual(200);
  });

  it('stays silent and returns the original result when there is no canary', () => {
    const report = vi.fn();
    installHooks(report);
    expect(realCp.execSync('echo hola').toString()).toBe('hola\n');
    expect(report).not.toHaveBeenCalled();
  });

  it('keeps the original result when report throws', () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    installHooks(() => {
      throw new Error('report failed');
    });
    expect(realCp.execSync('echo BS87654321').toString()).toBe('BS87654321\n');
  });

  it('keeps the promisified shape of exec (util.promisify.custom is preserved)', async () => {
    const report = vi.fn();
    installHooks(report);
    const result = await promisify(realCp.exec)('echo BS11223344');
    expect(result).toEqual({ stdout: 'BS11223344\n', stderr: '' });
    expect(report).toHaveBeenCalledTimes(1);
  });

  it('reports fs.readFileSync when the path contains the canary, and keeps ENOENT', () => {
    const report = vi.fn();
    installHooks(report);
    const file = path.join(tmp, 'BS0badf00d.txt');
    fs.writeFileSync(file, 'contenido');
    expect(realFs.readFileSync(file, 'utf8')).toBe('contenido');
    expect(report).toHaveBeenCalledTimes(1);
    expect((report.mock.calls[0][0] as SinkEvent).sink).toBe('fs.readFileSync');

    expect(() => realFs.readFileSync(path.join(tmp, 'BS0badf00d-missing'))).toThrow(/ENOENT/);
  });

  it('does not instrument the same function twice', () => {
    const report = vi.fn();
    installHooks(report);
    installHooks(report);
    realCp.execSync('echo BS22334455');
    expect(report).toHaveBeenCalledTimes(1);
  });
});

/** Driver falso con la forma de pg: registra los argumentos que recibe para comprobar que llegan intactos. */
function writeFakePg(): void {
  const dir = path.join(tmp, 'node_modules', 'pg');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'index.js'),
    [
      'class Client {',
      '  constructor() { this.calls = []; }',
      '  query(config, values, callback) {',
      '    this.calls.push({ config, values, callback, self: this });',
      "    if (config && Object.getOwnPropertyDescriptor(config, 'text')?.value === 'boom') throw new Error('driver failure');",
      '    return Promise.resolve({ rows: [{ ok: 1 }], self: this });',
      '  }',
      '}',
      'class Pool { query(config) { return Promise.resolve({ rows: [], config, self: this }); } }',
      'module.exports = { Client, Pool };',
      '',
    ].join('\n'),
  );
  fs.writeFileSync(path.join(tmp, 'package.json'), '{"name":"app"}');
  process.env.BASESEC_AGENT_ROOT = tmp;
}

type FakeClient = { calls: Array<{ config: unknown; values: unknown; callback: unknown; self: unknown }>; query(...args: unknown[]): Promise<{ rows: unknown[]; self: unknown }> };

describe('agent hooks never change what the application observes', () => {
  it('exec with a callback: same callback arguments, same return type, same shape', async () => {
    const report = vi.fn();
    const original = realCp.exec;
    installHooks(report);
    const patched = realCp.exec;
    expect(patched).not.toBe(original);
    expect(patched.length).toBe(original.length);
    expect(patched.name).toBe(original.name);

    const { child, error, stdout, stderr } = await new Promise<{ child: cp.ChildProcess; error: Error | null; stdout: string; stderr: string }>(
      (resolve) => {
        const child = realCp.exec('echo BS55667788', (error, stdout, stderr) => resolve({ child, error, stdout, stderr }));
      },
    );
    expect(child.constructor.name).toBe('ChildProcess');
    expect(error).toBeNull();
    expect(stdout).toBe('BS55667788\n');
    expect(stderr).toBe('');
    expect(report).toHaveBeenCalledTimes(1);

    // El error del propio comando también llega igual a la callback.
    const failed = await new Promise<Error | null>((resolve) => {
      realCp.exec('echo BS55667788 && exit 3', (err) => resolve(err));
    });
    expect((failed as NodeJS.ErrnoException & { code?: number }).code).toBe(3);
  });

  it('exec keeps working when report throws or the agent socket is down', async () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    installHooks(() => {
      throw new Error('report failed');
    });
    const result = await promisify(realCp.exec)('echo BS99887766');
    expect(result.stdout).toBe('BS99887766\n');
    expect(() => realCp.execSync('echo BS99887766 && exit 4', { stdio: 'pipe' })).toThrow(/Command failed/);

    // Socket caído: el servidor real, ya cerrado, sigue aceptando emit sin lanzar.
    restore();
    const dir = fs.mkdtempSync(path.join(tmp, 'sock-'));
    const previous = process.env.BASESEC_AGENT_DIR;
    process.env.BASESEC_AGENT_DIR = dir;
    try {
      const server = startAgentServer();
      expect(server).not.toBeNull();
      server?.close();
      installHooks((event) => server?.emit(event));
      expect(realCp.execSync('echo BS13572468').toString()).toBe('BS13572468\n');
    } finally {
      if (previous === undefined) delete process.env.BASESEC_AGENT_DIR;
      else process.env.BASESEC_AGENT_DIR = previous;
    }
  });

  it('fs.promises.readFile: resolves with the same content and rejects with the same error', async () => {
    const report = vi.fn();
    installHooks(report);
    const file = path.join(tmp, 'BS1a2b3c4d.txt');
    fs.writeFileSync(file, 'datos');
    const content: unknown = await realFsPromises.readFile(file, 'utf8');
    expect(content).toBe('datos');
    const pending = realFsPromises.readFile(path.join(tmp, 'BS1a2b3c4d-missing'));
    expect(pending).toBeInstanceOf(Promise);
    await expect(pending).rejects.toMatchObject({ code: 'ENOENT' });
    expect(report).toHaveBeenCalledTimes(2);
    expect((report.mock.calls[0][0] as SinkEvent).sink).toBe('fs/promises.readFile');
  });

  it('fs.promises.readFile with a throwing report resolves exactly the same', async () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    installHooks(() => {
      throw new Error('report failed');
    });
    const file = path.join(tmp, 'BS5e6f7a8b.txt');
    fs.writeFileSync(file, 'datos');
    expect(await realFsPromises.readFile(file, 'utf8')).toBe('datos');
  });

  it('pg query with {text}: reports, passes the very same arguments and this, returns the driver promise', async () => {
    writeFakePg();
    const report = vi.fn();
    installHooks(report);
    const pg = load(path.join(tmp, 'node_modules', 'pg')) as { Client: new () => FakeClient; Pool: new () => { query(c: unknown): Promise<{ self: unknown; config: unknown }> } };
    const client = new pg.Client();
    const config = { text: "SELECT * FROM t WHERE n = 'BS0a0b0c0d'", values: [1] };
    const callback = (): void => undefined;
    const result = await client.query(config, [2], callback);

    expect(result).toEqual({ rows: [{ ok: 1 }], self: client });
    expect(client.calls).toHaveLength(1);
    expect(client.calls[0].config).toBe(config);
    expect(client.calls[0].values).toEqual([2]);
    expect(client.calls[0].callback).toBe(callback);
    expect(client.calls[0].self).toBe(client);
    expect(report).toHaveBeenCalledTimes(1);
    const event = report.mock.calls[0][0] as SinkEvent;
    expect(event.sink).toBe('pg.Client.query');
    expect(event.canary).toBe('BS0a0b0c0d');

    const pool = new pg.Pool();
    const poolResult = await pool.query({ text: 'SELECT BS1e1f2a2b' });
    expect(poolResult.self).toBe(pool);
    expect(report).toHaveBeenCalledTimes(2);
  });

  it('pg: the driver own synchronous error propagates unchanged, with and without report failures', () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    writeFakePg();
    installHooks(() => {
      throw new Error('report failed');
    });
    const pg = load(path.join(tmp, 'node_modules', 'pg')) as { Client: new () => FakeClient };
    expect(() => new pg.Client().query({ text: 'boom' })).toThrow('driver failure');
  });

  it('does not run application code while looking for a canary (getters, toJSON, subclasses)', async () => {
    writeFakePg();
    const report = vi.fn();
    installHooks(report);
    const pg = load(path.join(tmp, 'node_modules', 'pg')) as { Client: new () => FakeClient };
    const client = new pg.Client();
    let touched = 0;
    const withGetter = {
      get filter(): string {
        touched += 1;
        return 'BS0000aaaa';
      },
      toJSON(): string {
        touched += 1;
        return 'BS0000bbbb';
      },
    };
    class Custom {
      get text(): string {
        touched += 1;
        return 'BS0000cccc';
      }
    }
    class Items extends Array<string> {
      static get [Symbol.species](): ArrayConstructor {
        touched += 1;
        return Array;
      }
    }
    await client.query(withGetter);
    const afterGetter = touched;
    await client.query(new Custom());
    const afterCustom = touched;
    await client.query(Items.from(['BS0000dddd']));
    expect([afterGetter, afterCustom, touched]).toEqual([0, 0, 0]);
    expect(report).not.toHaveBeenCalled();
  });

  it('only inspects a literal object in the first argument (options such as env are not scanned)', () => {
    const report = vi.fn();
    installHooks(report);
    expect(realCp.execFileSync('echo', ['x'], { env: { ...process.env, TOKEN: 'BS0f0e0d0c' } }).toString()).toBe('x\n');
    expect(report).not.toHaveBeenCalled();
    // Los argumentos del comando (array) sí.
    realCp.execFileSync('echo', ['BS0f0e0d0c']);
    expect(report).toHaveBeenCalledTimes(1);
  });

  it('still reports (with no frames) when the app replaced Error.prepareStackTrace with something odd', () => {
    const report = vi.fn();
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    installHooks(report);
    Error.prepareStackTrace = () => ['not a string'] as unknown as string;
    expect(realCp.execSync('echo BS7a7b7c7d').toString()).toBe('BS7a7b7c7d\n');
    Error.prepareStackTrace = previousPrepare;
    expect(report).toHaveBeenCalledTimes(1);
    expect((report.mock.calls[0][0] as SinkEvent).stack).toEqual([]);
    expect(stderr.mock.calls.some(([chunk]) => String(chunk).includes('[basesec-agent]'))).toBe(false);
  });

  it('keeps arity, name and own properties of the patched functions, and the promisify shape', () => {
    const before = {
      exec: { length: realCp.exec.length, name: realCp.exec.name, custom: (realCp.exec as unknown as Record<symbol, unknown>)[promisify.custom] },
      readFileSync: { length: realFs.readFileSync.length, name: realFs.readFileSync.name },
      spawn: { length: realCp.spawn.length, name: realCp.spawn.name },
    };
    installHooks(vi.fn());
    expect(realCp.exec.length).toBe(before.exec.length);
    expect(realCp.exec.name).toBe(before.exec.name);
    expect(typeof (realCp.exec as unknown as Record<symbol, unknown>)[promisify.custom]).toBe(typeof before.exec.custom);
    expect(realFs.readFileSync.length).toBe(before.readFileSync.length);
    expect(realFs.readFileSync.name).toBe(before.readFileSync.name);
    expect(realCp.spawn.length).toBe(before.spawn.length);
    expect(realCp.spawn.name).toBe(before.spawn.name);
  });

  it('installing twice with different reports wraps once: only the first report fires, once', () => {
    const first = vi.fn();
    const second = vi.fn();
    installHooks(first);
    const wrapped = realCp.execSync;
    installHooks(second);
    expect(realCp.execSync).toBe(wrapped);
    realCp.execSync('echo BS3c3d3e3f');
    expect(first).toHaveBeenCalledTimes(1);
    expect(second).not.toHaveBeenCalled();
  });

  it('reports a sink only once when Node calls another sink internally (exec -> execFile)', () => {
    const report = vi.fn();
    installHooks(report);
    return new Promise<void>((resolve) => {
      realCp.exec('echo BS4d4e4f40', () => {
        expect(report).toHaveBeenCalledTimes(1);
        resolve();
      });
    });
  });
});

