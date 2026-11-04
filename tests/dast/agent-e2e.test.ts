import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { buildSync } from 'esbuild';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startAgentCollector } from '../../src/dast/agent-client';
import type { AgentEventSource } from '../../src/dast/agent-client';

/*
 * Prueba de punta a punta con un proceso hijo ESM real. El agente se compila al vuelo con esbuild (el mismo
 * formato que dist/agent.cjs) a un temporal, así que el test no depende de `pnpm build`. La app importa
 * `execSync` con nombre: el evento solo llega si syncBuiltinESMExports hace visible el parche.
 */

let tmp: string;
let bundle: string;
const children: ChildProcess[] = [];
const sources: AgentEventSource[] = [];

function canary(): string {
  return `BS${crypto.randomBytes(4).toString('hex')}`;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** App ESM: ejecuta `command` con execSync y se queda viva un rato para que BaseSec se conecte. */
function writeApp(name: string, command: string): string {
  const file = path.join(tmp, name);
  fs.writeFileSync(
    file,
    [
      "import { execSync } from 'node:child_process';",
      `const out = execSync(${JSON.stringify(command)}).toString();`,
      'process.stdout.write(out);',
      'setTimeout(() => process.exit(0), 8000);',
      '',
    ].join('\n'),
  );
  return file;
}

async function runApp(app: string, dir: string): Promise<{ child: ChildProcess; source: AgentEventSource; stdout: () => string }> {
  const child = spawn(process.execPath, ['--require', bundle, app], {
    env: { ...process.env, NODE_OPTIONS: '', BASESEC_AGENT_DIR: dir },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  let stdout = '';
  child.stdout?.on('data', (chunk: Buffer) => {
    stdout += chunk.toString('utf8');
  });
  const socket = path.join(dir, `${child.pid}.sock`);
  const deadline = Date.now() + 5000;
  while (!fs.existsSync(socket)) {
    if (Date.now() > deadline) throw new Error(`the agent socket never appeared; stderr was not captured`);
    await delay(25);
  }
  const source = startAgentCollector(dir);
  sources.push(source);
  return { child, source, stdout: () => stdout };
}

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-agent-e2e-'));
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
  for (const source of sources) source.close();
  for (const child of children) child.kill('SIGKILL');
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('agent end to end', () => {
  it('reports a sink that receives a canary from an ESM app, with the user stack', async () => {
    const dir = fs.mkdtempSync(path.join(tmp, 'sockets-'));
    const value = canary();
    const app = writeApp('app-canary.mjs', `echo ${value}`);
    const { source, stdout } = await runApp(app, dir);

    const events = await source.collect();
    expect(events).toHaveLength(1);
    expect(events[0].canary).toBe(value);
    expect(events[0].sink).toBe('child_process.execSync');
    expect(events[0].stack[0]).toEqual({ file: app, line: 2 });
    expect(events[0].stack.every((frame) => fs.existsSync(frame.file))).toBe(true);
    // La app recibe el resultado real: el parche no altera la salida.
    expect(stdout()).toBe(`${value}\n`);
  }, 20000);

  it('sends nothing when no argument carries a canary', async () => {
    const dir = fs.mkdtempSync(path.join(tmp, 'sockets-'));
    const app = writeApp('app-plain.mjs', 'echo hola');
    const { source, stdout } = await runApp(app, dir);

    const events = await source.collect();
    expect(events).toEqual([]);
    expect(stdout()).toBe('hola\n');
  }, 20000);

  it('does not keep the process alive, prints nothing and cleans its socket up', async () => {
    const dir = fs.mkdtempSync(path.join(tmp, 'sockets-'));
    const app = path.join(tmp, 'app-exit.mjs');
    fs.writeFileSync(app, "import { execSync } from 'node:child_process';\nprocess.stdout.write(execSync('echo BS00c0ffee').toString());\n");
    const started = Date.now();
    const result = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
      const child = spawn(process.execPath, ['--require', bundle, app], {
        env: { ...process.env, NODE_OPTIONS: '', BASESEC_AGENT_DIR: dir },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      children.push(child);
      let stdout = '';
      let stderr = '';
      child.stdout?.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')));
      child.stderr?.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
      child.once('error', reject);
      child.once('exit', (code) => resolve({ code, stdout, stderr }));
    });
    expect(result).toEqual({ code: 0, stdout: 'BS00c0ffee\n', stderr: '' });
    expect(Date.now() - started).toBeLessThan(5000);
    expect(fs.readdirSync(dir)).toEqual([]);
  }, 20000);

  it('loads silently with --require on an empty program and with an unusable agent directory', async () => {
    const file = path.join(tmp, 'blocker');
    fs.writeFileSync(file, 'x');
    for (const agentDir of [fs.mkdtempSync(path.join(tmp, 'sockets-')), path.join(file, 'sub')]) {
      const result = await new Promise<{ code: number | null; stdout: string }>((resolve, reject) => {
        const child = spawn(process.execPath, ['--require', bundle, '-e', 'process.stdout.write("ok")'], {
          env: { ...process.env, NODE_OPTIONS: '', BASESEC_AGENT_DIR: agentDir },
          stdio: ['ignore', 'pipe', 'ignore'],
        });
        children.push(child);
        let stdout = '';
        child.stdout?.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')));
        child.once('error', reject);
        child.once('exit', (code) => resolve({ code, stdout }));
      });
      // Con el directorio inutilizable la app corre igual, sin instrumentar.
      expect(result).toEqual({ code: 0, stdout: 'ok' });
    }
  }, 20000);
});

