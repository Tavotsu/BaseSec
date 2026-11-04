import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { startAgentServer } from '../../src/dast/agent/channel';
import type { AgentServer, SinkEvent } from '../../src/dast/agent/channel';

let tmp: string;
let previousDir: string | undefined;
const servers: AgentServer[] = [];

function event(canary: string): SinkEvent {
  return { canary, sink: 'child_process.exec', snippet: `echo ${canary}`, stack: [{ file: '/app/x.js', line: 3 }] };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(check: () => boolean): Promise<void> {
  const deadline = Date.now() + 3000;
  while (!check()) {
    if (Date.now() > deadline) throw new Error('timed out waiting for the socket');
    await delay(20);
  }
}

function mode(file: string): number {
  return fs.statSync(file).mode & 0o777;
}

/** Cliente de prueba: lee `count` líneas JSON del socket y cierra. */
function readEvents(socketPath: string, count: number): Promise<SinkEvent[]> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    const got: SinkEvent[] = [];
    let pending = '';
    socket.on('data', (chunk: Buffer) => {
      pending += chunk.toString('utf8');
      let newline = pending.indexOf('\n');
      while (newline !== -1) {
        got.push(JSON.parse(pending.slice(0, newline)) as SinkEvent);
        pending = pending.slice(newline + 1);
        newline = pending.indexOf('\n');
      }
      if (got.length >= count) {
        socket.destroy();
        resolve(got);
      }
    });
    socket.on('error', reject);
  });
}

function start(): AgentServer {
  const server = startAgentServer();
  if (server === null) throw new Error('startAgentServer returned null');
  servers.push(server);
  return server;
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-channel-'));
  previousDir = process.env.BASESEC_AGENT_DIR;
  process.env.BASESEC_AGENT_DIR = path.join(tmp, 'agent');
});

afterEach(() => {
  for (const server of servers.splice(0)) server.close();
  if (previousDir === undefined) delete process.env.BASESEC_AGENT_DIR;
  else process.env.BASESEC_AGENT_DIR = previousDir;
  fs.rmSync(tmp, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe('agent channel', () => {
  it('creates a 0700 directory and a 0600 socket named after the pid', async () => {
    start();
    const socketPath = path.join(process.env.BASESEC_AGENT_DIR as string, `${process.pid}.sock`);
    await waitFor(() => fs.existsSync(socketPath) && mode(socketPath) === 0o600);
    expect(mode(process.env.BASESEC_AGENT_DIR as string)).toBe(0o700);
  });

  it('delivers buffered events to a late client and then live events', async () => {
    const server = start();
    const socketPath = path.join(process.env.BASESEC_AGENT_DIR as string, `${process.pid}.sock`);
    await waitFor(() => fs.existsSync(socketPath) && mode(socketPath) === 0o600);
    server.emit(event('BS00000001'));
    server.emit(event('BS00000002'));

    const received = readEvents(socketPath, 3);
    await delay(50);
    server.emit(event('BS00000003'));
    const events = await received;
    expect(events.map((e) => e.canary)).toEqual(['BS00000001', 'BS00000002', 'BS00000003']);
    expect(events[0].stack).toEqual([{ file: '/app/x.js', line: 3 }]);
  });

  it('removes the socket on close', async () => {
    const server = start();
    const socketPath = path.join(process.env.BASESEC_AGENT_DIR as string, `${process.pid}.sock`);
    await waitFor(() => fs.existsSync(socketPath));
    server.close();
    expect(fs.existsSync(socketPath)).toBe(false);
  });

  it('returns null without throwing when the directory cannot be created', () => {
    fs.writeFileSync(path.join(tmp, 'blocker'), 'x');
    process.env.BASESEC_AGENT_DIR = path.join(tmp, 'blocker', 'sub');
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    expect(startAgentServer()).toBeNull();
    expect(stderr).toHaveBeenCalled();
  });

  it('refuses a directory that is readable by other users', () => {
    const dir = process.env.BASESEC_AGENT_DIR as string;
    fs.mkdirSync(dir, { mode: 0o755 });
    fs.chmodSync(dir, 0o755);
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    expect(startAgentServer()).toBeNull();
  });

  it('refuses a symbolic link as the directory', () => {
    const real = path.join(tmp, 'real');
    fs.mkdirSync(real, { mode: 0o700 });
    const link = path.join(tmp, 'link');
    fs.symlinkSync(real, link);
    process.env.BASESEC_AGENT_DIR = link;
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    expect(startAgentServer()).toBeNull();
    expect(fs.readdirSync(real)).toEqual([]);
  });

  it.skipIf(typeof process.getuid !== 'function' || process.getuid() !== 0)('refuses a directory owned by another user', () => {
    const dir = process.env.BASESEC_AGENT_DIR as string;
    fs.mkdirSync(dir, { mode: 0o700 });
    fs.chownSync(dir, 4242, 4242);
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    expect(startAgentServer()).toBeNull();
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  it('does not throw when the socket path is too long for the OS', async () => {
    process.env.BASESEC_AGENT_DIR = path.join(tmp, 'x'.repeat(200));
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const server = startAgentServer();
    server?.emit(event('BS00000009'));
    await delay(100);
    server?.close();
    expect(stderr).toHaveBeenCalled();
  });

  it('emit after close is harmless and writes nothing to disk besides the socket', async () => {
    const dir = process.env.BASESEC_AGENT_DIR as string;
    const server = start();
    await waitFor(() => fs.existsSync(path.join(dir, `${process.pid}.sock`)));
    expect(fs.readdirSync(dir)).toEqual([`${process.pid}.sock`]);
    server.close();
    expect(() => server.emit(event('BS0000000a'))).not.toThrow();
    server.close();
    expect(fs.readdirSync(dir)).toEqual([]);
  });
});
