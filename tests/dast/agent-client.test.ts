import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { startAgentCollector } from '../../src/dast/agent-client';
import type { AgentEventSource } from '../../src/dast/agent-client';

let tmp: string;
const sources: AgentEventSource[] = [];
const servers: net.Server[] = [];

function listen(dir: string, onConnection: (socket: net.Socket) => void): Promise<void> {
  return new Promise((resolve) => {
    const server = net.createServer(onConnection);
    servers.push(server);
    server.listen(path.join(dir, '1234.sock'), () => resolve());
  });
}

const LINE = `${JSON.stringify({ canary: 'BS0a0b0c0d', sink: 'child_process.exec', snippet: 'echo BS0a0b0c0d', stack: [] })}\n`;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-client-'));
});

afterEach(async () => {
  for (const source of sources.splice(0)) source.close();
  for (const server of servers.splice(0)) await new Promise((resolve) => server.close(resolve));
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('agent collector', () => {
  it('collects the events of a socket in a private directory of its own', async () => {
    const dir = path.join(tmp, 'ok');
    fs.mkdirSync(dir, { mode: 0o700 });
    await listen(dir, (socket) => socket.write(LINE));
    const source = startAgentCollector(dir);
    sources.push(source);
    expect((await source.collect()).map((event) => event.canary)).toEqual(['BS0a0b0c0d']);
  });

  it('ignores sockets in a directory that other users can access', async () => {
    const dir = path.join(tmp, 'open');
    fs.mkdirSync(dir);
    fs.chmodSync(dir, 0o755);
    await listen(dir, (socket) => socket.write(LINE));
    const source = startAgentCollector(dir);
    sources.push(source);
    expect(await source.collect()).toEqual([]);
  });

  it('drops a peer that sends a huge line without a newline, and keeps going', async () => {
    const dir = path.join(tmp, 'flood');
    fs.mkdirSync(dir, { mode: 0o700 });
    await listen(dir, (socket) => {
      socket.on('error', () => undefined);
      socket.write('x'.repeat(2 * 1024 * 1024));
    });
    const source = startAgentCollector(dir);
    sources.push(source);
    expect(await source.collect()).toEqual([]);
  });

  it('discards malformed lines and events with a bad canary', async () => {
    const dir = path.join(tmp, 'bad');
    fs.mkdirSync(dir, { mode: 0o700 });
    await listen(dir, (socket) => {
      socket.write('not json\n');
      socket.write(`${JSON.stringify({ canary: 'nope', sink: 's', snippet: '', stack: [] })}\n`);
      socket.write(LINE);
    });
    const source = startAgentCollector(dir);
    sources.push(source);
    expect((await source.collect()).map((event) => event.canary)).toEqual(['BS0a0b0c0d']);
  });
});
