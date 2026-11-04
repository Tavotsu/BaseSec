import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import type { SinkEvent } from './agent/channel';
import { resolveAgentDir } from './agent/channel';
import { stripControl } from './probe';

/** Fuente de eventos del agente que consume el runner. Un test puede darle una propia. */
export interface AgentEventSource {
  /** Eventos recibidos hasta ahora. Espera un instante para que lleguen los que salieron con la última petición. */
  collect(): Promise<SinkEvent[]>;
  close(): void;
}

const SCAN_INTERVAL_MS = 200;
const SETTLE_MS = 250;
const CANARY = /^BS[0-9a-f]{8}$/;
/** Una línea del agente mide unos pocos KB; sin salto de línea tras 1 MB el otro extremo no es un agente. */
const MAX_PENDING_CHARS = 1024 * 1024;

/**
 * Solo se leen sockets de un directorio propio, sin enlaces y sin acceso para otros usuarios (el mismo criterio con
 * el que el agente crea el suyo): en un directorio ajeno cualquiera podría plantar eventos falsos.
 */
function isPrivateOwnDir(dir: string): boolean {
  try {
    const stat = fs.lstatSync(dir);
    if (!stat.isDirectory()) return false;
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) return false;
    return (stat.mode & 0o077) === 0;
  } catch (error) {
    void error;
    return false;
  }
}

/** Acepta solo eventos con la forma que emite el agente. Lo que no encaja se descarta. */
function parseEvent(line: string): SinkEvent | undefined {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch (error) {
    void error;
    return undefined;
  }
  if (value === null || typeof value !== 'object') return undefined;
  const event = value as Partial<SinkEvent>;
  if (typeof event.canary !== 'string' || !CANARY.test(event.canary)) return undefined;
  if (typeof event.sink !== 'string' || typeof event.snippet !== 'string' || !Array.isArray(event.stack)) return undefined;
  const stack = event.stack.filter(
    (frame): frame is SinkEvent['stack'][number] =>
      typeof frame === 'object' && frame !== null && typeof frame.file === 'string' && typeof frame.line === 'number',
  );
  return { canary: event.canary, sink: event.sink, snippet: stripControl(event.snippet, true), stack };
}

/**
 * Cliente del agente: se conecta a cada `<pid>.sock` del directorio (vigilándolo durante el análisis, porque los
 * procesos pueden arrancar después) y acumula los eventos. Ningún error de socket llega al análisis.
 */
export function startAgentCollector(dir: string = resolveAgentDir()): AgentEventSource {
  const sockets = new Map<string, net.Socket>();
  const events: SinkEvent[] = [];
  let closed = false;

  const connect = (name: string): void => {
    const socket = net.createConnection(path.join(dir, name));
    sockets.set(name, socket);
    let pending = '';
    socket.on('data', (chunk: Buffer) => {
      pending += chunk.toString('utf8');
      if (pending.length > MAX_PENDING_CHARS && !pending.includes('\n')) {
        socket.destroy();
        return;
      }
      let newline = pending.indexOf('\n');
      while (newline !== -1) {
        const event = parseEvent(pending.slice(0, newline));
        if (event !== undefined) events.push(event);
        pending = pending.slice(newline + 1);
        newline = pending.indexOf('\n');
      }
    });
    socket.on('error', () => {
      socket.destroy();
    });
  };

  const scan = (): void => {
    if (closed || !isPrivateOwnDir(dir)) return;
    let names: string[];
    try {
      names = fs.readdirSync(dir);
    } catch (error) {
      void error;
      return;
    }
    for (const name of names) {
      if (name.endsWith('.sock') && !sockets.has(name)) connect(name);
    }
  };

  scan();
  const timer = setInterval(scan, SCAN_INTERVAL_MS);
  timer.unref();

  return {
    async collect(): Promise<SinkEvent[]> {
      scan();
      await new Promise<void>((resolve) => setTimeout(resolve, SETTLE_MS));
      scan();
      return [...events];
    },
    close(): void {
      if (closed) return;
      closed = true;
      clearInterval(timer);
      for (const socket of sockets.values()) socket.destroy();
      sockets.clear();
    },
  };
}
