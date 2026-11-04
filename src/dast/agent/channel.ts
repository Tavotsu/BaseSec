import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';

/** Un frame del stack, con ruta absoluta de un fichero del usuario. */
export interface StackFrame {
  file: string;
  line: number;
}

/** Evento que el agente envía a BaseSec: un argumento de un sink contenía un canario BS<8hex>. */
export interface SinkEvent {
  canary: string;
  sink: string;
  snippet: string;
  stack: StackFrame[];
}

export interface AgentServer {
  emit(event: SinkEvent): void;
  close(): void;
}

const BUFFER_LIMIT = 1000;
const PREFIX = '[basesec-agent]';

/** Aviso por stderr. Nunca lanza: si stderr no sirve, el agente se calla en vez de romper la app. */
export function agentWarn(message: string): void {
  try {
    process.stderr.write(`${PREFIX} ${message}\n`);
  } catch (error) {
    void error;
  }
}

/** Directorio de sockets: BASESEC_AGENT_DIR si está definido; si no, <tmp>/basesec-agent-<uid>. */
export function resolveAgentDir(env: NodeJS.ProcessEnv = process.env): string {
  const fromEnv = env.BASESEC_AGENT_DIR;
  if (fromEnv !== undefined && fromEnv !== '') return fromEnv;
  const uid = typeof process.getuid === 'function' ? process.getuid() : 'win';
  return path.join(os.tmpdir(), `basesec-agent-${uid}`);
}

/**
 * Crea el directorio si falta y comprueba que es un directorio propio, no un enlace, con permisos 0700. Si no lo es,
 * lanza: un directorio ajeno o accesible por otros usuarios revelaría los eventos.
 */
function ensurePrivateDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${dir} is not a directory`);
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new Error(`${dir} is not owned by the current user`);
  }
  if ((stat.mode & 0o077) !== 0) throw new Error(`${dir} must be readable only by its owner (0700)`);
}

/**
 * Servidor del agente: escucha en `<dir>/<pid>.sock` (0600 dentro de un dir 0700). Guarda los últimos 1000 eventos y
 * los entrega a cada cliente que conecta; después emite en vivo. Devuelve null si no puede preparar el directorio
 * (la app sigue sin instrumentar). No mantiene vivo el proceso.
 */
export function startAgentServer(): AgentServer | null {
  if (process.platform === 'win32') {
    agentWarn('the IAST agent does not support Windows yet; the application runs without instrumentation');
    return null;
  }
  let dir: string;
  let socketPath: string;
  try {
    dir = resolveAgentDir();
    ensurePrivateDir(dir);
    socketPath = path.join(dir, `${process.pid}.sock`);
  } catch (error) {
    agentWarn(`cannot prepare the agent directory (${error instanceof Error ? error.message : String(error)}); running without instrumentation`);
    return null;
  }

  const sockets = new Set<net.Socket>();
  const buffer: string[] = [];
  let closed = false;

  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('error', () => {
      sockets.delete(socket);
      socket.destroy();
    });
    socket.on('close', () => {
      sockets.delete(socket);
    });
    for (const line of buffer) socket.write(line);
    socket.unref();
  });
  server.on('error', (error) => {
    agentWarn(`socket error (${error.message}); BaseSec will not receive events from this process`);
  });
  server.unref();

  const close = (): void => {
    if (closed) return;
    closed = true;
    try {
      server.close();
    } catch (error) {
      agentWarn(`could not close the socket server: ${error instanceof Error ? error.message : String(error)}`);
    }
    for (const socket of sockets) socket.destroy();
    sockets.clear();
    try {
      if (fs.existsSync(socketPath)) fs.unlinkSync(socketPath);
    } catch (error) {
      agentWarn(`could not remove ${socketPath}: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const emit = (event: SinkEvent): void => {
    try {
      const line = `${JSON.stringify(event)}\n`;
      buffer.push(line);
      if (buffer.length > BUFFER_LIMIT) buffer.shift();
      for (const socket of sockets) socket.write(line);
    } catch (error) {
      agentWarn(`could not report an event: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  try {
    if (fs.existsSync(socketPath)) fs.unlinkSync(socketPath);
    server.listen(socketPath, () => {
      try {
        fs.chmodSync(socketPath, 0o600);
      } catch (error) {
        agentWarn(`could not restrict ${socketPath}: ${error instanceof Error ? error.message : String(error)}`);
      }
    });
  } catch (error) {
    agentWarn(`cannot open the socket (${error instanceof Error ? error.message : String(error)}); running without instrumentation`);
    return null;
  }

  process.on('exit', close);
  return { emit, close };
}
