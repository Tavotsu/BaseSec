import { spawn, spawnSync } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DastConfigError } from './config';

/** La app no llegó a responder o no arrancó: exit 2 en el CLI. */
export class AppStartError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AppStartError';
  }
}

export interface StartAppOptions {
  /** Comando de shell de la app (`pnpm dev`). */
  command: string;
  /** Origen del target, sin path. */
  origin: string;
  /** Path del healthcheck (mismo origen). */
  health: string;
  /** Segundos que se espera a que la app responda 2xx. */
  timeoutS: number;
  /** Ruta absoluta de dist/agent.cjs. */
  agentBundle: string;
  /** Directorio de trabajo del comando (y raíz de la app para los drivers). */
  cwd: string;
}

export interface StartedApp {
  /** Directorio de sockets del agente de esta ejecución. */
  dir: string;
  /** Teardown del grupo de procesos y borrado del directorio. Idempotente. */
  stop(): Promise<void>;
}

const GRACE_MS = 2000;
const HEALTH_INTERVAL_MS = 500;
const PROBE_TIMEOUT_MS = 2000;
export const DEFAULT_START_TIMEOUT_S = 60;
export const EXIT_ON_SIGINT = 130;
export const EXIT_ON_SIGTERM = 143;
const EXIT_ON_SIGNAL: Partial<Record<NodeJS.Signals, number>> = { SIGINT: EXIT_ON_SIGINT, SIGTERM: EXIT_ON_SIGTERM, SIGHUP: 129 };

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Ruta absoluta de dist/agent.cjs. En el bundle del CLI (dist/index.js) está al lado; desde el código fuente
 * (`pnpm dev`, src/dast/) está en ../../dist.
 */
export function resolveAgentBundle(): string {
  const candidates = [new URL('./agent.cjs', import.meta.url), new URL('../../dist/agent.cjs', import.meta.url)];
  for (const candidate of candidates) {
    const file = fileURLToPath(candidate);
    if (fs.existsSync(file)) return file;
  }
  throw new DastConfigError('IAST agent bundle not found (dist/agent.cjs). Run pnpm build first.');
}

/** Comprueba que el healthcheck cae en el mismo origen y devuelve la URL absoluta. */
export function healthUrl(origin: string, health: string): URL {
  if (!health.startsWith('/') || health.startsWith('//')) {
    throw new DastConfigError('Healthcheck path must start with "/" and must not be an absolute URL');
  }
  const resolved = new URL(health, origin);
  if (resolved.origin !== origin) throw new DastConfigError('Healthcheck path must stay on the target origin');
  return resolved;
}

function probeOnce(url: URL): Promise<boolean> {
  return new Promise((resolve) => {
    const request = http.get(url, { timeout: PROBE_TIMEOUT_MS }, (response) => {
      response.resume();
      const status = response.statusCode ?? 0;
      resolve(status >= 200 && status < 300);
    });
    request.on('timeout', () => request.destroy());
    request.on('error', () => resolve(false));
  });
}

/** Hace poll al healthcheck hasta 2xx, el plazo o la salida del proceso. */
async function waitForHealth(url: URL, timeoutMs: number, exited: () => boolean): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (exited()) return false;
    if (await probeOnce(url)) return true;
    await delay(HEALTH_INTERVAL_MS);
  }
  return false;
}

/** Comando de NODE_OPTIONS que carga el agente. La ruta va entre comillas, con `\` y `"` escapados. */
function requireFlag(bundle: string): string {
  return `--require "${bundle.replace(/[\\"]/g, '\\$&')}"`;
}

/** Envía una señal a todo el grupo del proceso (nietos incluidos). En Windows, al árbol con taskkill. */
function signalGroup(pid: number, signal: 'SIGTERM' | 'SIGKILL'): void {
  if (process.platform === 'win32') {
    spawnSync('taskkill', ['/pid', String(pid), '/T', '/F'], { stdio: 'ignore' });
    return;
  }
  try {
    process.kill(-pid, signal);
  } catch (error) {
    // ESRCH: el grupo ya no existe. Cualquier otro error también significa que no hay nada más que hacer.
    void error;
  }
}

/** true mientras quede algún proceso en el grupo (aunque el líder ya haya salido). */
function groupAlive(child: ChildProcess): boolean {
  if (child.pid === undefined) return false;
  if (process.platform === 'win32') return child.exitCode === null && child.signalCode === null;
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

/** Arranca la app con el agente, espera a que responda y devuelve el teardown. Lanza AppStartError si no responde. */
export async function startTargetApp(options: StartAppOptions): Promise<StartedApp> {
  const url = healthUrl(options.origin, options.health);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-agent-'));
  const nodeOptions = [process.env.NODE_OPTIONS, requireFlag(options.agentBundle)].filter(Boolean).join(' ');
  const env = {
    ...process.env,
    NODE_OPTIONS: nodeOptions,
    BASESEC_AGENT_DIR: dir,
    BASESEC_AGENT_ROOT: options.cwd,
  };

  let child: ChildProcess;
  try {
    child = spawn(options.command, {
      shell: true,
      cwd: options.cwd,
      env,
      // Grupo propio en POSIX: el teardown mata también a los nietos (un `pnpm dev` lanza el servidor como nieto).
      detached: process.platform !== 'win32',
      // stdout de la app a stderr: el stdout de BaseSec puede llevar el informe.
      stdio: ['ignore', 2, 2],
    });
  } catch (error) {
    fs.rmSync(dir, { recursive: true, force: true });
    throw new AppStartError(`Could not start "${options.command}": ${error instanceof Error ? error.message : String(error)}`);
  }

  let exited = false;
  let spawnFailure: Error | undefined;
  child.once('exit', () => {
    exited = true;
  });
  child.once('error', (error) => {
    spawnFailure = error;
    exited = true;
  });

  let stopping: Promise<void> | undefined;
  const stop = (): Promise<void> => {
    stopping ??= (async () => {
      // Los handlers siguen puestos durante el teardown: una segunda señal no debe matar a BaseSec a medias.
      const pid = child.pid;
      if (pid !== undefined) {
        signalGroup(pid, 'SIGTERM');
        const graceEnd = Date.now() + GRACE_MS;
        while (groupAlive(child) && Date.now() < graceEnd) await delay(50);
        if (groupAlive(child)) signalGroup(pid, 'SIGKILL');
        const killEnd = Date.now() + GRACE_MS;
        while (groupAlive(child) && Date.now() < killEnd) await delay(20);
      }
      fs.rmSync(dir, { recursive: true, force: true });
      process.off('SIGINT', onSignal);
      process.off('SIGTERM', onSignal);
      process.off('SIGHUP', onSignal);
      process.off('exit', onExit);
    })();
    return stopping;
  };

  // Ctrl-C y SIGTERM: el terminal no llega al grupo (es propio), así que BaseSec mata el grupo antes de salir.
  const onSignal = (signal: NodeJS.Signals): void => {
    void stop().finally(() => process.exit(EXIT_ON_SIGNAL[signal] ?? EXIT_ON_SIGTERM));
  };
  // Último recurso (process.exit, excepción no capturada): sincrónico, sin esperas.
  const onExit = (): void => {
    if (child.pid !== undefined && groupAlive(child)) signalGroup(child.pid, 'SIGKILL');
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  process.on('SIGHUP', onSignal);
  process.on('exit', onExit);

  const healthy = await waitForHealth(url, options.timeoutS * 1000, () => exited);
  if (!healthy) {
    // La razón se calcula antes del teardown: stop() mata el proceso y lo marcaría como salido.
    const reason = spawnFailure !== undefined
      ? spawnFailure.message
      : exited
        ? 'the command exited before answering'
        : `no answer within ${options.timeoutS}s`;
    await stop();
    throw new AppStartError(`The app did not become healthy at ${url.href} (${reason}).`);
  }
  return { dir, stop };
}
