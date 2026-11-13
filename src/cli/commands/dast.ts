import * as fs from 'node:fs';
import * as path from 'node:path';
import pc from 'picocolors';
import prompts from 'prompts';
import { loadConfig } from '../../config/loader';
import { getFormatter } from '../../report/formatter';
import { Guard } from '../../dast/guard';
import { DastConfigError, expandEnvHeaders, parseHeaderFlag } from '../../dast/config';
import { DastTargetUnreachableError, runDast } from '../../dast/runner';
import { startAgentCollector } from '../../dast/agent-client';
import type { AgentEventSource } from '../../dast/agent-client';
import { AppStartError, DEFAULT_START_TIMEOUT_S, resolveAgentBundle, startTargetApp } from '../../dast/agent-launcher';
import type { StartedApp } from '../../dast/agent-launcher';
import { resolveAgentDir } from '../../dast/agent/channel';
import { GuardError } from '../../dast/types';
import { RouteArtifactError, isArtifactStale, loadRouteArtifact, toSurfaceEndpoints } from '../../dast/surface';
import type { LoadedSurface } from '../../dast/surface';
import { Pipeline } from '../../core/pipeline';
import { defaultArtifactPath, findProjectRoot } from '../../core/route-emitter';
import type { DastConfig, OutputFormat, ScanResult, Severity, basesecConfig } from '../../rules/types';
import type { RouteArtifact } from '../../framework/routes/types';
import { severityGte } from '../../utils/severity';
import { logger } from '../../utils/logger';
import { printError } from '../output';
import { emitReport } from '../report-output';

export interface DastCliOptions {
  format?: OutputFormat;
  output?: string;
  severity?: Severity;
  strict?: boolean;
  quiet?: boolean;
  verbose?: boolean;
  noColor?: boolean;
  config?: string;
  health?: string;
  /** Repetible: "Name: value". */
  header?: string[];
  allowRemote?: boolean;
  allowVulnerableNode?: boolean;
  /** Número o texto (cac entrega texto); se valida aquí. */
  rps?: number | string;
  concurrency?: number | string;
  maxRequests?: number | string;
  timeout?: number | string;
  requestTimeout?: number | string;
  evidenceDir?: string;
  /** false con --no-evidence; undefined = lo que diga la config (por defecto true). */
  evidence?: boolean;
  rules?: string;
  /** Artefacto de rutas explícito. */
  routes?: string;
  /** Ruta de código de la que derivar las rutas en memoria, sin escribir nada. */
  scan?: string;
  /** --probe-rate-limit: activa DAST-010. Sin el flag manda dast.probeRateLimit de la config. */
  probeRateLimit?: boolean;
  /** --agent: correlaciona las inyecciones con los sinks reales del agente IAST (requiere superficie). */
  agent?: boolean;
  /** --start <cmd>: arranca la app con el agente inyectado y la detiene al terminar. Implica --agent. */
  start?: string | true;
  /** --start-timeout <s>: segundos que se espera a que la app responda. */
  startTimeout?: number | string;
  /** --agent-dir <dir>: directorio de sockets del agente en modo manual. */
  agentDir?: string;
  /** Ruta de dist/agent.cjs. Solo para tests: por defecto se resuelve desde el bundle del CLI. */
  agentBundle?: string;
}

const SURFACE_LABEL: Record<LoadedSurface['source'], string> = {
  artifact: 'saved artifact',
  scan: 'scan',
  'routes-file': 'routes file',
};

export const DEFAULTS = {
  rps: 20,
  concurrency: 5,
  maxRequests: 5000,
  timeout: 300,
  requestTimeout: 10000,
} as const;

export function toPositiveInteger(name: string, value: number | string): number {
  const parsed = typeof value === 'number' ? value : /^\d+$/.test(value.trim()) ? Number(value.trim()) : NaN;
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new DastConfigError(`${name} must be a positive integer (got: ${String(value)})`);
  }
  return parsed;
}

export function resolveInteger(
  name: string,
  cliValue: number | string | undefined,
  configValue: number | undefined,
  fallback: number,
): number {
  if (cliValue !== undefined) return toPositiveInteger(name, cliValue);
  if (configValue !== undefined) return toPositiveInteger(name, configValue);
  return fallback;
}

/** Ruta de evidencia absoluta; debe ser un directorio existente o uno creable en un ancestro escribible. */
export function validateEvidenceDir(raw: string): string {
  const resolved = path.resolve(raw);
  let probe = resolved;
  try {
    while (!fs.existsSync(probe)) {
      const parent = path.dirname(probe);
      if (parent === probe) break;
      probe = parent;
    }
    if (!fs.statSync(probe).isDirectory()) {
      throw new DastConfigError(`--evidence-dir is not a directory: ${resolved}`);
    }
    fs.accessSync(probe, fs.constants.W_OK);
  } catch (e) {
    if (e instanceof DastConfigError) throw e;
    throw new DastConfigError(`--evidence-dir cannot be written: ${resolved}`);
  }
  return resolved;
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/^\[|\]$/g, '');
}

/**
 * Quita credenciales de URL (`user:pass@`) de un mensaje y sustituye el target tal como lo escribió el usuario
 * por su origen: ni los errores ni el progreso deben mostrar `user:pass@host`.
 */
export function scrubMessage(message: string, rawTarget: string, origin: string | undefined): string {
  let out = message;
  if (origin !== undefined && rawTarget !== '') out = out.split(rawTarget).join(origin);
  return out.replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/?#]*@/gi, '$1');
}

/** Sin credenciales: `retryCommand` lleva el origen, nunca la URL completa del usuario. */
function printRemoteBlocked(hostname: string, retryCommand: string): void {
  console.error(pc.red(`  ✖ Remote host blocked: ${hostname}`));
  console.error('');
  console.error('    BaseSec only tests loopback and private networks by default.');
  console.error("    Testing a system without its owner's written authorization is a crime in most jurisdictions.");
  console.error('');
  console.error(`    If you are authorized:  ${retryCommand}`);
}

function loadSurfaceFile(file: string): RouteArtifact {
  try {
    return loadRouteArtifact(path.resolve(file));
  } catch (e) {
    if (e instanceof RouteArtifactError) throw new DastConfigError(e.message);
    throw e;
  }
}

/**
 * Superficie de ataque (plan §5.3, §9.1): `--routes`, `--scan`, o el artefacto por defecto del proyecto.
 * Un error en `--routes` o `--scan` es de configuración (exit 3). Un artefacto por defecto inválido
 * se ignora con aviso. Sin nada de eso, undefined (modo sin código fuente).
 */
async function resolveSurface(options: DastCliOptions, quiet: boolean): Promise<LoadedSurface | undefined> {
  if (options.routes !== undefined) {
    if (options.routes.trim() === '') throw new DastConfigError('--routes needs a file path');
    const artifact = loadSurfaceFile(options.routes);
    return { artifact, source: 'routes-file', stale: isArtifactStale(artifact) };
  }

  if (options.scan !== undefined) {
    if (options.scan.trim() === '') throw new DastConfigError('--scan needs a path');
    const scanPath = path.resolve(options.scan);
    if (!fs.existsSync(scanPath)) throw new DastConfigError(`--scan path does not exist: ${options.scan}`);
    let result: ScanResult;
    try {
      // noCache: la caché de análisis escribe en ~/.basesec/cache, y --scan no escribe nada en disco.
      // noDeps: el artefacto ignora los hallazgos de dependencias.
      result = await new Pipeline(undefined, { noCache: true }).run(scanPath, { emitRoutes: true, noDeps: true });
    } catch (e) {
      throw new DastConfigError(`Could not build routes from ${options.scan}: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (!result.routes) throw new DastConfigError(`Could not build routes from ${options.scan}`);
    // Recién generado a partir del código actual: nunca está obsoleto.
    return { artifact: result.routes, source: 'scan', stale: false };
  }

  const defaultFile = defaultArtifactPath(findProjectRoot(process.cwd()));
  if (!fs.existsSync(defaultFile)) return undefined;
  try {
    const artifact = loadRouteArtifact(defaultFile);
    return { artifact, source: 'artifact', stale: isArtifactStale(artifact) };
  } catch (e) {
    if (!(e instanceof RouteArtifactError)) throw e;
    if (!quiet) {
      console.error(pc.yellow(`  ⚠ Saved route artifact ignored: ${e.message}`));
    }
    return undefined;
  }
}

export function printSurfaceNotices(surface: LoadedSurface): void {
  const endpoints = toSurfaceEndpoints(surface.artifact);
  const mutating = endpoints.filter((endpoint) => endpoint.mutating).length;
  console.error(
    pc.cyan(
      `  Routes: ${surface.artifact.routes.length} from ${SURFACE_LABEL[surface.source]} · ${surface.artifact.unresolved.length} unresolved`,
    ),
  );
  if (mutating > 0) {
    console.error(
      pc.blue(
        `  ℹ ${mutating} of ${endpoints.length} endpoints skipped (POST/PUT/PATCH/DELETE). Mutation testing is not available yet.`,
      ),
    );
  }
  if (surface.stale) {
    console.error(pc.yellow('  ⚠ The route artifact is older than the source code; re-run basesec scan --emit-routes.'));
  }
}

/** Cabeceras de la config con las de `--header` encima (mismo nombre, sin distinguir mayúsculas). */
export function mergeDastHeaders(configHeaders: Record<string, string> | undefined, flags: string[]): Record<string, string> {
  const merged = new Map<string, [string, string]>();
  for (const [name, value] of Object.entries(configHeaders ?? {})) {
    merged.set(name.toLowerCase(), [name, value]);
  }
  for (const raw of flags) {
    const [name, value] = parseHeaderFlag(raw);
    merged.set(name.toLowerCase(), [name, value]);
  }
  return Object.fromEntries(merged.values());
}

/**
 * Barandilla de destino (plan §8.1) antes de cualquier petición: un host no local exige --allow-remote, y luego
 * confirmación por TTY o BASESEC_ALLOW_REMOTE=1. Devuelve 3 si se niega (ya impreso) o undefined si se puede seguir.
 * La comparten `dast` y `scan --verify`.
 */
export async function confirmTargetAccess(args: {
  target: string;
  hostname: string;
  origin: string;
  allowRemote: boolean;
  isTTY: boolean;
  envAllowRemote: boolean;
  /** Comando que el mensaje sugiere si el usuario está autorizado (distinto en `dast` y en `scan --verify`). */
  retryCommand: string;
}): Promise<number | undefined> {
  const safe = (message: string): string => scrubMessage(message, args.target, args.origin);
  try {
    // Probe sin --allow-remote: solo sirve para saber si el host es remoto, antes de preguntar.
    await new Guard().assertTargetAllowed(args.target, { isTTY: args.isTTY });
  } catch (e) {
    if (e instanceof GuardError && e.code === 'remote-blocked') {
      if (!args.allowRemote) {
        printRemoteBlocked(args.hostname, args.retryCommand);
        return 3;
      }
      if (args.isTTY) {
        const answer = await prompts({
          type: 'text',
          name: 'value',
          message: 'Type the host to confirm you are authorized to test it:',
          // El prompt va por stderr: stdout puede estar llevando el JSON del informe.
          stdout: process.stderr,
        });
        if (typeof answer.value !== 'string' || normalizeHost(answer.value) !== normalizeHost(args.hostname)) {
          printError('Host confirmation did not match. No requests were sent.');
          return 3;
        }
      } else if (!args.envAllowRemote) {
        printError('Remote host without a terminal: set BASESEC_ALLOW_REMOTE=1 to allow it. No requests were sent.');
        return 3;
      }
    } else if (e instanceof GuardError) {
      printError(safe(e.message));
      return 3;
    } else {
      throw e;
    }
  }
  return undefined;
}

/** Avisos al terminar el ataque: endpoints atacados y evidencia que no pudo escribirse. */
export function printAttackNotices(result: ScanResult, evidence: boolean, quiet: boolean): void {
  const attacked = result.stats.dast?.endpoints.attacked ?? 0;
  if (!quiet && attacked > 0) {
    console.error(pc.cyan(`  Sent non-destructive payloads to ${attacked} endpoint(s); mutations are off.`));
  }

  if (evidence && !quiet && result.findings.length > 0 && result.stats.dast?.evidenceDir === undefined) {
    console.error(pc.yellow('  ⚠ Evidence files could not be written (run with --verbose for details).'));
  }
}

/** Progreso en stderr: una línea que se reescribe en un TTY, líneas sueltas si no. `clear()` borra la línea. */
export function createProgressReporter(quiet: boolean): {
  onProgress: ((event: { done: number; total: number; requests: number; label: string }) => void) | undefined;
  clear: () => void;
} {
  const progressTTY = !quiet && process.stderr.isTTY === true;
  return {
    onProgress: quiet
      ? undefined
      : (event): void => {
          if (progressTTY) {
            process.stderr.write(`\r\x1b[K  ${event.done}/${event.total} · ${event.requests} requests · ${event.label}`);
          } else {
            process.stderr.write(`[${event.done}/${event.total}] ${event.label} · ${event.requests} requests\n`);
          }
        },
    clear: (): void => {
      if (progressTTY) process.stderr.write('\r\x1b[K');
    },
  };
}

interface AgentSessionArgs {
  start: string | true | undefined;
  startTimeout: number;
  agentDirFlag: string | undefined;
  agentBundle: string | undefined;
  origin: string;
  health: string;
  quiet: boolean;
}

/** Sockets del agente en `dir` que ya existen (cero: la app aún no lo ha cargado). */
function countAgentSockets(dir: string): number {
  try {
    return fs.readdirSync(dir).filter((name) => name.endsWith('.sock')).length;
  } catch (error) {
    void error;
    return 0;
  }
}

/**
 * Modo `--start`: arranca la app con el agente y espera a que responda (lanza AppStartError si no lo hace). Modo
 * manual: el usuario ya la arrancó con NODE_OPTIONS; se usa `--agent-dir` o el directorio por defecto.
 */
async function startAgentSession(args: AgentSessionArgs): Promise<{ dir: string; app?: StartedApp }> {
  if (typeof args.start === 'string') {
    const bundle = args.agentBundle ?? resolveAgentBundle();
    if (!args.quiet) console.error(pc.cyan(`  Starting the app with the IAST agent: ${args.start}`));
    const app = await startTargetApp({
      command: args.start,
      origin: args.origin,
      health: args.health,
      timeoutS: args.startTimeout,
      agentBundle: bundle,
      cwd: process.cwd(),
    });
    return { dir: app.dir, app };
  }
  const dir = args.agentDirFlag !== undefined ? path.resolve(args.agentDirFlag) : resolveAgentDir();
  if (!args.quiet && countAgentSockets(dir) === 0) {
    console.error(pc.yellow(`  ⚠ No agent socket in ${dir} yet. Start the app with NODE_OPTIONS="--require <path to dist/agent.cjs>".`));
  }
  return { dir };
}

/**
 * Comando `basesec dast <url>`. Sin superficie es el modo sin código fuente. Devuelve el exit code:
 * 0 sin hallazgos (o con hallazgos sin --strict), 1 hallazgos con --strict,
 * 2 target inalcanzable o error inesperado, 3 configuración, validación o barandillas.
 */
export async function runDastCommand(url: string | undefined, options: DastCliOptions): Promise<number> {
  if (options.verbose) {
    logger.isVerbose = true;
  }
  const quiet = options.quiet === true;

  if (options.routes !== undefined && options.scan !== undefined) {
    printError('--routes and --scan cannot be used together');
    return 3;
  }

  let fileConfig: Partial<basesecConfig> = {};
  if (options.config) {
    try {
      fileConfig = loadConfig(options.config, process.cwd());
    } catch (e) {
      printError(`Could not load config file: ${e instanceof Error ? e.message : String(e)}`);
      return 3;
    }
  } else {
    try {
      fileConfig = loadConfig(undefined, process.cwd());
    } catch (e) {
      logger.warn('Failed to load config file, using defaults', e);
    }
  }
  const dastConfig: DastConfig = fileConfig.dast ?? {};

  const target = url !== undefined ? String(url) : dastConfig.target;
  if (!target) {
    printError('No target URL. Usage: basesec dast <url>, or set dast.target in the config file.');
    return 3;
  }

  const format: OutputFormat = options.format ?? 'terminal';
  const severity: Severity = options.severity ?? 'low';

  let numbers: {
    rps: number;
    concurrency: number;
    maxRequests: number;
    timeout: number;
    requestTimeout: number;
    startTimeout: number;
  };
  let evidenceDir: string | undefined;
  let headers: Record<string, string>;
  try {
    numbers = {
      rps: resolveInteger('--rps', options.rps, dastConfig.rps, DEFAULTS.rps),
      concurrency: resolveInteger('--concurrency', options.concurrency, dastConfig.concurrency, DEFAULTS.concurrency),
      maxRequests: resolveInteger('--max-requests', options.maxRequests, dastConfig.maxRequests, DEFAULTS.maxRequests),
      timeout: resolveInteger('--timeout', options.timeout, dastConfig.timeout, DEFAULTS.timeout),
      requestTimeout: resolveInteger(
        '--request-timeout',
        options.requestTimeout,
        dastConfig.requestTimeout,
        DEFAULTS.requestTimeout,
      ),
      startTimeout: resolveInteger('--start-timeout', options.startTimeout, dastConfig.startTimeout, DEFAULT_START_TIMEOUT_S),
    };
    const rawEvidenceDir = options.evidenceDir ?? dastConfig.evidenceDir;
    evidenceDir = rawEvidenceDir !== undefined ? validateEvidenceDir(String(rawEvidenceDir)) : undefined;

    headers = mergeDastHeaders(dastConfig.headers, options.header ?? []);
    // Valida `$env:` antes de cualquier pregunta; runDast vuelve a expandir los valores crudos.
    expandEnvHeaders(headers);
  } catch (e) {
    if (e instanceof DastConfigError) {
      printError(e.message);
      return 3;
    }
    throw e;
  }

  if (options.start !== undefined && (typeof options.start !== 'string' || options.start.trim() === '')) {
    printError('--start needs a command, e.g. --start "pnpm dev"');
    return 3;
  }
  if (options.start !== undefined && options.agentDir !== undefined) {
    printError('--agent-dir cannot be combined with --start: --start uses its own directory');
    return 3;
  }
  if (options.agentDir !== undefined && options.agent !== true) {
    printError('--agent-dir needs --agent');
    return 3;
  }
  if (options.startTimeout !== undefined && options.start === undefined) {
    printError('--start-timeout needs --start');
    return 3;
  }
  // --start implica --agent; la configuración solo activa el agente, nunca lanza procesos (start no viene de config).
  const agentRequested = options.agent === true || options.start !== undefined || dastConfig.agent === true;

  const evidence = options.evidence ?? dastConfig.evidence ?? true;
  const rules = options.rules !== undefined
    ? String(options.rules).split(',').map((id) => id.trim()).filter((id) => id !== '')
    : dastConfig.rules;
  const health = options.health !== undefined ? String(options.health) : (dastConfig.health ?? '/');
  const isTTY = process.stdin.isTTY === true;
  const allowRemoteRequested = options.allowRemote === true || dastConfig.allowRemote === true;
  const envAllowRemote = process.env.BASESEC_ALLOW_REMOTE === '1';

  let hostname: string;
  let origin: string;
  try {
    const parsedTarget = new URL(target);
    hostname = parsedTarget.hostname;
    origin = parsedTarget.origin;
  } catch {
    printError('Invalid target URL.');
    return 3;
  }
  const safe = (message: string): string => scrubMessage(message, target, origin);

  // Node vulnerable: se comprueba antes de la sonda y de cualquier prompt. runDast lo repite (defensa para quien lo llame directamente).
  try {
    new Guard({ allowVulnerableNode: options.allowVulnerableNode === true }).assertNodeSupported();
  } catch (e) {
    if (e instanceof GuardError) {
      printError(safe(e.message));
      return 3;
    }
    throw e;
  }

  const denied = await confirmTargetAccess({
    target,
    hostname,
    origin,
    allowRemote: allowRemoteRequested,
    isTTY,
    envAllowRemote,
    retryCommand: `basesec dast ${origin} --allow-remote`,
  });
  if (denied !== undefined) return denied;

  // Después de la confirmación de host y antes de cualquier petición al target.
  let surface: LoadedSurface | undefined;
  try {
    surface = await resolveSurface(options, quiet);
  } catch (e) {
    if (e instanceof DastConfigError) {
      printError(safe(e.message));
      return 3;
    }
    throw e;
  }

  if (agentRequested && surface === undefined) {
    printError('--agent needs routes to attack: pass --routes, --scan, or emit them first with basesec scan --emit-routes');
    return 3;
  }

  if (!quiet) {
    if (surface) {
      printSurfaceNotices(surface);
    } else {
      console.error(pc.yellow('  ⚠ No source code: no routes to attack.'));
      console.error(pc.yellow('    Only headers, cookies and errors of / and the healthcheck are checked.'));
    }
  }

  const progress = createProgressReporter(quiet);

  let result: ScanResult;
  let app: StartedApp | undefined;
  let agentSource: AgentEventSource | undefined;
  try {
    if (agentRequested) {
      const agentDir = await startAgentSession({
        start: options.start,
        startTimeout: numbers.startTimeout,
        agentDirFlag: options.agentDir ?? dastConfig.agentDir,
        agentBundle: options.agentBundle,
        origin,
        health,
        quiet,
      });
      app = agentDir.app;
      agentSource = startAgentCollector(agentDir.dir);
      if (!quiet) {
        console.error(pc.cyan(`  IAST agent: sockets in ${agentDir.dir}`));
      }
    }
    result = await runDast({
      agent: agentSource,
      url: target,
      surface,
      health,
      headers,
      allowRemote: allowRemoteRequested,
      allowRemoteEnv: envAllowRemote,
      allowVulnerableNode: options.allowVulnerableNode === true,
      isTTY,
      rps: numbers.rps,
      concurrency: numbers.concurrency,
      maxRequests: numbers.maxRequests,
      timeout: numbers.timeout,
      requestTimeout: numbers.requestTimeout,
      evidence,
      evidenceDir,
      rules,
      // Solo por config: rutas públicas a propósito que DAST-008 no debe reportar.
      publicRoutes: dastConfig.publicRoutes,
      probeRateLimit: options.probeRateLimit === true || dastConfig.probeRateLimit === true,
      onProgress: progress.onProgress,
    });
  } catch (e) {
    if (e instanceof GuardError || e instanceof DastConfigError) {
      printError(safe(e.message));
      return 3;
    }
    if (e instanceof DastTargetUnreachableError) {
      printError(`${safe(e.message)}. Is the application running?`);
      return 2;
    }
    if (e instanceof AppStartError) {
      printError(safe(e.message));
      return 2;
    }
    printError(safe(e instanceof Error ? e.message : String(e)));
    return 2;
  } finally {
    progress.clear();
    agentSource?.close();
    // Teardown garantizado del grupo de procesos de --start, también ante errores.
    if (app !== undefined) await app.stop();
  }

  printAttackNotices(result, evidence, quiet);

  const filtered = result.findings.filter((finding) => severityGte(finding.severity, severity));
  const filteredResult: ScanResult = { ...result, findings: filtered };
  const output = getFormatter(format).format(filteredResult, result.stats.dast?.target ?? hostname);

  if (!(await emitReport(output, format, options.output, true))) {
    return 0;
  }

  if (options.strict && filtered.length > 0) {
    return 1;
  }
  return 0;
}
