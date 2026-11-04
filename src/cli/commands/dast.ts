import * as fs from 'node:fs';
import * as path from 'node:path';
import pc from 'picocolors';
import prompts from 'prompts';
import { loadConfig } from '../../config/loader';
import { getFormatter } from '../../report/formatter';
import { Guard } from '../../dast/guard';
import { DastConfigError, expandEnvHeaders, parseHeaderFlag } from '../../dast/config';
import { DastTargetUnreachableError, runDast } from '../../dast/runner';
import { GuardError } from '../../dast/types';
import type { DastConfig, OutputFormat, ScanResult, Severity, basesecConfig } from '../../rules/types';
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
}

const DEFAULTS = {
  rps: 20,
  concurrency: 5,
  maxRequests: 5000,
  timeout: 300,
  requestTimeout: 10000,
} as const;

function toPositiveInteger(name: string, value: number | string): number {
  const parsed = typeof value === 'number' ? value : /^\d+$/.test(value.trim()) ? Number(value.trim()) : NaN;
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new DastConfigError(`${name} must be a positive integer (got: ${String(value)})`);
  }
  return parsed;
}

function resolveInteger(
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
function validateEvidenceDir(raw: string): string {
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
function scrubMessage(message: string, rawTarget: string, origin: string | undefined): string {
  let out = message;
  if (origin !== undefined && rawTarget !== '') out = out.split(rawTarget).join(origin);
  return out.replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/?#]*@/gi, '$1');
}

/** `origin` sin credenciales: nunca se imprime la URL completa del usuario. */
function printRemoteBlocked(hostname: string, origin: string): void {
  console.error(pc.red(`  ✖ Remote host blocked: ${hostname}`));
  console.error('');
  console.error('    BaseSec only tests loopback and private networks by default.');
  console.error("    Testing a system without its owner's written authorization is a crime in most jurisdictions.");
  console.error('');
  console.error(`    If you are authorized:  basesec dast ${origin} --allow-remote`);
}

/**
 * Comando `basesec dast <url>` en modo sin código fuente. Devuelve el exit code:
 * 0 sin hallazgos (o con hallazgos sin --strict), 1 hallazgos con --strict,
 * 2 target inalcanzable o error inesperado, 3 configuración, validación o barandillas.
 */
export async function runDastCommand(url: string | undefined, options: DastCliOptions): Promise<number> {
  if (options.verbose) {
    logger.isVerbose = true;
  }
  const quiet = options.quiet === true;

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

  let numbers: { rps: number; concurrency: number; maxRequests: number; timeout: number; requestTimeout: number };
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
    };
    const rawEvidenceDir = options.evidenceDir ?? dastConfig.evidenceDir;
    evidenceDir = rawEvidenceDir !== undefined ? validateEvidenceDir(String(rawEvidenceDir)) : undefined;

    // Config primero; cada --header sustituye a la de config con el mismo nombre (sin distinguir mayúsculas).
    const merged = new Map<string, [string, string]>();
    for (const [name, value] of Object.entries(dastConfig.headers ?? {})) {
      merged.set(name.toLowerCase(), [name, value]);
    }
    for (const raw of options.header ?? []) {
      const [name, value] = parseHeaderFlag(raw);
      merged.set(name.toLowerCase(), [name, value]);
    }
    headers = Object.fromEntries(merged.values());
    // Valida `$env:` antes de cualquier pregunta; runDast vuelve a expandir los valores crudos.
    expandEnvHeaders(headers);
  } catch (e) {
    if (e instanceof DastConfigError) {
      printError(e.message);
      return 3;
    }
    throw e;
  }

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

  try {
    // Probe sin --allow-remote: solo sirve para saber si el host es remoto, antes de preguntar.
    await new Guard().assertTargetAllowed(target, { isTTY });
  } catch (e) {
    if (e instanceof GuardError && e.code === 'remote-blocked') {
      if (!allowRemoteRequested) {
        printRemoteBlocked(hostname, origin);
        return 3;
      }
      if (isTTY) {
        const answer = await prompts({
          type: 'text',
          name: 'value',
          message: 'Type the host to confirm you are authorized to test it:',
          // El prompt va por stderr: stdout puede estar llevando el JSON del informe.
          stdout: process.stderr,
        });
        if (typeof answer.value !== 'string' || normalizeHost(answer.value) !== normalizeHost(hostname)) {
          printError('Host confirmation did not match. No requests were sent.');
          return 3;
        }
      } else if (!envAllowRemote) {
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

  if (!quiet) {
    console.error(pc.yellow('  ⚠ No source code: no routes to attack.'));
    console.error(pc.yellow('    Only headers, cookies and errors of / and the healthcheck are checked.'));
  }

  const progressTTY = !quiet && process.stderr.isTTY === true;
  const onProgress = quiet
    ? undefined
    : (event: { done: number; total: number; requests: number; label: string }): void => {
        if (progressTTY) {
          process.stderr.write(`\r\x1b[K  ${event.done}/${event.total} · ${event.requests} requests · ${event.label}`);
        } else {
          process.stderr.write(`[${event.done}/${event.total}] ${event.label} · ${event.requests} requests\n`);
        }
      };

  let result: ScanResult;
  try {
    result = await runDast({
      url: target,
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
      onProgress,
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
    printError(safe(e instanceof Error ? e.message : String(e)));
    return 2;
  } finally {
    if (progressTTY) process.stderr.write('\r\x1b[K');
  }

  if (evidence && !quiet && result.findings.length > 0 && result.stats.dast?.evidenceDir === undefined) {
    console.error(pc.yellow('  ⚠ Evidence files could not be written (run with --verbose for details).'));
  }

  const filtered = result.findings.filter((finding) => severityGte(finding.severity, severity));
  const filteredResult: ScanResult = { ...result, findings: filtered };
  const output = getFormatter(format).format(filteredResult, result.stats.dast?.target ?? hostname);

  if (!(await emitReport(output, format, options.output))) {
    return 0;
  }

  if (options.strict && filtered.length > 0) {
    return 1;
  }
  return 0;
}
