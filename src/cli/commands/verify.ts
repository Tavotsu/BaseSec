import pc from 'picocolors';
import { getFormatter } from '../../report/formatter';
import { Guard } from '../../dast/guard';
import { DastConfigError, expandEnvHeaders } from '../../dast/config';
import { DastTargetUnreachableError, runDast } from '../../dast/runner';
import { GuardError } from '../../dast/types';
import { correlate } from '../../dast/correlate';
import { startAgentCollector } from '../../dast/agent-client';
import { resolveAgentDir } from '../../dast/agent/channel';
import type { LoadedSurface } from '../../dast/surface';
import type { CliOptions, DastConfig, ScanResult } from '../../rules/types';
import { logger } from '../../utils/logger';
import { printError } from '../output';
import { emitReport } from '../report-output';
import { analyzeTarget, filterBySeverity } from './scan';
import {
  DEFAULTS,
  confirmTargetAccess,
  createProgressReporter,
  mergeDastHeaders,
  printAttackNotices,
  printSurfaceNotices,
  resolveInteger,
  scrubMessage,
  validateEvidenceDir,
} from './dast';

/**
 * `basesec scan <path> --verify --target <url>` (plan §7.7). Analiza de forma estática, ataca el target con las rutas
 * de ese mismo código (el motor de `dast`) y correlaciona: un estático confirmado pasa a `verified`, sin duplicarse.
 * Exit codes como `scan` y `dast`: 0 limpio, 1 hallazgos con --strict, 2 target inalcanzable o error de ejecución,
 * 3 configuración, validación o barandillas.
 */
export async function runVerify(targetPath: string, options: CliOptions): Promise<number> {
  const started = Date.now();
  if (options.verbose) {
    logger.isVerbose = true;
  }
  const quiet = options.quiet === true;
  const rawTarget = options.target ?? '';
  const flags = options.verifyDast ?? {};

  // Suelo de Node antes de cualquier petición: el servidor del target puede ser hostil.
  try {
    new Guard({ allowVulnerableNode: flags.allowVulnerableNode === true }).assertNodeSupported();
  } catch (e) {
    if (e instanceof GuardError) {
      printError(e.message);
      return 3;
    }
    throw e;
  }

  let origin: string;
  let hostname: string;
  try {
    const parsedTarget = new URL(rawTarget);
    origin = parsedTarget.origin;
    hostname = parsedTarget.hostname;
  } catch {
    printError('Invalid target URL.');
    return 3;
  }
  const safe = (message: string): string => scrubMessage(message, rawTarget, origin);
  const isTTY = process.stdin.isTTY === true;
  const envAllowRemote = process.env.BASESEC_ALLOW_REMOTE === '1';

  const analysis = await analyzeTarget(targetPath, options, true);
  if (typeof analysis === 'number') {
    return analysis;
  }
  const { result: staticResult, fileConfig } = analysis;
  const dastConfig: DastConfig = fileConfig.dast ?? {};

  // Valores de --dast-* sobre los de `dast` en la config. Se validan antes de cualquier pregunta o petición.
  let numbers: { rps: number; concurrency: number; maxRequests: number; timeout: number; requestTimeout: number };
  let evidenceDir: string | undefined;
  let headers: Record<string, string>;
  try {
    numbers = {
      rps: resolveInteger('--dast-rps', flags.rps, dastConfig.rps, DEFAULTS.rps),
      concurrency: resolveInteger('--dast-concurrency', undefined, dastConfig.concurrency, DEFAULTS.concurrency),
      maxRequests: resolveInteger('--dast-max-requests', flags.maxRequests, dastConfig.maxRequests, DEFAULTS.maxRequests),
      timeout: resolveInteger('--dast-timeout', flags.timeout, dastConfig.timeout, DEFAULTS.timeout),
      requestTimeout: resolveInteger(
        '--dast-request-timeout',
        flags.requestTimeout,
        dastConfig.requestTimeout,
        DEFAULTS.requestTimeout,
      ),
    };
    const rawEvidenceDir = flags.evidenceDir ?? dastConfig.evidenceDir;
    evidenceDir = rawEvidenceDir !== undefined ? validateEvidenceDir(String(rawEvidenceDir)) : undefined;
    headers = mergeDastHeaders(dastConfig.headers, flags.headers ?? []);
    expandEnvHeaders(headers);
  } catch (e) {
    if (e instanceof DastConfigError) {
      printError(safe(e.message));
      return 3;
    }
    throw e;
  }

  const allowRemoteRequested = flags.allowRemote === true || dastConfig.allowRemote === true;
  const denied = await confirmTargetAccess({
    target: rawTarget,
    hostname,
    origin,
    allowRemote: allowRemoteRequested,
    isTTY,
    envAllowRemote,
    retryCommand: `basesec scan <path> --verify --target ${origin} --dast-allow-remote`,
  });
  if (denied !== undefined) {
    return denied;
  }

  const routes = staticResult.routes;
  if (routes === undefined || routes.routes.length === 0) {
    console.error(pc.yellow('  ⚠ No routes extracted; nothing to verify dynamically. Reporting the static findings only.'));
    return writeReport(staticResult, options, targetPath);
  }

  const surface: LoadedSurface = { artifact: routes, source: 'scan', stale: false };
  if (!quiet) {
    printSurfaceNotices(surface);
  }

  const evidence = flags.evidence ?? dastConfig.evidence ?? true;
  const rules = flags.rules !== undefined
    ? String(flags.rules).split(',').map((id) => id.trim()).filter((id) => id !== '')
    : dastConfig.rules;
  const progress = createProgressReporter(quiet);

  // --dast-agent: modo manual. La app ya arrancó con NODE_OPTIONS; sus sockets están en BASESEC_AGENT_DIR (o el default).
  const agentSource = flags.agent === true ? startAgentCollector(resolveAgentDir()) : undefined;
  let dynamic: ScanResult;
  try {
    dynamic = await runDast({
      agent: agentSource,
      url: rawTarget,
      surface,
      health: dastConfig.health ?? '/',
      headers,
      allowRemote: allowRemoteRequested,
      allowRemoteEnv: envAllowRemote,
      allowVulnerableNode: flags.allowVulnerableNode === true,
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
      probeRateLimit: flags.probeRateLimit === true || dastConfig.probeRateLimit === true,
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
    printError(safe(e instanceof Error ? e.message : String(e)));
    return 2;
  } finally {
    progress.clear();
    agentSource?.close();
  }

  printAttackNotices(dynamic, evidence, quiet);

  const merged = correlate(staticResult.findings, dynamic.findings, routes);
  const correlated: ScanResult = {
    findings: merged.findings,
    stats: { ...staticResult.stats, dast: dynamic.stats.dast },
    duration: Date.now() - started,
  };
  return writeReport(correlated, options, targetPath);
}

/** Filtra por severidad, formatea y escribe el informe como `scan`. Devuelve 1 con --strict si quedan hallazgos. */
async function writeReport(result: ScanResult, options: CliOptions, targetPath: string): Promise<number> {
  const filtered = filterBySeverity(result, options.severity);
  const filteredResult: ScanResult = { ...result, findings: filtered, stats: { ...result.stats } };
  const output = getFormatter(options.format).format(filteredResult, targetPath);

  if (!(await emitReport(output, options.format, options.output))) {
    return 0;
  }
  if (options.strict && filtered.length > 0) {
    return 1;
  }
  return 0;
}
