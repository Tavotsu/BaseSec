import { Pipeline } from '../../core/pipeline';
import { getFormatter } from '../../report/formatter';
import { loadConfig } from '../../config/loader';
import type { CliOptions, ScanResult, basesecConfig } from '../../rules/types';
import { severityGte } from '../../utils/severity';
import { logger } from '../../utils/logger';
import { emitReport } from '../report-output';
import { writeRouteArtifact } from '../../core/route-emitter';
import { validateRouteOptions } from '../validation';
import * as path from 'node:path';

export interface TargetAnalysis {
  result: ScanResult;
  /** Config leída del fichero (o {} si no hay). `scan --verify` toma de aquí la sección `dast`. */
  fileConfig: Partial<basesecConfig>;
}

/**
 * Config del fichero. Con `--config` que no carga: 3, ya impreso. Sin `--config`, un fallo avisa (en --verbose) y sigue
 * con los valores por defecto. Es la única lectura de config de `scan` y de `scan --verify`: `verify` la carga antes
 * de escanear (necesita la sección `dast`) y se la pasa a `analyzeTarget`, así el fichero se lee una sola vez.
 */
export function loadFileConfig(targetPath: string, options: CliOptions): Partial<basesecConfig> | number {
  if (options.config) {
    try {
      return loadConfig(options.config, targetPath);
    } catch (e) {
      console.error(`  Error: Could not load config file: ${e instanceof Error ? e.message : String(e)}`);
      return 3;
    }
  }
  try {
    return loadConfig(undefined, targetPath);
  } catch (e) {
    logger.warn('Failed to load config file, using defaults', e);
    return {};
  }
}

/**
 * Análisis estático con la configuración de `scan`. Lo usan `scan` y `scan --verify`, que así analizan igual.
 * Devuelve 3 (sin analizar) si el fichero de config indicado no carga. `preloaded` evita releer el fichero.
 */
export async function analyzeTarget(
  targetPath: string,
  options: CliOptions,
  emitRoutes: boolean,
  preloaded?: Partial<basesecConfig>,
): Promise<TargetAnalysis | number> {
  const pipeline = new Pipeline(undefined, {
    workers: options.workers,
    noCache: options.noCache,
  });

  const loaded = preloaded ?? loadFileConfig(targetPath, options);
  if (typeof loaded === 'number') {
    return loaded;
  }
  const fileConfig: Partial<basesecConfig> = loaded;

  const ruleFilter = options.rules
    ? options.rules.split(',').map((r) => r.trim())
    : undefined;

  const cliOverrides: Partial<basesecConfig> = {
    severity: options.severity,
    ignore: options.ignore,
    framework: options.framework,
    taintAnalysis: options.noTaint ? false : undefined,
  };

  if (options.format) {
    cliOverrides.output = { format: options.format };
  }

  const mergedConfig = {
    ...fileConfig,
    ...cliOverrides,
    ignore: [
      ...new Set([
        ...(fileConfig.ignore ?? []),
        ...(cliOverrides.ignore ?? []),
      ]),
    ],
  };

  const result: ScanResult = await pipeline.run(targetPath, {
    format: options.format,
    output: options.output,
    severity: options.severity,
    ignore: mergedConfig.ignore,
    framework: (mergedConfig.framework as 'auto' | 'express' | 'nestjs' | 'mongoose' | 'typeorm' | 'fastify' | 'koa' | 'prisma' | 'react' | 'nextjs' | 'vue' | 'angular' | 'svelte') ?? options.framework,
    noTaint: options.noTaint,
    rulesFilter: ruleFilter,
    noDeps: options.noDeps,
    readEnv: options.readEnv,
    ai: options.ai,
    aiProvider: options.aiProvider,
    aiModel: options.aiModel,
    aiDryRun: options.aiDryRun,
    aiContext: options.aiContext,
    emitRoutes,
  });

  return { result, fileConfig };
}

export async function runScan(
  targetPath: string,
  options: CliOptions,
): Promise<number> {
  const routeError = validateRouteOptions({
    emitRoutes: options.emitRoutes === true,
    routesOut: options.routesOut,
    ai: options.ai === true,
  });
  if (routeError) {
    console.error(`  Error: ${routeError}`);
    return 2;
  }

  if (options.verbose) {
    logger.isVerbose = true;
  }

  const analysis = await analyzeTarget(targetPath, options, options.emitRoutes === true);
  if (typeof analysis === 'number') {
    return analysis;
  }
  const { result } = analysis;

  if (options.emitRoutes) {
    if (!result.routes) {
      throw new Error('Route artifact was not built.');
    }
    const written = writeRouteArtifact(
      result.routes,
      options.routesOut ? path.resolve(options.routesOut) : undefined,
    );
    const routes = result.routes.routes;
    const expressCount = routes.filter((r) => r.framework === 'express').length;
    const nestCount = routes.filter((r) => r.framework === 'nestjs').length;
    const nextCount = routes.filter((r) => r.framework === 'nextjs').length;
    console.log(`  Routes: ${routes.length} (${expressCount} express, ${nestCount} nestjs, ${nextCount} nextjs) · unresolved: ${result.routes.unresolved.length}`);
    console.log(`  Artifact: ${written}`);
    return 0;
  }

  const filtered = filterBySeverity(result, options.severity);
  const filteredResult: ScanResult = {
    ...result,
    findings: filtered,
    stats: {
      ...result.stats,
    },
  };

  const formatter = getFormatter(options.format);
  const output = formatter.format(filteredResult, targetPath);

  if (!(await emitReport(output, options.format, options.output))) {
    return 0;
  }

  if (options.strict && filtered.length > 0) {
    return 1;
  }

  return 0;
}

export function filterBySeverity(
  result: ScanResult,
  minSeverity: string,
): typeof result.findings {
  return result.findings.filter((f) =>
    severityGte(f.severity, minSeverity as any),
  );
}