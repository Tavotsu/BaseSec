import { Pipeline } from '../../core/pipeline';
import { getFormatter } from '../../report/formatter';
import { loadConfig } from '../../config/loader';
import type { CliOptions, ScanResult, basesecConfig } from '../../rules/types';
import { severityGte } from '../../utils/severity';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { logger } from '../../utils/logger';

export async function runScan(
  targetPath: string,
  options: CliOptions,
): Promise<number> {
  if (options.verbose) {
    logger.isVerbose = true;
  }

  const pipeline = new Pipeline(undefined, {
    workers: options.workers,
    noCache: options.noCache,
  });

  let fileConfig: Partial<basesecConfig> = {};
  if (options.config) {
    try {
      fileConfig = loadConfig(options.config, targetPath);
    } catch (e) {
      console.error(`  Error: Could not load config file: ${e instanceof Error ? e.message : String(e)}`);
      return 3;
    }
  } else {
    try {
      fileConfig = loadConfig(undefined, targetPath);
    } catch {
      // No config file found, use defaults
    }
  }

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
    framework: (mergedConfig.framework as 'auto' | 'express' | 'nestjs' | 'mongoose' | 'typeorm' | 'fastify' | 'koa' | 'prisma') ?? options.framework,
    noTaint: options.noTaint,
    rulesFilter: ruleFilter,
    noDeps: options.noDeps,
    readEnv: options.readEnv,
  });

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

  if (options.output) {
    const dir = path.dirname(options.output);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(options.output, output, 'utf-8');
    console.log(`Report written to ${options.output}`);
  } else {
    console.log(output);
  }

  if (options.strict && filtered.length > 0) {
    return 1;
  }

  return 0;
}

function filterBySeverity(
  result: ScanResult,
  minSeverity: string,
): typeof result.findings {
  return result.findings.filter((f) =>
    severityGte(f.severity, minSeverity as any),
  );
}