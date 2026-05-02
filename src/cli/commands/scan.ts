import { Pipeline } from '../../core/pipeline';
import { getFormatter } from '../../report/formatter';
import type { CliOptions, ScanResult } from '../../rules/types';
import { severityGte } from '../../utils/severity';

export async function runScan(
  targetPath: string,
  options: CliOptions,
): Promise<number> {
  const pipeline = new Pipeline();

  const result: ScanResult = await pipeline.run(targetPath, {
    format: options.format,
    output: options.output,
    severity: options.severity,
    ignore: options.ignore,
    framework: options.framework,
    noTaint: options.noTaint,
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
    const fs = await import('node:fs');
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