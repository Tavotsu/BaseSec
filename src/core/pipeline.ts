import type { Rule } from '../rules/types';
import { FileCollector } from './file-collector';
import { Parser } from './parser';
import { Analyzer } from './analyzer';
import { ResultStore } from './result-store';
import { mergeConfigWithDefaults, DEFAULT_CONFIG } from '../config/defaults';
import type {
  secbaseConfig,
  ScanResult,
  ScanStats,
  CliOptions,
} from '../rules/types';

const BUILTIN_RULES: Rule[] = [];

export class Pipeline {
  private collector = new FileCollector();
  private parser = new Parser();
  private analyzer = new Analyzer();
  private store = new ResultStore();

  async run(
    targetPath: string,
    cliOptions: Partial<CliOptions> = {},
  ): Promise<ScanResult> {
    const start = Date.now();

    const config = mergeConfigWithDefaults({}, {
      framework: cliOptions.framework,
      severity: cliOptions.severity,
      ignore: cliOptions.ignore,
      taintAnalysis: cliOptions.noTaint ? false : undefined,
    });

    const collectResult = this.collector.collect(targetPath, {
      ignorePatterns: config.ignore,
    });

    const parsedFiles = this.parser.parseFiles(collectResult.files);

    const findings = this.analyzer.analyze(
      parsedFiles,
      BUILTIN_RULES,
      config,
    );

    this.store.addMany(findings);

    const stats: ScanStats = {
      filesScanned: parsedFiles.length,
      filesSkipped:
        collectResult.skippedBySize + collectResult.skippedByLimit,
      rulesRun: BUILTIN_RULES.length,
      frameworks: [],
    };

    const duration = Date.now() - start;

    return {
      findings: this.store.getFindings(),
      stats,
      duration,
    };
  }
}