import type { Rule } from '../rules/types';
import { FileCollector } from './file-collector';
import { Parser } from './parser';
import { Analyzer } from './analyzer';
import { ResultStore } from './result-store';
import { mergeConfigWithDefaults } from '../config/defaults';
import { ALL_RULES } from '../rules/index';
import { detectFrameworks } from '../framework/detector';
import { RuleRegistry } from '../rules/registry';
import { loadCustomRules } from '../rules/loader';
import type {
  secbaseConfig,
  ScanResult,
  ScanStats,
  CliOptions,
} from '../rules/types';

export class Pipeline {
  private collector = new FileCollector();
  private parser = new Parser();
  private analyzer = new Analyzer();
  private store = new ResultStore();
  private registry: RuleRegistry;
  private rules: Rule[];

  constructor(rules: Rule[] = ALL_RULES) {
    this.rules = rules;
    this.registry = new RuleRegistry();
    this.registry.registerMany(rules);
  }

  registerRules(rules: Rule[]): void {
    this.rules.push(...rules);
    this.registry.registerMany(rules);
  }

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

    if (config.rules && config.rules.length > 0) {
      const { errors } = await loadCustomRules(config.rules, this.registry);
      for (const err of errors) {
        console.error(`  Warning: ${err}`);
      }
    }

    const collectResult = this.collector.collect(targetPath, {
      ignorePatterns: config.ignore,
    });

    const parsedFiles = this.parser.parseFiles(collectResult.files);

    const frameworks = detectFrameworks(
      cliOptions.framework ?? 'auto',
      parsedFiles,
      targetPath,
    );

    let rulesToRun = this.registry.getAll();
    if (cliOptions.rulesFilter && cliOptions.rulesFilter.length > 0) {
      rulesToRun = rulesToRun.filter((r) =>
        cliOptions.rulesFilter!.includes(r.id),
      );
    }

    const findings = this.analyzer.analyze(
      parsedFiles,
      rulesToRun,
      config,
      frameworks,
    );

    this.store.addMany(findings);

    const stats: ScanStats = {
      filesScanned: parsedFiles.length,
      filesSkipped:
        collectResult.skippedBySize + collectResult.skippedByLimit,
      rulesRun: rulesToRun.length,
      frameworks,
    };

    const duration = Date.now() - start;

    return {
      findings: this.store.getFindings(),
      stats,
      duration,
    };
  }
}