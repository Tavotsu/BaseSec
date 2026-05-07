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
import { AnalysisCache, shouldUseCache } from './analysis-cache';
import { getWorkerCount, shouldUseWorkers, WorkerPool } from './worker-pool';
import { severityGte } from '../utils/severity';
import type {
  basesecConfig,
  ScanResult,
  ScanStats,
  CliOptions,
  Finding,
} from '../rules/types';

export class Pipeline {
  private collector = new FileCollector();
  private parser = new Parser();
  private analyzer = new Analyzer();
  private store = new ResultStore();
  private registry: RuleRegistry;
  private rules: Rule[];
  private cache: AnalysisCache;
  private numWorkers: number;
  private cliWorkers?: number;
  private useCache: boolean;

  constructor(
    rules: Rule[] = ALL_RULES,
    options?: { workers?: number; noCache?: boolean },
  ) {
    this.rules = rules;
    this.registry = new RuleRegistry();
    this.registry.registerMany(rules);
    this.useCache = shouldUseCache(options?.noCache);
    this.cache = new AnalysisCache({ enabled: this.useCache });
    this.numWorkers = getWorkerCount(options?.workers);
    this.cliWorkers = options?.workers;
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

    const findings = await this.analyzeWithCache(parsedFiles, rulesToRun, config, frameworks);

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

  private async analyzeWithCache(
    parsedFiles: import('../rules/types').ParsedFile[],
    rules: Rule[],
    config: basesecConfig,
    frameworks: string[],
  ): Promise<Finding[]> {
    const allFindings: Finding[] = [];
    const configHash = this.cache.computeConfigHash({
      framework: config.framework,
      severity: config.severity,
      taintAnalysis: config.taintAnalysis,
      rulesConfig: config.rulesConfig,
      sanitizers: config.sanitizers,
      rules: rules.map((r) => r.id),
    });

    const filesToAnalyze: import('../rules/types').ParsedFile[] = [];

    if (!this.useCache) {
      filesToAnalyze.push(...parsedFiles);
    } else {
      for (const file of parsedFiles) {
        const cached = this.cache.get(file.filePath, file.content, configHash);
        if (cached) {
          allFindings.push(...cached);
        } else {
          filesToAnalyze.push(file);
        }
      }
    }

    if (filesToAnalyze.length > 0) {
      let freshFindings: Finding[] = [];
      const useWorkers = shouldUseWorkers(filesToAnalyze.length, this.cliWorkers);

      if (useWorkers) {
        const pool = new WorkerPool(this.numWorkers);
        try {
          const promises = filesToAnalyze.map(file => 
            pool.analyzeFile({
              file: { filePath: file.filePath, content: file.content },
              config,
              frameworks,
              ruleIds: rules.map(r => r.id)
            })
          );
          
          const results = await Promise.all(promises);
          for (const res of results) {
            freshFindings.push(...res.findings);
          }
        } finally {
          await pool.close();
        }
      } else {
        freshFindings = this.analyzer.analyze(filesToAnalyze, rules, config, frameworks);
      }

      if (this.useCache) {
        for (const file of filesToAnalyze) {
          const fileFindings = freshFindings.filter((f) => f.filePath === file.filePath);
          this.cache.set(file.filePath, file.content, configHash, fileFindings);
        }
      }

      allFindings.push(...freshFindings);
    }

    return this.filterBySeverity(allFindings, config.severity);
  }

  private filterBySeverity(findings: Finding[], minSeverity: string): Finding[] {
    return findings.filter((f) => severityGte(f.severity, minSeverity as any));
  }

  clearCache(): void {
    this.cache.clear();
  }

  getCacheStats(): { entries: number; sizeBytes: number } {
    return this.cache.stats;
  }
}