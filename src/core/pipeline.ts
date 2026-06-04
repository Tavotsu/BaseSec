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
import { loadConfig } from '../config/loader';
import { AnalysisCache, shouldUseCache } from './analysis-cache';
import { getWorkerCount, shouldUseWorkers, WorkerPool } from './worker-pool';
import { severityGte } from '../utils/severity';
import { logger } from '../utils/logger';
import { checkConsent, promptConsent } from '../ai/consent';
import { validateAiConfig, resolveAiOptions } from '../ai/config';
import { resolveProvider } from '../ai/providers/resolver';
import { enrichFindings } from '../ai/enricher';
import { detectSuspiciousFiles, analyzeSuspiciousFiles } from '../ai/parallel-analyzer';
import { mergeFindings } from '../ai/merger';
import { formatDryRun } from '../ai/privacy';
import * as fs from 'node:fs';
import * as path from 'node:path';
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

    let fileConfig: Partial<import('../rules/types').basesecConfig> = {};
    try {
      fileConfig = loadConfig(undefined, targetPath);
    } catch {
      // No config file found, use defaults
    }

    const config = mergeConfigWithDefaults(fileConfig, {
      framework: cliOptions.framework,
      severity: cliOptions.severity,
      ignore: cliOptions.ignore,
      taintAnalysis: cliOptions.noTaint ? false : undefined,
    });

    if (config.rules && config.rules.length > 0) {
      const { errors } = await loadCustomRules(config.rules, this.registry);
      for (const err of errors) {
        logger.warn(err);
      }
    }

    const collectResult = this.collector.collect(targetPath, {
      ignorePatterns: config.ignore,
      readEnv: cliOptions.readEnv,
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

    let findings = await this.analyzeWithCache(parsedFiles, rulesToRun, config, frameworks);

    if (!cliOptions.noDeps) {
      const depFindings = this.checkDependencies(targetPath, rulesToRun, config);
      findings.push(...depFindings);
    }

    const hasAiFlag = cliOptions.ai === true;
    const hasAiConfig = config.ai?.enabled === true;

    if (hasAiFlag && !hasAiConfig) {
      throw new Error(
        'AI flag detected but ai.enabled is not set in your config. ' +
        "Run 'basesec init' or add ai.enabled: true to your config file."
      );
    }

    if (hasAiFlag && hasAiConfig) {
      const validation = validateAiConfig(config.ai, cliOptions);
      if (!validation.valid) {
        throw new Error(validation.errors.join('\n'));
      }

      const aiOptions = resolveAiOptions(config.ai, cliOptions)!;

      let consentOk = checkConsent();
      if (!consentOk) {
        consentOk = await promptConsent(aiOptions.provider, aiOptions.contextLevel);
        if (!consentOk) {
          logger.warn('AI analysis skipped: user declined consent.');
        }
      }

      if (consentOk) {
        if (aiOptions.dryRun) {
          console.log(formatDryRun(findings, aiOptions.contextLevel));
        } else {
          const provider = await resolveProvider(config.ai!);

          const fileContents = new Map<string, string>();
          for (const f of parsedFiles) {
            fileContents.set(f.filePath, f.content);
          }

          findings = await enrichFindings(findings, provider, {
            contextLevel: aiOptions.contextLevel,
            maxFindings: aiOptions.maxFindings,
            model: aiOptions.model,
            timeout: aiOptions.timeout,
            fileContents,
          });

          const taintGraphs = this.analyzer.getTaintGraphs();
          const suspiciousFiles = detectSuspiciousFiles(parsedFiles, taintGraphs, findings);
          if (suspiciousFiles.length > 0) {
            const aiFindings = await analyzeSuspiciousFiles(
              suspiciousFiles,
              taintGraphs,
              provider,
              {
                contextLevel: aiOptions.contextLevel,
                model: aiOptions.model,
                timeout: aiOptions.timeout,
              }
            );
            findings = mergeFindings(findings, aiFindings);
          }
        }
      }
    } else {
      const taintGraphs = this.analyzer.getTaintGraphs();
      const suspicious = detectSuspiciousFiles(parsedFiles, taintGraphs, findings);
      if (suspicious.length > 0) {
        logger.warn(
          `Suspicious taint flows detected in ${suspicious.length} file(s) with no matching rules.\n` +
          `   To deep-analyze these files, enable AI: basesec scan ./src --ai\n` +
          `   Verify all AI conditions are met (config + consent).`
        );
      }
    }

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
      const useWorkers = shouldUseWorkers(filesToAnalyze.length, this.cliWorkers, config.workers?.threshold);

      if (useWorkers) {
        const pool = new WorkerPool(this.cliWorkers ?? config.workers?.max ?? this.numWorkers);
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
          if (config.taintAnalysis) {
            this.analyzer.analyze(filesToAnalyze, [], config, frameworks);
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

  private checkDependencies(targetPath: string, rules: Rule[], config: basesecConfig): Finding[] {
    const findings: Finding[] = [];
    const packageJsonPath = path.join(path.resolve(targetPath), 'package.json');

    if (!fs.existsSync(packageJsonPath)) return findings;

    try {
      const content = fs.readFileSync(packageJsonPath, 'utf-8');
      const depRules = rules.filter((r) => r.category === 'dependency-check');

      if (depRules.length === 0) return findings;

      const parser = new Parser();
      const [parsedFile] = parser.parseFiles([packageJsonPath]);

      if (!parsedFile) return findings;

      for (const rule of depRules) {
        try {
          const ruleFindings = rule.detect({
            sourceFile: parsedFile.sourceFile,
            filePath: packageJsonPath,
            content,
            config,
          });
          findings.push(...ruleFindings);
        } catch (e) {
          logger.warn(`Rule ${rule.id} failed on package.json: ${e instanceof Error ? e.message : String(e)}`);
        }
      }
    } catch (e) {
      logger.warn('Could not read package.json', e);
    }

    return findings;
  }

  clearCache(): void {
    this.cache.clear();
  }

  getCacheStats(): { entries: number; sizeBytes: number } {
    return this.cache.stats;
  }
}