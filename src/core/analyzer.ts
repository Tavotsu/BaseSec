import type { Rule, Finding, RuleContext, secbaseConfig, TaintGraph } from '../rules/types';
import type { ParsedFile } from '../rules/types';
import { analyzeFile } from '../taint/engine';

export class Analyzer {
  private taintGraphs: Map<string, TaintGraph> = new Map();

  analyze(
    parsedFiles: ParsedFile[],
    rules: Rule[],
    config: secbaseConfig,
    frameworks: string[] = [],
  ): Finding[] {
    const allFindings: Finding[] = [];

    if (config.taintAnalysis) {
      this.buildTaintGraphs(parsedFiles, frameworks, config.sanitizers);
    }

    const enabledRules = this.filterEnabledRules(rules, config);

    for (const parsedFile of parsedFiles) {
      const taintGraph = config.taintAnalysis
        ? this.taintGraphs.get(parsedFile.filePath)
        : undefined;

      const ctx: RuleContext = {
        sourceFile: parsedFile.sourceFile,
        filePath: parsedFile.filePath,
        content: parsedFile.content,
        config,
        taintGraph,
      };

      for (const rule of enabledRules) {
        try {
          const findings = rule.detect(ctx);
          allFindings.push(...findings);
        } catch (e) {
          console.error(`  Rule ${rule.id} failed on ${parsedFile.filePath}: ${e instanceof Error ? e.message : String(e)}`);
        }
      }
    }

    return allFindings;
  }

  private buildTaintGraphs(
    parsedFiles: ParsedFile[],
    frameworks: string[],
    _customSanitizers: string[],
  ): void {
    this.taintGraphs.clear();
    for (const file of parsedFiles) {
      try {
        const graph = analyzeFile(file, frameworks, _customSanitizers);
        this.taintGraphs.set(file.filePath, graph);
      } catch {
        // Skip files where taint analysis fails
      }
    }
  }

  private filterEnabledRules(
    rules: Rule[],
    config: secbaseConfig,
  ): Rule[] {
    return rules.filter((rule) => {
      const override = config.rulesConfig[rule.id];
      if (override === false) return false;
      return true;
    }).map((rule) => {
      const override = config.rulesConfig[rule.id];
      if (override && typeof override === 'object' && override.severity) {
        return { ...rule, severity: override.severity };
      }
      return rule;
    });
  }
}