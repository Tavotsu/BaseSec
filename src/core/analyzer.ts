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

    const enabledRules = this.filterEnabledRules(rules, config, frameworks);
    const severityOverrides = new Map<string, import('../rules/types').Severity>();
    for (const rule of enabledRules) {
      const override = config.rulesConfig[rule.id];
      if (override && typeof override === 'object' && override.severity) {
        severityOverrides.set(rule.id, override.severity);
      }
    }

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
          for (const f of findings) {
            if (severityOverrides.has(rule.id)) {
              f.severity = severityOverrides.get(rule.id)!;
            }
          }
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
    frameworks: string[] = [],
  ): Rule[] {
    const fwSet = new Set(frameworks.length > 0 ? frameworks : ['*']);
    const hasUniversal = fwSet.has('*');
    const hasExpress = fwSet.has('express');
    const hasNestjs = fwSet.has('nestjs');

    return rules.filter((rule) => {
      const override = config.rulesConfig[rule.id];
      if (override === false) return false;

      if (hasUniversal) return true;

      const ruleFw = rule.frameworks;
      if (ruleFw.includes('*')) return true;

      if (ruleFw.some((f) => fwSet.has(f))) return true;

      if (hasExpress && ruleFw.includes('express')) return true;
      if (hasNestjs && ruleFw.includes('nestjs')) return true;

      return false;
    }).map((rule) => {
      const override = config.rulesConfig[rule.id];
      if (override && typeof override === 'object' && override.severity) {
        return { ...rule, severity: override.severity };
      }
      return rule;
    });
  }
}