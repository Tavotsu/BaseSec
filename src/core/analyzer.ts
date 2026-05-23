import type { Rule, Finding, RuleContext, basesecConfig, TaintGraph } from '../rules/types';
import type { ParsedFile } from '../rules/types';
import { analyzeFile } from '../taint/engine';
import { logger } from '../utils/logger';

export class Analyzer {
  private taintGraphs: Map<string, TaintGraph> = new Map();

  analyze(
    parsedFiles: ParsedFile[],
    rules: Rule[],
    config: basesecConfig,
    frameworks: string[] = [],
  ): Finding[] {
    const allFindings: Finding[] = [];

    if (config.taintAnalysis) {
      this.buildTaintGraphs(parsedFiles, frameworks, config.sanitizers ?? [], allFindings);
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

      const isEnvFile = parsedFile.filePath.includes('.env');

      for (const rule of enabledRules) {
        if (isEnvFile && rule.id !== 'SEC-001') continue;

        try {
          const findings = rule.detect(ctx);
          for (const f of findings) {
            if (severityOverrides.has(rule.id)) {
              f.severity = severityOverrides.get(rule.id)!;
            }
          }
          allFindings.push(...findings);
        } catch (e) {
          logger.warn(`Rule ${rule.id} failed on ${parsedFile.filePath}`, e);
          allFindings.push({
            ruleId: 'SYS-001',
            ruleName: 'Rule Execution Failed',
            category: 'error-handling',
            severity: 'info',
            filePath: parsedFile.filePath,
            line: 1,
            column: 1,
            endLine: 1,
            endColumn: 1,
            message: `Rule ${rule.id} failed to execute: ${e instanceof Error ? e.message : String(e)}`,
            codeSnippet: '',
            remediation: 'Check rule implementation or report a bug.',
            references: [],
            confidence: 'high',
          });
        }
      }
    }

    return allFindings;
  }

  private buildTaintGraphs(
    parsedFiles: ParsedFile[],
    frameworks: string[],
    customSanitizers: string[],
    findings: Finding[],
  ): void {
    this.taintGraphs.clear();
    for (const file of parsedFiles) {
      try {
        const graph = analyzeFile(file, frameworks, customSanitizers);
        this.taintGraphs.set(file.filePath, graph);
      } catch (e) {
        logger.warn(`Taint analysis failed for ${file.filePath}`, e);
        findings.push({
          ruleId: 'SYS-002',
          ruleName: 'Taint Analysis Failed',
          category: 'error-handling',
          severity: 'info',
          filePath: file.filePath,
          line: 1,
          column: 1,
          endLine: 1,
          endColumn: 1,
          message: `Taint analysis failed: ${e instanceof Error ? e.message : String(e)}`,
          codeSnippet: '',
          remediation: 'Report a bug if this persists.',
          references: [],
          confidence: 'high',
        });
      }
    }
  }

  private filterEnabledRules(
    rules: Rule[],
    config: basesecConfig,
    frameworks: string[] = [],
  ): Rule[] {
    const fwSet = new Set(frameworks.length > 0 ? frameworks : ['*']);
    const hasUniversal = fwSet.has('*');

    return rules.filter((rule) => {
      const override = config.rulesConfig[rule.id];
      if (override === false) return false;

      if (hasUniversal) return true;

      const ruleFw = rule.frameworks;
      if (ruleFw.includes('*')) return true;

      return ruleFw.some((f) => fwSet.has(f));
    });
  }
}