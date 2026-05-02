import type { Rule, Finding, RuleContext, secbaseConfig } from '../rules/types';
import type { ParsedFile } from '../rules/types';

export class Analyzer {
  analyze(
    parsedFiles: ParsedFile[],
    rules: Rule[],
    config: secbaseConfig,
  ): Finding[] {
    const allFindings: Finding[] = [];

    const enabledRules = this.filterEnabledRules(rules, config);

    for (const parsedFile of parsedFiles) {
      const ctx: RuleContext = {
        sourceFile: parsedFile.sourceFile,
        filePath: parsedFile.filePath,
        content: parsedFile.content,
        config,
      };

      for (const rule of enabledRules) {
        try {
          const findings = rule.detect(ctx);
          allFindings.push(...findings);
        } catch {
          // omitir errores de reglas de forma silenciosa
        }
      }
    }

    return allFindings;
  }

  private filterEnabledRules(
    rules: Rule[],
    config: secbaseConfig,
  ): Rule[] {
    return rules.filter((rule) => {
      const override = config.rulesConfig[rule.id];
      if (override === false) return false;
      return true;
    });
  }
}