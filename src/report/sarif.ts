import type { ScanResult, Finding } from '../rules/types';
import type { ReportFormatter } from './formatter';

const SEVERITY_MAP: Record<string, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

export class SarifFormatter implements ReportFormatter {
  format(result: ScanResult, target: string): string {
    const rules = this.buildRules(result.findings);
    const results = this.buildResults(result.findings);

    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Sarif/schema/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'basesec',
              version: '0.1.0',
              informationUri: 'https://github.com/basesec/basesec',
              rules,
            },
          },
          results,
        },
      ],
    };

    return JSON.stringify(sarif, null, 2);
  }

  private buildRules(findings: Finding[]): object[] {
    const seen = new Set<string>();
    const rules: object[] = [];

    for (const f of findings) {
      if (seen.has(f.ruleId)) continue;
      seen.add(f.ruleId);

      rules.push({
        id: f.ruleId,
        name: f.ruleName,
        shortDescription: { text: f.message },
        fullDescription: { text: f.remediation },
        properties: {
          tags: [f.category],
          severity: f.severity,
        },
      });
    }

    return rules;
  }

  private buildResults(findings: Finding[]): object[] {
    return findings.map((f) => ({
      ruleId: f.ruleId,
      level: SEVERITY_MAP[f.severity] ?? 'warning',
      message: { text: f.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.filePath,
            },
            region: {
              startLine: Math.max(1, f.line),
              startColumn: Math.max(1, f.column),
              ...(f.endLine > f.line ? { endLine: f.endLine, endColumn: Math.max(1, f.endColumn) } : {}),
            },
          },
        },
      ],
    }));
  }
}