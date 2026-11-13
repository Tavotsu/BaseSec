import { VERSION } from '../version';
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
              version: VERSION,
              informationUri: 'https://github.com/basesec/basesec',
              rules,
            },
          },
          results,
          ...(result.stats.dast ? { properties: { dast: result.stats.dast } } : {}),
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
    return findings.map((f) => {
      // Un hallazgo a nivel de target (sin fichero, con endpoint) no tiene physicalLocation.
      const isTargetLevel = f.filePath === '' && Boolean(f.endpoint);
      const location = !isTargetLevel
        ? {
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
          }
        : {
            logicalLocations: [{ fullyQualifiedName: f.endpoint ?? '', kind: 'resource' }],
          };

      const result: Record<string, unknown> = {
        ruleId: f.ruleId,
        level: SEVERITY_MAP[f.severity] ?? 'warning',
        message: { text: f.message },
        locations: [location],
      };

      const aiProperties = f.aiExplanation || f.aiEnhanced || f.aiGenerated
        ? {
            ...(f.aiExplanation ? { aiExplanation: f.aiExplanation } : {}),
            ...(f.aiEnhanced != null ? { aiEnhanced: f.aiEnhanced } : {}),
            ...(f.aiGenerated != null ? { aiGenerated: f.aiGenerated } : {}),
          }
        : undefined;
      const dynamicProperties = f.source === 'dynamic' || f.verified !== undefined
        ? {
            verified: f.verified,
            endpoint: f.endpoint,
            ...(f.evidence?.correlation !== undefined ? { correlation: f.evidence.correlation } : {}),
            ...(f.evidence?.oracle ? { oracle: f.evidence.oracle } : {}),
            ...(f.evidence?.file ? { evidenceFile: f.evidence.file } : {}),
          }
        : undefined;
      if (aiProperties || dynamicProperties) {
        result['properties'] = { ...(aiProperties ?? {}), ...(dynamicProperties ?? {}) };
      }

      return result;
    });
  }
}