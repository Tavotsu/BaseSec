import type { ScanResult, Finding, Severity } from '../rules/types';
import type { ReportFormatter } from './formatter';

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

function escapeMarkdownCode(text: string): string {
  return text.replace(/```/g, '\\`\\`\\`');
}

export class MarkdownFormatter implements ReportFormatter {
  format(result: ScanResult, target: string): string {
    const lines: string[] = [];

    lines.push('# secbase Security Report');
    lines.push('');
    lines.push(`**Version:** 0.1.0`);
    lines.push(`**Target:** ${target}`);
    if (result.stats.frameworks.length > 0) {
      lines.push(`**Frameworks:** ${result.stats.frameworks.join(', ')}`);
    }
    lines.push(`**Date:** ${new Date().toISOString()}`);
    lines.push('');

    lines.push('---');
    lines.push('');
    lines.push('## Summary');
    lines.push('');

    const severityLevels: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const totalBySeverity = new Map<string, number>();
    for (const f of result.findings) {
      totalBySeverity.set(f.severity, (totalBySeverity.get(f.severity) ?? 0) + 1);
    }

    lines.push('| Severity | Count |');
    lines.push('|----------|-------|');
    for (const s of severityLevels) {
      const count = totalBySeverity.get(s) ?? 0;
      lines.push(`| ${SEVERITY_LABELS[s] ?? s} | ${count} |`);
    }
    lines.push('');
    lines.push(`**Total Findings:** ${result.findings.length}`);
    lines.push(`**Files Scanned:** ${result.stats.filesScanned} | **Duration:** ${(result.duration / 1000).toFixed(1)}s`);
    lines.push('');
    lines.push('---');
    lines.push('');

    if (result.findings.length === 0) {
      lines.push('No vulnerabilities found.');
      lines.push('');
      return lines.join('\n');
    }

    lines.push('## Findings');
    lines.push('');

    const sortedFindings = [...result.findings].sort((a, b) => {
      const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] ?? 99) - (order[b.severity] ?? 99);
    });

    for (const finding of sortedFindings) {
      const label = SEVERITY_LABELS[finding.severity] ?? finding.severity.toUpperCase();
      lines.push(`### [${label}] ${finding.ruleId}: ${finding.ruleName}`);
      lines.push('');
      lines.push(`**File:** \`${finding.filePath}:${finding.line}\``);
      lines.push('');
      lines.push('```typescript');
      lines.push(escapeMarkdownCode(finding.codeSnippet));
      lines.push('```');
      lines.push('');
      lines.push(`**Message:** ${finding.message}`);
      lines.push('');
      lines.push(`**Remedy:** ${finding.remediation}`);
      lines.push('');

      if (finding.references.length > 0) {
        lines.push('**References:**');
        for (const ref of finding.references) {
          lines.push(`- ${ref}`);
        }
        lines.push('');
      }

      lines.push('---');
      lines.push('');
    }

    const categories = new Map<string, number>();
    for (const f of result.findings) {
      categories.set(f.category, (categories.get(f.category) ?? 0) + 1);
    }

    lines.push('## Categories');
    lines.push('');
    for (const [cat, count] of categories) {
      lines.push(`- **${cat}:** ${count}`);
    }
    lines.push('');

    return lines.join('\n');
  }
}