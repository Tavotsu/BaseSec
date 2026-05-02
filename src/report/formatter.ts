import pc from 'picocolors';
import type { Finding, ScanResult, OutputFormat } from '../rules/types';

export interface ReportFormatter {
  format(result: ScanResult, target: string): string;
}

export function getFormatter(format: OutputFormat): ReportFormatter {
  switch (format) {
    case 'json':
      return new JsonFormatter();
    case 'terminal':
    default:
      return new TerminalFormatter();
  }
}

class TerminalFormatter implements ReportFormatter {
  format(result: ScanResult, target: string): string {
    const lines: string[] = [];

    lines.push('');
    lines.push(pc.cyan(`  Scanning: ${target}`));
    if (result.stats.frameworks.length > 0) {
      lines.push(pc.cyan(`  Frameworks: ${result.stats.frameworks.join(', ')}`));
    }
    lines.push(
      pc.cyan(
        `  Files: ${result.stats.filesScanned} | Skipped: ${result.stats.filesSkipped}`,
      ),
    );
    lines.push('');

    if (result.findings.length === 0) {
      lines.push(pc.green('  No vulnerabilities found.'));
      lines.push('');
      return lines.join('\n');
    }

    lines.push('  ─'.repeat(30));
    lines.push('');

    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'] as const;
    const severityColors: Record<string, (s: string) => string> = {
      critical: pc.red,
      high: pc.red,
      medium: pc.yellow,
      low: pc.blue,
      info: pc.gray,
    };
    const severityLabels: Record<string, string> = {
      critical: 'CRITICAL',
      high: 'HIGH',
      medium: 'MEDIUM',
      low: 'LOW',
      info: 'INFO',
    };

    for (const finding of result.findings) {
      const colorFn = severityColors[finding.severity] ?? pc.white;
      const label = severityLabels[finding.severity] ?? finding.severity.toUpperCase();

      lines.push(
        colorFn(`  [${label}] ${finding.ruleId}: ${finding.ruleName}`),
      );
      lines.push(pc.gray(`    File: ${finding.filePath}:${finding.line}`));
      lines.push(pc.white(`    Code: ${finding.codeSnippet}`));
      lines.push(pc.gray(`    ${finding.message}`));
      lines.push(pc.green(`    Remedy: ${finding.remediation}`));
      lines.push('');
    }

    lines.push('  ─'.repeat(30));
    lines.push('');

    const totalBySeverity = new Map<string, number>();
    for (const f of result.findings) {
      totalBySeverity.set(f.severity, (totalBySeverity.get(f.severity) ?? 0) + 1);
    }

    let summaryLine = pc.yellow(
      `  Scan complete: ${result.findings.length} finding${result.findings.length === 1 ? '' : 's'}`,
    );
    const parts: string[] = [];
    for (const s of severityOrder) {
      const count = totalBySeverity.get(s) ?? 0;
      if (count > 0) {
        const colorFn = severityColors[s];
        parts.push(colorFn(`${count} ${s}`));
      }
    }
    if (parts.length > 0) {
      summaryLine += ' (' + parts.join(', ') + ')';
    }
    lines.push(summaryLine);
    lines.push(pc.gray(`  Duration: ${(result.duration / 1000).toFixed(1)}s`));
    lines.push('');

    return lines.join('\n');
  }
}

class JsonFormatter implements ReportFormatter {
  format(result: ScanResult, target: string): string {
    const output = {
      version: '0.1.0',
      timestamp: new Date().toISOString(),
      target,
      frameworks: result.stats.frameworks,
      stats: {
        filesScanned: result.stats.filesScanned,
        filesSkipped: result.stats.filesSkipped,
        duration: result.duration,
        rulesRun: result.stats.rulesRun,
      },
      findings: result.findings,
    };
    return JSON.stringify(output, null, 2);
  }
}