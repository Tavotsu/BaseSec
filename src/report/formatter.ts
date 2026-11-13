import pc from 'picocolors';
import { VERSION } from '../version';
import type { Finding, ScanResult, OutputFormat, Severity } from '../rules/types';
import { SarifFormatter } from './sarif';
import { MarkdownFormatter } from './markdown';
import { HtmlFormatter } from './html';

export interface ReportFormatter {
  format(result: ScanResult, target: string): string;
}

export function getFormatter(format: OutputFormat): ReportFormatter {
  switch (format) {
    case 'json':
      return new JsonFormatter();
    case 'sarif':
      return new SarifFormatter();
    case 'html':
      return new HtmlFormatter();
    case 'markdown':
      return new MarkdownFormatter();
    case 'terminal':
    default:
      return new TerminalFormatter();
  }
}

/** Texto fijo de `scan --verify`: no confirmado no es lo mismo que no vulnerable. */
const NOT_CONFIRMED_NOTE = 'Findings not verified are "not confirmed at runtime", which is not the same as "not vulnerable".';

class TerminalFormatter implements ReportFormatter {
  format(result: ScanResult, target: string): string {
    const lines: string[] = [];

    lines.push('');
    const dast = result.stats.dast;
    // Solo `scan --verify` combina superficie dinámica con análisis estático (`dast` no tiene archivos escaneados).
    const verifyMode = dast !== undefined && result.stats.filesScanned > 0;
    lines.push(pc.cyan(`  Scanning: ${target}`));
    if (result.stats.frameworks.length > 0) {
      lines.push(pc.cyan(`  Frameworks: ${result.stats.frameworks.join(', ')}`));
    }
    if (dast && result.stats.filesScanned === 0) {
      lines.push(pc.cyan(`  Target: ${dast.target} · mode: ${dast.mode} · ${dast.requests} requests`));
      if (dast.incomplete) {
        lines.push(pc.yellow(`  ⚠ Incomplete analysis: ${dast.incomplete}`));
      }
      if (dast.mode === 'no-source') {
        lines.push(pc.yellow('  No source code: only headers, cookies and errors of / and the healthcheck were checked.'));
      }
    } else {
      lines.push(
        pc.cyan(
          `  Files: ${result.stats.filesScanned} | Skipped: ${result.stats.filesSkipped}`,
        ),
      );
      if (verifyMode && dast) {
        lines.push(pc.cyan(`  Target: ${dast.target} · mode: ${dast.mode} · ${dast.requests} requests`));
      }
    }
    lines.push('');

    if (result.findings.length === 0) {
      lines.push(
        pc.green(
          dast ? '  No issues confirmed at runtime (this is not the same as "secure").' : '  No vulnerabilities found.',
        ),
      );
      if (verifyMode) {
        lines.push(pc.gray(`  ${NOT_CONFIRMED_NOTE}`));
      }
      lines.push('');
      return lines.join('\n');
    }

    lines.push('  ─'.repeat(30));
    lines.push('');

    const severityLevels: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const severityRank = Object.fromEntries(severityLevels.map((s, i) => [s, i]));
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

    const sortedFindings = [...result.findings].sort(
      (a, b) => (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99),
    );

    for (const finding of sortedFindings) {
      const colorFn = severityColors[finding.severity] ?? pc.white;
      const label = severityLabels[finding.severity] ?? finding.severity.toUpperCase();

      lines.push(
        colorFn(`  [${label}] ${finding.ruleId}: ${finding.ruleName}`),
      );
      if (finding.verified === true) {
        lines.push(pc.green('    ✓ VERIFIED (runtime)'));
      }
      if (finding.filePath === '' && finding.endpoint) {
        lines.push(pc.gray(`    Endpoint: ${finding.endpoint}`));
      } else {
        lines.push(pc.gray(`    File: ${finding.filePath}:${finding.line}`));
        if (finding.endpoint) {
          lines.push(pc.gray(`    Endpoint: ${finding.endpoint}`));
        }
      }
      if (verifyMode && finding.verified === true && finding.evidence) {
        lines.push(...evidenceLines(finding));
      }
      if (finding.codeSnippet) {
        lines.push(pc.white(`    Code: ${finding.codeSnippet}`));
      }
      lines.push(pc.gray(`    ${finding.message}`));
      lines.push(pc.green(`    Remedy: ${finding.remediation}`));
      if (finding.aiExplanation) {
        lines.push(pc.magenta(`    🤖 AI: ${finding.aiExplanation}`));
      }
      if (finding.aiGenerated) {
        lines.push(pc.magenta(`    [AI-generated finding]`));
      }
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
    for (const s of severityLevels) {
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
    if (verifyMode) {
      const staticFindings = result.findings.filter((f) => f.source !== 'dynamic');
      const verified = staticFindings.filter((f) => f.verified === true).length;
      const runtimeOnly = result.findings.length - staticFindings.length;
      lines.push(pc.green(`  Verified at runtime: ${verified} of ${staticFindings.length} static findings; ${runtimeOnly} runtime-only findings.`));
    }
    lines.push(pc.gray(`  Duration: ${(result.duration / 1000).toFixed(1)}s`));
    if (verifyMode) {
      lines.push(pc.gray(`  ${NOT_CONFIRMED_NOTE}`));
    }
    lines.push('');

    return lines.join('\n');
  }
}

/** Evidencia de un hallazgo confirmado por `scan --verify`: petición, respuesta y, si lo hay, payload y enlace. */
function evidenceLines(finding: Finding): string[] {
  const evidence = finding.evidence;
  if (!evidence) return [];
  const lines = [
    pc.gray(`    Request: ${evidence.request}`),
    pc.gray(`    Response: ${evidence.response.split('\n')[0]}`),
  ];
  if (evidence.payload !== '') {
    lines.push(pc.gray(`    Payload: ${evidence.payload}`));
    lines.push(pc.gray(`    Oracle: ${evidence.oracle}`));
  }
  if (evidence.correlation !== undefined) {
    lines.push(pc.gray(`    Link: ${evidence.correlation}`));
  }
  if (evidence.file !== undefined) {
    lines.push(pc.gray(`    Evidence file: ${evidence.file}`));
  }
  return lines;
}

class JsonFormatter implements ReportFormatter {
  format(result: ScanResult, target: string): string {
    const output = {
      version: VERSION,
      timestamp: new Date().toISOString(),
      target,
      frameworks: result.stats.frameworks,
      stats: {
        filesScanned: result.stats.filesScanned,
        filesSkipped: result.stats.filesSkipped,
        duration: result.duration,
        rulesRun: result.stats.rulesRun,
        ...(result.stats.dast ? { dast: result.stats.dast } : {}),
      },
      findings: result.findings,
    };
    return JSON.stringify(output, null, 2);
  }
}