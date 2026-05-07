import pc from 'picocolors';
import type { Finding, ScanResult, Severity } from '../rules/types';
import type { ReportFormatter } from './formatter';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function severityToColor(severity: Severity): string {
  switch (severity) {
    case 'critical': return '#dc2626';
    case 'high': return '#ef4444';
    case 'medium': return '#f59e0b';
    case 'low': return '#3b82f6';
    case 'info': return '#6b7280';
    default: return '#374151';
  }
}

function severityToBadge(severity: Severity): string {
  const color = severityToColor(severity);
  const label = severity.toUpperCase();
  return `<span style="background-color:${color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;">${label}</span>`;
}

export class HtmlFormatter implements ReportFormatter {
  format(result: ScanResult, target: string): string {
    const sorted = [...result.findings].sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    );

    const totalBySeverity = new Map<string, number>();
    for (const f of result.findings) {
      totalBySeverity.set(f.severity, (totalBySeverity.get(f.severity) ?? 0) + 1);
    }

    const totalByCategory = new Map<string, number>();
    for (const f of result.findings) {
      totalByCategory.set(f.category, (totalByCategory.get(f.category) ?? 0) + 1);
    }

    const severityStats = SEVERITY_ORDER
      .filter((s) => (totalBySeverity.get(s) ?? 0) > 0)
      .map((s) => `<div class="stat-item"><span style="background-color:${severityToColor(s)};color:#fff;padding:4px 12px;border-radius:4px;">${s.toUpperCase()}</span> <strong>${totalBySeverity.get(s) ?? 0}</strong></div>`)
      .join('\n          ');

    const categoryStats = [...totalByCategory.entries()]
      .map(([cat, count]) => `<div class="stat-item">${escapeHtml(cat)}: <strong>${count}</strong></div>`)
      .join('\n          ');

    const findingsRows = sorted.map((f, i) => {
      const color = severityToColor(f.severity);
      return `
            <tr>
              <td>${severityToBadge(f.severity)}</td>
              <td><code>${escapeHtml(f.ruleId)}</code></td>
              <td>${escapeHtml(f.ruleName)}</td>
              <td>${escapeHtml(f.category)}</td>
              <td><a href="#finding-${i}">${escapeHtml(f.filePath)}:${f.line}</a></td>
            </tr>`;
    }).join('\n');

    const findingDetails = sorted.map((f, i) => {
      const color = severityToColor(f.severity);
      return `
          <div id="finding-${i}" class="finding-card" style="border-left:4px solid ${color};">
            <div class="finding-header">
              ${severityToBadge(f.severity)}
              <span class="finding-id">${escapeHtml(f.ruleId)}: ${escapeHtml(f.ruleName)}</span>
            </div>
            <div class="finding-body">
              <table class="finding-detail">
                <tr><td><strong>File:</strong></td><td><code>${escapeHtml(f.filePath)}:${f.line}:${f.column}</code></td></tr>
                <tr><td><strong>Category:</strong></td><td>${escapeHtml(f.category)}</td></tr>
                <tr><td><strong>Confidence:</strong></td><td>${escapeHtml(f.confidence)}</td></tr>
                <tr><td><strong>Message:</strong></td><td>${escapeHtml(f.message)}</td></tr>
              </table>
              <div class="code-block"><pre>${escapeHtml(f.codeSnippet)}</pre></div>
              <div class="remediation">
                <strong>Remediation:</strong> ${escapeHtml(f.remediation)}
              </div>
              ${f.references.length > 0 ? `
              <div class="references">
                <strong>References:</strong>
                <ul>${f.references.map((r) => `<li><a href="${escapeHtml(r)}" target="_blank">${escapeHtml(r)}</a></li>`).join('')}</ul>
              </div>` : ''}
            </div>
          </div>`;
    }).join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>basesec Security Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 24px; }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { color: #22d3ee; font-size: 28px; margin-bottom: 8px; }
    h2 { color: #94a3b8; font-size: 18px; font-weight: 400; margin-bottom: 24px; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .stats-card { background: #1e293b; border-radius: 8px; padding: 16px; }
    .stats-card h3 { color: #94a3b8; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 32px; }
    th { background: #1e293b; color: #94a3b8; text-align: left; padding: 12px; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; }
    td { padding: 10px 12px; border-bottom: 1px solid #1e293b; }
    tr:hover { background: #1e293b; }
    .finding-card { background: #1e293b; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .finding-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
    .finding-id { font-weight: 600; font-size: 16px; }
    .finding-body { padding-left: 4px; }
    .finding-detail td { padding: 4px 8px; border: none; }
    .finding-detail td:first-child { width: 120px; color: #94a3b8; }
    .code-block { background: #0f172a; border-radius: 6px; padding: 12px; margin: 12px 0; overflow-x: auto; }
    .code-block pre { font-family: 'Fira Code', 'Cascadia Code', monospace; font-size: 13px; color: #e2e8f0; white-space: pre; }
    .remediation { background: #064e3b; border-radius: 6px; padding: 12px; margin: 12px 0; }
    .references { margin-top: 8px; }
    .references ul { padding-left: 20px; }
    .references a { color: #22d3ee; }
    .stat-item { margin-bottom: 6px; }
    .empty { color: #22c55e; font-size: 20px; text-align: center; padding: 48px; }
    code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>basesec Security Report</h1>
    <h2>Target: ${escapeHtml(target)} | ${result.stats.frameworks.length > 0 ? `Frameworks: ${escapeHtml(result.stats.frameworks.join(', '))}` : 'No frameworks detected'}</h2>

    <div class="stats-grid">
      <div class="stats-card">
        <h3>Overview</h3>
        <div class="stat-item">Files scanned: <strong>${result.stats.filesScanned}</strong></div>
        <div class="stat-item">Files skipped: <strong>${result.stats.filesSkipped}</strong></div>
        <div class="stat-item">Rules run: <strong>${result.stats.rulesRun}</strong></div>
        <div class="stat-item">Findings: <strong>${result.findings.length}</strong></div>
        <div class="stat-item">Duration: <strong>${(result.duration / 1000).toFixed(1)}s</strong></div>
      </div>
      <div class="stats-card">
        <h3>By Severity</h3>
        ${severityStats || '<div class="stat-item">No findings</div>'}
      </div>
      <div class="stats-card">
        <h3>By Category</h3>
        ${categoryStats || '<div class="stat-item">No findings</div>'}
      </div>
    </div>

    ${result.findings.length > 0 ? `
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>ID</th>
          <th>Name</th>
          <th>Category</th>
          <th>Location</th>
        </tr>
      </thead>
      <tbody>
        ${findingsRows}
      </tbody>
    </table>

    <h2 style="color: #22d3ee; font-size: 22px; margin-bottom: 16px;">Detailed Findings</h2>
    ${findingDetails}
    ` : `
    <div class="empty">No vulnerabilities found.</div>
    `}
  </div>
</body>
</html>`;
  }
}