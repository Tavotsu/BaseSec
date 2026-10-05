import { defineRule } from '../../define-rule';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

interface AuditAdvisory {
  id: number;
  title: string;
  severity: string;
  module_name: string;
  findings: { paths: string[] }[];
  url: string;
}

interface AuditResult {
  advisories: Record<string, AuditAdvisory>;
}

export const DEP002 = defineRule({
  id: 'DEP-002',
  name: 'Vulnerable Dependencies',
  description: 'Detects dependencies with known vulnerabilities via pnpm audit.',
  category: 'dependency-check',
  severity: 'critical',
  frameworks: ['*'],
  tags: ['owasp:a6', 'cwe:1104', 'dependency-check'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    const isPackageJson = path.basename(ctx.filePath) === 'package.json';
    if (!isPackageJson) return findings;

    const projectDir = path.dirname(ctx.filePath);

    try {
      const hasPnpmLock = fs.existsSync(path.join(projectDir, 'pnpm-lock.yaml'));
      const hasNpmLock = fs.existsSync(path.join(projectDir, 'package-lock.json'));
      const cli = hasPnpmLock ? 'pnpm' : hasNpmLock ? 'npm' : 'pnpm';
      const command = getCliCommand(cli);

      const output = execFileSync(command, ['audit', '--json'], {
        cwd: projectDir,
        encoding: 'utf-8',
        timeout: 30000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      appendAuditFindings(findings, parseAuditResult(output), ctx.filePath, ctx.content);
    } catch (e: unknown) {
      if (e && typeof e === 'object' && 'status' in e && (e as Record<string, unknown>).status === 1) {
        // npm audit returns exit code 1 when vulnerabilities found
        // Try to parse stdout from the error
        try {
          const errOutput = (e as unknown as { stdout?: string | Buffer }).stdout;
          if (errOutput) {
            const raw = typeof errOutput === 'string' ? errOutput : errOutput.toString('utf-8');
            appendAuditFindings(findings, parseAuditResult(raw), ctx.filePath, ctx.content);
          }
        } catch {
          // Could not parse audit output
        }
      }
      // pnpm/npm not installed or other error — skip silently
    }

    return findings;
  },
});

function mapAuditSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
  switch (severity) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'moderate': return 'medium';
    case 'low': return 'low';
    default: return 'medium';
  }
}

function getCliCommand(baseName: 'pnpm' | 'npm'): string {
  if (process.platform === 'win32') return `${baseName}.cmd`;
  return baseName;
}

function parseAuditResult(raw: string): AuditAdvisory[] {
  const result = JSON.parse(raw) as Partial<AuditResult>;
  if (!result.advisories || typeof result.advisories !== 'object') return [];
  return Object.values(result.advisories);
}

function appendAuditFindings(
  findings: import('../../../rules/types').Finding[],
  advisories: AuditAdvisory[],
  filePath: string,
  content: string
): void {
  for (const advisory of advisories) {
    const severity = mapAuditSeverity(advisory.severity);
    const depPath = advisory.findings?.[0]?.paths?.[0] ?? advisory.module_name;
    const lines = content.split('\n');
    const lineNum = lines.findIndex((l) => l.includes(`"${advisory.module_name}"`)) + 1;

    findings.push({
      ruleId: 'DEP-002',
      ruleName: 'Vulnerable Dependencies',
      category: 'dependency-check',
      severity,
      filePath,
      line: lineNum > 0 ? lineNum : 1,
      column: 1,
      endLine: lineNum > 0 ? lineNum : 1,
      endColumn: 120,
      message: `Vulnerability in ${advisory.module_name} (via ${depPath}): ${advisory.title}`,
      codeSnippet: `  "${advisory.module_name}"`,
      remediation: `Update ${advisory.module_name} to a patched version. Advisory: ${advisory.url}`,
      references: [advisory.url],
      confidence: 'high',
    });
  }
}
