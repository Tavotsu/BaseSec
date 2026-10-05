import { defineRule } from '../../define-rule';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

export const DEP004 = defineRule({
  id: 'DEP-004',
  name: 'Lockfile Mismatch',
  description: 'Detects when package.json dependencies are out of sync with the lockfile.',
  category: 'dependency-check',
  severity: 'medium',
  frameworks: ['*'],
  tags: ['owasp:a6', 'cwe:1104', 'dependency-check'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    const isPackageJson = path.basename(ctx.filePath) === 'package.json';
    if (!isPackageJson) return findings;

    const projectDir = path.dirname(ctx.filePath);
    const hasPnpmLock = fs.existsSync(path.join(projectDir, 'pnpm-lock.yaml'));
    const hasNpmLock = fs.existsSync(path.join(projectDir, 'package-lock.json'));
    const hasYarnLock = fs.existsSync(path.join(projectDir, 'yarn.lock'));

    if (!hasPnpmLock && !hasNpmLock && !hasYarnLock) {
      findings.push({
        ruleId: 'DEP-004',
        ruleName: 'Lockfile Mismatch',
        category: 'dependency-check',
        severity: 'medium',
        filePath: ctx.filePath,
        line: 1,
        column: 1,
        endLine: 1,
        endColumn: 1,
        message: 'No lockfile found (pnpm-lock.yaml, package-lock.json, or yarn.lock).',
        codeSnippet: '',
        remediation: 'Run your package manager to generate a lockfile (e.g., pnpm install).',
        references: ['https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json'],
        confidence: 'high',
      });
      return findings;
    }

    try {
      let command: string;
      let args: string[];
      if (hasPnpmLock) {
        command = getCliCommand('pnpm');
        args = ['install', '--frozen-lockfile', '--dry-run', '--ignore-scripts'];
      } else if (hasYarnLock) {
        command = getCliCommand('yarn');
        args = ['install', '--frozen-lockfile', '--check-files', '--ignore-scripts'];
      } else {
        command = getCliCommand('npm');
        args = ['install', '--package-lock-only', '--dry-run', '--ignore-scripts'];
      }

      execFileSync(command, args, {
        cwd: projectDir,
        encoding: 'utf-8',
        timeout: 30000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch {
      findings.push({
        ruleId: 'DEP-004',
        ruleName: 'Lockfile Mismatch',
        category: 'dependency-check',
        severity: 'medium',
        filePath: ctx.filePath,
        line: 1,
        column: 1,
        endLine: 1,
        endColumn: 1,
        message: 'package.json and lockfile are out of sync.',
        codeSnippet: '',
        remediation: 'Run your package manager to update the lockfile (e.g., pnpm install).',
        references: ['https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json'],
        confidence: 'high',
      });
    }

    return findings;
  },
});

function getCliCommand(baseName: 'pnpm' | 'npm' | 'yarn'): string {
  if (process.platform === 'win32') return `${baseName}.cmd`;
  return baseName;
}