import { defineRule } from '../../define-rule';
import * as fs from 'node:fs';
import * as path from 'node:path';

interface CveEntry {
  id: string;
  ranges: string[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
}

const VULNERABLE_PACKAGES: Record<string, CveEntry[]> = {
  'express': [
    { id: 'CVE-2024-29041', ranges: ['<4.19.2'], severity: 'high', title: 'Open redirect in express' },
    { id: 'CVE-2024-43796', ranges: ['<4.20.0'], severity: 'high', title: 'XSS via res.redirect' },
  ],
  'lodash': [
    { id: 'CVE-2021-23337', ranges: ['<4.17.21'], severity: 'high', title: 'Command injection via template' },
    { id: 'CVE-2020-28500', ranges: ['<4.17.21'], severity: 'medium', title: 'ReDoS in trim functions' },
  ],
  'axios': [
    { id: 'CVE-2023-45857', ranges: ['<1.6.0'], severity: 'medium', title: 'CSRF token exposure' },
    { id: 'CVE-2024-39338', ranges: ['<1.7.4'], severity: 'high', title: 'SSRF in axios' },
  ],
  'jsonwebtoken': [
    { id: 'CVE-2022-23529', ranges: ['<9.0.0'], severity: 'high', title: 'Insecure key retrieval' },
  ],
  'node-fetch': [
    { id: 'CVE-2022-0235', ranges: ['<2.6.7'], severity: 'medium', title: 'Exposure of sensitive information' },
    { id: 'CVE-2022-46175', ranges: ['<3.3.0'], severity: 'high', title: 'Prototype pollution' },
  ],
  'semver': [
    { id: 'CVE-2022-25883', ranges: ['<7.5.2'], severity: 'medium', title: 'ReDoS in semver' },
  ],
  'word-wrap': [
    { id: 'CVE-2023-26115', ranges: ['<1.2.4'], severity: 'medium', title: 'ReDoS' },
  ],
  'tough-cookie': [
    { id: 'CVE-2023-26136', ranges: ['<4.1.3'], severity: 'high', title: 'Prototype pollution' },
  ],
  'xml2js': [
    { id: 'CVE-2023-0842', ranges: ['<0.6.0'], severity: 'high', title: 'Prototype pollution' },
  ],
  'mysql': [
    { id: 'CVE-2024-21507', ranges: ['<2.18.1'], severity: 'high', title: 'SQL injection in multiple statements' },
  ],
  'pg': [
    { id: 'CVE-2024-21508', ranges: ['<8.12.0'], severity: 'critical', title: 'SQL injection' },
  ],
  'mongoose': [
    { id: 'CVE-2024-52905', ranges: ['<8.8.3'], severity: 'high', title: 'Prototype pollution via $where' },
  ],
  'fastify': [
    { id: 'CVE-2024-22209', ranges: ['<4.26.0'], severity: 'medium', title: 'Content smuggling' },
  ],
  'helmet': [
    { id: 'CVE-2024-29041', ranges: ['<7.1.0'], severity: 'medium', title: 'Missing X-Download-Options header' },
  ],
};

function satisfiesRange(version: string, range: string): boolean {
  const op = range.slice(0, 2).trim();
  const target = range.replace(/^[<>=!]+\s*/, '');

  const vParts = version.replace(/^v/, '').split('.').map(Number);
  const tParts = target.split('.').map(Number);

  for (let i = 0; i < Math.max(vParts.length, tParts.length); i++) {
    const v = vParts[i] ?? 0;
    const t = tParts[i] ?? 0;
    if (v < t) return true;
    if (v > t) return false;
  }
  return false;
}

export const DEP001 = defineRule({
  id: 'DEP-001',
  name: 'Outdated Dependencies with Known CVEs',
  description: 'Detects dependencies with known security vulnerabilities based on version ranges.',
  category: 'dependency-check',
  severity: 'high',
  frameworks: ['*'],
  tags: ['owasp:a6', 'cwe:1104', 'dependency-check'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    const isPackageJson = path.basename(ctx.filePath) === 'package.json';
    if (!isPackageJson) return findings;

    try {
      const parsed = JSON.parse(ctx.content);
      const deps = { ...parsed.dependencies, ...parsed.devDependencies };

      for (const [pkgName, version] of Object.entries(deps)) {
        const cves = VULNERABLE_PACKAGES[pkgName];
        if (!cves) continue;

        const cleanVersion = String(version).replace(/^[\^~>=<]*/, '');
        for (const cve of cves) {
          for (const range of cve.ranges) {
            if (satisfiesRange(cleanVersion, range)) {
              const lines = ctx.content.split('\n');
              const lineNum = lines.findIndex((l) => l.includes(`"${pkgName}"`)) + 1;

              findings.push({
                ruleId: 'DEP-001',
                ruleName: 'Outdated Dependencies with Known CVEs',
                category: 'dependency-check',
                severity: cve.severity,
                filePath: ctx.filePath,
                line: lineNum > 0 ? lineNum : 1,
                column: 1,
                endLine: lineNum > 0 ? lineNum : 1,
                endColumn: 120,
                message: `${cve.id}: ${cve.title} — ${pkgName}@${cleanVersion} (vulnerable: ${range})`,
                codeSnippet: `  "${pkgName}": "${version}"`,
                remediation: `Update ${pkgName} to a version that is not affected by ${cve.id}.`,
                references: [`https://nvd.nist.gov/vuln/detail/${cve.id}`],
                confidence: 'high',
              });
            }
          }
        }
      }
    } catch {
      // Not valid JSON, skip
    }

    return findings;
  },
});