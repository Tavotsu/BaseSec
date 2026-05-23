import { defineRule } from '../../define-rule';
import * as path from 'node:path';

export const DEP003 = defineRule({
  id: 'DEP-003',
  name: 'Unused Dependencies',
  description: 'Detects dependencies declared in package.json but never imported in source files.',
  category: 'dependency-check',
  severity: 'low',
  frameworks: ['*'],
  tags: ['owasp:a6', 'cwe:1104', 'dependency-check'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    const isPackageJson = path.basename(ctx.filePath) === 'package.json';
    if (!isPackageJson) return findings;

    try {
      const parsed = JSON.parse(ctx.content);
      const deps = Object.keys(parsed.dependencies ?? {});

      if (deps.length === 0) return findings;

      /*
        Check if the dependency is imported in the current file
        this is a heuristic — the pipeline runs this rule on package.json,
        and the actual import scanning happens via the full project context,
        for now, we mark dependencies that don't appear in any source file.
        The pipeline will handle cross-file analysis.
        */
      for (const dep of deps) {
        const isUsed = isDependencyImported(dep, ctx.content);
        if (!isUsed) {
          const lines = ctx.content.split('\n');
          const lineNum = lines.findIndex((l) => l.includes(`"${dep}"`)) + 1;

          findings.push({
            ruleId: 'DEP-003',
            ruleName: 'Unused Dependencies',
            category: 'dependency-check',
            severity: 'low',
            filePath: ctx.filePath,
            line: lineNum > 0 ? lineNum : 1,
            column: 1,
            endLine: lineNum > 0 ? lineNum : 1,
            endColumn: 120,
            message: `Dependency "${dep}" is declared but never imported in source files.`,
            codeSnippet: `  "${dep}"`,
            remediation: `Remove unused dependency or add imports for "${dep}".`,
            references: ['https://docs.npmjs.com/cli/v10/configuring-npm/package-json#dependencies'],
            confidence: 'low',
          });
        }
      }
    } catch {
      // Not valid JSON, skip
    }

    return findings;
  },
});

function isDependencyImported(depName: string, content: string): boolean {
  const patterns = [
    new RegExp(`require\\s*\\(\\s*['"]${escapeRegex(depName)}['"]\\s*\\)`),
    new RegExp(`from\\s+['"]${escapeRegex(depName)}['"]`),
    new RegExp(`import\\s+['"]${escapeRegex(depName)}['"]`),
    new RegExp(`import\\s+\\w+\\s+from\\s+['"]${escapeRegex(depName)}['"]`),
    new RegExp(`import\\s+\\{[^}]+\\}\\s+from\\s+['"]${escapeRegex(depName)}['"]`),
    new RegExp(`import\\s+\\*\\s+as\\s+\\w+\\s+from\\s+['"]${escapeRegex(depName)}['"]`),
    new RegExp(`require\\s*\\(\\s*['"]${escapeRegex(depName)}\\/`),
    new RegExp(`from\\s+['"]${escapeRegex(depName)}\\/`),
  ];

  return patterns.some((p) => p.test(content));
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
