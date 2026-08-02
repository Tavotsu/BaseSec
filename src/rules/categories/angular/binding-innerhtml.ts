import { defineRule } from '../../define-rule';
import { getCodeSnippet } from '../../../utils/ast-helpers';
import { lineAtIndex } from '../../../framework/frontend';
import type { Finding } from '../../../rules/types';

// ponytail: text scan of inline templates; Angular sanitizes [innerHTML] by
// default, so confidence stays low unless paired with an NG-001 bypass.
const NG_INNERHTML = /\[innerHTML\]\s*=\s*(?:"([^"]*)"|'([^']*)')/g;

export const NG003 = defineRule({
  id: 'NG-003',
  name: 'Tainted [innerHTML] Binding',
  description: 'Detects Angular [innerHTML] template bindings; sanitized by default but risky when combined with a sanitizer bypass.',
  category: 'xss',
  severity: 'medium',
  frameworks: ['angular'],
  tags: ['owasp:a3', 'cwe:79', 'angular'],
  detect(ctx) {
    const findings: Finding[] = [];
    NG_INNERHTML.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = NG_INNERHTML.exec(ctx.content)) !== null) {
      const expr = m[1] ?? m[2] ?? '';
      const { line, column } = lineAtIndex(ctx.content, m.index);
      findings.push({
        ruleId: 'NG-003',
        ruleName: 'Tainted [innerHTML] Binding',
        category: 'xss',
        severity: 'medium',
        filePath: ctx.filePath,
        line,
        column,
        endLine: line,
        endColumn: column + m[0].length,
        message: `[innerHTML] binds \`${expr}\`; safe only if the value is never passed through bypassSecurityTrustHtml.`,
        codeSnippet: getCodeSnippet(ctx.content, line),
        remediation: 'Keep relying on Angular sanitization; never feed [innerHTML] a value from bypassSecurityTrustHtml.',
        references: ['https://angular.dev/best-practices/security', 'https://cwe.mitre.org/data/definitions/79.html'],
        confidence: 'low',
      });
    }
    return findings;
  },
});
