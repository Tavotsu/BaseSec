import { defineRule } from '../../define-rule';
import { getCodeSnippet } from '../../../utils/ast-helpers';
import { lineAtIndex } from '../../../framework/frontend';
import type { Finding } from '../../../rules/types';

// ponytail: text scan over raw content, no template AST. Ceiling: the expression
// capture stops at the first `}`. Upgrade path: the svelte compiler's RawMustacheTag.
const HTML_TAG = /\{@html\s+([^}]+)\}/g;
const STATIC_STRING = /^(['"]).*\1$/;

export const SVELTE001 = defineRule({
  id: 'SVELTE-001',
  name: '{@html} with Dynamic Expression',
  description: 'Detects Svelte {@html} blocks rendering a non-literal expression, bypassing escaping (XSS).',
  category: 'xss',
  severity: 'critical',
  frameworks: ['svelte'],
  tags: ['owasp:a3', 'cwe:79', 'svelte'],
  detect(ctx) {
    const findings: Finding[] = [];
    HTML_TAG.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = HTML_TAG.exec(ctx.content)) !== null) {
      const expr = (m[1] ?? '').trim();
      if (STATIC_STRING.test(expr)) continue;
      const { line, column } = lineAtIndex(ctx.content, m.index);
      findings.push({
        ruleId: 'SVELTE-001',
        ruleName: '{@html} with Dynamic Expression',
        category: 'xss',
        severity: 'critical',
        filePath: ctx.filePath,
        line,
        column,
        endLine: line,
        endColumn: column + m[0].length,
        message: `{@html} renders raw HTML from \`${expr}\`, bypassing Svelte escaping (XSS).`,
        codeSnippet: getCodeSnippet(ctx.content, line),
        remediation: 'Render text with {expr}; if HTML is required, sanitize it with DOMPurify first.',
        references: ['https://svelte.dev/docs/special-tags#html', 'https://cwe.mitre.org/data/definitions/79.html'],
        confidence: 'medium',
      });
    }
    return findings;
  },
});
