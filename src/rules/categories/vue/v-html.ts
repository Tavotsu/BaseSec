import { defineRule } from '../../define-rule';
import { getCodeSnippet } from '../../../utils/ast-helpers';
import { lineAtIndex } from '../../../framework/frontend';
import type { Finding } from '../../../rules/types';

// ponytail: text scan over raw content, no template AST — catches both inline
// templates and <template> blocks. Ceiling: a `v-html=` inside a script string
// literal also matches. Upgrade path: @vue/compiler-sfc's template AST.
const V_HTML = /v-html\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
// v-html takes an expression, so a quoted literal inside it is a constant — same
// carve-out SVELTE-001 makes for {@html '...'}.
const STATIC_STRING = /^(['"]).*\1$/;

export const VUE001 = defineRule({
  id: 'VUE-001',
  name: 'v-html with Dynamic Binding',
  description: 'Detects Vue v-html directives, which render raw HTML and bypass template escaping (XSS).',
  category: 'xss',
  severity: 'critical',
  frameworks: ['vue'],
  tags: ['owasp:a3', 'cwe:79', 'vue'],
  detect(ctx) {
    const findings: Finding[] = [];
    V_HTML.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = V_HTML.exec(ctx.content)) !== null) {
      const expr = (m[1] ?? m[2] ?? '').trim();
      if (STATIC_STRING.test(expr)) continue;
      const { line, column } = lineAtIndex(ctx.content, m.index);
      findings.push({
        ruleId: 'VUE-001',
        ruleName: 'v-html with Dynamic Binding',
        category: 'xss',
        severity: 'critical',
        filePath: ctx.filePath,
        line,
        column,
        endLine: line,
        endColumn: column + m[0].length,
        message: `v-html renders raw HTML from \`${expr}\`, bypassing Vue's escaping (XSS).`,
        codeSnippet: getCodeSnippet(ctx.content, line),
        remediation: 'Render text with {{ }} or v-text; if HTML is required, sanitize it with DOMPurify first.',
        references: ['https://vuejs.org/guide/best-practices/security.html', 'https://cwe.mitre.org/data/definitions/79.html'],
        confidence: 'medium',
      });
    }
    return findings;
  },
});
