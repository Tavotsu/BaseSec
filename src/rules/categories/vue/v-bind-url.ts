import { defineRule } from '../../define-rule';
import { getCodeSnippet } from '../../../utils/ast-helpers';
import { lineAtIndex } from '../../../framework/frontend';
import type { Finding } from '../../../rules/types';

const V_BIND_URL = /(?::|v-bind:)(href|src)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
const USER_HINT = /route|query|param|props|location|\.search|\.hash|\$page/i;

export const VUE002 = defineRule({
  id: 'VUE-002',
  name: 'Unvalidated URL in Vue :href/:src',
  description: 'Detects Vue :href/:src bindings derived from route/props/URL data without validation, allowing javascript: URI injection.',
  category: 'xss',
  severity: 'high',
  frameworks: ['vue'],
  tags: ['owasp:a3', 'cwe:79', 'vue'],
  detect(ctx) {
    const findings: Finding[] = [];
    V_BIND_URL.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = V_BIND_URL.exec(ctx.content)) !== null) {
      const attr = m[1];
      const expr = m[2] ?? m[3] ?? '';
      if (!USER_HINT.test(expr)) continue;
      const { line, column } = lineAtIndex(ctx.content, m.index);
      findings.push({
        ruleId: 'VUE-002',
        ruleName: 'Unvalidated URL in Vue :href/:src',
        category: 'xss',
        severity: 'high',
        filePath: ctx.filePath,
        line,
        column,
        endLine: line,
        endColumn: column + m[0].length,
        message: `Vue \`:${attr}\` bound to user-derived \`${expr}\` may allow a javascript: URI.`,
        codeSnippet: getCodeSnippet(ctx.content, line),
        remediation: 'Validate the URL scheme (allow only http/https/mailto) before binding it.',
        references: ['https://vuejs.org/guide/best-practices/security.html', 'https://cwe.mitre.org/data/definitions/79.html'],
        confidence: 'low',
      });
    }
    return findings;
  },
});
