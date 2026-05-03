import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const AUTH003 = defineRule({
  id: 'AUTH-003',
  name: 'Permissive CORS Configuration',
  description: 'Detects CORS configuration with origin: "*" which is insecure.',
  category: 'auth',
  severity: 'high',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['owasp:a5', 'cwe:942', 'auth'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];
    const seenLines = new Set<number>();

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const text = node.getText(ctx.sourceFile);
        if (text.includes('cors') && text.includes('origin') && text.includes('*')) {
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          if (seenLines.has(line)) return 'continue';
          seenLines.add(line);

          const hasCredentials = text.includes('credentials');
          findings.push({
            ruleId: 'AUTH-003',
            ruleName: 'Permissive CORS Configuration',
            category: 'auth',
            severity: hasCredentials ? 'high' : 'medium',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + text.length,
            message: hasCredentials
              ? `CORS configured with origin: "*" and credentials, allowing any origin with credentials.`
              : `CORS configured with origin: "*", allowing any origin.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Restrict CORS origins to trusted domains: cors({ origin: ["https://myapp.com"], credentials: true })',
            references: ['https://owasp.org/www-community/attacks/CORS_OriginHeadscratcher'],
            confidence: hasCredentials ? 'high' : 'medium',
          });
        }
      }
      return 'continue';
    });

    return findings;
  },
});