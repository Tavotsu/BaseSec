import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

export const CONF003 = defineRule({
  id: 'CONF-003',
  name: 'Insecure Cookie Configuration',
  description: 'Detects cookie/session configuration without secure and httpOnly flags.',
  category: 'misconfiguration',
  severity: 'medium',
  frameworks: ['express', '*'],
  tags: ['owasp:a5', 'cwe:614', 'misconfiguration'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const text = node.getText(ctx.sourceFile);
        if (text.includes('cookie(') || text.includes('session(') || text.includes('cookieSession(')) {
          if (text.includes('secure:') && !text.includes('secure: true') && !text.includes('secure:true')) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'CONF-003',
              ruleName: 'Insecure Cookie Configuration',
              category: 'misconfiguration',
              severity: 'medium',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + text.length,
              message: `Cookie/session configured without secure: true.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Set secure: true and httpOnly: true for all cookie configurations.',
              references: ['https://owasp.org/www-community/controls/SecureCookie'],
              confidence: 'medium',
            });
          }
          if (!text.includes('httpOnly') && !text.includes('httponly') && (text.includes('cookie(') || text.includes('session('))) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'CONF-003',
              ruleName: 'Insecure Cookie Configuration',
              category: 'misconfiguration',
              severity: 'medium',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + text.length,
              message: `Cookie/session configured without httpOnly flag.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Set httpOnly: true and secure: true for all cookie configurations.',
              references: ['https://owasp.org/www-community/controls/SecureCookie'],
              confidence: 'low',
            });
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});