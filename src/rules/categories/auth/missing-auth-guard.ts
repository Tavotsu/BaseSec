import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

const MUTATING_METHODS = ['post', 'put', 'patch', 'delete'];
const AUTH_MIDDLEWARE_NAMES = ['authenticate', 'auth', 'requireAuth', 'isAuthenticated', 'checkAuth', 'verifyToken', 'jwt', 'passport', 'isAuth', 'ensureAuth', 'loginRequired', 'authMiddleware', 'requireLogin', 'isAuthenticated'];

export const AUTH001 = defineRule({
  id: 'AUTH-001',
  name: 'Missing Authentication Guard',
  description: 'Detects mutating routes (POST, PUT, PATCH, DELETE) without authentication middleware.',
  category: 'auth',
  severity: 'high',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['owasp:a1', 'cwe:306', 'auth'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr) && MUTATING_METHODS.includes(expr.name.text)) {
          const args = node.arguments;
          const hasAuthMiddleware = args.some((arg) => {
            if (ts.isIdentifier(arg)) {
              return AUTH_MIDDLEWARE_NAMES.some((name) =>
                arg.text.toLowerCase().includes(name.toLowerCase()),
              );
            }
            return false;
          });

          if (!hasAuthMiddleware && args.length > 0) {
            const text = node.getText(ctx.sourceFile);
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'AUTH-001',
              ruleName: 'Missing Authentication Guard',
              category: 'auth',
              severity: 'high',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + text.length,
              message: `Route handler for \`.${expr.name.text}()\` has no authentication middleware.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Add authentication middleware to all mutating endpoints.',
              references: ['https://owasp.org/www-project-web-security-testing-guide/', 'https://cwe.mitre.org/data/definitions/306.html'],
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