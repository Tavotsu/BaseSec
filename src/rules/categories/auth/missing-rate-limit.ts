import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

const AUTH_ENDPOINTS = ['/login', '/register', '/signup', '/auth', '/password-reset', '/forgot-password', '/verify'];
const RATE_LIMIT_NAMES = ['rateLimit', 'rateLimiter', 'rate', 'throttle', 'limiter'];

export const AUTH004 = defineRule({
  id: 'AUTH-004',
  name: 'Missing Rate Limiting on Auth Endpoints',
  description: 'Detects authentication endpoints without rate limiting middleware.',
  category: 'auth',
  severity: 'medium',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['owasp:a7', 'cwe:307', 'auth'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const method = expr.name.text;
          if (method === 'post' || method === 'get') {
            const firstArg = node.arguments[0];
            if (firstArg && ts.isStringLiteral(firstArg)) {
              const path = firstArg.text;
              const isAuthEndpoint = AUTH_ENDPOINTS.some(
                (ep) => path.toLowerCase().includes(ep),
              );
              if (isAuthEndpoint) {
                const args = node.arguments;
                const hasRateLimiter = args.some((arg) => {
                  if (ts.isIdentifier(arg)) {
                    return RATE_LIMIT_NAMES.some((name) =>
                      arg.text.toLowerCase().includes(name.toLowerCase()),
                    );
                  }
                  if (ts.isCallExpression(arg)) {
                    const argText = arg.getText(ctx.sourceFile);
                    return RATE_LIMIT_NAMES.some((name) =>
                      argText.toLowerCase().includes(name.toLowerCase()),
                    );
                  }
                  return false;
                });

                if (!hasRateLimiter) {
                  const text = node.getText(ctx.sourceFile);
                  const { line, column } = getLineAndColumn(ctx.sourceFile, node);
                  findings.push({
                    ruleId: 'AUTH-004',
                    ruleName: 'Missing Rate Limiting on Auth Endpoints',
                    category: 'auth',
                    severity: 'medium',
                    filePath: ctx.filePath,
                    line,
                    column,
                    endLine: line,
                    endColumn: column + text.length,
                    message: `Authentication endpoint "${path}" lacks rate limiting middleware.`,
                    codeSnippet: getCodeSnippet(ctx.content, line),
                    remediation: 'Add rate limiting middleware (e.g., express-rate-limit) to all authentication endpoints.',
                    references: ['https://owasp.org/www-community/attacks/Brute_force_attack'],
                    confidence: 'low',
                  });
                }
              }
            }
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});