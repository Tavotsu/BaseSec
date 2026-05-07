import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { findCallExpressions, getLineAndColumn, getCodeSnippet } from '../../../utils/ast-helpers';

const WEAK_SECRETS = [
  'secret', 'password', 'key', 'token', 'changeme', 'default',
  '123456', 'qwerty', 'abc123', 'letmein', 'admin', 'master',
];

export const AUTH002 = defineRule({
  id: 'AUTH-002',
  name: 'Hardcoded JWT Secret',
  description: 'Detects JWT sign/verify calls with hardcoded secrets, which should use environment variables.',
  category: 'auth',
  severity: 'critical',
  frameworks: ['express', 'nestjs', '*'],
  tags: ['owasp:a7', 'cwe:798', 'auth'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    for (const fn of ['sign', 'verify']) {
      const calls = findCallExpressions(ctx.sourceFile, fn);
      for (const call of calls) {
        const text = call.getText(ctx.sourceFile);
        if (!text.includes('jwt') && !text.includes('Jwt') && !text.includes('JWT') && !text.includes('jsonwebtoken')) {
          continue;
        }

        if (call.arguments.length >= 2) {
          const secretArg = call.arguments[1];
          if (ts.isStringLiteral(secretArg)) {
            const secretValue = secretArg.text;
            const isWeak = secretValue.length < 32 || WEAK_SECRETS.some((w) => secretValue.toLowerCase().includes(w));
            const { line, column } = getLineAndColumn(ctx.sourceFile, call);
            findings.push({
              ruleId: 'AUTH-002',
              ruleName: 'Hardcoded JWT Secret',
              category: 'auth',
              severity: isWeak ? 'critical' : 'high',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + text.length,
              message: isWeak
                ? `Hardcoded weak JWT secret: "${secretValue.length > 20 ? secretValue.substring(0, 20) + '...' : secretValue}". Use environment variables.`
                : `Hardcoded JWT secret found. Use environment variables instead.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Use environment variables for JWT secrets: jwt.sign(payload, process.env.JWT_SECRET)',
              references: ['https://cwe.mitre.org/data/definitions/798.html'],
              confidence: 'high',
            });
          }

          if (ts.isBinaryExpression(secretArg) && (secretArg.operatorToken.kind === ts.SyntaxKind.BarBarToken || secretArg.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)) {
            const argText = secretArg.getText(ctx.sourceFile);
            if ((argText.includes('||') || argText.includes('??')) && (argText.includes("'") || argText.includes('"'))) {
              const fallbackMatch = argText.match(/(?:\|\||\?\?)\s*['"](.+?)['"]/);
              if (fallbackMatch) {
                const { line, column } = getLineAndColumn(ctx.sourceFile, call);
                findings.push({
                  ruleId: 'AUTH-002',
                  ruleName: 'Hardcoded JWT Secret Fallback',
                  category: 'auth',
                  severity: 'high',
                  filePath: ctx.filePath,
                  line,
                  column,
                  endLine: line,
                  endColumn: column + text.length,
                  message: `JWT secret with hardcoded fallback: \`${fallbackMatch[1].substring(0, 30)}\`. Use environment variables without fallbacks.`,
                  codeSnippet: getCodeSnippet(ctx.content, line),
                  remediation: 'Use process.env.JWT_SECRET without fallback values.',
                  references: ['https://cwe.mitre.org/data/definitions/798.html'],
                  confidence: 'high',
                });
              }
            }
          }
        }
      }
    }

    return findings;
  },
});