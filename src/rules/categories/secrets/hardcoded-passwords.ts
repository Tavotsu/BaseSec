import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

const PASSWORD_VAR_NAMES = /^(password|passwd|pwd|pass|db_pass|db_password|db_passwd|database_password|mongo_password|redis_password|mysql_password|postgres_password|smtp_password|ftp_password)$/i;

export const SEC002 = defineRule({
  id: 'SEC-002',
  name: 'Hardcoded Password',
  description: 'Detects hardcoded passwords in variable assignments.',
  category: 'secrets',
  severity: 'critical',
  frameworks: ['*'],
  tags: ['owasp:a7', 'cwe:798', 'secrets'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isVariableDeclaration(node) && node.initializer && ts.isStringLiteral(node.initializer)) {
        const varName = ts.isIdentifier(node.name) ? node.name.text : '';
        if (PASSWORD_VAR_NAMES.test(varName)) {
          const text = node.getText(ctx.sourceFile);
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          findings.push({
            ruleId: 'SEC-002',
            ruleName: 'Hardcoded Password',
            category: 'secrets',
            severity: 'critical',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + text.length,
            message: `Hardcoded password in variable "${varName}". Use environment variables.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Use environment variables or secret managers for passwords.',
            references: ['https://cwe.mitre.org/data/definitions/798.html'],
            confidence: 'high',
          });
        }
      }

      if (ts.isBinaryExpression(node) && (node.operatorToken.kind === ts.SyntaxKind.BarBarToken || node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)) {
        const text = node.getText(ctx.sourceFile);
        if (PASSWORD_VAR_NAMES.test(text.split(/\|\||\?\?/)[0].split('.').pop()?.trim() || '')) {
          const rightText = node.right.getText(ctx.sourceFile);
          if (ts.isStringLiteral(node.right) || (rightText.startsWith("'") || rightText.startsWith('"'))) {
            const { line, column } = getLineAndColumn(ctx.sourceFile, node);
            findings.push({
              ruleId: 'SEC-002',
              ruleName: 'Hardcoded Password Fallback',
              category: 'secrets',
              severity: 'high',
              filePath: ctx.filePath,
              line,
              column,
              endLine: line,
              endColumn: column + text.length,
              message: `Password with hardcoded fallback value. Use process.env without fallback.`,
              codeSnippet: getCodeSnippet(ctx.content, line),
              remediation: 'Use process.env.DB_PASSWORD without fallback values.',
              references: ['https://cwe.mitre.org/data/definitions/798.html'],
              confidence: 'high',
            });
          }
        }
      }
      return 'continue';
    });

    return findings;
  },
});