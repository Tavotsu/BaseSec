import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { SECRET_VAR_PATTERNS, SECRET_VALUE_PATTERNS } from '../../../utils/patterns';

export const SEC001 = defineRule({
  id: 'SEC-001',
  name: 'Hardcoded API Key',
  description: 'Detects hardcoded API keys, secrets, and tokens in source code.',
  category: 'secrets',
  severity: 'critical',
  frameworks: ['*'],
  tags: ['owasp:a7', 'cwe:798', 'secrets'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isVariableDeclaration(node) && node.initializer && ts.isStringLiteral(node.initializer)) {
        const varName = ts.isIdentifier(node.name) ? node.name.text : '';
        const value = node.initializer.text;

        const isSecretVar = SECRET_VAR_PATTERNS.some((p) => p.test(varName));
        const isSecretValue = SECRET_VALUE_PATTERNS.some((p) => p.pattern.test(value));

        if (isSecretVar && value.length > 0) {
          const text = node.getText(ctx.sourceFile);
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          const matchedPattern = SECRET_VALUE_PATTERNS.find((p) => p.pattern.test(value));
          findings.push({
            ruleId: 'SEC-001',
            ruleName: 'Hardcoded API Key',
            category: 'secrets',
            severity: 'critical',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + text.length,
            message: matchedPattern
              ? `Hardcoded ${matchedPattern.name} detected in variable "${varName}".`
              : `Hardcoded secret detected in variable "${varName}". Use environment variables instead.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Store secrets in environment variables or secret managers. Never commit secrets to source code.',
            references: ['https://cwe.mitre.org/data/definitions/798.html'],
            confidence: isSecretValue ? 'high' : 'medium',
          });
        }
      }

      if (ts.isPropertyAssignment(node) && ts.isStringLiteral(node.initializer)) {
        const propName = ts.isIdentifier(node.name) ? node.name.text : ts.isStringLiteral(node.name) ? node.name.text : '';
        const value = node.initializer.text;

        const isSecretProp = SECRET_VAR_PATTERNS.some((p) => p.test(propName));
        if (isSecretProp && value.length > 0) {
          const text = node.getText(ctx.sourceFile);
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          findings.push({
            ruleId: 'SEC-001',
            ruleName: 'Hardcoded API Key',
            category: 'secrets',
            severity: 'critical',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + text.length,
            message: `Hardcoded secret in property "${propName}". Use environment variables.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Store secrets in environment variables or secret managers.',
            references: ['https://cwe.mitre.org/data/definitions/798.html'],
            confidence: 'medium',
          });
        }
      }
      return 'continue';
    });

    return findings;
  },
});