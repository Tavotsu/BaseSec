import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import * as path from 'node:path';
import { SECRET_VAR_PATTERNS, SECRET_VALUE_PATTERNS } from '../../../utils/patterns';
import { redactSecret } from '../../../utils/redact';

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

    const isEnvFile = path.basename(ctx.filePath).includes('.env');
    if (isEnvFile) {
      const lines = ctx.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#')) continue;

        const eqIdx = line.indexOf('=');
        if (eqIdx === -1) continue;

        const key = line.substring(0, eqIdx).trim();
        let value = line.substring(eqIdx + 1).trim();
        // Remove quotes if present
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.substring(1, value.length - 1);
        }

        const isSecretVar = SECRET_VAR_PATTERNS.some((p) => p.test(key));
        const isSecretValue = SECRET_VALUE_PATTERNS.some((p) => p.pattern.test(value));
        const matchedPattern = SECRET_VALUE_PATTERNS.find((p) => p.pattern.test(value));

        if (isSecretVar && value.length > 0) {
          findings.push({
            ruleId: 'SEC-001',
            ruleName: 'Hardcoded API Key',
            category: 'secrets',
            severity: 'critical',
            filePath: ctx.filePath,
            line: i + 1,
            column: 1,
            endLine: i + 1,
            endColumn: line.length + 1,
            message: matchedPattern
              ? `Hardcoded ${matchedPattern.name} detected in env variable "${key}".`
              : `Hardcoded secret detected in env variable "${key}".`,
            codeSnippet: redactSecret(line, value),
            remediation: 'Do not store sensitive credentials in plain text. Use a secret manager.',
            references: ['https://cwe.mitre.org/data/definitions/798.html'],
            confidence: isSecretValue ? 'high' : 'medium',
          });
        } else if (!isSecretVar && isSecretValue) {
          findings.push({
            ruleId: 'SEC-001',
            ruleName: 'Hardcoded API Key',
            category: 'secrets',
            severity: 'high',
            filePath: ctx.filePath,
            line: i + 1,
            column: 1,
            endLine: i + 1,
            endColumn: line.length + 1,
            message: matchedPattern
              ? `Potential ${matchedPattern.name} detected in env variable.`
              : `Potential hardcoded secret detected by value pattern in env variable.`,
            codeSnippet: redactSecret(line, value),
            remediation: 'Do not store sensitive credentials in plain text. Use a secret manager.',
            references: ['https://cwe.mitre.org/data/definitions/798.html'],
            confidence: 'low',
          });
        }
      }
      return findings;
    }

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
            codeSnippet: redactSecret(getCodeSnippet(ctx.content, line), value),
            remediation: 'Store secrets in environment variables or secret managers. Never commit secrets to source code.',
            references: ['https://cwe.mitre.org/data/definitions/798.html'],
            confidence: isSecretValue ? 'high' : 'medium',
          });
        } else if (!isSecretVar && isSecretValue) {
          const text = node.getText(ctx.sourceFile);
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          const matchedPattern = SECRET_VALUE_PATTERNS.find((p) => p.pattern.test(value));
          findings.push({
            ruleId: 'SEC-001',
            ruleName: 'Hardcoded API Key',
            category: 'secrets',
            severity: 'high',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + text.length,
            message: matchedPattern
              ? `Potential ${matchedPattern.name} detected. Variable name does not indicate a secret.`
              : `Potential hardcoded secret detected by value pattern. Use environment variables.`,
            codeSnippet: redactSecret(getCodeSnippet(ctx.content, line), value),
            remediation: 'Store secrets in environment variables or secret managers. Never commit secrets to source code.',
            references: ['https://cwe.mitre.org/data/definitions/798.html'],
            confidence: 'low',
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
          const isSecretValue = SECRET_VALUE_PATTERNS.some((p) => p.pattern.test(value));
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
              ? `Hardcoded ${matchedPattern.name} in property "${propName}".`
              : `Hardcoded secret in property "${propName}". Use environment variables.`,
            codeSnippet: redactSecret(getCodeSnippet(ctx.content, line), value),
            remediation: 'Store secrets in environment variables or secret managers.',
            references: ['https://cwe.mitre.org/data/definitions/798.html'],
            confidence: isSecretValue ? 'high' : 'medium',
          });
        }
      }
      return 'continue';
    });

    return findings;
  },
});