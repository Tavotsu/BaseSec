import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

const CRYPTO_METHODS = ['createCipheriv', 'createDecipheriv', 'createCipher', 'createDecipher', 'createSign', 'createVerify'];

export const SEC003 = defineRule({
  id: 'SEC-003',
  name: 'Hardcoded Cryptographic Key',
  description: 'Detects hardcoded encryption keys, IVs, or nonces in crypto operations.',
  category: 'secrets',
  severity: 'critical',
  frameworks: ['*'],
  tags: ['owasp:a7', 'cwe:798', 'cwe:321', 'secrets'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr) && CRYPTO_METHODS.includes(expr.name.text)) {
          if (node.arguments.length > 0) {
            const firstArg = node.arguments[0];
            if (ts.isStringLiteral(firstArg)) {
              const text = node.getText(ctx.sourceFile);
              const { line, column } = getLineAndColumn(ctx.sourceFile, node);
              findings.push({
                ruleId: 'SEC-003',
                ruleName: 'Hardcoded Cryptographic Key',
                category: 'secrets',
                severity: 'critical',
                filePath: ctx.filePath,
                line,
                column,
                endLine: line,
                endColumn: column + text.length,
                message: `Hardcoded key in crypto.${expr.name.text}(). Store encryption keys in environment variables.`,
                codeSnippet: getCodeSnippet(ctx.content, line),
                remediation: 'Store encryption keys in environment variables or secret managers.',
                references: ['https://cwe.mitre.org/data/definitions/321.html'],
                confidence: 'high',
              });
            }

            if (node.arguments.length > 1) {
              const secondArg = node.arguments[1];
              if (ts.isStringLiteral(secondArg)) {
                const text = node.getText(ctx.sourceFile);
                const { line, column } = getLineAndColumn(ctx.sourceFile, node);
                findings.push({
                  ruleId: 'SEC-003',
                  ruleName: 'Hardcoded IV/Nonce',
                  category: 'secrets',
                  severity: 'high',
                  filePath: ctx.filePath,
                  line,
                  column,
                  endLine: line,
                  endColumn: column + text.length,
                  message: `Hardcoded IV/nonce in crypto.${expr.name.text}(). Use random IVs for each encryption.`,
                  codeSnippet: getCodeSnippet(ctx.content, line),
                  remediation: 'Generate random IVs using crypto.randomBytes(). Never reuse IVs.',
                  references: ['https://cwe.mitre.org/data/definitions/321.html'],
                  confidence: 'high',
                });
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