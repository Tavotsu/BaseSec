import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';

const CRYPTO_METHODS = ['createCipheriv', 'createDecipheriv', 'createSign', 'createVerify'];
const CRYPTO_DEP_METHODS = ['createCipher', 'createDecipher'];

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
        if (ts.isPropertyAccessExpression(expr) && (CRYPTO_METHODS.includes(expr.name.text) || CRYPTO_DEP_METHODS.includes(expr.name.text))) {
          const methodName = expr.name.text;
          if (node.arguments.length > 0) {
            const firstArg = node.arguments[0];
            if (ts.isStringLiteral(firstArg) && CRYPTO_DEP_METHODS.includes(methodName)) {
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
                message: `Deprecated crypto.${methodName}() with hardcoded password. Use ${methodName}iv() with a proper key instead.`,
                codeSnippet: getCodeSnippet(ctx.content, line),
                remediation: 'Use crypto.createCipheriv/createDecipheriv with keys from environment variables.',
                references: ['https://cwe.mitre.org/data/definitions/321.html'],
                confidence: 'high',
              });
            }

            if (node.arguments.length > 1) {
              const secondArg = node.arguments[1];
              if (ts.isStringLiteral(secondArg)) {
                const text = node.getText(ctx.sourceFile);
                const { line, column } = getLineAndColumn(ctx.sourceFile, node);
                const label = CRYPTO_METHODS.includes(methodName) ? 'IV/Nonce' : 'password';
                findings.push({
                  ruleId: 'SEC-003',
                  ruleName: CRYPTO_METHODS.includes(methodName) ? 'Hardcoded IV/Nonce' : 'Hardcoded Cryptographic Key',
                  category: 'secrets',
                  severity: CRYPTO_METHODS.includes(methodName) ? 'high' : 'critical',
                  filePath: ctx.filePath,
                  line,
                  column,
                  endLine: line,
                  endColumn: column + text.length,
                  message: `Hardcoded ${label} in crypto.${methodName}(). Use environment variables or crypto.randomBytes().`,
                  codeSnippet: getCodeSnippet(ctx.content, line),
                  remediation: CRYPTO_METHODS.includes(methodName)
                    ? 'Generate random IVs using crypto.randomBytes(). Never reuse IVs.'
                    : 'Store encryption keys in environment variables or secret managers.',
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