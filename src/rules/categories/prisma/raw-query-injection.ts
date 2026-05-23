import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { detectPrismaPatterns } from '../../../framework/prisma';
import { isTaintSource } from '../../../utils/patterns';
import { resolveConfidence, isExpressionTainted } from '../../../taint/integration';

export const PRISMA001 = defineRule({
  id: 'PRISMA-001',
  name: 'Prisma Raw Query Injection',
  description: 'Detects Prisma raw queries with string concatenation or unsafe interpolation of user input.',
  category: 'sql-injection',
  severity: 'critical',
  frameworks: ['prisma', '*'],
  tags: ['owasp:a1', 'cwe:89', 'sql-injection'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    const prismaInfo = detectPrismaPatterns(ctx.sourceFile, ctx.taintGraph);
    
    if (prismaInfo.hasRawQueryInjection) {
      for (const line of prismaInfo.injectionLines) {
        findings.push({
          ruleId: 'PRISMA-001',
          ruleName: 'Prisma Raw Query Injection',
          category: 'sql-injection',
          severity: 'critical',
          filePath: ctx.filePath,
          line,
          column: 1,
          endLine: line,
          endColumn: 120,
          message: 'SQL injection detected in Prisma raw query. User input is unsafely interpolated or concatenated.',
          codeSnippet: getCodeSnippet(ctx.content, line),
          remediation: 'Use Prisma\'s tagged template literals (e.g., prisma.$queryRaw`SELECT ... ${value}`) for automatic parameterization.',
          references: ['https://www.prisma.io/docs/concepts/components/prisma-client/raw-database-access'],
          confidence: 'high',
        });
      }
    }

    return findings;
  },
});
