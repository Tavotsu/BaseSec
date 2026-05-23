import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { detectPrismaPatterns } from '../../../framework/prisma';

export const PRISMA002 = defineRule({
  id: 'PRISMA-002',
  name: 'Unsafe Prisma Raw Query',
  description: 'Detects the use of Prisma\'s Unsafe raw query methods which are prone to SQL injection.',
  category: 'sql-injection',
  severity: 'high',
  frameworks: ['prisma', '*'],
  tags: ['owasp:a1', 'cwe:89', 'sql-injection'],
  detect(ctx) {
    const findings: import('../../../rules/types').Finding[] = [];

    const prismaInfo = detectPrismaPatterns(ctx.sourceFile, ctx.taintGraph);
    
    if (prismaInfo.hasRawQueryUnsafe) {
      for (const line of prismaInfo.rawUnsafeLines) {
        // Don't duplicate with PRISMA001 if it's already an injection
        if (prismaInfo.injectionLines.includes(line)) continue;
        
        findings.push({
          ruleId: 'PRISMA-002',
          ruleName: 'Unsafe Prisma Raw Query',
          category: 'sql-injection',
          severity: 'high',
          filePath: ctx.filePath,
          line,
          column: 1,
          endLine: line,
          endColumn: 120,
          message: 'Use of $queryRawUnsafe or $executeRawUnsafe detected. These methods do not parameterize inputs automatically.',
          codeSnippet: getCodeSnippet(ctx.content, line),
          remediation: 'Prefer $queryRaw or $executeRaw with tagged template literals for automatic parameterization.',
          references: ['https://www.prisma.io/docs/concepts/components/prisma-client/raw-database-access#queryrawunsafe'],
          confidence: 'medium',
        });
      }
    }

    return findings;
  },
});
