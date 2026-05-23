import * as ts from 'typescript';
import { visit } from '../utils/ast-helpers';
import { isTaintSource } from '../utils/patterns';
import { isExpressionTainted } from '../taint/integration';
import type { TaintGraph } from '../rules/types';

export interface PrismaPatternInfo {
  hasRawQueryUnsafe: boolean;
  hasRawQueryInjection: boolean;
  rawUnsafeLines: number[];
  injectionLines: number[];
}

const PRISMA_RAW_METHODS = ['$queryRaw', '$executeRaw'];
const PRISMA_RAW_UNSAFE_METHODS = ['$queryRawUnsafe', '$executeRawUnsafe'];
const PRISMA_RECEIVERS = ['prisma', 'db', 'PrismaClient'];

export function detectPrismaPatterns(
  sourceFile: ts.SourceFile,
  taintGraph?: TaintGraph,
): PrismaPatternInfo {
  const info: PrismaPatternInfo = {
    hasRawQueryUnsafe: false,
    hasRawQueryInjection: false,
    rawUnsafeLines: [],
    injectionLines: [],
  };

  visit(sourceFile, (node) => {
    if (ts.isCallExpression(node)) {
      const expr = node.expression;
      
      if (ts.isPropertyAccessExpression(expr)) {
        const methodName = expr.name.text;
        const objText = expr.expression.getText(sourceFile);
        
        const isPrismaReceiver = PRISMA_RECEIVERS.some((r) => objText.includes(r));
        
        if (isPrismaReceiver) {
          if (PRISMA_RAW_UNSAFE_METHODS.includes(methodName)) {
            info.hasRawQueryUnsafe = true;
            const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
            info.rawUnsafeLines.push(pos.line + 1);
            
            // Check for injection in unsafe methods
            if (node.arguments.length > 0) {
              const arg = node.arguments[0];
              const argText = arg.getText(sourceFile);
              if (ts.isBinaryExpression(arg) || ts.isTemplateExpression(arg) || isTaintSource(argText) || (taintGraph && isExpressionTainted(taintGraph, argText))) {
                info.hasRawQueryInjection = true;
                info.injectionLines.push(pos.line + 1);
              }
            }
          } else if (PRISMA_RAW_METHODS.includes(methodName)) {
            // Check for injection in safe methods (using template literals incorrectly or string concat)
            if (node.arguments.length > 0) {
              const arg = node.arguments[0];
              const argText = arg.getText(sourceFile);
              
              // Note: $queryRaw should be used with tagged template literals (e.g. $queryRaw`...`)
              // but if it's called as a regular function with a binary expression or tainted var, it's an injection
              if (ts.isBinaryExpression(arg) || isTaintSource(argText) || (taintGraph && isExpressionTainted(taintGraph, argText))) {
                info.hasRawQueryInjection = true;
                const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
                info.injectionLines.push(pos.line + 1);
              }
            }
          }
        }
      } else if (ts.isTaggedTemplateExpression(node.parent) && ts.isPropertyAccessExpression(node.parent.tag)) {
        // Handle tagged template literal e.g. prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`
        // Prisma's tagged template literal safely parametersizes interpolations.
        // However, if the interpolated value itself is built from string concatenation before being passed, 
        // it might still be vulnerable, but Prisma's `$queryRaw` tagged template is generally safe.
      }
    }
    
    // Also check tagged template literals for $queryRawUnsafe (which doesn't exist, but just in case)
    if (ts.isTaggedTemplateExpression(node)) {
        const tag = node.tag;
        if (ts.isPropertyAccessExpression(tag)) {
            const methodName = tag.name.text;
            const objText = tag.expression.getText(sourceFile);
            const isPrismaReceiver = PRISMA_RECEIVERS.some((r) => objText.includes(r));
            if (isPrismaReceiver && PRISMA_RAW_UNSAFE_METHODS.includes(methodName)) {
                info.hasRawQueryUnsafe = true;
                const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
                info.rawUnsafeLines.push(pos.line + 1);
                
                // If it has expressions, it's vulnerable
                if (ts.isTemplateExpression(node.template) && node.template.templateSpans.length > 0) {
                    info.hasRawQueryInjection = true;
                    info.injectionLines.push(pos.line + 1);
                }
            }
        }
    }

    return 'continue';
  });

  return info;
}