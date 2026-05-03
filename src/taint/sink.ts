import * as ts from 'typescript';
import type { TaintSinkInfo, SinkDefinition } from './types';
import { visit } from '../utils/ast-helpers';

const SINK_DEFINITIONS: SinkDefinition[] = [
  { pattern: 'exec', category: 'command-injection' },
  { pattern: 'execSync', category: 'command-injection' },
  { pattern: 'spawn', category: 'command-injection' },
  { pattern: 'execFile', category: 'command-injection' },
  { pattern: 'eval', category: 'command-injection' },
  { pattern: 'Function', category: 'command-injection' },
  { pattern: 'query', category: 'sql-injection' },
  { pattern: 'raw', category: 'sql-injection' },
  { pattern: 'find', category: 'nosql-injection' },
  { pattern: '$where', category: 'nosql-injection' },
  { pattern: 'send', category: 'xss' },
  { pattern: 'json', category: 'xss' },
  { pattern: 'redirect', category: 'xss' },
  { pattern: 'set', category: 'xss' },
  { pattern: 'setHeader', category: 'xss' },
  { pattern: 'readFile', category: 'path-traversal' },
  { pattern: 'readFileSync', category: 'path-traversal' },
  { pattern: 'writeFile', category: 'path-traversal' },
  { pattern: 'writeFileSync', category: 'path-traversal' },
  { pattern: 'unlink', category: 'path-traversal' },
  { pattern: 'unlinkSync', category: 'path-traversal' },
  { pattern: 'createReadStream', category: 'path-traversal' },
  { pattern: 'sign', category: 'auth' },
];

const DANGEROUS_STANDALONE = new Set([
  'exec', 'execSync', 'spawn', 'execFile', 'execFileSync',
  'eval',
]);

const SINK_METHOD_RECEIVERS: Record<string, string[]> = {
  query: ['db', 'connection', 'repository', 'manager', 'getConnection', 'knex', 'pool', 'client', 'sequelize', 'pg', 'mysql'],
  raw: ['db', 'knex', 'connection'],
  find: ['Model', 'model', 'collection'],
  $where: ['Model', 'model', 'collection'],
  send: ['res'],
  json: ['res'],
  redirect: ['res'],
  set: ['res'],
  setHeader: ['res'],
  sign: ['jwt', 'jsonwebtoken'],
};

export function findSinks(
  sourceFile: ts.SourceFile,
): TaintSinkInfo[] {
  const sinks: TaintSinkInfo[] = [];

  visit(sourceFile, (node) => {
    if (ts.isCallExpression(node)) {
      const expr = node.expression;

      if (ts.isIdentifier(expr)) {
        if (DANGEROUS_STANDALONE.has(expr.text)) {
          const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
          sinks.push({
            category: getSinkCategory(expr.text),
            functionName: expr.text,
            line: pos.line + 1,
            column: pos.character + 1,
          });
        }
      }

      if (ts.isPropertyAccessExpression(expr)) {
        const methodName = expr.name.text;
        if (isDangerousMethod(methodName, expr.expression, sourceFile)) {
          const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
          const objText = expr.expression.getText(sourceFile);
          sinks.push({
            category: getSinkCategory(methodName),
            functionName: `${objText}.${methodName}`,
            line: pos.line + 1,
            column: pos.character + 1,
          });
        }
      }
    }

    if (ts.isNewExpression(node)) {
      if (ts.isIdentifier(node.expression) && node.expression.text === 'Function') {
        const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
        sinks.push({
          category: 'command-injection',
          functionName: 'new Function',
          line: pos.line + 1,
          column: pos.character + 1,
        });
      }
    }

    return 'continue';
  });

  return deduplicateSinks(sinks);
}

function getSinkCategory(name: string): SinkDefinition['category'] {
  const def = SINK_DEFINITIONS.find((d) => d.pattern === name);
  return def?.category ?? 'command-injection';
}

const ALWAYS_DANGEROUS_METHODS = new Set([
  'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
  'unlink', 'unlinkSync', 'readdir', 'createReadStream',
]);

function isDangerousMethod(
  methodName: string,
  receiver: ts.Expression,
  sourceFile: ts.SourceFile,
): boolean {
  if (ALWAYS_DANGEROUS_METHODS.has(methodName)) return true;

  const receivers = SINK_METHOD_RECEIVERS[methodName];
  if (!receivers) return false;

  const objText = receiver.getText(sourceFile).toLowerCase();
  for (const pattern of receivers) {
    if (objText.includes(pattern.toLowerCase())) return true;
  }

  const startsWithLower = objText.charAt(0);
  if (methodName === 'send' || methodName === 'json' || methodName === 'redirect' || methodName === 'set' || methodName === 'setHeader') {
    return startsWithLower === 'r' || objText.includes('res') || objText.includes('response');
  }

  return false;
}

function deduplicateSinks(sinks: TaintSinkInfo[]): TaintSinkInfo[] {
  const seen = new Set<string>();
  return sinks.filter((s) => {
    const key = `${s.functionName}\x00${s.line}:${s.column}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export { SINK_DEFINITIONS };