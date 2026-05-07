import * as ts from 'typescript';
import type { TaintGraph, TaintFlow, TaintSourceInfo, TaintSinkInfo } from './types';
import { findSources } from './source';
import { findSinks } from './sink';
import { TaintPropagation } from './propagation';
import { isExpressionTainted as isTainted, isExpressionSanitized as isSanitized } from './integration';
import type { ParsedFile } from '../rules/types';

export { isTainted as isExpressionTainted, isSanitized as isExpressionSanitized };

export function analyzeFile(
  parsedFile: ParsedFile,
  frameworks: string[],
  customSanitizers: string[],
): TaintGraph {
  const { sourceFile, filePath, content } = parsedFile;

  const sources = findSources(sourceFile, content, frameworks);
  const sinks = findSinks(sourceFile);

  const propagation = new TaintPropagation(sourceFile, content, customSanitizers);
  const taintMap = propagation.analyze();

  const flows = buildFlows(sources, sinks, taintMap, content, sourceFile);

  return {
    filePath,
    taintMap,
    sources,
    sinks,
    flows,
  };
}

function buildFlows(
  sources: TaintSourceInfo[],
  sinks: TaintSinkInfo[],
  taintMap: Map<string, import('./types').TaintInfo>,
  content: string,
  sourceFile: ts.SourceFile,
): TaintFlow[] {
  const flows: TaintFlow[] = [];

  for (const sink of sinks) {
    const sinkLine = sink.line;
    const lines = content.split('\n');
    if (sinkLine < 1 || sinkLine > lines.length) continue;

    const sinkLineText = lines[sinkLine - 1];

    for (const [varName, info] of taintMap) {
      if (info.isSanitized) continue;

      if (lineContainsVar(sinkLineText, varName)) {
        for (const src of info.sources) {
          flows.push({
            source: src,
            sink,
            path: [src.expression, varName, sink.functionName],
            isSanitized: info.isSanitized,
            sanitizersApplied: info.sanitizers,
          });
        }
      }
    }

    for (const source of sources) {
      if (lineContainsTaintSource(sinkLineText, source.expression)) {
        if (sink.line !== source.line) {
          flows.push({
            source,
            sink,
            path: [source.expression, sink.functionName],
            isSanitized: false,
            sanitizersApplied: [],
          });
        }
      }
    }
  }

  return deduplicateFlows(flows);
}

function lineContainsVar(line: string, varName: string): boolean {
  const patterns = [
    new RegExp(`\\b${escapeRegex(varName)}\\b`),
  ];
  return patterns.some((p) => p.test(line));
}

function lineContainsTaintSource(line: string, sourceExpr: string): boolean {
  return line.includes(sourceExpr);
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function deduplicateFlows(flows: TaintFlow[]): TaintFlow[] {
  const seen = new Set<string>();
  return flows.filter((f) => {
    const key = `${f.source.expression}\x00${f.sink.functionName}\x00${f.sink.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function getTaintSourcesForExpression(
  graph: TaintGraph,
  expression: string,
): TaintSourceInfo[] {
  const result: TaintSourceInfo[] = [];

  for (const src of graph.sources) {
    if (expression === src.expression || expression.startsWith(src.kind + '.')) {
      result.push(src);
    }
  }

  for (const [varName, info] of graph.taintMap) {
    if (expression === varName || expression.startsWith(varName + '.') || expression.startsWith(varName + '[')) {
      result.push(...info.sources);
    }
  }

  return result;
}