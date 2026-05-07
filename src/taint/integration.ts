import type { TaintGraph, Confidence } from '../rules/types';

function matchesExpression(expression: string, target: string): boolean {
  if (!target || !expression) return false;
  if (expression === target) return true;
  if (expression.startsWith(target + '.')) return true;
  if (expression.startsWith(target + '[')) return true;
  return false;
}

export function resolveConfidence(
  graph: TaintGraph | undefined,
  expression: string,
  defaultConfidence: Confidence,
): Confidence {
  if (!graph) return defaultConfidence;
  if (!expression) return defaultConfidence;

  if (isExpressionSanitized(graph, expression)) {
    return 'low';
  }

  if (isExpressionTainted(graph, expression)) {
    return 'high';
  }

  return 'medium';
}

export function isExpressionTainted(
  graph: TaintGraph | undefined,
  expression: string,
): boolean {
  if (!graph) return false;
  if (!expression) return false;

  for (const src of graph.sources) {
    if (expression === src.expression || expression.startsWith(src.kind + '.')) {
      return true;
    }
  }

  for (const flow of graph.flows) {
    if (flow.isSanitized) continue;
    if (matchesExpression(expression, flow.source.expression)) {
      return true;
    }
  }

  for (const [varName, info] of graph.taintMap) {
    if (info.isSanitized) continue;
    if (matchesExpression(expression, varName)) {
      return true;
    }
  }

  return false;
}

export function isExpressionSanitized(
  graph: TaintGraph | undefined,
  expression: string,
): boolean {
  if (!graph) return false;
  if (!expression) return false;

  const hasUnsanitizedFlow = graph.flows.some(
    (flow) => !flow.isSanitized && matchesExpression(expression, flow.source.expression),
  );
  if (hasUnsanitizedFlow) return false;

  for (const [varName, info] of graph.taintMap) {
    if (!info.isSanitized) continue;
    if (matchesExpression(expression, varName)) {
      return true;
    }
  }

  return false;
}

export function shouldSuppressWithTaint(
  graph: TaintGraph | undefined,
  expression: string,
): boolean {
  if (!graph) return false;
  return isExpressionSanitized(graph, expression);
}