import type { RuleCategory } from '../rules/types';

export interface TaintSourceInfo {
  kind: string;
  expression: string;
  line: number;
  column: number;
  variableName?: string;
}

export interface TaintSinkInfo {
  category: RuleCategory;
  functionName: string;
  line: number;
  column: number;
}

export interface TaintFlow {
  source: TaintSourceInfo;
  sink: TaintSinkInfo;
  path: string[];
  isSanitized: boolean;
  sanitizersApplied: string[];
}

export interface TaintInfo {
  sources: TaintSourceInfo[];
  isSanitized: boolean;
  sanitizers: string[];
}

export interface TaintGraph {
  filePath: string;
  taintMap: Map<string, TaintInfo>;
  sources: TaintSourceInfo[];
  sinks: TaintSinkInfo[];
  flows: TaintFlow[];
}

export interface SourceDefinition {
  pattern: string;
  framework: string;
}

export interface SinkDefinition {
  pattern: string;
  category: RuleCategory;
}

export interface SanitizerDefinition {
  pattern: string;
  category: RuleCategory | '*';
}