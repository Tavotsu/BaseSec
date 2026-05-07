export { Pipeline } from './core/pipeline';
export { FileCollector } from './core/file-collector';
export { Parser } from './core/parser';
export { Analyzer } from './core/analyzer';
export { ResultStore } from './core/result-store';
export { detectFrameworks } from './framework/detector';
export { analyzeFile, isExpressionTainted } from './taint/engine';

export type { Rule, Finding, RuleContext, basesecConfig, TaintGraph } from './rules/types';
export type { TaintSourceInfo, TaintSinkInfo, TaintFlow, TaintInfo } from './taint/types';
export type { DetectedFramework } from './framework/detector';
export { ALL_RULES } from './rules/index';
export { defineConfig } from './config/schema';
export { loadConfig } from './config/loader';
export { mergeConfigWithDefaults } from './config/defaults';

export { main } from './cli/index';