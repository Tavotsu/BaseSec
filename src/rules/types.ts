export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type RuleCategory =
  | 'sql-injection'
  | 'nosql-injection'
  | 'xss'
  | 'command-injection'
  | 'path-traversal'
  | 'auth'
  | 'secrets'
  | 'error-handling'
  | 'misconfiguration'
  | 'deprecated';

export type Framework = 'express' | 'nestjs' | 'mongoose' | 'typeorm' | '*';

export type Confidence = 'high' | 'medium' | 'low';

export interface Finding {
  ruleId: string;
  ruleName: string;
  category: RuleCategory;
  severity: Severity;
  filePath: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  message: string;
  codeSnippet: string;
  remediation: string;
  references: string[];
  confidence: Confidence;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  category: RuleCategory;
  severity: Severity;
  frameworks: Framework[];
  tags: string[];
  detect(ctx: RuleContext): Finding[];
}

export interface TaintGraph {
  filePath: string;
  taintMap: Map<string, import('../taint/types').TaintInfo>;
  sources: import('../taint/types').TaintSourceInfo[];
  sinks: import('../taint/types').TaintSinkInfo[];
  flows: import('../taint/types').TaintFlow[];
}

export interface RuleContext {
  sourceFile: import('typescript').SourceFile;
  filePath: string;
  content: string;
  config: basesecConfig;
  taintGraph?: TaintGraph;
}

export type OutputFormat = 'terminal' | 'json' | 'sarif' | 'html' | 'markdown';

export type RuleConfigOverride = {
  severity?: Severity;
  ignorePaths?: string[];
  confidence?: Confidence;
};

export interface basesecConfig {
  target: string[];
  ignore: string[];
  framework: 'auto' | 'express' | 'nestjs' | 'mongoose' | 'typeorm';
  severity: Severity;
  taintAnalysis: boolean;
  rules: string[];
  rulesConfig: Record<string, RuleConfigOverride | false>;
  sanitizers: string[];
  output: {
    format: OutputFormat;
    filePath?: string;
  };
}

export interface CliOptions {
  format: OutputFormat;
  output?: string;
  severity: Severity;
  rules?: string;
  ignore: string[];
  config?: string;
  noTaint: boolean;
  quiet: boolean;
  strict: boolean;
  framework: 'auto' | 'express' | 'nestjs' | 'mongoose' | 'typeorm';
  noColor: boolean;
  noBanner: boolean;
  rulesFilter?: string[];
  workers?: number;
  noCache?: boolean;
}

export interface ScanResult {
  findings: Finding[];
  stats: ScanStats;
  duration: number;
}

export interface ScanStats {
  filesScanned: number;
  filesSkipped: number;
  rulesRun: number;
  frameworks: string[];
}

export interface ParsedFile {
  filePath: string;
  sourceFile: import('typescript').SourceFile;
  content: string;
  size: number;
}

export type ParseError = {
  filePath: string;
  error: string;
};