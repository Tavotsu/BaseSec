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
  | 'dependency-check'
  | 'deprecated';

export type Framework = 'express' | 'nestjs' | 'mongoose' | 'typeorm' | 'fastify' | 'koa' | 'prisma' | 'react' | 'nextjs' | 'vue' | 'angular' | 'svelte' | '*';

export type Confidence = 'high' | 'medium' | 'low';

export type FindingSource = 'static' | 'dynamic';

export type CorrelationKind = 'handler' | 'import-graph' | 'agent' | 'runtime-property';

export interface DastEvidence {
  /** Método y URL absoluta, ya redactada. Ej: "GET http://localhost:3000/". */
  request: string;
  /** Status + headers relevantes (+ primeros bytes del body si aplica), ya redactado. */
  response: string;
  /** Payload enviado; '' en reglas de inspección. */
  payload: string;
  oracle: 'reflection' | 'sql-error' | 'timing' | 'diff' | 'redirect' | 'header' | 'agent';
  correlation?: CorrelationKind;
  file?: string;
  sink?: { fn: string; filePath: string; line: number };
}

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
  aiEnhanced?: boolean;
  aiExplanation?: string;
  aiGenerated?: boolean;
  originalConfidence?: Confidence;
  /** Ausente = 'static'. Solo se marca explícitamente lo dinámico. */
  source?: FindingSource;
  /** true solo si un oráculo confirmó explotación real. */
  verified?: boolean;
  /** Presente cuando verified === true, o en hallazgos DAST-only. */
  evidence?: DastEvidence;
  /** Endpoint atacado ("GET /api/users/:id") o el origen ("http://localhost:3000") a nivel de target. */
  endpoint?: string;
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

export interface AiConfig {
  enabled: boolean;
  provider: 'openai' | 'ollama';
  model?: string;
  contextLevel: 'minimal' | 'context' | 'file';
  baseUrl?: string;
  maxFindings?: number;
  timeout?: number;
}

export interface DastConfig {
  target?: string;
  headers?: Record<string, string>;
  health?: string;
  allowRemote?: boolean;
  rps?: number;
  concurrency?: number;
  maxRequests?: number;
  timeout?: number;          // segundos, global
  requestTimeout?: number;   // ms
  evidence?: boolean;
  evidenceDir?: string;
  rules?: string[];
}

export interface basesecConfig {
  target: string[];
  ignore: string[];
  framework: 'auto' | 'express' | 'nestjs' | 'mongoose' | 'typeorm' | 'fastify' | 'koa' | 'prisma' | 'react' | 'nextjs' | 'vue' | 'angular' | 'svelte';
  severity: Severity;
  taintAnalysis: boolean;
  rules: string[];
  rulesConfig: Record<string, RuleConfigOverride | false>;
  sanitizers: string[];
  maxFileSize: number;
  maxFiles: number;
  cache?: {
    maxAge?: number;
    dir?: string;
  };
  workers?: {
    threshold?: number;
    max?: number;
  };
  output: {
    format: OutputFormat;
    filePath?: string;
  };
  ai?: AiConfig;
  dast?: DastConfig;
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
  framework: 'auto' | 'express' | 'nestjs' | 'mongoose' | 'typeorm' | 'fastify' | 'koa' | 'prisma' | 'react' | 'nextjs' | 'vue' | 'angular' | 'svelte';
  noColor: boolean;
  noBanner: boolean;
  rulesFilter?: string[];
  workers?: number;
  noCache?: boolean;
  noDeps?: boolean;
  maxFileSize?: number;
  maxFiles?: number;
  verbose?: boolean;
  readEnv?: boolean;
  ai?: boolean;
  aiProvider?: string;
  aiModel?: string;
  aiDryRun?: boolean;
  aiContext?: string;
}

export interface ScanResult {
  findings: Finding[];
  stats: ScanStats;
  duration: number;
}

export interface DastStats {
  /** Origen del target, sin credenciales (sin user:pass@). */
  target: string;
  mode: 'full' | 'no-source';
  routesSource: 'artifact' | 'scan' | 'routes-file' | 'none';
  routesStale: boolean;
  readOnly: boolean;
  agent: boolean;
  endpoints: { total: number; analyzed: number; skippedMutating: number; unresolved: number };
  requests: number;
  incomplete?: 'budget' | 'timeout';
  /** Ausente si no se escribió evidencia (--no-evidence o ningún hallazgo). */
  evidenceDir?: string;
}

export interface ScanStats {
  filesScanned: number;
  filesSkipped: number;
  rulesRun: number;
  frameworks: string[];
  dast?: DastStats;
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