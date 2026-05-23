import type { basesecConfig, Severity, OutputFormat, RuleConfigOverride } from '../rules/types';

export interface basesecConfigSchema {
  target?: string[];
  ignore?: string[];
  framework?: 'auto' | 'express' | 'nestjs' | 'mongoose' | 'typeorm';
  severity?: Severity;
  taintAnalysis?: boolean;
  rules?: string[];
  rulesConfig?: Record<string, RuleConfigOverride | false>;
  sanitizers?: string[];
  maxFileSize?: number;
  maxFiles?: number;
  cache?: {
    maxAge?: number;
    dir?: string;
  };
  workers?: {
    threshold?: number;
    max?: number;
  };
  output?: {
    format?: OutputFormat;
    filePath?: string;
  };
}

export function defineConfig(config: basesecConfigSchema): basesecConfigSchema {
  return config;
}