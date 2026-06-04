import type { basesecConfig, Severity, OutputFormat, RuleConfigOverride, AiConfig } from '../rules/types';

export interface basesecConfigSchema {
  target?: string[];
  ignore?: string[];
  framework?: 'auto' | 'express' | 'nestjs' | 'mongoose' | 'typeorm' | 'fastify' | 'koa' | 'prisma';
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
  ai?: {
    enabled?: boolean;
    provider?: 'openai' | 'ollama';
    model?: string;
    contextLevel?: 'minimal' | 'context' | 'file';
    baseUrl?: string;
    maxFindings?: number;
    timeout?: number;
  };
}

export function defineConfig(config: basesecConfigSchema): basesecConfigSchema {
  return config;
}