import type { secbaseConfig, Severity, OutputFormat, RuleConfigOverride } from '../rules/types';

export interface SecbaseConfigSchema {
  target?: string[];
  ignore?: string[];
  framework?: 'auto' | 'express' | 'nestjs';
  severity?: Severity;
  taintAnalysis?: boolean;
  rules?: string[];
  rulesConfig?: Record<string, RuleConfigOverride | false>;
  sanitizers?: string[];
  output?: {
    format?: OutputFormat;
    filePath?: string;
  };
}

export function defineConfig(config: SecbaseConfigSchema): SecbaseConfigSchema {
  return config;
}