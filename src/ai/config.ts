import type { AiConfig, CliOptions } from '../rules/types';

export interface ResolvedAiOptions {
  enabled: boolean;
  provider: 'openai' | 'ollama';
  model?: string;
  contextLevel: 'minimal' | 'context' | 'file';
  baseUrl?: string;
  maxFindings: number;
  timeout: number;
  dryRun: boolean;
}

export interface AiValidationResult {
  valid: boolean;
  errors: string[];
}

const VALID_CONTEXT_LEVELS = ['minimal', 'context', 'file'] as const;

export function validateAiConfig(
  config: AiConfig | undefined,
  cliOptions: Partial<CliOptions>,
): AiValidationResult {
  const errors: string[] = [];

  const hasFlag = cliOptions.ai === true;
  const hasConfig = config?.enabled === true;

  if (hasFlag && !hasConfig) {
    errors.push(
      'AI flag detected but ai.enabled is not set in your config. ' +
      "Run 'basesec init' or add ai.enabled: true to your config file."
    );
    return { valid: false, errors };
  }

  if (!hasFlag || !hasConfig) {
    return { valid: true, errors };
  }

  if (!config) {
    errors.push('ai config block is required when ai.enabled is true');
    return { valid: false, errors };
  }

  if (!['openai', 'ollama'].includes(config.provider)) {
    errors.push(`Invalid ai.provider: "${config.provider}". Must be "openai" or "ollama".`);
  }

  if (config.provider === 'openai' && !process.env['OPENAI_API_KEY']) {
    errors.push('OPENAI_API_KEY environment variable is not set (required for OpenAI provider)');
  }

  const ctxLevel = cliOptions.aiContext ?? config.contextLevel;
  if (!VALID_CONTEXT_LEVELS.includes(ctxLevel as 'minimal' | 'context' | 'file')) {
    errors.push(`Invalid contextLevel: "${ctxLevel}". Must be one of: ${VALID_CONTEXT_LEVELS.join(', ')}`);
  }

  const maxFindings = config.maxFindings ?? 50;
  if (maxFindings <= 0) {
    errors.push(`ai.maxFindings must be greater than 0 (got: ${maxFindings})`);
  }

  return { valid: errors.length === 0, errors };
}

export function resolveAiOptions(
  config: AiConfig | undefined,
  cliOptions: Partial<CliOptions>,
): ResolvedAiOptions | null {
  if (!cliOptions.ai || !config?.enabled) return null;

  const provider = (cliOptions.aiProvider as 'openai' | 'ollama' | undefined) ?? config.provider;
  const model = cliOptions.aiModel ?? config.model;
  const contextLevel = (cliOptions.aiContext as 'minimal' | 'context' | 'file' | undefined) ?? config.contextLevel;

  return {
    enabled: true,
    provider,
    model,
    contextLevel,
    baseUrl: config.baseUrl,
    maxFindings: config.maxFindings ?? 50,
    timeout: config.timeout ?? 30000,
    dryRun: cliOptions.aiDryRun === true,
  };
}
