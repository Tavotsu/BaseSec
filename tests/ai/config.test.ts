import { describe, it, expect } from 'vitest';
import { validateAiConfig, resolveAiOptions } from '../../src/ai/config';
import type { AiConfig } from '../../src/rules/types';

const baseConfig: AiConfig = {
  enabled: true,
  provider: 'ollama',
  contextLevel: 'minimal',
  maxFindings: 50,
  timeout: 30000,
};

describe('validateAiConfig', () => {
  it('valid when neither flag nor config set', () => {
    const result = validateAiConfig(undefined, {});
    expect(result.valid).toBe(true);
  });

  it('error when --ai flag set but config.ai.enabled is false', () => {
    const result = validateAiConfig({ ...baseConfig, enabled: false }, { ai: true });
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('ai.enabled');
  });

  it('error when --ai flag set but no ai config at all', () => {
    const result = validateAiConfig(undefined, { ai: true });
    expect(result.valid).toBe(false);
  });

  it('valid with ollama double opt-in', () => {
    const result = validateAiConfig(baseConfig, { ai: true });
    expect(result.valid).toBe(true);
  });

  it('error when openai provider but no API key', () => {
    delete process.env['OPENAI_API_KEY'];
    const result = validateAiConfig({ ...baseConfig, provider: 'openai' }, { ai: true });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('OPENAI_API_KEY'))).toBe(true);
  });

  it('error when maxFindings is 0', () => {
    const result = validateAiConfig({ ...baseConfig, maxFindings: 0 }, { ai: true });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('maxFindings'))).toBe(true);
  });

  it('error on invalid contextLevel override', () => {
    const result = validateAiConfig(baseConfig, { ai: true, aiContext: 'full' as any });
    expect(result.valid).toBe(false);
  });
});

describe('resolveAiOptions', () => {
  it('returns null when ai flag not set', () => {
    expect(resolveAiOptions(baseConfig, {})).toBeNull();
  });

  it('returns null when config.ai.enabled is false', () => {
    expect(resolveAiOptions({ ...baseConfig, enabled: false }, { ai: true })).toBeNull();
  });

  it('resolves defaults correctly', () => {
    const opts = resolveAiOptions(baseConfig, { ai: true });
    expect(opts).not.toBeNull();
    expect(opts!.provider).toBe('ollama');
    expect(opts!.contextLevel).toBe('minimal');
    expect(opts!.maxFindings).toBe(50);
    expect(opts!.dryRun).toBe(false);
  });

  it('CLI overrides take precedence', () => {
    const opts = resolveAiOptions(baseConfig, {
      ai: true,
      aiProvider: 'openai',
      aiModel: 'gpt-4',
      aiContext: 'file',
      aiDryRun: true,
    });
    expect(opts!.provider).toBe('openai');
    expect(opts!.model).toBe('gpt-4');
    expect(opts!.contextLevel).toBe('file');
    expect(opts!.dryRun).toBe(true);
  });
});
