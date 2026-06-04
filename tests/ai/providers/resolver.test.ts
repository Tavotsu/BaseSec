import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { resolveProvider } from '../../../src/ai/providers/resolver';
import type { AiConfig } from '../../../src/rules/types';

const baseConfig: AiConfig = {
  enabled: true,
  provider: 'ollama',
  contextLevel: 'minimal',
};

describe('resolveProvider', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env['OPENAI_API_KEY'];
  });

  it('resolves ollama when config.provider is ollama and it is running', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
    const provider = await resolveProvider(baseConfig);
    expect(provider.name).toBe('ollama');
  });

  it('throws when config.provider is ollama but ollama is not running', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));
    await expect(resolveProvider(baseConfig)).rejects.toThrow('Ollama is not running');
  });

  it('resolves openai when config.provider is openai and API key set', async () => {
    process.env['OPENAI_API_KEY'] = 'test-key';
    const provider = await resolveProvider({ ...baseConfig, provider: 'openai' });
    expect(provider.name).toBe('openai');
  });

  it('auto-detects ollama when no provider set and ollama running', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
    const config = { ...baseConfig, provider: undefined as any };
    const provider = await resolveProvider(config);
    expect(provider.name).toBe('ollama');
  });

  it('auto-detects openai when ollama not running and OPENAI_API_KEY set', async () => {
    process.env['OPENAI_API_KEY'] = 'test-key';
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));
    const config = { ...baseConfig, provider: undefined as any };
    const provider = await resolveProvider(config);
    expect(provider.name).toBe('openai');
  });

  it('throws when no provider available', async () => {
    delete process.env['OPENAI_API_KEY'];
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));
    const config = { ...baseConfig, provider: undefined as any };
    await expect(resolveProvider(config)).rejects.toThrow('No AI provider available');
  });
});
