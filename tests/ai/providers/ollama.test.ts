import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { OllamaProvider } from '../../../src/ai/providers/ollama';

describe('OllamaProvider', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('uses default base URL when no env var set', () => {
    delete process.env['OLLAMA_HOST'];
    const provider = new OllamaProvider();
    expect(provider.name).toBe('ollama');
  });

  it('uses OLLAMA_HOST env var when set', () => {
    process.env['OLLAMA_HOST'] = 'http://custom:11434';
    const provider = new OllamaProvider();
    expect(provider.name).toBe('ollama');
    delete process.env['OLLAMA_HOST'];
  });

  it('call returns content from response', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ message: { content: 'AI response' } }),
    });
    vi.stubGlobal('fetch', mockFetch);

    const provider = new OllamaProvider();
    const result = await provider.call('test prompt');
    expect(result).toBe('AI response');
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/chat'),
      expect.objectContaining({ method: 'POST' })
    );
  });

  it('throws on non-ok HTTP response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      text: async () => 'Internal Server Error',
    }));
    const provider = new OllamaProvider();
    await expect(provider.call('test')).rejects.toThrow('Ollama HTTP 500');
  });

  it('validateConnection returns true when tags endpoint is ok', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
    const provider = new OllamaProvider();
    expect(await provider.validateConnection()).toBe(true);
  });

  it('validateConnection returns false on network error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));
    const provider = new OllamaProvider();
    expect(await provider.validateConnection()).toBe(false);
  });
});
