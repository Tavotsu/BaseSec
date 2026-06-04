import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { OpenAIProvider } from '../../../src/ai/providers/openai';

describe('OpenAIProvider', () => {
  beforeEach(() => {
    process.env['OPENAI_API_KEY'] = 'test-key-1234567890';
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    delete process.env['OPENAI_API_KEY'];
    vi.unstubAllGlobals();
  });

  it('throws on construction when no API key', () => {
    delete process.env['OPENAI_API_KEY'];
    expect(() => new OpenAIProvider()).toThrow('OPENAI_API_KEY');
  });

  it('call returns content from choices', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ choices: [{ message: { content: 'AI result' } }] }),
    }));
    const provider = new OpenAIProvider();
    const result = await provider.call('test prompt');
    expect(result).toBe('AI result');
  });

  it('includes Authorization header with API key', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ choices: [{ message: { content: '' } }] }),
    });
    vi.stubGlobal('fetch', mockFetch);
    const provider = new OpenAIProvider();
    await provider.call('test');
    const callArgs = mockFetch.mock.calls[0][1] as RequestInit;
    expect((callArgs.headers as Record<string, string>)['Authorization']).toContain('test-key-1234567890');
  });

  it('sends json_object format when jsonMode is true', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ choices: [{ message: { content: '{}' } }] }),
    });
    vi.stubGlobal('fetch', mockFetch);
    const provider = new OpenAIProvider();
    await provider.call('test', { jsonMode: true });
    const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
    expect(body.response_format.type).toBe('json_object');
  });

  it('throws on non-ok HTTP response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => 'Unauthorized',
    }));
    const provider = new OpenAIProvider();
    await expect(provider.call('test')).rejects.toThrow('OpenAI HTTP 401');
  });

  it('validateConnection returns true on ok response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
    const provider = new OpenAIProvider();
    expect(await provider.validateConnection()).toBe(true);
  });

  it('validateConnection returns false on network error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network error')));
    const provider = new OpenAIProvider();
    expect(await provider.validateConnection()).toBe(false);
  });
});
