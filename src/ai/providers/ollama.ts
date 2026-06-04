import type { LlmProvider, LlmCallOptions } from './types';
import { logger } from '../../utils/logger';

const DEFAULT_MODEL = 'llama3.2';
const DEFAULT_BASE_URL = 'http://localhost:11434';

export class OllamaProvider implements LlmProvider {
  readonly name = 'ollama';
  private baseUrl: string;

  constructor(baseUrl?: string) {
    const raw = (process.env['OLLAMA_HOST'] ?? baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '');
    const parsed = new URL(raw);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`Ollama baseUrl must use http or https protocol (got: ${parsed.protocol})`);
    }
    const isExplicit = !!(process.env['OLLAMA_HOST'] ?? baseUrl);
    const isLocal = ['localhost', '127.0.0.1', '[::1]', '::1'].includes(parsed.hostname);
    if (!isLocal && !isExplicit) {
      throw new Error(`Ollama baseUrl "${raw}" is not a local address. Set OLLAMA_HOST or ai.baseUrl explicitly to allow remote hosts.`);
    }
    this.baseUrl = raw;
  }

  async call(prompt: string, options: LlmCallOptions = {}): Promise<string> {
    const model = options.model ?? DEFAULT_MODEL;
    const controller = new AbortController();
    const timeoutMs = options.timeout ?? 30000;
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(`${this.baseUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          model,
          stream: false,
          options: {
            temperature: options.temperature ?? 0.1,
            ...(options.maxTokens != null ? { num_predict: options.maxTokens } : {}),
          },
          messages: [{ role: 'user', content: prompt }],
        }),
      });

      if (!response.ok) {
        throw new Error(`Ollama HTTP ${response.status}: ${await response.text()}`);
      }

      const data = await response.json() as { message?: { content?: string } };
      return data.message?.content ?? '';
    } catch (e) {
      if ((e as Error).name === 'AbortError') {
        throw new Error(`Ollama request timed out after ${timeoutMs}ms`);
      }
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  async validateConnection(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/api/tags`, {
        signal: AbortSignal.timeout(5000),
      });
      return response.ok;
    } catch (e) {
      logger.warn('Ollama connection check failed', e);
      return false;
    }
  }
}
