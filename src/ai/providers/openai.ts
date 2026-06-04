import type { LlmProvider, LlmCallOptions } from './types';
import { logger } from '../../utils/logger';

const DEFAULT_MODEL = 'gpt-4o-mini';
const BASE_URL = 'https://api.openai.com/v1/chat/completions';

export class OpenAIProvider implements LlmProvider {
  readonly name = 'openai';
  private apiKey: string;

  constructor() {
    const key = process.env['OPENAI_API_KEY'];
    if (!key) {
      throw new Error('OPENAI_API_KEY environment variable is not set');
    }
    this.apiKey = key;
  }

  async call(prompt: string, options: LlmCallOptions = {}): Promise<string> {
    const model = options.model ?? DEFAULT_MODEL;
    const controller = new AbortController();
    const timeoutMs = options.timeout ?? 30000;
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const body: Record<string, unknown> = {
        model,
        temperature: options.temperature ?? 0.1,
        messages: [{ role: 'user', content: prompt }],
        ...(options.maxTokens != null ? { max_tokens: options.maxTokens } : {}),
        ...(options.jsonMode ? { response_format: { type: 'json_object' } } : {}),
      };

      const response = await fetch(BASE_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
        },
        signal: controller.signal,
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OpenAI HTTP ${response.status}: ${errorText}`);
      }

      const data = await response.json() as {
        choices?: { message?: { content?: string } }[];
      };
      return data.choices?.[0]?.message?.content ?? '';
    } catch (e) {
      if ((e as Error).name === 'AbortError') {
        throw new Error(`OpenAI request timed out after ${timeoutMs}ms`);
      }
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  async validateConnection(): Promise<boolean> {
    try {
      const response = await fetch('https://api.openai.com/v1/models', {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${this.apiKey}` },
        signal: AbortSignal.timeout(5000),
      });
      return response.ok;
    } catch (e) {
      logger.warn('OpenAI connection check failed', e);
      return false;
    }
  }
}
