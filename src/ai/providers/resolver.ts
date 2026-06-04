import type { LlmProvider } from './types';
import type { AiConfig } from '../../rules/types';
import { OllamaProvider } from './ollama';
import { OpenAIProvider } from './openai';

export async function resolveProvider(config: AiConfig): Promise<LlmProvider> {
  if (config.provider === 'ollama') {
    const provider = new OllamaProvider(config.baseUrl);
    const alive = await provider.validateConnection();
    if (!alive) {
      throw new Error(
        'Ollama is not running or unreachable. Start Ollama with: ollama serve'
      );
    }
    return provider;
  }

  if (config.provider === 'openai') {
    const provider = new OpenAIProvider();
    return provider;
  }

  const ollama = new OllamaProvider(config.baseUrl);
  const ollamaAlive = await ollama.validateConnection();
  if (ollamaAlive) {
    return ollama;
  }

  if (process.env['OPENAI_API_KEY']) {
    return new OpenAIProvider();
  }

  throw new Error(
    'No AI provider available. Either start Ollama (ollama serve) or set OPENAI_API_KEY. ' +
    'You can also specify a provider in your config: ai.provider: "ollama" | "openai"'
  );
}
