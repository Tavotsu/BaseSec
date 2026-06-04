export interface LlmCallOptions {
  model?: string;
  temperature?: number;
  maxTokens?: number;
  timeout?: number;
  jsonMode?: boolean;
}

export interface LlmProvider {
  name: string;
  call(prompt: string, options?: LlmCallOptions): Promise<string>;
  validateConnection(): Promise<boolean>;
}
