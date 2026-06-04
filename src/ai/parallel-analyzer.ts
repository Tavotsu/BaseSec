import type { Finding, ParsedFile, TaintGraph, RuleCategory, Severity, Confidence } from '../rules/types';
import type { LlmProvider } from './providers/types';
import { redactForLlm } from './privacy';
import { buildAnalysisPrompt, parseAnalysisResponse } from './prompt';
import { logger } from '../utils/logger';

export interface ParallelAnalyzerOptions {
  contextLevel: 'minimal' | 'context' | 'file';
  model?: string;
  timeout?: number;
}

export function detectSuspiciousFiles(
  parsedFiles: ParsedFile[],
  taintGraphs: Map<string, TaintGraph>,
  existingFindings: Finding[],
): ParsedFile[] {
  const filesWithFindings = new Set(existingFindings.map((f) => f.filePath));

  return parsedFiles.filter((file) => {
    if (filesWithFindings.has(file.filePath)) return false;
    const graph = taintGraphs.get(file.filePath);
    if (!graph) return false;
    return graph.flows.length > 0;
  });
}

export async function analyzeSuspiciousFiles(
  files: ParsedFile[],
  taintGraphs: Map<string, TaintGraph>,
  provider: LlmProvider,
  options: ParallelAnalyzerOptions,
): Promise<Finding[]> {
  const allFindings: Finding[] = [];

  for (const file of files) {
    let content: string;

    if (options.contextLevel === 'file') {
      content = file.content;
    } else if (options.contextLevel === 'context') {
      const lines = file.content.split('\n');
      content = lines.slice(0, 100).join('\n');
    } else {
      const graph = taintGraphs.get(file.filePath);
      content = graph?.flows.map((f) => f.source?.expression ?? '').join('\n') ?? file.content.substring(0, 500);
    }

    const redacted = redactForLlm(content);
    const prompt = buildAnalysisPrompt({ fileContent: redacted });

    try {
      const raw = await provider.call(prompt, {
        model: options.model,
        temperature: 0.1,
        timeout: options.timeout,
        jsonMode: true,
      });

      const responses = parseAnalysisResponse(raw);

      for (const item of responses) {
        const finding: Finding = {
          ruleId: 'AI-001',
          ruleName: 'AI-detected vulnerability',
          category: (item.category as RuleCategory) ?? 'misconfiguration',
          severity: item.severity as Severity,
          filePath: file.filePath,
          line: item.line,
          column: 1,
          endLine: item.line,
          endColumn: 1,
          message: item.message,
          codeSnippet: '',
          remediation: item.remediation,
          references: [],
          confidence: item.confidence as Confidence,
          aiGenerated: true,
        };
        allFindings.push(finding);
      }
    } catch (e) {
      logger.warn(`AI parallel analysis failed for ${file.filePath}`, e);
    }
  }

  return allFindings;
}
