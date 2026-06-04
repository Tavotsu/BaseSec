import type { Finding } from '../rules/types';
import type { LlmProvider } from './providers/types';
import { prepareContext } from './privacy';
import { buildEnrichmentPrompt, parseEnrichmentResponse } from './prompt';
import { logger } from '../utils/logger';

export interface EnricherOptions {
  contextLevel: 'minimal' | 'context' | 'file';
  maxFindings?: number;
  model?: string;
  timeout?: number;
  fileContents?: Map<string, string>;
}

export async function enrichFindings(
  findings: Finding[],
  provider: LlmProvider,
  options: EnricherOptions,
): Promise<Finding[]> {
  const limit = options.maxFindings ?? 50;
  const toEnrich = findings.slice(0, limit);
  const rest = findings.slice(limit);

  const enriched: Finding[] = [];

  for (const finding of toEnrich) {
    const fileContent = options.fileContents?.get(finding.filePath) ?? finding.codeSnippet;
    const redacted = prepareContext(finding, fileContent, options.contextLevel);

    const prompt = buildEnrichmentPrompt({
      ruleId: finding.ruleId,
      ruleName: finding.ruleName,
      severity: finding.severity,
      category: finding.category,
      codeSnippet: redacted,
      message: finding.message,
    });

    try {
      const raw = await provider.call(prompt, {
        model: options.model,
        temperature: 0.1,
        timeout: options.timeout,
        jsonMode: true,
      });

      const parsed = parseEnrichmentResponse(raw);

      if (!parsed) {
        enriched.push(finding);
        continue;
      }

      const enrichedFinding: Finding = {
        ...finding,
        aiEnhanced: true,
        aiExplanation: parsed.explanation,
        originalConfidence: finding.confidence,
      };

      if (!parsed.isValid) {
        enrichedFinding.confidence = 'low';
      } else {
        enrichedFinding.confidence = parsed.confidence;
        if (parsed.remediation) {
          enrichedFinding.remediation = parsed.remediation;
        }
      }

      enriched.push(enrichedFinding);
    } catch (e) {
      logger.warn(`AI enrichment failed for ${finding.ruleId} @ ${finding.filePath}:${finding.line}`, e);
      enriched.push(finding);
    }
  }

  return [...enriched, ...rest];
}
