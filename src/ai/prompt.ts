import type { Finding } from '../rules/types';

export interface EnrichmentPromptData {
  ruleId: string;
  ruleName: string;
  severity: string;
  category: string;
  codeSnippet: string;
  message: string;
}

export interface AnalysisPromptData {
  fileContent: string;
}

export function buildEnrichmentPrompt(data: EnrichmentPromptData): string {
  return `You are a security code reviewer. Analyze this potential vulnerability.

Rule: ${data.ruleId} - ${data.ruleName}
Severity: ${data.severity}
Category: ${data.category}
Code:
${data.codeSnippet}

Assessment: ${data.message}

Respond in JSON only:
{
  "isValid": boolean,
  "confidence": "high" | "medium" | "low",
  "explanation": "why this is/isn't a real vulnerability",
  "remediation": "specific fix for this code"
}`;
}

export function buildAnalysisPrompt(data: AnalysisPromptData): string {
  return `You are a security auditor for Node.js backends.
Analyze this code for security vulnerabilities not covered by standard SAST rules.

Focus on: logic flaws, race conditions, insecure defaults, business logic vulnerabilities.

Code:
${data.fileContent}

Respond in JSON only. Return an array of findings:
[{
  "line": number,
  "severity": "critical" | "high" | "medium" | "low",
  "category": "string",
  "message": "description of the vulnerability",
  "remediation": "how to fix it",
  "confidence": "high" | "medium" | "low"
}]

If no vulnerabilities found, return an empty array: []`;
}

export interface EnrichmentResponse {
  isValid: boolean;
  confidence: 'high' | 'medium' | 'low';
  explanation: string;
  remediation: string;
}

export interface AnalysisFindingResponse {
  line: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  message: string;
  remediation: string;
  confidence: 'high' | 'medium' | 'low';
}

export function parseEnrichmentResponse(raw: string): EnrichmentResponse | null {
  try {
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;
    const parsed = JSON.parse(jsonMatch[0]) as Partial<EnrichmentResponse>;
    if (typeof parsed.isValid !== 'boolean') return null;
    return {
      isValid: parsed.isValid,
      confidence: (['high', 'medium', 'low'] as const).includes(parsed.confidence as 'high' | 'medium' | 'low')
        ? (parsed.confidence as 'high' | 'medium' | 'low')
        : 'medium',
      explanation: parsed.explanation ?? '',
      remediation: parsed.remediation ?? '',
    };
  } catch {
    return null;
  }
}

export function parseAnalysisResponse(raw: string): AnalysisFindingResponse[] {
  try {
    const jsonMatch = raw.match(/\[[\s\S]*\]/);
    if (!jsonMatch) return [];
    const parsed = JSON.parse(jsonMatch[0]);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is AnalysisFindingResponse =>
      typeof item === 'object' &&
      item !== null &&
      typeof item.line === 'number' &&
      typeof item.message === 'string'
    );
  } catch {
    return [];
  }
}
