import type { Finding, Severity } from '../rules/types';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function severityRank(s: string): number {
  const idx = SEVERITY_ORDER.indexOf(s as Severity);
  return idx === -1 ? 99 : idx;
}

function isDuplicate(aiF: Finding, staticF: Finding): boolean {
  if (aiF.filePath !== staticF.filePath) return false;
  if (Math.abs(aiF.line - staticF.line) > 3) return false;
  if (aiF.category !== staticF.category) return false;
  return true;
}

export function mergeFindings(
  staticFindings: Finding[],
  aiFindings: Finding[],
): Finding[] {
  const unique = aiFindings.filter(
    (aiF) => !staticFindings.some((staticF) => isDuplicate(aiF, staticF)),
  );

  const merged = [...staticFindings, ...unique];
  return merged.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}
