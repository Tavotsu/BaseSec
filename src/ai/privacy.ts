import type { Finding } from '../rules/types';
import { redactSecret } from '../utils/redact';

const SECRET_PATTERN = /(['"`]?)([A-Za-z0-9+/]{20,})(['"`]?)/g;
const FILE_PATH_PATTERN = /(?:\/[\w.\-]+){2,}/g;

export function redactForLlm(code: string): string {
  let result = code.replace(FILE_PATH_PATTERN, '[REDACTED_PATH]');
  result = result.replace(SECRET_PATTERN, (match, q1, secret, q2) => {
    if (secret.length >= 20) {
      return `${q1}${redactSecret(secret, secret)}${q2}`;
    }
    return match;
  });
  return result;
}

export function prepareContext(
  finding: Finding,
  fileContent: string,
  contextLevel: 'minimal' | 'context' | 'file',
): string {
  let raw: string;

  if (contextLevel === 'minimal') {
    raw = finding.codeSnippet;
  } else if (contextLevel === 'file') {
    raw = fileContent;
  } else {
    const lines = fileContent.split('\n');
    const targetLine = Math.max(0, finding.line - 1);
    const start = Math.max(0, targetLine - 10);
    const end = Math.min(lines.length - 1, targetLine + 10);
    raw = lines.slice(start, end + 1).join('\n');
  }

  return redactForLlm(raw);
}

export function formatDryRun(
  findings: Finding[],
  contextLevel: 'minimal' | 'context' | 'file',
): string {
  const lines: string[] = [];
  lines.push('  [DRY RUN] The following data would be sent to the LLM provider:');
  lines.push('');

  for (const f of findings) {
    lines.push(`  Finding: ${f.ruleId} @ ${f.filePath}:${f.line}`);
    const rawContext = contextLevel === 'minimal'
      ? f.codeSnippet
      : `[${contextLevel} context — full file content read at scan time]`;
    const redacted = redactForLlm(rawContext);
    lines.push(`  Context (${contextLevel}):`);
    lines.push(`  ${redacted.substring(0, 200)}${redacted.length > 200 ? '...' : ''}`);
    lines.push('');
  }

  return lines.join('\n');
}
