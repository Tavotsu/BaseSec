export function redactSecret(snippet: string, secretValue: string): string {
  if (!secretValue || secretValue.length < 3) return snippet;
  const maxVisible = Math.floor(secretValue.length / 2);
  const visibleLength = Math.min(6, Math.max(2, Math.min(maxVisible, Math.floor(secretValue.length * 0.2))));
  const redactedValue = secretValue.substring(0, visibleLength) + '**************';
  return snippet.replaceAll(secretValue, redactedValue);
}