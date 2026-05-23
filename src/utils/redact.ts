export function redactSecret(snippet: string, secretValue: string): string {
  if (!secretValue || secretValue.length < 3) return snippet;
  // Keep first 4 characters or 20% of the string, whichever is larger, but no more than 6
  const visibleLength = Math.min(6, Math.max(4, Math.floor(secretValue.length * 0.2)));
  const redactedValue = secretValue.substring(0, visibleLength) + '**************';
  // Replace the secret value in the snippet
  return snippet.replace(secretValue, redactedValue);
}