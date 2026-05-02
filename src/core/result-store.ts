import type { Finding } from '../rules/types';

interface FindingKey {
  ruleId: string;
  filePath: string;
  line: number;
  snippetNormalized: string;
}

function normalizeSnippet(snippet: string): string {
  return snippet.replace(/\s+/g, ' ').trim();
}

export class ResultStore {
  private findings: Finding[] = [];
  private seen: Set<string> = new Set();

  add(finding: Finding): boolean {
    const key = this.getKey(finding);
    if (this.seen.has(key)) {
      return false;
    }
    this.seen.add(key);
    this.findings.push(finding);
    return true;
  }

  addMany(findings: Finding[]): number {
    let added = 0;
    for (const f of findings) {
      if (this.add(f)) added++;
    }
    return added;
  }

  getFindings(): Finding[] {
    return [...this.findings];
  }

  getFindingsByCategory(): Map<string, Finding[]> {
    const map = new Map<string, Finding[]>();
    for (const f of this.findings) {
      const list = map.get(f.category) ?? [];
      list.push(f);
      map.set(f.category, list);
    }
    return map;
  }

  getFindingsBySeverity(): Map<string, Finding[]> {
    const map = new Map<string, Finding[]>();
    for (const f of this.findings) {
      const list = map.get(f.severity) ?? [];
      list.push(f);
      map.set(f.severity, list);
    }
    return map;
  }

  count(): number {
    return this.findings.length;
  }

  clear(): void {
    this.findings = [];
    this.seen.clear();
  }

  private getKey(finding: Finding): string {
    const snippet = normalizeSnippet(finding.codeSnippet);
    return `${finding.ruleId}|${finding.filePath}|${finding.line}|${snippet}`;
  }
}