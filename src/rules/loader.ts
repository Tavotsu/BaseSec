import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Rule } from './types';
import { RuleRegistry } from './registry';

export async function loadCustomRules(
  rulesDirs: string[],
  registry: RuleRegistry,
): Promise<{ loaded: number; errors: string[] }> {
  let loaded = 0;
  const errors: string[] = [];

  for (const dir of rulesDirs) {
    const absDir = path.resolve(dir);
    if (!fs.existsSync(absDir)) continue;

    const entries: string[] = [];
    try {
      for (const entry of fs.readdirSync(absDir)) {
        if (entry.endsWith('.js') || entry.endsWith('.mjs') || entry.endsWith('.cjs')) {
          entries.push(path.join(absDir, entry));
        }
      }
    } catch (e) {
      errors.push(`Cannot read rules directory ${absDir}: ${e instanceof Error ? e.message : String(e)}`);
      continue;
    }

    for (const filePath of entries) {
      try {
        const moduleUrl = new URL(`file://${filePath}`);
        const mod = await import(moduleUrl.href);

        const ruleExports = Object.values(mod).filter(
          (v) => typeof v === 'object' && v !== null && 'id' in v && 'detect' in v && typeof (v as any).detect === 'function',
        ) as Rule[];

        for (const rule of ruleExports) {
          registry.register(rule);
          loaded++;
        }
      } catch (e) {
        errors.push(`Failed to load rule from ${filePath}: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }

  return { loaded, errors };
}

export function discoverRuleFiles(dir: string): string[] {
  const absDir = path.resolve(dir);
  if (!fs.existsSync(absDir)) return [];

  try {
    return fs.readdirSync(absDir)
      .filter((f) => f.endsWith('.js') || f.endsWith('.mjs') || f.endsWith('.cjs'))
      .map((f) => path.join(absDir, f));
  } catch {
    return [];
  }
}