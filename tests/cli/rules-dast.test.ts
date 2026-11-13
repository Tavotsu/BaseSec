import * as path from 'node:path';
import { execFile } from 'node:child_process';
import { describe, it, expect } from 'vitest';
import { ALL_RULES } from '../../src/rules/index';
import { ALL_DAST_RULES } from '../../src/dast/rules/index';
import { DAST_CATALOG } from '../../src/dast/catalog';
import { ACTIVE_RULE_IDS, RATE_LIMIT_RULE, UNAUTH_RULE } from '../../src/dast/active-checks';
import { CLASS_META, INJECTION_RULE_IDS } from '../../src/dast/inject';
import { runDast } from '../../src/dast/runner';

const ROOT = path.resolve(__dirname, '..', '..');
const TSX_CLI = path.join(ROOT, 'node_modules', 'tsx', 'dist', 'cli.mjs');
const CLI = path.join(ROOT, 'src', 'cli', 'index.ts');

/** Ejecuta `basesec rules <args>` con tsx, sin color, y devuelve stdout. */
function runRules(args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      [TSX_CLI, CLI, 'rules', ...args],
      { cwd: ROOT, env: { ...process.env, NO_COLOR: '1' } },
      (error, stdout) => {
        if (error) reject(error);
        else resolve(stdout);
      },
    );
  });
}

const EXPECTED_DAST_IDS = [
  'DAST-001', 'DAST-002', 'DAST-003', 'DAST-004', 'DAST-005', 'DAST-006', 'DAST-007', 'DAST-008',
  'DAST-010', 'DAST-011', 'DAST-101', 'DAST-102', 'DAST-103', 'DAST-104', 'DAST-105',
];

describe('DAST catalog', () => {
  it('lists every implemented DAST rule and not DAST-009', () => {
    expect(DAST_CATALOG.map((entry) => entry.id)).toEqual(EXPECTED_DAST_IDS);
    expect(DAST_CATALOG.some((entry) => entry.id === 'DAST-009')).toBe(false);
  });

  it('passive entries match the rule objects in name, severity, category and scope', () => {
    for (const rule of ALL_DAST_RULES) {
      const entry = DAST_CATALOG.find((item) => item.id === rule.id);
      expect(entry, rule.id).toBeDefined();
      expect(entry?.name, rule.id).toBe(rule.name);
      expect(entry?.severity, rule.id).toBe(rule.severity);
      expect(entry?.category, rule.id).toBe(rule.category);
      expect(entry?.scope, rule.id).toBe(rule.once ? 'target' : 'endpoint');
    }
  });

  it('lists exactly the rules the code implements (passive, active and injection), no more and no less', () => {
    const implemented = [...ALL_DAST_RULES.map((rule) => rule.id), ...ACTIVE_RULE_IDS, ...INJECTION_RULE_IDS].sort();
    expect(DAST_CATALOG.map((entry) => entry.id).sort()).toEqual(implemented);
  });

  it('active and injection entries match the metadata of the code that runs them', () => {
    const metas = [UNAUTH_RULE, RATE_LIMIT_RULE, ...Object.values(CLASS_META)];
    expect(metas).toHaveLength(ACTIVE_RULE_IDS.length + INJECTION_RULE_IDS.length);
    for (const meta of metas) {
      const entry = DAST_CATALOG.find((item) => item.id === meta.id);
      expect(entry, meta.id).toBeDefined();
      expect(entry?.name, meta.id).toBe(meta.name);
      expect(entry?.severity, meta.id).toBe(meta.severity);
      expect(entry?.category, meta.id).toBe(meta.category);
    }
  });

  it('every catalog ID is accepted by --rules (the runner lists it as valid)', async () => {
    const error = await runDast({ url: 'http://127.0.0.1:9', rules: ['DAST-999'], evidence: false }).catch((e: unknown) => e);
    const message = error instanceof Error ? error.message : '';
    for (const entry of DAST_CATALOG) {
      expect(message, entry.id).toContain(entry.id);
    }
    expect(message).not.toContain('DAST-009');
  });

  it('injection and active entries carry the severity of their class', () => {
    const severityOf = (id: string) => DAST_CATALOG.find((entry) => entry.id === id)?.severity;
    expect(severityOf('DAST-101')).toBe('critical');
    expect(severityOf('DAST-102')).toBe('high');
    expect(severityOf('DAST-103')).toBe('critical');
    expect(severityOf('DAST-104')).toBe('critical');
    expect(severityOf('DAST-105')).toBe('high');
    expect(severityOf('DAST-008')).toBe('medium');
    expect(severityOf('DAST-010')).toBe('low');
  });
});

describe('CLI: basesec rules', () => {
  it('ALL_RULES still has 65 SAST rules', () => {
    expect(ALL_RULES).toHaveLength(65);
  });

  it('--dast prints the whole implemented DAST catalog, without DAST-009', async () => {
    const out = await runRules(['--dast']);
    expect(out).toContain('basesec rules --dast (15 DAST rules)');
    for (const id of EXPECTED_DAST_IDS) {
      expect(out).toMatch(new RegExp(`${id}: `));
    }
    expect(out).not.toMatch(/DAST-009/);
    expect(out).toMatch(/MEDIUM\s+DAST-008: Unauthenticated sensitive endpoint/);
    expect(out).toMatch(/LOW\s+DAST-010: Missing rate limiting/);
  });

  it('the default title counts the 65 SAST rules', async () => {
    const out = await runRules([]);
    expect(out).toContain('basesec rules (65 rules)');
    expect(out).toContain('DAST (runtime)');
    expect(out).toMatch(/DAST-101: SQL injection/);
  });
}, 60_000);
