import { describe, it, expect, vi } from 'vitest';
import { loadCustomRules, discoverRuleFiles } from '../../src/rules/loader';
import { RuleRegistry } from '../../src/rules/registry';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { Rule } from '../../src/rules/types';

describe('loadCustomRules', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-loader-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('loads a valid custom rule from JS file', async () => {
    const ruleCode = `
      export const customRule = {
        id: 'CUSTOM-001',
        name: 'Custom Rule',
        description: 'A test rule',
        severity: 'medium',
        category: 'custom',
        frameworks: ['*'],
        detect: () => []
      };
    `;
    fs.writeFileSync(path.join(tmpDir, 'custom-rule.js'), ruleCode);

    const registry = new RuleRegistry();
    const result = await loadCustomRules([tmpDir], registry);
    expect(result.loaded).toBe(1);
    expect(result.errors).toHaveLength(0);
  });

  it('returns errors for invalid rule files', async () => {
    fs.writeFileSync(path.join(tmpDir, 'bad-rule.js'), 'this is not valid JS ^^^');

    const registry = new RuleRegistry();
    const result = await loadCustomRules([tmpDir], registry);
    expect(result.loaded).toBe(0);
    expect(result.errors.length).toBeGreaterThanOrEqual(1);
  });

  it('skips non-JS files', async () => {
    fs.writeFileSync(path.join(tmpDir, 'readme.md'), '# Docs');
    fs.writeFileSync(path.join(tmpDir, 'data.json'), '{}');

    const registry = new RuleRegistry();
    const result = await loadCustomRules([tmpDir], registry);
    expect(result.loaded).toBe(0);
    expect(result.errors).toHaveLength(0);
  });

  it('handles non-existent directory gracefully', async () => {
    const registry = new RuleRegistry();
    const result = await loadCustomRules(['/nonexistent/dir'], registry);
    expect(result.loaded).toBe(0);
    expect(result.errors).toHaveLength(0);
  });

  it('handles empty directory', async () => {
    const registry = new RuleRegistry();
    const result = await loadCustomRules([tmpDir], registry);
    expect(result.loaded).toBe(0);
    expect(result.errors).toHaveLength(0);
  });

  it('handles unreadable directory', async () => {
    const unreadable = path.join(tmpDir, 'unreadable');
    fs.mkdirSync(unreadable, { recursive: true });
    fs.chmodSync(unreadable, 0o000);

    const registry = new RuleRegistry();
    const result = await loadCustomRules([unreadable], registry);
    expect(result.errors.length).toBeGreaterThanOrEqual(1);
  });

  it('loads MJS files', async () => {
    const ruleCode = `
      export const mjsRule = {
        id: 'CUSTOM-002',
        name: 'MJS Rule',
        description: 'An ESM rule',
        severity: 'low',
        category: 'custom',
        frameworks: ['*'],
        detect: () => []
      };
    `;
    fs.writeFileSync(path.join(tmpDir, 'esm-rule.mjs'), ruleCode);

    const registry = new RuleRegistry();
    const result = await loadCustomRules([tmpDir], registry);
    expect(result.loaded).toBeGreaterThanOrEqual(1);
  });

  it('loads multiple rules from different directories', async () => {
    const dir1 = path.join(tmpDir, 'dir1');
    const dir2 = path.join(tmpDir, 'dir2');
    fs.mkdirSync(dir1, { recursive: true });
    fs.mkdirSync(dir2, { recursive: true });

    fs.writeFileSync(path.join(dir1, 'rule1.js'), `
      export const rule1 = { id: 'CUSTOM-010', name: 'R1', description: 'D1', severity: 'low', category: 'c1', frameworks: ['*'], detect: () => [] };
    `);
    fs.writeFileSync(path.join(dir2, 'rule2.js'), `
      export const rule2 = { id: 'CUSTOM-011', name: 'R2', description: 'D2', severity: 'low', category: 'c2', frameworks: ['*'], detect: () => [] };
    `);

    const registry = new RuleRegistry();
    const result = await loadCustomRules([dir1, dir2], registry);
    expect(result.loaded).toBeGreaterThanOrEqual(2);
  });
});

describe('discoverRuleFiles', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-disc-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('discovers JS files in directory', () => {
    fs.writeFileSync(path.join(tmpDir, 'rule.js'), '// rule');
    fs.writeFileSync(path.join(tmpDir, 'other.txt'), 'not a rule');

    const files = discoverRuleFiles(tmpDir);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/rule\.js$/);
  });

  it('discovers MJS and CJS files', () => {
    fs.writeFileSync(path.join(tmpDir, 'rule1.mjs'), '// rule');
    fs.writeFileSync(path.join(tmpDir, 'rule2.cjs'), '// rule');

    const files = discoverRuleFiles(tmpDir);
    expect(files).toHaveLength(2);
  });

  it('returns empty array for non-existent directory', () => {
    const files = discoverRuleFiles('/nonexistent/path');
    expect(files).toEqual([]);
  });
});