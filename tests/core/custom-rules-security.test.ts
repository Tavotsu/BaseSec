import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { Pipeline } from '../../src/core/pipeline';
import { DEFAULT_CONFIG } from '../../src/config/defaults';

describe('Custom rules execution safety (CWE-829)', () => {
  let tmpDir: string;
  let originalCwd: string;

  beforeEach(() => {
    originalCwd = process.cwd();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-cwe829-'));
    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'src', 'app.js'), 'const x = 1;\n');
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('defaults DEFAULT_CONFIG.rules to an empty array', () => {
    expect(DEFAULT_CONFIG.rules).toEqual([]);
  });

  it('does NOT execute ./rules/*.js during a default zero-config scan', async () => {
    const markerPath = path.join(tmpDir, 'rce-marker-default.txt');
    const rulesDir = path.join(tmpDir, 'rules');
    fs.mkdirSync(rulesDir, { recursive: true });
    fs.writeFileSync(
      path.join(rulesDir, 'pwn.mjs'),
      `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(markerPath)}, 'pwned'); export const x = {};\n`,
    );

    process.chdir(tmpDir);
    const pipeline = new Pipeline([], { noCache: true, workers: 0 });
    await pipeline.run('.', { noDeps: true });

    expect(fs.existsSync(markerPath)).toBe(false);
  });

  it('does NOT execute custom rules from target .basesecrc without --allow-custom-rules', async () => {
    const markerPath = path.join(tmpDir, 'rce-marker-rc.txt');
    const evilDir = path.join(tmpDir, 'evil');
    fs.mkdirSync(evilDir, { recursive: true });
    fs.writeFileSync(
      path.join(evilDir, 'pwn.mjs'),
      `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(markerPath)}, 'pwned'); export const x = {};\n`,
    );
    fs.writeFileSync(
      path.join(tmpDir, '.basesecrc'),
      JSON.stringify({ rules: [evilDir] }),
    );

    const pipeline = new Pipeline([], { noCache: true, workers: 0 });
    await pipeline.run(tmpDir, { noDeps: true });

    expect(fs.existsSync(markerPath)).toBe(false);
  });

  it('does NOT execute custom rules from target package.json basesec config without --allow-custom-rules', async () => {
    const markerPath = path.join(tmpDir, 'rce-marker-pkg.txt');
    const evilDir = path.join(tmpDir, 'evil-pkg');
    fs.mkdirSync(evilDir, { recursive: true });
    fs.writeFileSync(
      path.join(evilDir, 'pwn.mjs'),
      `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(markerPath)}, 'pwned'); export const x = {};\n`,
    );
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({ name: 'victim', basesec: { rules: [evilDir] } }),
    );

    const pipeline = new Pipeline([], { noCache: true, workers: 0 });
    await pipeline.run(tmpDir, { noDeps: true });

    expect(fs.existsSync(markerPath)).toBe(false);
  });

  it('loads custom rules from config when allowCustomRules is explicitly enabled', async () => {
    const customDir = path.join(tmpDir, 'trusted-rules');
    fs.mkdirSync(customDir, { recursive: true });
    fs.writeFileSync(
      path.join(customDir, 'custom.mjs'),
      `export const customRule = {
        id: 'CUSTOM-TEST-001',
        name: 'Custom Test Rule',
        description: 'Detects test marker',
        severity: 'high',
        category: 'misconfiguration',
        frameworks: ['*'],
        tags: [],
        detect: (ctx) => [{
          ruleId: 'CUSTOM-TEST-001',
          message: 'Custom finding',
          severity: 'high',
          category: 'misconfiguration',
          confidence: 'high',
          filePath: ctx.filePath,
          line: 1,
          column: 1,
          codeSnippet: 'const x = 1;',
          remediation: 'None'
        }]
      };\n`,
    );
    fs.writeFileSync(
      path.join(tmpDir, '.basesecrc'),
      JSON.stringify({ rules: [customDir] }),
    );

    const pipeline = new Pipeline([], { noCache: true, workers: 0 });
    const result = await pipeline.run(tmpDir, { noDeps: true, allowCustomRules: true });

    expect(result.findings.some((f) => f.ruleId === 'CUSTOM-TEST-001')).toBe(true);
  });

  it('loads CLI customRules while still blocking untrusted config rules when allowCustomRules is false', async () => {
    const markerPath = path.join(tmpDir, 'rce-marker-untrusted.txt');
    const evilDir = path.join(tmpDir, 'evil');
    const trustedDir = fs.mkdtempSync(path.join(os.tmpdir(), 'basesec-trusted-rules-'));

    try {
      fs.mkdirSync(evilDir, { recursive: true });
      fs.writeFileSync(
        path.join(evilDir, 'pwn.mjs'),
        `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(markerPath)}, 'pwned'); export const x = {};\n`,
      );
      fs.writeFileSync(
        path.join(tmpDir, '.basesecrc'),
        JSON.stringify({ rules: [evilDir] }),
      );
      fs.writeFileSync(
        path.join(trustedDir, 'trusted.mjs'),
        `export const trustedRule = {
          id: 'CUSTOM-CLI-001',
          name: 'CLI Custom Rule',
          description: 'CLI rule',
          severity: 'medium',
          category: 'misconfiguration',
          frameworks: ['*'],
          tags: [],
          detect: (ctx) => [{
            ruleId: 'CUSTOM-CLI-001',
            message: 'CLI finding',
            severity: 'medium',
            category: 'misconfiguration',
            confidence: 'high',
            filePath: ctx.filePath,
            line: 1,
            column: 1,
            codeSnippet: 'const x = 1;',
            remediation: 'None'
          }]
        };\n`,
      );

      const pipeline = new Pipeline([], { noCache: true, workers: 0 });
      const result = await pipeline.run(tmpDir, {
        noDeps: true,
        customRules: [trustedDir],
      });

      expect(fs.existsSync(markerPath)).toBe(false);
      expect(result.findings.some((f) => f.ruleId === 'CUSTOM-CLI-001')).toBe(true);
    } finally {
      fs.rmSync(trustedDir, { recursive: true, force: true });
    }
  });
});
