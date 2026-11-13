import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { defineConfig } from '../../src/config/index';

describe('basesec/config entry', () => {
  it('exports defineConfig as a function', () => {
    expect(typeof defineConfig).toBe('function');
  });

  it('returns the same object it receives', () => {
    const config = { target: ['src'], severity: 'high' as const };
    expect(defineConfig(config)).toBe(config);
  });
});

describe('subpath basesec/config: empaquetado y CI', () => {
  const root = path.resolve(__dirname, '../..');
  const read = (file: string): string => fs.readFileSync(path.join(root, file), 'utf-8');

  it('package.json exporta ./config hacia dist/config.js y tsup lo genera como entrada', () => {
    const pkg = JSON.parse(read('package.json')) as { exports: Record<string, string> };
    expect(pkg.exports['./config']).toBe('./dist/config.js');
    expect(pkg.exports['./agent']).toBe('./dist/agent.cjs');
    expect(read('tsup.config.ts')).toMatch(/config:\s*'src\/config\/index\.ts'/);
  });

  it('el CI no fija la versión de pnpm: la toma de packageManager (ambas a la vez hacen fallar pnpm/action-setup)', () => {
    const pkg = JSON.parse(read('package.json')) as { packageManager?: string };
    const ci = read('.github/workflows/ci.yml');
    expect(pkg.packageManager).toMatch(/^pnpm@/);
    const setup = ci.slice(ci.indexOf('uses: pnpm/action-setup'), ci.indexOf('actions/setup-node'));
    expect(setup).not.toMatch(/version\s*:/);
  });
});
