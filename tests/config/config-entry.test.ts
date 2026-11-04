import { describe, it, expect } from 'vitest';
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
