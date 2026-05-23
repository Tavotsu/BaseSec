import { describe, it, expect } from 'vitest';
import { RuleRegistry } from '../../src/rules/registry';
import { ALL_RULES } from '../../src/rules/index';

describe('RuleRegistry', () => {
  it('registers rule successfully', () => {
    const registry = new RuleRegistry();
    registry.register(ALL_RULES[0]);
    expect(registry.get(ALL_RULES[0].id)).toBeDefined();
  });

  it('registerMany adds multiple rules', () => {
    const registry = new RuleRegistry();
    registry.registerMany(ALL_RULES);
    expect(registry.getAll().length).toBe(ALL_RULES.length);
  });

  it('overwrites when registering duplicate rule id', () => {
    const registry = new RuleRegistry();
    registry.register(ALL_RULES[0]);
    expect(() => registry.register(ALL_RULES[0])).not.toThrow();
    expect(registry.getAll().length).toBe(1);
  });

  it('getByCategory filters correctly', () => {
    const registry = new RuleRegistry();
    registry.registerMany(ALL_RULES);
    const xssRules = registry.getByCategory('xss');
    expect(xssRules.length).toBeGreaterThan(0);
    for (const rule of xssRules) {
      expect(rule.category).toBe('xss');
    }
  });

  it('getByFramework filters correctly', () => {
    const registry = new RuleRegistry();
    registry.registerMany(ALL_RULES);
    const expressRules = registry.getByFramework('express');
    expect(expressRules.length).toBeGreaterThan(0);
    // Express rules include '*' and 'express'
    for (const rule of expressRules) {
      expect(rule.frameworks.includes('express') || rule.frameworks.includes('*')).toBe(true);
    }
  });
});
