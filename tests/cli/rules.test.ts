import { describe, it, expect } from 'vitest';
import * as ts from 'typescript';
import { createSourceFile } from '../helpers';
import { ALL_RULES } from '../../src/rules/index';
import { RuleRegistry } from '../../src/rules/registry';

describe('CLI: rules command data', () => {
  it('ALL_RULES has 42 rules', () => {
    expect(ALL_RULES).toHaveLength(42);
  });

  it('every rule has required fields', () => {
    for (const rule of ALL_RULES) {
      expect(rule.id).toBeTruthy();
      expect(rule.name).toBeTruthy();
      expect(rule.category).toBeTruthy();
      expect(rule.severity).toBeTruthy();
      expect(Array.isArray(rule.frameworks)).toBe(true);
      expect(typeof rule.detect).toBe('function');
    }
  });

  it('rule IDs follow CATEGORY-NNN pattern', () => {
    const pattern = /^[A-Z]+-\d{3}$/;
    for (const rule of ALL_RULES) {
      expect(pattern.test(rule.id), `Rule ID "${rule.id}" does not match CATEGORY-NNN`).toBe(true);
    }
  });

  it('no duplicate rule IDs', () => {
    const ids = ALL_RULES.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it('severity values are valid', () => {
    const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
    for (const rule of ALL_RULES) {
      expect(validSeverities).toContain(rule.severity);
    }
  });

  it('framework values are valid', () => {
    const validFrameworks = ['express', 'nestjs', 'mongoose', 'typeorm', 'fastify', 'koa', 'prisma', '*'];
    for (const rule of ALL_RULES) {
      for (const fw of rule.frameworks) {
        expect(validFrameworks).toContain(fw);
      }
    }
  });

  it('categories have expected count of rules', () => {
    const categories = new Map<string, number>();
    for (const rule of ALL_RULES) {
      categories.set(rule.category, (categories.get(rule.category) ?? 0) + 1);
    }
    expect(categories.get('sql-injection')).toBe(6);
    expect(categories.get('nosql-injection')).toBe(3);
    expect(categories.get('xss')).toBe(7);
    expect(categories.get('command-injection')).toBe(3);
    expect(categories.get('path-traversal')).toBe(2);
    expect(categories.get('auth')).toBe(5);
    expect(categories.get('secrets')).toBe(3);
    expect(categories.get('error-handling')).toBe(3);
    expect(categories.get('misconfiguration')).toBe(6);
    expect(categories.get('dependency-check')).toBe(4);
  });
});

describe('RuleRegistry', () => {
  it('registers and retrieves rules', () => {
    const registry = new RuleRegistry();
    const rule = ALL_RULES[0];
    registry.register(rule);
    expect(registry.get(rule.id)).toBe(rule);
  });

  it('getAll returns all registered rules', () => {
    const registry = new RuleRegistry();
    registry.registerMany(ALL_RULES);
    expect(registry.getAll()).toHaveLength(42);
  });

  it('getByCategory returns rules in category', () => {
    const registry = new RuleRegistry();
    registry.registerMany(ALL_RULES);
    const sqlRules = registry.getByCategory('sql-injection');
    expect(sqlRules).toHaveLength(6);
    for (const r of sqlRules) {
      expect(r.category).toBe('sql-injection');
    }
  });

  it('getByFramework returns matching rules', () => {
    const registry = new RuleRegistry();
    registry.registerMany(ALL_RULES);
    const expressRules = registry.getByFramework('express');
    expect(expressRules.length).toBeGreaterThan(0);
    for (const r of expressRules) {
      expect(r.frameworks.includes('express') || r.frameworks.includes('*')).toBe(true);
    }
  });

  it('getIds returns all rule IDs', () => {
    const registry = new RuleRegistry();
    registry.registerMany(ALL_RULES);
    const ids = registry.getIds();
    expect(ids).toHaveLength(42);
  });
});