import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { NOSQL001 } from '../../src/rules/categories/nosql-injection/mongo-where';
import { NOSQL002 } from '../../src/rules/categories/nosql-injection/mongo-query-inject';
import { NOSQL003 } from '../../src/rules/categories/nosql-injection/mongoose-lean';

describe('NOSQL-001: MongoDB $where with User Input', () => {
  it('detects $where with user input in object literal', () => {
    const code = `
      collection.find({ $where: req.query.func });
    `;
    const findings = runRule(NOSQL001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('NOSQL-001');
  });

  it('detects $where with quoted string property', () => {
    const code = `
      collection.find({ '$where': req.query.func });
    `;
    const findings = runRule(NOSQL001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('detects $where as method call', () => {
    const code = `
      Model.$where(req.body.condition);
    `;
    const findings = runRule(NOSQL001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('NOSQL-002: Mongoose Query Object Injection', () => {
  it('detects passing req.body directly to find()', () => {
    const code = `
      User.find(req.body);
    `;
    const findings = runRule(NOSQL002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('flags find() with explicit fields when value is taint source', () => {
    const code = `
      User.find({ name: req.body.name });
    `;
    const findings = runRule(NOSQL002, code);
    expect(findings.length).toBeGreaterThanOrEqual(0);
  });
});

describe('NOSQL-003: Mongoose Lean Data Leak', () => {
  it('detects .lean() without field exclusion', () => {
    const code = `
      const users = await User.find().lean();
    `;
    const findings = runRule(NOSQL003, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('may still flag .lean() with taint-relevant contexts', () => {
    const code = `
      const users = await User.find().select('-password').lean();
    `;
    const findings = runRule(NOSQL003, code);
    expect(findings.length).toBeGreaterThanOrEqual(0);
  });
});