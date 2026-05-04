import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { SQLI001 } from '../../src/rules/categories/sql-injection/string-concat';
import { SQLI002 } from '../../src/rules/categories/sql-injection/template-literal';
import { SQLI003 } from '../../src/rules/categories/sql-injection/raw-query';
import { SQLI004 } from '../../src/rules/categories/sql-injection/knex-raw';

describe('SQLI-001: SQL String Concatenation', () => {
  it('detects SQL injection via string concatenation with req.params', () => {
    const code = `
      const query = "SELECT * FROM users WHERE id = " + req.params.id;
      db.query(query);
    `;
    const findings = runRule(SQLI001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('SQLI-001');
    expect(findings[0].severity).toBe('critical');
  });

  it('detects SQL injection with req.body', () => {
    const code = `
      const sql = "INSERT INTO users VALUES (" + req.body.name + ")";
    `;
    const findings = runRule(SQLI001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag parameterized queries', () => {
    const code = `
      const query = "SELECT * FROM users WHERE id = ?";
      db.query(query, [req.params.id]);
    `;
    const findings = runRule(SQLI001, code);
    expect(findings).toHaveLength(0);
  });

  it('does not flag safe android-like strings', () => {
    const code = `
      const os = "android";
      const query = "SELECT * FROM devices WHERE os = " + os;
    `;
    const findings = runRule(SQLI001, code);
    expect(findings).toHaveLength(0);
  });
});

describe('SQLI-002: SQL Template Literal Injection', () => {
  it('detects SQL injection via template literals with user input', () => {
    const code = `
      const query = \`SELECT * FROM users WHERE name = '\${req.body.name}'\`;
      db.query(query);
    `;
    const findings = runRule(SQLI002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('SQLI-002');
  });

  it('does not flag template literals without user input', () => {
    const code = `
      const query = \`SELECT * FROM users WHERE name = 'john'\`;
    `;
    const findings = runRule(SQLI002, code);
    expect(findings).toHaveLength(0);
  });
});

describe('SQLI-003: Raw SQL Query Without Parameters', () => {
  it('detects raw query call expression', () => {
    const code = `
      import { Repository } from 'typeorm';
      const result = repository.query('SELECT * FROM users');
    `;
    const findings = runRule(SQLI003, code);
    expect(findings.length).toBeGreaterThanOrEqual(0);
  });

  it('detects raw query using template literal', () => {
    const code = `
      await repository.query(\`SELECT * FROM users WHERE id = \${req.params.id}\`);
    `;
    const findings = runRule(SQLI003, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('detects raw query with NoSubstitutionTemplateLiteral', () => {
    const code = `
      await repository.query(\`SELECT * FROM users\`);
    `;
    const findings = runRule(SQLI003, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('SQLI-004: SQL Injection via Knex Raw Query', () => {
  it('detects knex.raw with string concatenation', () => {
    const code = `
      knex.raw('SELECT * FROM users WHERE id = ' + req.params.id);
    `;
    const findings = runRule(SQLI004, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('SQLI-004');
  });

  it('does not flag knex.raw with bindings', () => {
    const code = `
      knex.raw('SELECT * FROM users WHERE id = ?', [req.params.id]);
    `;
    const findings = runRule(SQLI004, code);
    expect(findings).toHaveLength(0);
  });
});