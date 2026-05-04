import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { AUTH001 } from '../../src/rules/categories/auth/missing-auth-guard';
import { AUTH002 } from '../../src/rules/categories/auth/weak-jwt-secret';
import { AUTH003 } from '../../src/rules/categories/auth/cors-misconfig';

describe('AUTH-001: Missing Authentication Guard', () => {
  it('detects POST route without auth middleware', () => {
    const code = `
      app.post('/data', (req, res) => { res.json(req.body); });
    `;
    const findings = runRule(AUTH001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('AUTH-001');
  });

  it('does not flag route with auth middleware (Identifier)', () => {
    const code = `
      app.post('/secure', authenticate, (req, res) => { res.json(req.body); });
    `;
    const findings = runRule(AUTH001, code);
    expect(findings).toHaveLength(0);
  });

  it('does not flag route with auth middleware (CallExpression)', () => {
    const code = `
      app.post('/secure', auth(), (req, res) => { res.json(req.body); });
    `;
    const findings = runRule(AUTH001, code);
    expect(findings).toHaveLength(0);
  });

  it('does not flag route with passport.authenticate', () => {
    const code = `
      app.post('/login', passport.authenticate('local'), (req, res) => {});
    `;
    const findings = runRule(AUTH001, code);
    expect(findings).toHaveLength(0);
  });
});

describe('AUTH-002: Hardcoded JWT Secret', () => {
  it('detects jwt.sign() with hardcoded string', () => {
    const code = `
      const token = jwt.sign({ id: 1 }, 'my-secret-key');
    `;
    const findings = runRule(AUTH002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('AUTH-002');
  });

  it('detects jwt.sign() with nullish coalescing fallback', () => {
    const code = `
      const token = jwt.sign({ id: 2 }, process.env.JWT_SECRET ?? 'fallback-key');
    `;
    const findings = runRule(AUTH002, code);
    expect(findings.some(f => f.severity === 'high')).toBe(true);
  });

  it('does not flag jwt.sign() with env var only', () => {
    const code = `
      jwt.sign({ id: 1 }, process.env.JWT_SECRET);
    `;
    const findings = runRule(AUTH002, code);
    expect(findings).toHaveLength(0);
  });

  it('detects jsonwebtoken.sign() with hardcoded secret', () => {
    const code = `
      const jwt = require('jsonwebtoken');
      jwt.sign({ id: 1 }, 'hardcoded-secret');
    `;
    const findings = runRule(AUTH002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('AUTH-003: Permissive CORS Configuration', () => {
  it('detects CORS with origin "*" and credentials: true', () => {
    const code = `
      app.use(cors({ origin: '*', credentials: true }));
    `;
    const findings = runRule(AUTH003, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('high');
  });

  it('reports medium severity for origin "*" without credentials', () => {
    const code = `
      app.use(cors({ origin: '*' }));
    `;
    const findings = runRule(AUTH003, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('medium');
  });

  it('does not flag CORS with specific origin', () => {
    const code = `
      app.use(cors({ origin: 'https://myapp.com' }));
    `;
    const findings = runRule(AUTH003, code);
    expect(findings).toHaveLength(0);
  });
});