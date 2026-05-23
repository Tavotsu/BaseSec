import { describe, it, expect } from 'vitest';
import { PRISMA001 } from '../../src/rules/categories/prisma/raw-query-injection';
import { PRISMA002 } from '../../src/rules/categories/prisma/unsafe-raw-query';
import { runRule } from '../helpers';

describe('Prisma Rules', () => {
  describe('PRISMA-001: Raw Query Injection', () => {
    it('detects $queryRaw with binary expression', () => {
      const code = `
        const result = await prisma.$queryRaw("SELECT * FROM users WHERE id = " + req.query.id);
      `;
      const findings = runRule(PRISMA001, code);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('PRISMA-001');
    });

    it('detects $queryRawUnsafe with injection', () => {
      const code = `
        const result = await prisma.$queryRawUnsafe("SELECT * FROM users WHERE id = " + req.body.id);
      `;
      const findings = runRule(PRISMA001, code);
      expect(findings).toHaveLength(1);
    });
  });

  describe('PRISMA-002: Unsafe Raw Query', () => {
    it('detects use of $queryRawUnsafe', () => {
      const code = `
        const sql = "SELECT * FROM users";
        const result = await prisma.$queryRawUnsafe(sql);
      `;
      const findings = runRule(PRISMA002, code);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('PRISMA-002');
    });

    it('passes on safe $queryRaw tagged template', () => {
      const code = `
        const result = await prisma.$queryRaw\`SELECT * FROM users WHERE id = \${id}\`;
      `;
      const findings = runRule(PRISMA002, code);
      expect(findings).toHaveLength(0);
    });
  });
});
