import { describe, it, expect } from 'vitest';
import { KOA001 } from '../../src/rules/categories/koa/missing-helmet';
import { KOA002 } from '../../src/rules/categories/koa/missing-cors';
import { KOA003 } from '../../src/rules/categories/koa/unsafe-ctx-body';
import { runRule } from '../helpers';

describe('Koa Rules', () => {
  describe('KOA-001: Missing Helmet', () => {
    it('detects missing helmet', () => {
      const code = `
        const Koa = require('koa');
        const app = new Koa();
      `;
      const findings = runRule(KOA001, code);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('KOA-001');
    });

    it('passes when helmet is present', () => {
      const code = `
        const Koa = require('koa');
        const helmet = require('koa-helmet');
        const app = new Koa();
        app.use(helmet());
      `;
      const findings = runRule(KOA001, code);
      expect(findings).toHaveLength(0);
    });
  });

  describe('KOA-002: Missing CORS', () => {
    it('detects permissive CORS configuration', () => {
      const code = `
        const Koa = require('koa');
        const cors = require('@koa/cors');
        const app = new Koa();
        app.use(cors({ origin: '*' }));
      `;
      const findings = runRule(KOA002, code);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('KOA-002');
    });

    it('passes on secure CORS', () => {
      const code = `
        const app = new Koa();
        app.use(cors({ origin: 'https://example.com' }));
      `;
      const findings = runRule(KOA002, code);
      expect(findings).toHaveLength(0);
    });
  });

  describe('KOA-003: Unsafe ctx.body with User Input', () => {
    it('detects assignment of taint to ctx.body', () => {
      const code = `
        app.use(ctx => {
          ctx.body = ctx.query.name;
        });
      `;
      const findings = runRule(KOA003, code);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('KOA-003');
    });

    it('passes when assigning safe string', () => {
      const code = `
        app.use(ctx => {
          ctx.body = "Hello World";
        });
      `;
      const findings = runRule(KOA003, code);
      expect(findings).toHaveLength(0);
    });
  });
});
