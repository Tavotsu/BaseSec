import { describe, it, expect } from 'vitest';
import { FASTIFY001 } from '../../src/rules/categories/fastify/missing-rate-limit';
import { FASTIFY002 } from '../../src/rules/categories/fastify/missing-helmet';
import { FASTIFY003 } from '../../src/rules/categories/fastify/missing-cors';
import { runRule } from '../helpers';

describe('Fastify Rules', () => {
  describe('FASTIFY-001: Missing Rate Limit', () => {
    it('detects missing rate limit', () => {
      const code = `
        const fastify = require('fastify')();
        fastify.get('/', (request, reply) => reply.send('ok'));
      `;
      const findings = runRule(FASTIFY001, code);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('FASTIFY-001');
    });

    it('passes when rate limit is present', () => {
      const code = `
        const fastify = require('fastify')();
        fastify.register(require('@fastify/rate-limit'));
      `;
      const findings = runRule(FASTIFY001, code);
      expect(findings).toHaveLength(0);
    });
  });

  describe('FASTIFY-002: Missing Helmet', () => {
    it('detects missing helmet', () => {
      const code = `
        const fastify = require('fastify')();
      `;
      const findings = runRule(FASTIFY002, code);
      expect(findings).toHaveLength(1);
    });

    it('passes when helmet is present', () => {
      const code = `
        const fastify = require('fastify')();
        fastify.register(require('@fastify/helmet'));
      `;
      const findings = runRule(FASTIFY002, code);
      expect(findings).toHaveLength(0);
    });
  });

  describe('FASTIFY-003: Missing CORS', () => {
    it('detects permissive CORS configuration', () => {
      const code = `
        const fastify = require('fastify')();
        fastify.register(require('@fastify/cors'), { origin: '*' });
      `;
      const findings = runRule(FASTIFY003, code);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('FASTIFY-003');
    });

    it('passes on secure CORS', () => {
      const code = `
        const fastify = require('fastify')();
        fastify.register(require('@fastify/cors'), { origin: 'https://example.com' });
      `;
      const findings = runRule(FASTIFY003, code);
      expect(findings).toHaveLength(0);
    });
  });
});
