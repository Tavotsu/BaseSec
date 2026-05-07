import { describe, it, expect } from 'vitest';
import { detectExpressPatterns } from '../../src/framework/express';
import { createSourceFile } from '../helpers';

describe('detectExpressPatterns', () => {
  it('detects helmet usage', () => {
    const code = `
      const express = require('express');
      const helmet = require('helmet');
      const app = express();
      app.use(helmet());
    `;
    const sourceFile = createSourceFile(code);
    const result = detectExpressPatterns(sourceFile, code);
    expect(result.hasHelmet).toBe(true);
  });

  it('detects CORS usage', () => {
    const code = `
      const express = require('express');
      const cors = require('cors');
      const app = express();
      app.use(cors());
    `;
    const sourceFile = createSourceFile(code);
    const result = detectExpressPatterns(sourceFile, code);
    expect(result.hasCORS).toBe(true);
  });

  it('detects routes', () => {
    const code = `
      const app = express();
      app.get('/users', (req, res) => res.json({}));
      app.post('/users', (req, res) => res.json({}));
    `;
    const sourceFile = createSourceFile(code);
    const result = detectExpressPatterns(sourceFile, code);
    expect(result.routes.length).toBeGreaterThanOrEqual(2);
    expect(result.routes.some(r => r.method === 'GET' && r.path === '/users')).toBe(true);
    expect(result.routes.some(r => r.method === 'POST' && r.path === '/users')).toBe(true);
  });

  it('detects error handler with 4 params', () => {
    const code = `
      const app = express();
      app.use((err, req, res, next) => {
        res.status(500).json({ error: err.message });
      });
    `;
    const sourceFile = createSourceFile(code);
    const result = detectExpressPatterns(sourceFile, code);
    expect(result.hasErrorHandler).toBe(true);
  });

  it('detects auth middleware in routes', () => {
    const code = `
      const app = express();
      app.get('/admin', authMiddleware, (req, res) => res.json({}));
      app.post('/login', (req, res) => res.json({}));
    `;
    const sourceFile = createSourceFile(code);
    const result = detectExpressPatterns(sourceFile, code);
    const adminRoute = result.routes.find(r => r.path === '/admin');
    expect(adminRoute).toBeDefined();
    expect(adminRoute!.hasAuth).toBe(true);
  });

  it('detects routes on router object', () => {
    const code = `
      const router = express.Router();
      router.get('/api/users', (req, res) => res.json({}));
    `;
    const sourceFile = createSourceFile(code);
    const result = detectExpressPatterns(sourceFile, code);
    expect(result.routes.length).toBeGreaterThanOrEqual(1);
  });

  it('returns empty results for non-express code', () => {
    const code = `
      const obj = { get: () => {} };
      obj.get('test', () => {});
    `;
    const sourceFile = createSourceFile(code);
    const result = detectExpressPatterns(sourceFile, code);
    expect(result.routes).toHaveLength(0);
    expect(result.hasHelmet).toBe(false);
    expect(result.hasCORS).toBe(false);
    expect(result.hasErrorHandler).toBe(false);
  });
});