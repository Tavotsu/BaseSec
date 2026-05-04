import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { XSS001 } from '../../src/rules/categories/xss/res-send-unsafe';
import { XSS002 } from '../../src/rules/categories/xss/missing-helmet';
import { XSS003 } from '../../src/rules/categories/xss/unsafe-headers';
import { XSS004 } from '../../src/rules/categories/xss/open-redirect';

describe('XSS-001: Unsafe res.send() with User Input', () => {
  it('detects res.send() with req.body', () => {
    const code = `
      app.get('/hello', (req, res) => {
        res.send(req.body);
      });
    `;
    const findings = runRule(XSS001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('XSS-001');
  });

  it('detects res.send() with template literal injection', () => {
    const code = `
      res.send(\`<h1>Hello \${req.query.name}</h1>\`);
    `;
    const findings = runRule(XSS001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('detects res.json() with user input', () => {
    const code = `
      res.json(req.body);
    `;
    const findings = runRule(XSS001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('XSS-002: Missing Helmet Middleware', () => {
  it('detects Express app without helmet', () => {
    const code = `
      const app = express();
      app.get('/', handler);
    `;
    const findings = runRule(XSS002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag Express app with helmet', () => {
    const code = `
      import helmet from 'helmet';
      const app = express();
      app.use(helmet());
      app.get('/', handler);
    `;
    const findings = runRule(XSS002, code);
    expect(findings).toHaveLength(0);
  });

  it('does not flag react-helmet as helmet middleware', () => {
    const code = `
      import { Helmet } from 'react-helmet';
      const app = express();
      app.get('/', (req, res) => res.send('ok'));
    `;
    const findings = runRule(XSS002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('XSS-003: Unsafe Response Header with User Input', () => {
  it('detects res.set() with user input', () => {
    const code = `
      res.set('X-Custom-Header', req.headers['x-input']);
    `;
    const findings = runRule(XSS003, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag map.set() or other receiver objects', () => {
    const code = `
      const map = new Map();
      map.set('key', 'value');
      const state = new Set();
      state.set('active');
    `;
    const findings = runRule(XSS003, code);
    expect(findings).toHaveLength(0);
  });
});

describe('XSS-004: Open Redirect', () => {
  it('detects res.redirect() with user input', () => {
    const code = `
      res.redirect(req.query.url);
    `;
    const findings = runRule(XSS004, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag res.redirect() with static URL', () => {
    const code = `
      res.redirect('/login');
    `;
    const findings = runRule(XSS004, code);
    expect(findings).toHaveLength(0);
  });
});