import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { ERR001 } from '../../src/rules/categories/error-handling/exposed-stack';
import { ERR002 } from '../../src/rules/categories/error-handling/catch-all';
import { ERR003 } from '../../src/rules/categories/error-handling/unhandled-rejection';

describe('ERR-001: Exposed Stack Trace', () => {
  it('detects err.stack sent to client', () => {
    const code = `
      app.use((err, req, res, next) => {
        res.status(500).json({ error: err.stack });
      });
    `;
    const findings = runRule(ERR001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('ERR-001');
  });

  it('detects err.message sent to client', () => {
    const code = `
      res.status(500).send(err.message);
    `;
    const findings = runRule(ERR001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag safe error handling', () => {
    const code = `
      app.use((err, req, res, next) => {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Error' });
      });
    `;
    const findings = runRule(ERR001, code);
    expect(findings).toHaveLength(0);
  });
});

describe('ERR-002: Missing Global Error Handler', () => {
  it('detects Express app without error handler', () => {
    const code = `
      const app = express();
      app.get('/', (req, res) => res.send('ok'));
      app.listen(3000);
    `;
    const findings = runRule(ERR002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag Express app with 4-argument error handler', () => {
    const code = `
      const app = express();
      app.use((err, req, res, next) => {
        res.status(500).send('Error');
      });
    `;
    const findings = runRule(ERR002, code);
    expect(findings).toHaveLength(0);
  });
});

describe('ERR-003: Unhandled Promise Rejection', () => {
  it('reports project-level finding without process.on handler', () => {
    const code = `
      app.get('/data', async (req, res) => {
        const data = await db.query('SELECT *');
        res.json(data);
      });
    `;
    const findings = runRule(ERR003, code);
    expect(findings.some(f => f.message.includes('unhandledRejection'))).toBe(true);
  });

  it('does not report project-level finding when process.on handler exists', () => {
    const code = `
      process.on('unhandledRejection', (reason) => {
        console.error(reason);
      });
      app.get('/data', async (req, res) => {
        const data = await db.query('SELECT *');
        res.json(data);
      });
    `;
    const findings = runRule(ERR003, code);
    expect(findings.some(f => f.message.includes('unhandledRejection'))).toBe(false);
  });
});