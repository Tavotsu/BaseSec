import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { CONF001 } from '../../src/rules/categories/misconfiguration/missing-csp';
import { CONF002 } from '../../src/rules/categories/misconfiguration/debug-mode';
import { CONF003 } from '../../src/rules/categories/misconfiguration/insecure-cookies';
import { CONF004 } from '../../src/rules/categories/misconfiguration/unlimited-body-parser';

describe('CONF-001: Missing Content-Security-Policy', () => {
  it('detects Express app without helmet or CSP', () => {
    const code = `
      const app = express();
      app.get('/', handler);
    `;
    const findings = runRule(CONF001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag Express app with helmet', () => {
    const code = `
      import helmet from 'helmet';
      const app = express();
      app.use(helmet());
    `;
    const findings = runRule(CONF001, code);
    expect(findings).toHaveLength(0);
  });
});

describe('CONF-002: Debug Mode in Production', () => {
  it('detects app.set("env", "development")', () => {
    const code = `
      const app = express();
      app.set('env', 'development');
    `;
    const findings = runRule(CONF002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag NODE_ENV production check', () => {
    const code = `
      if (process.env.NODE_ENV === 'production') {
        app.use(helmet());
      }
    `;
    const findings = runRule(CONF002, code);
    expect(findings).toHaveLength(0);
  });

  it('detects NestJS logger: true in create', () => {
    const code = `
      const app = await NestFactory.create(AppModule, { logger: true });
    `;
    const findings = runRule(CONF002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('CONF-003: Insecure Cookie Configuration', () => {
  it('detects session without secure and httpOnly', () => {
    const code = `
      app.use(session({ secret: 'keyboard cat' }));
    `;
    const findings = runRule(CONF003, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag properly configured session', () => {
    const code = `
      app.use(session({ secret: 'keyboard cat', secure: true, httpOnly: true }));
    `;
    const findings = runRule(CONF003, code);
    expect(findings).toHaveLength(0);
  });
});

describe('CONF-004: Unlimited Body Parser', () => {
  it('detects express.json() without limit', () => {
    const code = `
      app.use(express.json());
    `;
    const findings = runRule(CONF004, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('detects bodyParser.json() without limit', () => {
    const code = `
      app.use(bodyParser.json());
    `;
    const findings = runRule(CONF004, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag express.json() with limit', () => {
    const code = `
      app.use(express.json({ limit: '1mb' }));
    `;
    const findings = runRule(CONF004, code);
    expect(findings).toHaveLength(0);
  });
});