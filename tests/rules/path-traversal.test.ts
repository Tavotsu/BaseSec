import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { PATH001 } from '../../src/rules/categories/path-traversal/fs-user-path';
import { PATH002 } from '../../src/rules/categories/path-traversal/static-traversal';

describe('PATH-001: Path Traversal via User Input', () => {
  it('detects readFileSync with req.query', () => {
    const code = `
      const content = fs.readFileSync(req.query.filename, 'utf-8');
    `;
    const findings = runRule(PATH001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('PATH-001');
  });

  it('detects writeFile with taint source', () => {
    const code = `
      fs.writeFileSync(req.body.path, data);
    `;
    const findings = runRule(PATH001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('PATH-002: Insecure Static File Configuration', () => {
  it('detects express.static() without dotfiles option', () => {
    const code = `
      app.use(express.static('public'));
    `;
    const findings = runRule(PATH002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag express.static() with dotfiles: deny', () => {
    const code = `
      app.use(express.static('public', { dotfiles: 'deny' }));
    `;
    const findings = runRule(PATH002, code);
    expect(findings).toHaveLength(0);
  });

  it('flags express.static() with dotfiles: allow', () => {
    const code = `
      app.use(express.static('public', { dotfiles: 'allow' }));
    `;
    const findings = runRule(PATH002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});