import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { CMDI001 } from '../../src/rules/categories/command-injection/child-process';
import { CMDI002 } from '../../src/rules/categories/command-injection/eval-usage';
import { CMDI003 } from '../../src/rules/categories/command-injection/settimeout-string';

describe('CMDI-001: Command Injection via child_process', () => {
  it('detects exec with user input', () => {
    const code = `
      import { exec } from 'child_process';
      exec(\`ping \${req.body.host}\`);
    `;
    const findings = runRule(CMDI001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('CMDI-001');
    expect(findings[0].severity).toBe('critical');
  });

  it('detects execSync with string concatenation', () => {
    const code = `
      const { execSync } = require('child_process');
      execSync('ls ' + req.params.dir);
    `;
    const findings = runRule(CMDI001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag spawn with array arguments', () => {
    const code = `
      const { spawn } = require('child_process');
      spawn('ls', ['-la', safeArg]);
    `;
    const findings = runRule(CMDI001, code);
    expect(findings).toHaveLength(0);
  });

  it('does not flag obj.eval() as eval usage', () => {
    const code = `
      const result = math.eval('2+2');
    `;
    const findings = runRule(CMDI002, code);
    expect(findings).toHaveLength(0);
  });

  it('detects spawn with taint source', () => {
    const code = `
      const { spawn } = require('child_process');
      spawn(req.body.cmd, opts);
    `;
    const findings = runRule(CMDI001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('CMDI-002: Use of eval()', () => {
  it('detects eval() usage', () => {
    const code = `
      eval(req.query.code);
    `;
    const findings = runRule(CMDI002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.some(f => f.ruleId === 'CMDI-002' && f.ruleName === 'Use of eval()')).toBe(true);
  });

  it('detects new Function() usage', () => {
    const code = `
      const fn = new Function('return ' + req.body.code);
    `;
    const findings = runRule(CMDI002, code);
    expect(findings.some(f => f.ruleId === 'CMDI-002')).toBe(true);
  });

  it('does not flag obj.eval()', () => {
    const code = `
      const result = math.eval('2+2');
    `;
    const findings = runRule(CMDI002, code);
    expect(findings).toHaveLength(0);
  });
});

describe('CMDI-003: setTimeout/setInterval with String Argument', () => {
  it('detects setTimeout with string literal', () => {
    const code = `
      setTimeout('alert(1)', 1000);
    `;
    const findings = runRule(CMDI003, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('CMDI-003');
  });

  it('detects setTimeout with template literal containing user input', () => {
    const code = `
      setTimeout(\`alert(\${req.query.msg})\`, 1000);
    `;
    const findings = runRule(CMDI003, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag setTimeout with function argument', () => {
    const code = `
      setTimeout(() => { console.log('safe'); }, 1000);
    `;
    const findings = runRule(CMDI003, code);
    expect(findings).toHaveLength(0);
  });

  it('detects setTimeout with plain string (NoSubstitutionTemplateLiteral)', () => {
    const code = `
      setTimeout(\`console.log('x')\`, 100);
    `;
    const findings = runRule(CMDI003, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});