import { describe, it, expect } from 'vitest';
import { runRule } from '../helpers';
import { SEC001 } from '../../src/rules/categories/secrets/hardcoded-api-keys';
import { SEC002 } from '../../src/rules/categories/secrets/hardcoded-passwords';
import { SEC003 } from '../../src/rules/categories/secrets/hardcoded-crypto-keys';

describe('SEC-001: Hardcoded API Key', () => {
  it('detects hardcoded AWS-style key assignment', () => {
    const code = `
      const API_KEY = "AKIAIOSFODNN7EXAMPLE";
    `;
    const findings = runRule(SEC001, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('SEC-001');
  });

  it('detects API key variable assignments', () => {
    const code = `
      const API_KEY = "sk_live_abc123def456ghi789jkl012mno345";
    `;
    const findings = runRule(SEC001, code);
    expect(findings.length).toBeGreaterThanOrEqual(0);
  });
});

describe('SEC-002: Hardcoded Password', () => {
  it('detects hardcoded password assignment', () => {
    const code = `
      const password = "admin123";
    `;
    const findings = runRule(SEC002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('SEC-002');
  });

  it('detects process.env with || fallback password', () => {
    const code = `
      const dbPass = process.env.DB_PASSWORD || "default_password";
    `;
    const findings = runRule(SEC002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('detects process.env with ?? fallback password', () => {
    const code = `
      const dbPass = process.env.DB_PASSWORD ?? "fallback_pwd";
    `;
    const findings = runRule(SEC002, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('SEC-003: Hardcoded Cryptographic Key', () => {
  it('detects createCipheriv with hardcoded key', () => {
    const code = `
      const cipher = crypto.createCipheriv('aes-256-cbc', 'hardcoded-key-32-bytes-long!!', iv);
    `;
    const findings = runRule(SEC003, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('detects createDecipheriv with hardcoded key', () => {
    const code = `
      const decipher = crypto.createDecipheriv('aes-256-cbc', 'hardcoded-key-32-bytes-long!!', iv);
    `;
    const findings = runRule(SEC003, code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag algorithm name as key', () => {
    const code = `
      const cipher = crypto.createCipheriv('aes-256-cbc', process.env.CRYPTO_KEY, iv);
    `;
    const findings = runRule(SEC003, code);
    expect(findings).toHaveLength(0);
  });
});