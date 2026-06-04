import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { checkConsent, saveConsent, revokeConsent, getConsentPath } from '../../src/ai/consent';

const CONSENT_PATH = path.join(os.homedir(), '.basesec', 'ai-consent');

describe('consent', () => {
  beforeEach(() => {
    if (fs.existsSync(CONSENT_PATH)) fs.unlinkSync(CONSENT_PATH);
  });

  afterEach(() => {
    if (fs.existsSync(CONSENT_PATH)) fs.unlinkSync(CONSENT_PATH);
  });

  it('returns false when no consent file exists', () => {
    expect(checkConsent()).toBe(false);
  });

  it('saves and reads consent correctly', () => {
    saveConsent();
    expect(checkConsent()).toBe(true);
  });

  it('revokes consent', () => {
    saveConsent();
    revokeConsent();
    expect(checkConsent()).toBe(false);
  });

  it('returns false for malformed consent file', () => {
    const dir = path.dirname(CONSENT_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(CONSENT_PATH, 'not-json', 'utf-8');
    expect(checkConsent()).toBe(false);
  });

  it('returns false when accepted is false', () => {
    const dir = path.dirname(CONSENT_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(CONSENT_PATH, JSON.stringify({ accepted: false, version: '1.0', timestamp: '' }), 'utf-8');
    expect(checkConsent()).toBe(false);
  });

  it('returns false for wrong version', () => {
    const dir = path.dirname(CONSENT_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(CONSENT_PATH, JSON.stringify({ accepted: true, version: '0.9', timestamp: '' }), 'utf-8');
    expect(checkConsent()).toBe(false);
  });

  it('getConsentPath returns path inside home dir', () => {
    expect(getConsentPath()).toContain('.basesec');
  });
});
