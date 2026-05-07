import { describe, it, expect } from 'vitest';
import { severityGte, severityOrder, SEVERITY_LABELS, SEVERITY_COLORS } from '../../src/utils/severity';
import type { Severity } from '../../src/rules/types';

describe('severity utils', () => {
  describe('severityGte', () => {
    it('returns true for equal severities', () => {
      expect(severityGte('critical', 'critical')).toBe(true);
      expect(severityGte('high', 'high')).toBe(true);
      expect(severityGte('low', 'low')).toBe(true);
      expect(severityGte('info', 'info')).toBe(true);
    });

    it('returns true for higher severity than threshold', () => {
      expect(severityGte('critical', 'high')).toBe(true);
      expect(severityGte('critical', 'medium')).toBe(true);
      expect(severityGte('high', 'low')).toBe(true);
      expect(severityGte('medium', 'info')).toBe(true);
    });

    it('returns false for lower severity than threshold', () => {
      expect(severityGte('info', 'low')).toBe(false);
      expect(severityGte('low', 'medium')).toBe(false);
      expect(severityGte('medium', 'high')).toBe(false);
      expect(severityGte('high', 'critical')).toBe(false);
    });
  });

  describe('severityOrder', () => {
    it('orders severities correctly', () => {
      expect(severityOrder('critical')).toBeLessThan(severityOrder('high'));
      expect(severityOrder('high')).toBeLessThan(severityOrder('medium'));
      expect(severityOrder('medium')).toBeLessThan(severityOrder('low'));
      expect(severityOrder('low')).toBeLessThan(severityOrder('info'));
    });
  });

  describe('SEVERITY_LABELS', () => {
    it('has labels for all severities', () => {
      const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
      for (const s of severities) {
        expect(SEVERITY_LABELS[s]).toBeTruthy();
      }
    });
  });

  describe('SEVERITY_COLORS', () => {
    it('has color functions for all severities', () => {
      const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
      for (const s of severities) {
        expect(typeof SEVERITY_COLORS[s]).toBe('function');
      }
    });
  });
});