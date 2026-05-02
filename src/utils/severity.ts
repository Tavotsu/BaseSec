import type { Severity } from '../rules/types';

const SEVERITY_LEVELS: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function severityGte(a: Severity, b: Severity): boolean {
  return SEVERITY_LEVELS[a] <= SEVERITY_LEVELS[b];
}

export function severityOrder(s: Severity): number {
  return SEVERITY_LEVELS[s];
}

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '\x1b[91m',
  high: '\x1b[31m',
  medium: '\x1b[33m',
  low: '\x1b[34m',
  info: '\x1b[37m',
};

export const RESET = '\x1b[0m';