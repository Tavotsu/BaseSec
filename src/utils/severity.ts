import type { Severity } from '../rules/types';
import pc from 'picocolors';

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

export const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  critical: pc.red,
  high: pc.red,
  medium: pc.yellow,
  low: pc.blue,
  info: pc.gray,
};