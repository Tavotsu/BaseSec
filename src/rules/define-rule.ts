import type { Rule, RuleCategory, Severity, Framework, Confidence } from './types';

interface RuleDefinition {
  id: string;
  name: string;
  description: string;
  category: RuleCategory;
  severity: Severity;
  frameworks: Framework[];
  tags: string[];
  detect: (ctx: import('./types').RuleContext) => import('./types').Finding[];
}

export function defineRule(def: RuleDefinition): Rule {
  return def;
}