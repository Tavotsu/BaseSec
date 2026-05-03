import type { Rule } from './types';

export class RuleRegistry {
  private rules: Map<string, Rule> = new Map();

  register(rule: Rule): void {
    this.rules.set(rule.id, rule);
  }

  registerMany(rules: Rule[]): void {
    for (const rule of rules) {
      this.register(rule);
    }
  }

  get(id: string): Rule | undefined {
    return this.rules.get(id);
  }

  getByCategory(category: string): Rule[] {
    return [...this.rules.values()].filter((r) => r.category === category);
  }

  getByFramework(framework: string): Rule[] {
    return [...this.rules.values()].filter(
      (r) => r.frameworks.includes('*') || r.frameworks.includes(framework as any),
    );
  }

  getAll(): Rule[] {
    return [...this.rules.values()];
  }

  getIds(): string[] {
    return [...this.rules.keys()];
  }
}

export const registry = new RuleRegistry();