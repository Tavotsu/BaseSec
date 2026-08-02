import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import type { Finding } from '../../../rules/types';

const PUBLIC_PREFIX = /^(NEXT_PUBLIC_|VITE_|REACT_APP_)/;
// Nothing named this way is ever meant to reach the browser bundle.
const STRONG_SECRET = /(SECRET|PRIVATE|PASSWORD|PASSWD|CREDENTIAL)/i;
// Ambiguous: publishable/anon/site keys are shipped to the browser on purpose and
// use exactly these words, so a bare `_KEY`/`TOKEN` match is only a weak signal.
const WEAK_SECRET = /(_KEY|APIKEY|API_KEY|TOKEN)/i;
// ponytail: name-based allowlist for the vendor keys that are public by design.
// Upgrade path: resolve the value's usage (server vs client component) if this
// list starts needing an entry per SaaS vendor.
const PUBLIC_BY_DESIGN = /(PUBLISHABLE|ANON|SITE_KEY|PUBLIC_KEY|CLIENT_ID|MEASUREMENT_ID|SENTRY_DSN|FIREBASE|POSTHOG|MAPBOX|RECAPTCHA|TURNSTILE|ALGOLIA_SEARCH|GTM_|_GA_)/i;

export const NEXT001 = defineRule({
  id: 'NEXT-001',
  name: 'Secret Exposed via Public Env Prefix',
  description: 'Detects secrets read from NEXT_PUBLIC_/VITE_/REACT_APP_ env vars, which are inlined into the client bundle.',
  category: 'secrets',
  severity: 'critical',
  frameworks: ['react', 'nextjs'],
  tags: ['owasp:a2', 'cwe:200', 'secrets'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isPropertyAccessExpression(node)) {
        const envVar = node.name.text;
        const base = node.expression.getText(ctx.sourceFile);
        const isEnvAccess = base === 'process.env' || base === 'import.meta.env';
        if (!isEnvAccess || !PUBLIC_PREFIX.test(envVar)) return 'continue';

        const strong = STRONG_SECRET.test(envVar);
        if (!strong && (PUBLIC_BY_DESIGN.test(envVar) || !WEAK_SECRET.test(envVar))) return 'continue';

        {
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          findings.push({
            ruleId: 'NEXT-001',
            ruleName: 'Secret Exposed via Public Env Prefix',
            category: 'secrets',
            severity: strong ? 'critical' : 'medium',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + node.getText(ctx.sourceFile).length,
            message: strong
              ? `\`${envVar}\` is a public env var (inlined into the browser bundle) but is named as a secret.`
              : `\`${envVar}\` is inlined into the browser bundle — confirm this key is safe to publish.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Move secrets to a server-only env var (no NEXT_PUBLIC_/VITE_/REACT_APP_ prefix) and access them server-side.',
            references: ['https://nextjs.org/docs/app/building-your-application/configuring/environment-variables', 'https://cwe.mitre.org/data/definitions/200.html'],
            confidence: strong ? 'high' : 'low',
          });
        }
      }
      return 'continue';
    });

    return findings;
  },
});
