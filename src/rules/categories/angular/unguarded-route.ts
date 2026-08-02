import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import type { Finding } from '../../../rules/types';

const SENSITIVE_PATHS = /^(admin|dashboard|settings|account|billing|users|config|manage)(\/|$)/i;
const GUARD_PROPS = new Set(['canActivate', 'canActivateChild', 'canMatch', 'canLoad']);
// A bare `{ path, label }` is a nav-menu entry, not a Route. Requiring one of these
// keeps the rule on real route definitions.
const ROUTE_PROPS = new Set(['component', 'loadComponent', 'loadChildren', 'redirectTo', 'children']);

export const NG006 = defineRule({
  id: 'NG-006',
  name: 'Sensitive Route Without Guard',
  description: 'Detects Angular route definitions for sensitive paths (admin, dashboard, settings...) that have no canActivate/canMatch guard.',
  category: 'auth',
  severity: 'medium',
  frameworks: ['angular'],
  tags: ['owasp:a1', 'cwe:306', 'angular'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isObjectLiteralExpression(node)) {
        let path: string | undefined;
        let hasGuard = false;
        let isRoute = false;
        for (const prop of node.properties) {
          if (!ts.isPropertyAssignment(prop)) continue;
          const key = prop.name.getText(ctx.sourceFile);
          if (key === 'path' && ts.isStringLiteral(prop.initializer)) path = prop.initializer.text;
          if (GUARD_PROPS.has(key)) hasGuard = true;
          if (ROUTE_PROPS.has(key)) isRoute = true;
        }
        if (isRoute && path !== undefined && SENSITIVE_PATHS.test(path) && !hasGuard) {
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          findings.push({
            ruleId: 'NG-006',
            ruleName: 'Sensitive Route Without Guard',
            category: 'auth',
            severity: 'medium',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + node.getText(ctx.sourceFile).length,
            message: `Route "${path}" is sensitive but has no canActivate/canMatch guard.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Protect the route with a canActivate/canMatch guard that enforces authentication/authorization.',
            references: ['https://angular.dev/guide/routing/common-router-tasks#preventing-unauthorized-access', 'https://cwe.mitre.org/data/definitions/306.html'],
            confidence: 'low',
          });
        }
      }
      return 'continue';
    });

    return findings;
  },
});
