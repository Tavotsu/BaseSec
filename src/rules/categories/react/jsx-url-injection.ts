import * as ts from 'typescript';
import { defineRule } from '../../define-rule';
import { getLineAndColumn, getCodeSnippet, visit } from '../../../utils/ast-helpers';
import { isStaticLiteral } from '../../../framework/frontend';
import { resolveConfidence } from '../../../taint/integration';
import type { Finding } from '../../../rules/types';

// href/src only: `action`/`formAction` frequently carry Next.js server-action
// functions, not URLs — flagging them is a false positive.
const URL_ATTRS = new Set(['href', 'src']);

// A javascript: URI only executes when the browser navigates to it or loads it as a
// document. `src` on a media element is fetched as data, so <img src={url}> is not
// the vector this rule describes. Custom components (<Link href>) stay in scope
// because they usually render an <a>.
const MEDIA_SRC_TAGS = new Set(['img', 'video', 'audio', 'source', 'track', 'picture', 'image']);

function jsxTagName(attr: ts.JsxAttribute, sourceFile: ts.SourceFile): string {
  const owner = attr.parent?.parent;
  return owner && (ts.isJsxOpeningElement(owner) || ts.isJsxSelfClosingElement(owner))
    ? owner.tagName.getText(sourceFile)
    : '';
}

export const REACT002 = defineRule({
  id: 'REACT-002',
  name: 'Unvalidated URL in JSX href/src',
  description: 'Detects JSX href/src attributes bound to a dynamic expression without validation, allowing javascript: URI injection.',
  category: 'xss',
  severity: 'high',
  frameworks: ['react', 'nextjs'],
  tags: ['owasp:a3', 'cwe:79', 'react'],
  detect(ctx) {
    const findings: Finding[] = [];

    visit(ctx.sourceFile, (node) => {
      if (ts.isJsxAttribute(node) && URL_ATTRS.has(node.name.getText(ctx.sourceFile))) {
        const attrName = node.name.getText(ctx.sourceFile);
        if (attrName === 'src' && MEDIA_SRC_TAGS.has(jsxTagName(node, ctx.sourceFile))) {
          return 'continue';
        }
        const init = node.initializer;
        if (init && ts.isJsxExpression(init) && init.expression && !isStaticLiteral(init.expression)) {
          const argText = init.expression.getText(ctx.sourceFile);
          const { line, column } = getLineAndColumn(ctx.sourceFile, node);
          findings.push({
            ruleId: 'REACT-002',
            ruleName: 'Unvalidated URL in JSX href/src',
            category: 'xss',
            severity: 'high',
            filePath: ctx.filePath,
            line,
            column,
            endLine: line,
            endColumn: column + node.getText(ctx.sourceFile).length,
            message: `JSX \`${node.name.getText(ctx.sourceFile)}\` bound to a dynamic value may allow a javascript: URI.`,
            codeSnippet: getCodeSnippet(ctx.content, line),
            remediation: 'Validate the URL scheme (allow only http/https/mailto) before using it in href/src.',
            references: ['https://owasp.org/www-community/attacks/xss/', 'https://cwe.mitre.org/data/definitions/79.html'],
            confidence: resolveConfidence(ctx.taintGraph, argText, 'medium'),
          });
        }
      }
      return 'continue';
    });

    return findings;
  },
});
