import type { DastRule } from '../types';
import { dynamicFinding } from '../probe';
import { logger } from '../../utils/logger';
import {
  cspPolicies,
  hasValue,
  header,
  isHtmlResponse,
  parseCsp,
  safeText,
  usableObservations,
} from './helpers';

const SERVER_VERSION = /\/\d|\d+\.\d+/;

interface ScriptVerdict {
  /** true si esta política limita de verdad la ejecución de scripts. */
  restricts: boolean;
  directive: string;
  weak: string[];
}

/**
 * Evalúa una política para scripts. Directiva efectiva: script-src, o default-src si no existe; sin ninguna
 * de las dos los scripts no están restringidos. Por CSP3, con nonce, hash o 'strict-dynamic' en la lista el
 * navegador ignora 'unsafe-inline' (y con 'strict-dynamic' también '*'), así que no debilitan. 'unsafe-eval'
 * sí sigue contando.
 */
function scriptVerdict(policy: string): ScriptVerdict {
  const directives = parseCsp(policy);
  const directive = directives.has('script-src') ? 'script-src' : 'default-src';
  const sources = directives.get(directive);
  if (sources === undefined) return { restricts: false, directive, weak: [] };

  const lowered = sources.map((source) => source.toLowerCase());
  const strictDynamic = lowered.includes("'strict-dynamic'");
  const hasNonceOrHash = strictDynamic || lowered.some((s) => /^'(?:nonce-|sha(?:256|384|512)-)/.test(s));
  const weak = sources.filter((source, index) => {
    const token = lowered[index];
    if (token === "'unsafe-inline'") return !hasNonceOrHash;
    if (token === '*') return !strictDynamic;
    return token === "'unsafe-eval'";
  });
  return { restricts: weak.length === 0, directive, weak };
}

export const DAST001: DastRule = {
  id: 'DAST-001',
  name: 'Missing security headers',
  description:
    'HTML responses lack X-Content-Type-Options, X-Frame-Options (or CSP frame-ancestors) or Referrer-Policy.',
  category: 'misconfiguration',
  severity: 'medium',
  once: true,
  async probe(ctx) {
    try {
      const observation = usableObservations(ctx.observations).find((o) => isHtmlResponse(o.response));
      if (!observation) return [];
      const { response } = observation;

      const missing: string[] = [];
      if ((header(response, 'x-content-type-options') ?? '').trim().toLowerCase() !== 'nosniff') {
        missing.push('X-Content-Type-Options');
      }
      const hasFrameAncestors = cspPolicies(response).some((policy) => parseCsp(policy).has('frame-ancestors'));
      if (!hasValue(header(response, 'x-frame-options')) && !hasFrameAncestors) {
        missing.push('X-Frame-Options or CSP frame-ancestors');
      }
      if (!hasValue(header(response, 'referrer-policy'))) {
        missing.push('Referrer-Policy');
      }
      if (missing.length === 0) return [];

      return [
        dynamicFinding({
          rule: DAST001,
          confidence: 'high',
          endpoint: ctx.target.origin,
          message: `HTML response is missing security headers: ${missing.join(', ')}.`,
          remediation:
            'Add X-Content-Type-Options: nosniff, Referrer-Policy, and either X-Frame-Options or a CSP frame-ancestors directive. In Express, helmet() sets them.',
          references: [
            'https://cwe.mitre.org/data/definitions/693.html',
            'https://owasp.org/www-project-secure-headers/',
          ],
          codeSnippet: `content-type: ${header(response, 'content-type') ?? ''}`,
          observation,
          knownSecrets: ctx.knownSecrets,
        }),
      ];
    } catch (e) {
      logger.warn('DAST-001 no pudo evaluarse', e);
      return [];
    }
  },
};

export const DAST002: DastRule = {
  id: 'DAST-002',
  name: 'Missing HSTS',
  description: 'HTTPS responses lack a Strict-Transport-Security header with a positive max-age.',
  category: 'misconfiguration',
  severity: 'medium',
  once: true,
  async probe(ctx) {
    try {
      if (!ctx.target.https) return [];
      const observation = usableObservations(ctx.observations)[0];
      if (!observation) return [];
      const { response } = observation;

      const hsts = header(response, 'strict-transport-security');
      let message: string;
      if (hasValue(hsts)) {
        const maxAge = /max-age\s*=\s*"?(\d+)"?/i.exec(hsts);
        if (maxAge !== null && Number(maxAge[1]) > 0) return [];
        message = 'Strict-Transport-Security has max-age=0 or an unparseable max-age.';
      } else {
        message = 'HTTPS response lacks the Strict-Transport-Security header.';
      }

      return [
        dynamicFinding({
          rule: DAST002,
          confidence: 'high',
          endpoint: ctx.target.origin,
          message,
          remediation:
            'Send Strict-Transport-Security with a max-age of at least one year (e.g. "max-age=31536000; includeSubDomains"). In Express, helmet() sets it.',
          references: [
            'https://cwe.mitre.org/data/definitions/319.html',
            'https://owasp.org/www-project-secure-headers/',
          ],
          codeSnippet: hasValue(hsts)
            ? `strict-transport-security: ${hsts}`
            : `HTTP ${response.status} ${observation.url}`,
          observation,
          knownSecrets: ctx.knownSecrets,
        }),
      ];
    } catch (e) {
      logger.warn('DAST-002 no pudo evaluarse', e);
      return [];
    }
  },
};

export const DAST003: DastRule = {
  id: 'DAST-003',
  name: 'Missing or weak Content-Security-Policy',
  description:
    'HTML responses lack a Content-Security-Policy, or script-src (or default-src) allows unsafe-inline, unsafe-eval or a bare wildcard.',
  category: 'misconfiguration',
  severity: 'medium',
  once: true,
  async probe(ctx) {
    try {
      const observation = usableObservations(ctx.observations).find((o) => isHtmlResponse(o.response));
      if (!observation) return [];
      const { response } = observation;

      const policies = cspPolicies(response);
      let message: string;
      let codeSnippet: string;
      if (policies.length === 0) {
        message = 'HTML response has no Content-Security-Policy header.';
        codeSnippet = `content-type: ${header(response, 'content-type') ?? ''}`;
      } else {
        // El navegador aplica todas las políticas: los scripts solo quedan sin proteger si NINGUNA los restringe.
        const verdicts = policies.map(scriptVerdict);
        if (verdicts.some((verdict) => verdict.restricts)) return [];
        const weak = verdicts.find((verdict) => verdict.weak.length > 0);
        message = weak
          ? `Content-Security-Policy is weak: ${weak.directive} allows ${weak.weak.join(', ')}.`
          : 'Content-Security-Policy does not restrict scripts: it has neither script-src nor default-src.';
        codeSnippet = `content-security-policy: ${header(response, 'content-security-policy') ?? ''}`;
      }

      return [
        dynamicFinding({
          rule: DAST003,
          confidence: 'high',
          endpoint: ctx.target.origin,
          message,
          remediation:
            "Send a Content-Security-Policy whose script-src avoids 'unsafe-inline', 'unsafe-eval' and '*' (use nonces or hashes). Content-Security-Policy-Report-Only does not enforce anything.",
          references: [
            'https://cwe.mitre.org/data/definitions/1021.html',
            'https://cwe.mitre.org/data/definitions/79.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
          ],
          codeSnippet,
          observation,
          knownSecrets: ctx.knownSecrets,
        }),
      ];
    } catch (e) {
      logger.warn('DAST-003 no pudo evaluarse', e);
      return [];
    }
  },
};

export const DAST007: DastRule = {
  id: 'DAST-007',
  name: 'Server banner leakage',
  description: 'Responses disclose the framework (X-Powered-By) or the server software version (Server header).',
  category: 'misconfiguration',
  severity: 'low',
  once: true,
  async probe(ctx) {
    try {
      for (const observation of usableObservations(ctx.observations)) {
        const { response } = observation;
        const poweredBy = header(response, 'x-powered-by');
        if (hasValue(poweredBy)) {
          return [
            dynamicFinding({
              rule: DAST007,
              confidence: 'high',
              endpoint: ctx.target.origin,
              message: `Response discloses the framework via X-Powered-By: ${safeText(poweredBy)}.`,
              remediation:
                'Remove the X-Powered-By header (app.disable("x-powered-by") in Express) and configure the server to hide its version in the Server header.',
              references: [
                'https://cwe.mitre.org/data/definitions/200.html',
                'https://owasp.org/www-project-secure-headers/',
              ],
              codeSnippet: `x-powered-by: ${poweredBy}`,
              observation,
              knownSecrets: ctx.knownSecrets,
            }),
          ];
        }
        const server = header(response, 'server');
        if (hasValue(server) && SERVER_VERSION.test(server)) {
          return [
            dynamicFinding({
              rule: DAST007,
              confidence: 'high',
              endpoint: ctx.target.origin,
              message: `Response discloses the server version via Server: ${safeText(server)}.`,
              remediation:
                'Configure the web server or reverse proxy to hide its version in the Server header (e.g. nginx: server_tokens off).',
              references: [
                'https://cwe.mitre.org/data/definitions/200.html',
                'https://owasp.org/www-project-secure-headers/',
              ],
              codeSnippet: `server: ${server}`,
              observation,
              knownSecrets: ctx.knownSecrets,
            }),
          ];
        }
      }
      return [];
    } catch (e) {
      logger.warn('DAST-007 no pudo evaluarse', e);
      return [];
    }
  },
};
