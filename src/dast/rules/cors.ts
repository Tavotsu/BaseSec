import { randomBytes } from 'node:crypto';
import type { DastObservation, DastRule, HttpResponse } from '../types';
import { BudgetExceededError } from '../types';
import type { Severity } from '../../rules/types';
import { dynamicFinding } from '../probe';
import { logger } from '../../utils/logger';
import { hasValue, header } from './helpers';

export const DAST004: DastRule = {
  id: 'DAST-004',
  name: 'Permissive CORS at runtime',
  description:
    'The runtime reflects an arbitrary Origin (or null, or *) in Access-Control-Allow-Origin while Access-Control-Allow-Credentials is true.',
  category: 'misconfiguration',
  severity: 'high',
  once: true,
  async probe(ctx) {
    // Origin que no puede ser legítimo: si el servidor lo refleja, acepta cualquier origen.
    const evilOrigin = `https://bs-${randomBytes(4).toString('hex')}.invalid`;
    const url = `${ctx.target.origin}/`;

    let response: HttpResponse;
    try {
      response = await ctx.client.request('GET', url, { headers: { Origin: evilOrigin } });
    } catch (e) {
      if (e instanceof BudgetExceededError) throw e;
      logger.warn('DAST-004: la petición de comprobación de CORS falló', e);
      return [];
    }

    try {
      if (response.status === 0) return [];
      const credentials = (header(response, 'access-control-allow-credentials') ?? '').trim().toLowerCase();
      const allowOrigin = (header(response, 'access-control-allow-origin') ?? '').trim();
      if (credentials !== 'true' || !hasValue(allowOrigin)) return [];

      let severity: Severity;
      let message: string;
      if (allowOrigin === evilOrigin) {
        severity = 'high';
        message = 'Runtime CORS reflects an arbitrary Origin with Access-Control-Allow-Credentials: true.';
      } else if (allowOrigin === 'null') {
        severity = 'high';
        message = 'Runtime CORS allows the "null" origin with Access-Control-Allow-Credentials: true.';
      } else if (allowOrigin === '*') {
        severity = 'medium';
        message =
          'Access-Control-Allow-Origin: * is combined with Access-Control-Allow-Credentials: true. Browsers reject this, but the configuration is broken.';
      } else {
        return [];
      }

      const observation: DastObservation = { endpoint: 'GET /', url, method: 'GET', response };
      return [
        dynamicFinding({
          rule: DAST004,
          severity,
          confidence: 'high',
          endpoint: ctx.target.origin,
          message,
          remediation:
            'Do not reflect the request Origin. Allow an explicit list of trusted origins, and only enable credentials for those. In Express, configure cors() with an allowlist instead of origin: true.',
          references: [
            'https://cwe.mitre.org/data/definitions/942.html',
            'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny',
          ],
          codeSnippet: `access-control-allow-origin: ${allowOrigin}`,
          observation,
          knownSecrets: ctx.knownSecrets,
        }),
      ];
    } catch (e) {
      logger.warn('DAST-004 no pudo evaluarse', e);
      return [];
    }
  },
};
