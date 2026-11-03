import type { Finding } from '../../rules/types';
import type { DastRule } from '../types';
import { dynamicFinding } from '../probe';
import { logger } from '../../utils/logger';
import { headerValues, safeText, usableObservations } from './helpers';

interface CookieIssue {
  /** Solo el nombre: nunca el valor. */
  name: string;
  missing: string[];
  /** Línea Set-Cookie original (la evidencia la redacta después). */
  line: string;
}

/** Cookies que el servidor borra (Max-Age <= 0 o Expires en el pasado) no se evalúan. */
function isDeletion(attributes: Map<string, string>): boolean {
  const maxAge = attributes.get('max-age');
  // Max-Age manda sobre Expires (RFC 6265 §5.3): si es válido, Expires se ignora.
  if (maxAge !== undefined && /^-?\d+$/.test(maxAge)) return Number(maxAge) <= 0;
  const expires = attributes.get('expires');
  if (expires !== undefined) {
    const time = Date.parse(expires);
    if (!Number.isNaN(time) && time < Date.now()) return true;
  }
  return false;
}

function cookieIssues(setCookieLines: string[], https: boolean): CookieIssue[] {
  const issues: CookieIssue[] = [];
  for (const line of setCookieLines) {
    const [pair, ...attributeParts] = line.split(';');
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    const name = pair.slice(0, eq).trim();

    const attributes = new Map<string, string>();
    for (const part of attributeParts) {
      const sep = part.indexOf('=');
      const key = (sep === -1 ? part : part.slice(0, sep)).trim().toLowerCase();
      attributes.set(key, sep === -1 ? '' : part.slice(sep + 1).trim());
    }
    if (isDeletion(attributes)) continue;

    const missing: string[] = [];
    if (!attributes.has('httponly')) missing.push('HttpOnly');
    if (!attributes.has('samesite')) missing.push('SameSite');
    if (https && !attributes.has('secure')) missing.push('Secure');
    if (missing.length > 0) issues.push({ name, missing, line });
  }
  return issues;
}

export const DAST005: DastRule = {
  id: 'DAST-005',
  name: 'Insecure cookie flags',
  description: 'Set-Cookie lacks HttpOnly or SameSite, or lacks Secure over HTTPS.',
  category: 'misconfiguration',
  severity: 'high',
  once: false,
  async probe(ctx) {
    try {
      const findings: Finding[] = [];
      for (const observation of usableObservations(ctx.observations)) {
        const issues = cookieIssues(headerValues(observation.response, 'set-cookie'), ctx.target.https);
        if (issues.length === 0) continue;

        const summary = issues.map((issue) => `${safeText(issue.name, 60)} (missing ${issue.missing.join(', ')})`).join('; ');
        findings.push(
          dynamicFinding({
            rule: DAST005,
            confidence: 'high',
            endpoint: observation.endpoint,
            message: `Cookies set without security flags: ${summary}.`,
            remediation:
              'Set HttpOnly and SameSite (Lax or Strict) on session cookies, and Secure when served over HTTPS. In Express with express-session use cookie: { httpOnly: true, sameSite: "lax", secure: true }.',
            references: [
              'https://cwe.mitre.org/data/definitions/1004.html',
              'https://cwe.mitre.org/data/definitions/614.html',
            ],
            codeSnippet: `set-cookie: ${issues[0].line}`,
            observation,
            knownSecrets: ctx.knownSecrets,
          }),
        );
      }
      return findings;
    } catch (e) {
      logger.warn('DAST-005 no pudo evaluarse', e);
      return [];
    }
  },
};
