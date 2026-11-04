import { header } from '../rules/helpers';
import { logger } from '../../utils/logger';
import { detected, notDetected } from './types';
import type { OracleInput, OracleResult } from './types';

/**
 * Open redirect. El ataque debe ser un 3xx cuyo `Location` apunta a un HOST distinto del target y ese host lleva el
 * canario (`bs-<canario>`, el host del payload). Que el canario aparezca solo en la ruta o en la query de la
 * redirección no basta: un login que manda a un IdP externo con `?return=<valor>` no es un open redirect. Confianza
 * `medium`. El runner pide con followRedirects:false, así que `attack.url` es el destino de la petición.
 */
export function redirectOracle(input: OracleInput): OracleResult {
  const { attack, canary } = input;
  if (attack.status < 300 || attack.status > 399) return notDetected('the response is not a redirect');
  const location = header(attack, 'location');
  if (location === undefined || location.trim() === '') return notDetected('no Location header');

  try {
    const targetHost = new URL(attack.url).host;
    const locationHost = new URL(location.trim(), attack.url).host;
    if (locationHost === targetHost) return notDetected('the redirect stays on the same host');
    if (!locationHost.toLowerCase().includes(`bs-${canary.toLowerCase()}`)) {
      return notDetected('the redirect host does not carry the canary');
    }
    return detected('redirect to a host other than the target that contains the canary', 'medium');
  } catch (e) {
    logger.warn('No se pudo interpretar el Location de la redirección', e);
    return notDetected('Location is not parseable');
  }
}
