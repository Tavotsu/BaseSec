import type { OutputFormat, Severity } from '../rules/types';

export const VALID_FORMATS: OutputFormat[] = ['terminal', 'json', 'sarif', 'html', 'markdown'];
export const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
