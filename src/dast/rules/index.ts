import type { DastRule } from '../types';
import { DAST001, DAST002, DAST003, DAST007 } from './headers';
import { DAST004 } from './cors';
import { DAST005 } from './cookies';
import { DAST006 } from './errors';

/** Reglas de inspección DAST (sin payloads). Se ejecutan por separado de ALL_RULES (SAST). */
export const ALL_DAST_RULES: DastRule[] = [DAST001, DAST002, DAST003, DAST004, DAST005, DAST006, DAST007];
