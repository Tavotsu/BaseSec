import type { Request } from 'express';
import { pool } from './pool';

export function queryUser(req: Request) {
  return pool.query('SELECT * FROM users WHERE id = ' + req.params.id);
}
