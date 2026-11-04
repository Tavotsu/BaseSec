import type { Request } from 'express';
import { queryUser } from '../db/users';

export function findUser(req: Request) {
  return queryUser(req);
}
