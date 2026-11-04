import type { Request, Response } from 'express';
import { findUser } from '../services/users';

export function getUser(req: Request, res: Response): void {
  const user = findUser(req);
  res.json(user);
}
