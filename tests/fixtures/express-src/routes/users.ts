import express from 'express';
import { getUser } from '../controllers/users';
import { requireAuth } from '../middleware/auth';
import { pool } from '../db/pool';

const router = express.Router();

router.get('/:id', requireAuth, getUser);

router.post('/', (req, res) => {
  const { email, name } = req.body;
  pool.query("INSERT INTO users (email, name) VALUES ('" + req.body.email + "', '" + name + "')");
  res.status(201).json({ email, name });
});

export default router;
