import express from 'express';
import usersRouter from './users';

const router = express.Router();

router.use('/users', usersRouter);
router.use('/legacy', require('./legacy'));

export { router as apiRouter };
