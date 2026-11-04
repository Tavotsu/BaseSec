import express from 'express';
import { apiRouter } from './routes/index';

const app = express();

app.use(express.json());
app.use('/api', apiRouter);

app.route('/health')
  .get((req, res) => res.json({ ok: true }))
  .head((req, res) => res.end());

export default app;
