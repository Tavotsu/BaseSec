import express from 'express';

const orphan = express.Router();

orphan.get('/secret', (req, res) => {
  res.send('never mounted');
});

export default orphan;
