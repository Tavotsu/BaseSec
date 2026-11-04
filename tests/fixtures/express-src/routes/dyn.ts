import express from 'express';

const SEGMENT = '/dynamic';
const dyn = express.Router();

dyn.get(SEGMENT, (req, res) => {
  res.send('dynamic path');
});

export default dyn;
