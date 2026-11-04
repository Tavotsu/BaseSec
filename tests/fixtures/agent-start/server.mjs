// App de prueba para --start: anota su entorno, lanza un nieto en su mismo grupo y responde en BS_TEST_PORT.
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import { spawn } from 'node:child_process';

const out = process.env.BS_TEST_OUT;
fs.writeFileSync(
  path.join(out, 'env.json'),
  JSON.stringify({ NODE_OPTIONS: process.env.NODE_OPTIONS ?? '', agentDir: process.env.BASESEC_AGENT_DIR ?? '' }),
);
const grandchild = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
fs.writeFileSync(path.join(out, 'grandchild.pid'), String(grandchild.pid));
http.createServer((_req, res) => res.end('ok')).listen(Number(process.env.BS_TEST_PORT), '127.0.0.1');
