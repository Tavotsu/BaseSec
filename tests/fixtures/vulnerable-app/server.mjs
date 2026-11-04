// Aplicación de prueba con node:http puro para la inyección activa de DAST (plan §11, fase 3).
// Determinista y local: cada endpoint vulnerable tiene un único comportamiento observable.
//
//   GET /users?id=        ' → 500 con firma de pg; si no, 200 {"ok":true}          (SQLi error → DAST-101)
//   GET /users/:id        igual que /users?id= pero el valor va en el path          (SQLi error en path)
//   GET /search?q=        refleja q sin escapar en <p>, content-type HTML            (XSS → DAST-105)
//   GET /safe?q=          refleja q escapado (&lt;)                                  (control: sin XSS)
//   GET /file?name=       ".." + "passwd" → /etc/passwd; ".." + "win.ini" → win.ini (path traversal → DAST-104)
//   GET /ping?host=       "sleep <n>" o "SLEEP(<n>)" → duerme min(n, 2) s            (timing → DAST-101/103)
//   GET /slow?x=          siempre tarda 1,2 s                                        (control: sin timing)
//   GET /items?role=      role[$ne]=x (objeto) devuelve todos los items              (NoSQLi diff → DAST-102)
//   GET /go?url=          302 con Location: url tal cual                             (open redirect → DAST-011)
//
// Controles (NO deben dar hallazgo), uno por oráculo:
//   GET /json?q=          refleja q sin escapar pero en application/json            (reflection: no es HTML)
//   GET /attr?q=          refleja q ESCAPADO dentro de un atributo                   (reflection: escapado)
//   GET /sanitize?q=      quita ; | $ ( ) < > " ' y refleja en HTML                  (reflection/echo: recortado)
//   GET /help?q=          200 con "syntax error at or near" también sin payload      (sql-error: ya en el baseline)
//   GET /docs?name=       200 con root:x:0:0: también sin payload                    (signature: ya en el baseline)
//   GET /flaky?x=         solo la PRIMERA petición con "sleep"/"SLEEP" tarda 1,2 s   (timing: una sola medición lenta)
//   GET /vary?x=          la longitud del body cambia en cada petición               (diff: variación natural)
//   GET /crash?role=      500 si role llega como objeto (role[$ne]=x)               (diff: error de tipo, no inyección)
//   GET /login?next=      302 a https://sso.example.org/login?return=<next>          (redirect: canario solo en la query)
//   GET /pair?a=&b=       el ' en b da el error pg; a se ignora                      (un finding, nombra b)
//   GET /dual?a=&b=       el ' en a O en b da el error pg                            (un finding por endpoint y clase)
//   GET /reflect?q=       refleja q sin escapar y, además, la cabecera Authorization (fuga de secretos)
//
// Sin stack traces. El servidor guarda el registro de peticiones para que los tests comprueben qué se envió.
import * as http from 'node:http';
import { pathToFileURL } from 'node:url';

const ITEMS = [{ role: 'user' }, { role: 'admin' }, { role: 'guest' }, { role: 'user' }];
const SLEEP = /sleep(?:\s+|\()(\d+)/i;
const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
let flakyHit = false;
let varyCount = 0;
const BRACKET = /^([A-Za-z_]\w*)\[(\$\w+)\]$/;

function escapeHtml(text) {
  return text.replace(/[&<>"']/g, (char) => ESCAPES[char]);
}

/** Subconjunto de la notación qs: `name=v` es un string; `name[$op]=v` es un objeto { $op: v }. */
function parseQuery(search) {
  const out = new Map();
  for (const [key, value] of new URLSearchParams(search)) {
    const bracket = BRACKET.exec(key);
    if (bracket) {
      const current = out.get(bracket[1]);
      const object = typeof current === 'object' && current !== null ? current : {};
      object[bracket[2]] = value;
      out.set(bracket[1], object);
    } else if (!out.has(key)) {
      out.set(key, value);
    }
  }
  return out;
}

/** Texto de un parámetro. Un objeto se convierte en "[object Object]", como haría una plantilla sin validar. */
function asText(value) {
  return value === undefined ? '' : String(value);
}

function safeDecode(segment) {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function send(res, status, contentType, body) {
  res.writeHead(status, { 'content-type': contentType });
  res.end(body);
}

function sendJson(res, status, value) {
  send(res, status, 'application/json; charset=utf-8', JSON.stringify(value));
}

async function handle(req, res, url) {
  const query = parseQuery(url.search);
  const path = url.pathname;

  if (path === '/') {
    send(res, 200, 'text/html; charset=utf-8', '<html><body>vulnerable fixture</body></html>');
    return;
  }

  if (path === '/users' || path.startsWith('/users/')) {
    const id = path === '/users' ? asText(query.get('id')) : safeDecode(path.slice('/users/'.length));
    if (id.includes("'")) {
      send(res, 500, 'text/plain; charset=utf-8', 'syntax error at or near "\'"');
      return;
    }
    sendJson(res, 200, { ok: true });
    return;
  }

  if (path === '/json') {
    send(res, 200, 'application/json; charset=utf-8', `{"q":"${asText(query.get('q'))}"}`);
    return;
  }

  if (path === '/attr') {
    send(res, 200, 'text/html; charset=utf-8', `<html><body><input value="${escapeHtml(asText(query.get('q')))}"></body></html>`);
    return;
  }

  if (path === '/sanitize') {
    const cleaned = asText(query.get('q')).replace(/[;|$()<>"']/g, '');
    send(res, 200, 'text/html; charset=utf-8', `<html><body><p>${cleaned}</p></body></html>`);
    return;
  }

  if (path === '/help') {
    send(res, 200, 'text/html; charset=utf-8', '<html><body><p>Help: a syntax error at or near a quote means the query is malformed.</p></body></html>');
    return;
  }

  if (path === '/docs') {
    send(res, 200, 'text/plain; charset=utf-8', 'Example passwd line: root:x:0:0:root:/root:/bin/bash\n');
    return;
  }

  if (path === '/flaky') {
    if (SLEEP.test(asText(query.get('x'))) && !flakyHit) {
      flakyHit = true;
      await sleep(1200);
    }
    sendJson(res, 200, { ok: true });
    return;
  }

  if (path === '/vary') {
    varyCount++;
    sendJson(res, 200, { filler: 'z'.repeat(((varyCount * 137) % 700) + 50) });
    return;
  }

  if (path === '/crash') {
    const role = query.get('role');
    if (typeof role === 'object' && role !== null) {
      send(res, 500, 'text/plain; charset=utf-8', 'TypeError: role.trim is not a function');
      return;
    }
    sendJson(res, 200, { ok: true });
    return;
  }

  if (path === '/login') {
    const next = asText(query.get('next'));
    res.writeHead(302, { location: `https://sso.example.org/login?return=${encodeURIComponent(next)}` });
    res.end('Found');
    return;
  }

  if (path === '/pair' || path === '/dual') {
    const a = asText(query.get('a'));
    const b = asText(query.get('b'));
    const broken = path === '/pair' ? b.includes("'") : a.includes("'") || b.includes("'");
    if (broken) {
      send(res, 500, 'text/plain; charset=utf-8', 'syntax error at or near "\'"');
      return;
    }
    sendJson(res, 200, { ok: true });
    return;
  }

  if (path === '/reflect') {
    const auth = String(req.headers.authorization ?? '');
    send(res, 200, 'text/html; charset=utf-8', `<html><body><p>${asText(query.get('q'))}</p><!-- auth: ${auth} --></body></html>`);
    return;
  }

  if (path === '/search') {
    send(res, 200, 'text/html; charset=utf-8', `<html><body><p>${asText(query.get('q'))}</p></body></html>`);
    return;
  }

  if (path === '/safe') {
    send(res, 200, 'text/html; charset=utf-8', `<html><body><p>${escapeHtml(asText(query.get('q')))}</p></body></html>`);
    return;
  }

  if (path === '/file') {
    const name = asText(query.get('name'));
    if (name.includes('..') && name.endsWith('passwd')) {
      send(res, 200, 'text/plain; charset=utf-8', 'root:x:0:0:root:/root:/bin/bash\n');
    } else if (name.includes('..') && name.endsWith('win.ini')) {
      send(res, 200, 'text/plain; charset=utf-8', '; for 16-bit app support\n[fonts]\n[extensions]\n');
    } else {
      sendJson(res, 200, { ok: true });
    }
    return;
  }

  if (path === '/ping') {
    const match = SLEEP.exec(asText(query.get('host')));
    if (match) await sleep(Math.min(Number(match[1]), 2) * 1000);
    sendJson(res, 200, { ok: true });
    return;
  }

  if (path === '/slow') {
    await sleep(1200);
    sendJson(res, 200, { ok: true });
    return;
  }

  if (path === '/items') {
    const role = query.get('role');
    const items = typeof role === 'string' ? ITEMS.filter((item) => item.role === role) : ITEMS;
    sendJson(res, 200, items);
    return;
  }

  if (path === '/go') {
    const target = asText(query.get('url'));
    if (target === '') {
      sendJson(res, 200, { ok: true });
      return;
    }
    res.writeHead(302, { location: target, 'content-type': 'text/plain; charset=utf-8' });
    res.end('Found');
    return;
  }

  send(res, 404, 'text/plain; charset=utf-8', 'not found');
}

/** Crea la aplicación. start() escucha en 127.0.0.1 con puerto efímero y devuelve el origen. */
export function createVulnerableApp() {
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push(`${req.method} ${req.url ?? '/'}`);
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    handle(req, res, url).catch(() => {
      if (!res.headersSent) send(res, 500, 'text/plain; charset=utf-8', 'error');
    });
  });
  return {
    requests,
    /** Reinicia el estado de los controles con memoria (/flaky, /vary). */
    reset() {
      flakyHit = false;
      varyCount = 0;
    },
    start() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
          const address = server.address();
          resolve(`http://127.0.0.1:${address.port}`);
        });
      });
    },
    stop() {
      return new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      });
    },
  };
}

// Ejecución directa: `node tests/fixtures/vulnerable-app/server.mjs` arranca la app e imprime su origen.
if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const app = createVulnerableApp();
  const origin = await app.start();
  process.stdout.write(`vulnerable-app listening on ${origin}\n`);
  const shutdown = () => {
    app.stop().then(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
