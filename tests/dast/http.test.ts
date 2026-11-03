import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as zlib from 'node:zlib';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { HttpClient } from '../../src/dast/http';
import { Guard } from '../../src/dast/guard';
import { BudgetExceededError, GuardError } from '../../src/dast/types';

const NINE_MB = 9 * 1024 * 1024;
const EIGHT_MB = 8 * 1024 * 1024;

let server: http.Server;
let base: string;
const hits: string[] = [];

function route(req: http.IncomingMessage, res: http.ServerResponse): void {
  const path = req.url ?? '/';
  switch (path) {
    case '/ok':
      res.writeHead(200, { 'content-type': 'text/plain' }).end('hello');
      return;
    case '/not-found':
      res.writeHead(404).end('nope');
      return;
    case '/redir-internal':
      res.writeHead(302, { location: `http://${req.headers.host}/ok` }).end();
      return;
    case '/redir-external':
      res.writeHead(302, { location: 'http://169.254.169.254/' }).end();
      return;
    case '/redir-loop':
      res.writeHead(302, { location: '/redir-loop' }).end();
      return;
    case '/set-cookie':
      res.writeHead(200, { 'set-cookie': 'sid=abc; Path=/; HttpOnly' }).end('set');
      return;
    case '/echo-cookie':
      res.writeHead(200).end(req.headers.cookie ?? '');
      return;
    case '/echo-header':
      res.writeHead(200).end(String(req.headers['x-test'] ?? ''));
      return;
    case '/mutate':
      res.writeHead(200).end(`${req.method} ok`);
      return;
    case '/hang':
      return;
    case '/gzip-big':
      res.writeHead(200, { 'content-encoding': 'gzip' }).end(zlib.gzipSync(Buffer.alloc(NINE_MB, 0x61)));
      return;
    case '/gzip-small':
      res.writeHead(200, { 'content-encoding': 'gzip' }).end(zlib.gzipSync('tiny body'));
      return;
    case '/br':
      res.writeHead(200, { 'content-encoding': 'br' }).end(zlib.brotliCompressSync(Buffer.from('hola br')));
      return;
    case '/unknown-encoding':
      res.writeHead(200, { 'content-encoding': 'x-custom' }).end('data');
      return;
    default:
      res.writeHead(404).end();
  }
}

beforeAll(async () => {
  server = http.createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`);
    route(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function makeClient(overrides: Partial<ConstructorParameters<typeof HttpClient>[0]> = {}): HttpClient {
  return new HttpClient({ guard: new Guard(), rps: 200, concurrency: 5, ...overrides });
}

describe('HttpClient basico', () => {
  it('una respuesta 200 con body devuelve status y body', async () => {
    const res = await makeClient().request('GET', `${base}/ok`);
    expect(res.status).toBe(200);
    expect(res.body).toBe('hello');
    expect(res.timedOut).toBe(false);
    expect(res.headers['content-type']).toBe('text/plain');
  });

  it('un 404 es una respuesta válida y no lanza', async () => {
    const res = await makeClient().request('GET', `${base}/not-found`);
    expect(res.status).toBe(404);
    expect(res.body).toBe('nope');
  });

  it('un host remoto se rechaza antes de emitir ninguna petición', async () => {
    const client = makeClient({ guard: new Guard({ resolver: async () => ['93.184.216.34'] }) });
    const before = hits.length;
    await expect(client.request('GET', 'http://remoto.test:8080/')).rejects.toMatchObject({
      code: 'remote-blocked',
    });
    expect(client.requestCount).toBe(0);
    expect(hits.length).toBe(before);
  });

  it('una IPv4 no canónica en la URL se rechaza sin emitir', async () => {
    const client = makeClient();
    await expect(client.request('GET', 'http://0177.0.0.1:1/')).rejects.toBeInstanceOf(GuardError);
    expect(client.requestCount).toBe(0);
  });

  it('un DELETE sin allowMutations nunca se emite', async () => {
    const client = makeClient();
    const before = hits.length;
    await expect(client.request('DELETE', `${base}/mutate`)).rejects.toMatchObject({ code: 'method-blocked' });
    expect(client.requestCount).toBe(0);
    expect(hits.slice(before)).toEqual([]);
  });

  it('un DELETE con allowMutations sí se emite', async () => {
    const client = makeClient({ guard: new Guard({ allowMutations: true }) });
    const res = await client.request('DELETE', `${base}/mutate`);
    expect(res.status).toBe(200);
    expect(res.body).toBe('DELETE ok');
  });

  it('cabeceras por defecto se fusionan y las de la petición ganan', async () => {
    const client = makeClient({ defaultHeaders: { 'x-test': 'default' } });
    expect((await client.request('GET', `${base}/echo-header`)).body).toBe('default');
    expect((await client.request('GET', `${base}/echo-header`, { headers: { 'X-Test': 'override' } })).body).toBe(
      'override',
    );
  });

  it('un timeout devuelve timedOut, status 0 y body vacío', async () => {
    const res = await makeClient({ requestTimeout: 100 }).request('GET', `${base}/hang`);
    expect(res.timedOut).toBe(true);
    expect(res.status).toBe(0);
    expect(res.body).toBe('');
  });
});

describe('HttpClient budget y rate limit', () => {
  it('con maxRequests 3, la cuarta petición lanza BudgetExceededError sin emitirse', async () => {
    const client = makeClient({ maxRequests: 3 });
    const before = hits.length;
    await client.request('GET', `${base}/ok`);
    await client.request('GET', `${base}/ok`);
    await client.request('GET', `${base}/ok`);
    await expect(client.request('GET', `${base}/ok`)).rejects.toBeInstanceOf(BudgetExceededError);
    expect(client.requestCount).toBe(3);
    expect(hits.length - before).toBe(3);
  });

  it('los saltos de redirect cuentan contra el presupuesto', async () => {
    const client = makeClient({ maxRequests: 1 });
    await expect(client.request('GET', `${base}/redir-internal`)).rejects.toBeInstanceOf(BudgetExceededError);
    expect(client.requestCount).toBe(1);
  });

  it('rps limita el espaciado entre peticiones', async () => {
    const client = makeClient({ rps: 5 });
    const started = Date.now();
    await Promise.all([
      client.request('GET', `${base}/ok`),
      client.request('GET', `${base}/ok`),
      client.request('GET', `${base}/ok`),
    ]);
    expect(Date.now() - started).toBeGreaterThanOrEqual(380);
  });
});

describe('HttpClient redirects', () => {
  it('un 302 a un host externo (metadata) no se sigue', async () => {
    const res = await makeClient().request('GET', `${base}/redir-external`);
    expect(res.status).toBe(302);
    expect(res.redirects).toEqual([]);
    expect(res.headers.location).toBe('http://169.254.169.254/');
  });

  it('un 302 interno se sigue y queda anotado', async () => {
    const res = await makeClient().request('GET', `${base}/redir-internal`);
    expect(res.status).toBe(200);
    expect(res.body).toBe('hello');
    expect(res.redirects).toHaveLength(1);
    expect(res.url).toBe(`${base}/ok`);
  });

  it('followRedirects false devuelve el 302 tal cual', async () => {
    const res = await makeClient().request('GET', `${base}/redir-internal`, { followRedirects: false });
    expect(res.status).toBe(302);
    expect(res.redirects).toEqual([]);
  });

  it('un bucle de redirects se corta en maxRedirects', async () => {
    const res = await makeClient({ maxRedirects: 3 }).request('GET', `${base}/redir-loop`);
    expect(res.status).toBe(302);
    expect(res.redirects).toHaveLength(3);
  });
});

describe('HttpClient decodificación del body', () => {
  it('gzip que descomprime a más de 8 MB se trunca y queda bodyDecoded', async () => {
    const res = await makeClient().request('GET', `${base}/gzip-big`);
    expect(res.bodyDecoded).toBe(true);
    expect(res.contentEncoding).toBe('gzip');
    expect(Buffer.byteLength(res.body)).toBe(EIGHT_MB);
  });

  it('gzip pequeño se descomprime completo', async () => {
    const res = await makeClient().request('GET', `${base}/gzip-small`);
    expect(res.body).toBe('tiny body');
    expect(res.bodyDecoded).toBe(true);
  });

  it('br se decodifica en un Node parcheado', async () => {
    const res = await makeClient().request('GET', `${base}/br`);
    expect(res.body).toBe('hola br');
    expect(res.bodyDecoded).toBe(true);
    expect(res.contentEncoding).toBe('br');
  });

  it('un content-encoding desconocido se trata como opaco', async () => {
    const res = await makeClient().request('GET', `${base}/unknown-encoding`);
    expect(res.body).toBe('');
    expect(res.bodyDecoded).toBe(false);
    expect(res.contentEncoding).toBe('x-custom');
  });

  it('el cliente envía accept-encoding gzip, deflate por defecto', async () => {
    let seen = '';
    const probe = http.createServer((req, res) => {
      seen = String(req.headers['accept-encoding'] ?? '');
      res.writeHead(200).end();
    });
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
    try {
      const port = (probe.address() as AddressInfo).port;
      await makeClient().request('GET', `http://127.0.0.1:${port}/`);
      expect(seen).toBe('gzip, deflate');
    } finally {
      await new Promise<void>((resolve) => probe.close(() => resolve()));
    }
  });
});

describe('HttpClient cookie jar', () => {
  it('reenvía al mismo host la cookie recibida en set-cookie', async () => {
    const client = makeClient();
    await client.request('GET', `${base}/set-cookie`);
    const res = await client.request('GET', `${base}/echo-cookie`);
    expect(res.body).toBe('sid=abc');
    expect(client.getCookies('127.0.0.1')).toBe('sid=abc');
  });

  it('un cliente nuevo no comparte el jar de otro', async () => {
    const res = await makeClient().request('GET', `${base}/echo-cookie`);
    expect(res.body).toBe('');
  });
});

describe('HttpClient endurecimiento (revisión de seguridad)', () => {
  interface Seen {
    method?: string;
    headers: http.IncomingHttpHeaders;
    url?: string;
  }
  const startProbe = async (
    handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
  ): Promise<{ server: http.Server; origin: string; close: () => Promise<void> }> => {
    const probe = http.createServer(handler);
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
    return {
      server: probe,
      origin: `http://127.0.0.1:${(probe.address() as AddressInfo).port}`,
      close: () => {
        probe.closeAllConnections();
        return new Promise<void>((resolve) => probe.close(() => resolve()));
      },
    };
  };

  it('un body identity enorme se corta en 8 MB sin acumularlo entero', async () => {
    let sentMb = 0;
    const big = await startProbe((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      const chunk = Buffer.alloc(1024 * 1024, 0x62);
      let sent = 0;
      const pump = (): void => {
        while (sent < 200) {
          sent++;
          sentMb = sent;
          if (!res.write(chunk)) {
            res.once('drain', pump);
            return;
          }
        }
        res.end();
      };
      res.on('close', () => {
        sent = 200;
      });
      pump();
    });
    try {
      const res = await makeClient().request('GET', `${big.origin}/`);
      expect(res.status).toBe(200);
      expect(res.bodyDecoded).toBe(true);
      expect(Buffer.byteLength(res.body)).toBe(EIGHT_MB);
      // El cliente cerró la conexión: el servidor no llegó a enviar los 200 MB.
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(sentMb).toBeLessThan(150);
    } finally {
      await big.close();
    }
  });

  it('un gzip comprimido enorme también se corta (límite de lectura) sin lanzar', async () => {
    const probe = await startProbe((_req, res) => {
      res.writeHead(200, { 'content-encoding': 'gzip' });
      const gz = zlib.createGzip();
      gz.pipe(res);
      const chunk = Buffer.from(Array.from({ length: 1024 * 1024 }, (_v, i) => 33 + ((i * 2654435761) % 90)));
      let n = 0;
      const pump = (): void => {
        while (n < 40) {
          n++;
          if (!gz.write(chunk)) {
            gz.once('drain', pump);
            return;
          }
        }
        gz.end();
      };
      res.on('close', () => {
        n = 40;
      });
      pump();
    });
    try {
      const res = await makeClient().request('GET', `${probe.origin}/`);
      expect(res.status).toBe(200);
      expect(Buffer.byteLength(res.body)).toBeLessThanOrEqual(EIGHT_MB);
      expect(res.body.length).toBeGreaterThan(0);
    } finally {
      await probe.close();
    }
  });

  it('un redirect a otro origen NO reenvía auth, cookies ni claves (solo cabeceras inocuas)', async () => {
    const seenB: Seen[] = [];
    const b = await startProbe((req, res) => {
      seenB.push({ method: req.method, headers: req.headers, url: req.url });
      res.writeHead(200).end('b');
    });
    const a = await startProbe((req, res) => {
      res.writeHead(302, { location: `${b.origin}/landing` }).end();
    });
    try {
      const client = makeClient({ defaultHeaders: { authorization: 'Bearer SECRET', 'x-api-key': 'K', accept: 'text/html' } });
      const res = await client.request('GET', `${a.origin}/go`, { headers: { cookie: 'manual=1' } });
      expect(res.status).toBe(200);
      expect(res.redirects).toHaveLength(1);
      expect(seenB).toHaveLength(1);
      const headers = seenB[0].headers;
      expect(headers.authorization).toBeUndefined();
      expect(headers['x-api-key']).toBeUndefined();
      expect(headers.cookie).toBeUndefined();
      expect(headers.accept).toBe('text/html');
    } finally {
      await a.close();
      await b.close();
    }
  });

  it('un redirect al mismo origen conserva la autenticación del usuario', async () => {
    const seen: Seen[] = [];
    const a = await startProbe((req, res) => {
      seen.push({ headers: req.headers, url: req.url });
      if (req.url === '/go') res.writeHead(302, { location: '/final' }).end();
      else res.writeHead(200).end('ok');
    });
    try {
      await makeClient({ defaultHeaders: { authorization: 'Bearer T' } }).request('GET', `${a.origin}/go`);
      expect(seen[1].url).toBe('/final');
      expect(seen[1].headers.authorization).toBe('Bearer T');
    } finally {
      await a.close();
    }
  });

  it('302 sobre POST se degrada a GET sin body ni content-length (no cuelga al servidor)', async () => {
    const seen: Seen[] = [];
    const a = await startProbe((req, res) => {
      seen.push({ method: req.method, headers: req.headers, url: req.url });
      if (req.url === '/post') res.writeHead(302, { location: '/after' }).end();
      else res.writeHead(200).end('done');
    });
    try {
      const client = makeClient({ guard: new Guard({ allowMutations: true }) });
      const res = await client.request('POST', `${a.origin}/post`, {
        body: 'a=1',
        headers: { 'content-length': '3', 'content-type': 'application/x-www-form-urlencoded' },
      });
      expect(res.status).toBe(200);
      expect(seen[1].method).toBe('GET');
      expect(seen[1].headers['content-length']).toBeUndefined();
      expect(seen[1].headers['content-type']).toBeUndefined();
    } finally {
      await a.close();
    }
  });

  it('307 con body hacia otro origen no se sigue', async () => {
    const seenB: Seen[] = [];
    const b = await startProbe((req, res) => {
      seenB.push({ headers: req.headers });
      res.writeHead(200).end();
    });
    const a = await startProbe((_req, res) => {
      res.writeHead(307, { location: `${b.origin}/x` }).end();
    });
    try {
      const client = makeClient({ guard: new Guard({ allowMutations: true }) });
      const res = await client.request('POST', `${a.origin}/`, { body: 'secret=1' });
      expect(res.status).toBe(307);
      expect(res.redirects).toEqual([]);
      expect(seenB).toHaveLength(0);
    } finally {
      await a.close();
      await b.close();
    }
  });

  it('un Location inválido o con esquema ajeno no se sigue ni lanza', async () => {
    const a = await startProbe((_req, res) => {
      res.writeHead(302, { location: 'javascript:alert(1)' }).end();
    });
    try {
      const res = await makeClient().request('GET', `${a.origin}/`);
      expect(res.status).toBe(302);
      expect(res.redirects).toEqual([]);
    } finally {
      await a.close();
    }
  });

  it('el semáforo se libera si la petición falla (concurrency 1)', async () => {
    const dead = await startProbe((_req, res) => res.end());
    const deadOrigin = dead.origin;
    await dead.close();
    const client = makeClient({ concurrency: 1 });
    await expect(client.request('GET', `${deadOrigin}/`)).rejects.toBeDefined();
    await expect(client.request('GET', `${deadOrigin}/`)).rejects.toBeDefined();
    const res = await client.request('GET', `${base}/ok`);
    expect(res.status).toBe(200);
  });

  it('el semáforo se libera tras un timeout y tras agotar el presupuesto', async () => {
    const client = makeClient({ concurrency: 1, requestTimeout: 100, maxRequests: 3 });
    expect((await client.request('GET', `${base}/hang`)).timedOut).toBe(true);
    expect((await client.request('GET', `${base}/ok`)).status).toBe(200);
    expect((await client.request('GET', `${base}/ok`)).status).toBe(200);
    await expect(client.request('GET', `${base}/ok`)).rejects.toBeInstanceOf(BudgetExceededError);
    await expect(client.request('GET', `${base}/ok`)).rejects.toBeInstanceOf(BudgetExceededError);
  });

  it('el presupuesto agotado se detecta antes de resolver DNS o emitir nada', async () => {
    const client = makeClient({ maxRequests: 1 });
    await client.request('GET', `${base}/ok`);
    await expect(client.request('GET', 'http://no-resuelve.invalid/')).rejects.toBeInstanceOf(BudgetExceededError);
  });

  it('un timeout a mitad del body devuelve timedOut y libera el socket', async () => {
    const slow = await startProbe((_req, res) => {
      res.writeHead(200);
      res.write('parcial');
    });
    try {
      const res = await makeClient({ requestTimeout: 150 }).request('GET', `${slow.origin}/`);
      expect(res.timedOut).toBe(true);
      expect(res.status).toBe(0);
      expect(res.body).toBe('');
    } finally {
      await slow.close();
    }
  });

  it('HEAD con content-encoding gzip y sin body no es un fallo de decodificación', async () => {
    const a = await startProbe((_req, res) => {
      res.writeHead(200, { 'content-encoding': 'gzip' }).end();
    });
    try {
      const res = await makeClient().request('HEAD', `${a.origin}/`);
      expect(res.body).toBe('');
      expect(res.bodyDecoded).toBe(true);
    } finally {
      await a.close();
    }
  });

  it('deflate crudo sin cabecera zlib queda sin decodificar y no lanza', async () => {
    const a = await startProbe((_req, res) => {
      res.writeHead(200, { 'content-encoding': 'deflate' }).end(zlib.deflateRawSync(Buffer.from('crudo')));
    });
    try {
      const res = await makeClient().request('GET', `${a.origin}/`);
      expect(res.status).toBe(200);
      expect(res.body).toBe('');
      expect(res.bodyDecoded).toBe(false);
    } finally {
      await a.close();
    }
  });

  it('un set-cookie hostil (valor con separadores o jar enorme) no envenena el jar', async () => {
    const a = await startProbe((req, res) => {
      if (req.url === '/echo') {
        res.writeHead(200).end(req.headers.cookie ?? '');
        return;
      }
      const many = Array.from({ length: 300 }, (_v, i) => `c${i}=v`);
      res.writeHead(200, { 'set-cookie': ['ok=1', 'bad=a b', 'bad2=x,y', ...many] }).end();
    });
    try {
      const client = makeClient();
      await client.request('GET', `${a.origin}/set`);
      const cookies = client.getCookies('127.0.0.1');
      expect(cookies).toContain('ok=1');
      expect(cookies).not.toContain('bad');
      expect(cookies.split('; ').length).toBeLessThanOrEqual(128);
      expect((await client.request('GET', `${a.origin}/echo`)).status).toBe(200);
    } finally {
      await a.close();
    }
  });
});
