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
