import { describe, it, expect } from 'vitest';
import { redactHttp, redactHeaders } from '../../src/dast/redact-http';

const CANARY = 'BS1a2b3c4d';

describe('redactHttp', () => {
  const evidence = [
    'GET /api/users/42?token=abc HTTP/1.1',
    'Host: app.local',
    'Authorization: Bearer xyz',
    'Cookie: sid=secret',
    'Content-Type: application/json',
    '',
    `{"jwt":"eyJhbGc.eyJzdWI.sig","marker":"${CANARY}"}`,
  ].join('\n');

  it('redacta cabeceras, query token, JWT y Bearer, pero conserva ruta y canario', () => {
    const out = redactHttp(evidence);
    expect(out).not.toContain('xyz');
    expect(out).not.toContain('secret');
    expect(out).not.toContain('eyJhbGc.eyJzdWI.sig');
    expect(out).not.toContain('token=abc');
    expect(out).toContain('/api/users/42');
    expect(out).toContain(CANARY);
  });

  it('conserva el nombre de la cookie y redacta solo su valor', () => {
    const out = redactHttp('Cookie: sid=secret; theme=dark');
    expect(out).toBe('Cookie: sid=[REDACTED]; theme=[REDACTED]');
  });

  it('en set-cookie conserva el nombre y los flags', () => {
    const out = redactHttp('Set-Cookie: sid=abc123; Path=/; HttpOnly');
    expect(out).toBe('Set-Cookie: sid=[REDACTED]; Path=/; HttpOnly');
  });

  it('un header content-type no se redacta (caso negativo)', () => {
    expect(redactHttp('Content-Type: application/json')).toBe('Content-Type: application/json');
  });

  it('un header x-request-id no se redacta aunque tenga un número largo', () => {
    expect(redactHttp('X-Request-Id: 1234567890')).toBe('X-Request-Id: 1234567890');
  });

  it('redacta cualquier header cuyo nombre case con token/secret/session/password', () => {
    expect(redactHttp('X-Csrf-Token: abcdef')).toBe('X-Csrf-Token: [REDACTED]');
    expect(redactHttp('Session-Id: 9f8e7d')).toBe('Session-Id: [REDACTED]');
    expect(redactHttp('X-Db-Password: hunter')).toBe('X-Db-Password: [REDACTED]');
  });

  it('x-api-key y x-auth-token se redactan', () => {
    const out = redactHttp('X-Api-Key: zzz111\nX-Auth-Token: yyy222');
    expect(out).toBe('X-Api-Key: [REDACTED]\nX-Auth-Token: [REDACTED]');
  });

  it('redacta el valor conocido de --header donde aparezca', () => {
    const secret = 'mi-clave-super-secreta';
    const out = redactHttp(`{"echo":"${secret}"}`, { knownSecrets: [secret] });
    expect(out).not.toContain(secret);
    expect(out).toContain('**************');
  });

  it('redacta parámetros de query sensibles y conserva los demás', () => {
    expect(redactHttp('/api?key=AAA&page=2')).toBe('/api?key=[REDACTED]&page=2');
    expect(redactHttp('/cb?access_token=ttt&sig=sss&id=7')).toBe(
      '/cb?access_token=[REDACTED]&sig=[REDACTED]&id=7',
    );
  });

  it('un path con números no se confunde con un secreto', () => {
    const text = 'GET /api/v1/users/12345/orders/9876543210';
    expect(redactHttp(text)).toBe(text);
  });

  it('un hex de 32 caracteres en el cuerpo no se redacta (Possible Hex Secret excluido)', () => {
    const text = 'commit 0123456789abcdef0123456789abcdef';
    expect(redactHttp(text)).toBe(text);
  });

  it('un token de GitHub en el cuerpo sí se redacta', () => {
    const token = `ghp_${'a'.repeat(36)}`;
    expect(redactHttp(`leaked ${token} here`)).toBe('leaked [REDACTED] here');
  });

  it('un Bearer en el cuerpo conserva la palabra Bearer', () => {
    expect(redactHttp('auth was Bearer abc.def')).toBe('auth was Bearer [REDACTED]');
  });

  it('el canario BS + 8 hex nunca se redacta', () => {
    expect(redactHttp(`payload ${CANARY} end`)).toBe(`payload ${CANARY} end`);
  });

  it('trunca el body a maxBodyBytes y lo indica', () => {
    const body = 'x'.repeat(50);
    const out = redactHttp(`HTTP/1.1 200 OK\n\n${body}`, { maxBodyBytes: 10 });
    expect(out).toBe('HTTP/1.1 200 OK\n\nxxxxxxxxxx …[truncado]');
  });

  it('un body dentro del límite no se trunca', () => {
    const text = 'HTTP/1.1 200 OK\n\nshort';
    expect(redactHttp(text, { maxBodyBytes: 100 })).toBe(text);
  });

  it('por defecto el límite es 8192 bytes', () => {
    const body = 'y'.repeat(9000);
    const out = redactHttp(`HTTP/1.1 200 OK\n\n${body}`);
    expect(out.endsWith(' …[truncado]')).toBe(true);
    expect(out.length).toBeLessThan(9000);
  });
});

describe('redactHeaders', () => {
  it('redacta authorization y deja content-type intacto', () => {
    const out = redactHeaders({ authorization: 'Bearer x', 'content-type': 'application/json' });
    expect(out).toEqual({ authorization: '[REDACTED]', 'content-type': 'application/json' });
  });

  it('en set-cookie como array redacta cada valor y conserva flags', () => {
    const out = redactHeaders({ 'set-cookie': ['a=1; Path=/', 'b=2'] });
    expect(out).toEqual({ 'set-cookie': ['a=[REDACTED]; Path=/', 'b=[REDACTED]'] });
  });

  it('no altera headers no sensibles ni muta el original', () => {
    const input = { 'x-request-id': 'abc', authorization: 'Basic zzz' };
    const out = redactHeaders(input);
    expect(out['x-request-id']).toBe('abc');
    expect(out.authorization).toBe('[REDACTED]');
    expect(input.authorization).toBe('Basic zzz');
  });
});

describe('redactHttp endurecimiento (revisión de seguridad)', () => {
  it('con secretos conocidos anidados redacta el largo completo (sin restos)', () => {
    const out = redactHttp('body: tok123456789 y tok', { knownSecrets: ['tok', 'tok123456789'] });
    expect(out).not.toContain('123456789');
  });

  it('el truncado cuenta bytes y no parte un carácter multibyte', () => {
    const body = 'ñ'.repeat(100); // 200 bytes
    const out = redactHttp(`HTTP/1.1 200 OK\r\n\r\n${body}`, { maxBodyBytes: 51 });
    expect(out).toContain('…[truncado]');
    expect(out).not.toContain('�');
    const kept = out.split('\r\n\r\n')[1].replace(' …[truncado]', '');
    expect(Buffer.byteLength(kept)).toBeLessThanOrEqual(51);
    expect(kept).toBe('ñ'.repeat(25));
  });

  it('una emoji de 4 bytes en el corte no deja basura', () => {
    const out = redactHttp(`x\n\n${'😀'.repeat(10)}`, { maxBodyBytes: 6 });
    expect(out).not.toContain('�');
    expect(out.startsWith('x\n\n😀 …[truncado]')).toBe(true);
  });

  it('un cuerpo hostil de varios MB no dispara el coste de las regex', () => {
    const hostile = `x\n\n${'eyJ'.repeat(1_000_000)}${'mongodb://:'.repeat(100_000)}`;
    const started = Date.now();
    const out = redactHttp(hostile);
    expect(Date.now() - started).toBeLessThan(3000);
    expect(Buffer.byteLength(out)).toBeLessThan(8192 + 100);
  });

  it('un token que cae justo en el corte queda redactado en la parte visible', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.firmaDeEjemplo123';
    const out = redactHttp(`h: v\n\n${'a'.repeat(10)}${jwt}`, { maxBodyBytes: 30 });
    expect(out).not.toContain('eyJhbGci');
  });

  it('un Bearer en minúsculas dentro del body se redacta', () => {
    expect(redactHttp('x\n\nauth bearer abc.def.ghi fin')).not.toContain('abc.def.ghi');
  });

  it('credenciales en la URL (user:pass@host) se redactan y conservan el usuario y el host', () => {
    const out = redactHttp('GET https://admin:hunter2@app.local/x HTTP/1.1');
    expect(out).not.toContain('hunter2');
    expect(out).toContain('admin:[REDACTED]@app.local');
  });

  it('parámetros api_key / refresh_token / client_secret se redactan; q y id no', () => {
    const out = redactHttp('GET /s?q=hola&api_key=AAA&id=7&refresh_token=BBB&client_secret=CCC HTTP/1.1');
    expect(out).not.toMatch(/AAA|BBB|CCC/);
    expect(out).toContain('q=hola');
    expect(out).toContain('id=7');
  });

  it('un id numérico largo en JSON no se redacta', () => {
    expect(redactHttp('x\n\n{"id":12345678901234567890}')).toContain('12345678901234567890');
  });

  it('maxBodyBytes inválido (negativo o NaN) cae al valor por defecto', () => {
    expect(redactHttp('x\n\nhola', { maxBodyBytes: -1 })).toBe('x\n\nhola');
    expect(redactHttp('x\n\nhola', { maxBodyBytes: Number.NaN })).toBe('x\n\nhola');
  });
});

describe('redactHttp cadenas de conexión (rendimiento y userinfo)', () => {
  it.each([
    ['mongodb', 'mongodb://admin:s3cr3tpw@db.internal:27017/app'],
    ['mongodb+srv', 'mongodb+srv://admin:s3cr3tpw@db.internal/app'],
    ['postgres', 'postgres://admin:s3cr3tpw@db.internal:5432/app'],
    ['mysql', 'mysql://admin:s3cr3tpw@db.internal:3306/app'],
    ['redis', 'redis://admin:s3cr3tpw@db.internal:6379/0'],
  ])('redacta el userinfo de una cadena %s y conserva esquema y host', (_name, conn) => {
    const out = redactHttp(`{"dsn":"${conn}","marker":"${CANARY}"}`);
    expect(out).not.toContain('s3cr3tpw');
    expect(out).not.toContain('admin');
    expect(out).toContain(conn.slice(0, conn.indexOf('://') + 3));
    expect(out).toContain('db.internal');
    expect(out).toContain(CANARY);
  });

  it('una URL normal sin credenciales no se toca', () => {
    expect(redactHttp('GET https://example.com/path HTTP/1.1')).toBe('GET https://example.com/path HTTP/1.1');
  });

  it('un body hostil de 64 KB se redacta en menos de 150 ms y conserva el canario', () => {
    const unit = 'mongodb://a:a';
    const mixed = 'mongodb://a:b:c:d:e:f:g:h:i:j:k:l:m:n:o:p:q:r:s:t:u:v:w:x:y:z:';
    const size = 64 * 1024;
    const hostile = `HTTP/1.1 200 OK\n\n${unit.repeat(size).slice(0, size)}${mixed.repeat(size).slice(0, size)}${CANARY}`;
    // maxBodyBytes alto para que el body completo pase por las regex (si no, se recorta antes).
    const started = performance.now();
    const out = redactHttp(hostile, { maxBodyBytes: 4 * size });
    const elapsed = performance.now() - started;
    expect(elapsed).toBeLessThan(150);
    expect(out).toContain(CANARY);
  });

  it('un texto hostil de 64 KB de `a.` repetido se redacta en menos de 150 ms (URL_USERINFO y HEADER_LINE acotados)', () => {
    const size = 64 * 1024;
    const hostile = `HTTP/1.1 200 OK\n\n${'a.'.repeat(size / 2)}${CANARY}`;
    // maxBodyBytes alto para que NO se recorte antes: la regex debe enfrentarse al texto completo.
    const started = performance.now();
    const out = redactHttp(hostile, { maxBodyBytes: 4 * size });
    const elapsed = performance.now() - started;
    expect(elapsed).toBeLessThan(150);
    expect(out).toContain(CANARY);
    // La redacción normal sigue funcionando tras acotar las regex.
    const conn = redactHttp(`{"dsn":"postgres://admin:s3cr3tpw@db.internal:5432/app","marker":"${CANARY}"}`);
    expect(conn).toBe(`{"dsn":"postgres://[REDACTED]@db.internal:5432/app","marker":"${CANARY}"}`);
    expect(redactHttp('GET https://admin:hunter2@app.local/x HTTP/1.1')).toBe(
      'GET https://admin:[REDACTED]@app.local/x HTTP/1.1',
    );
  });
});
