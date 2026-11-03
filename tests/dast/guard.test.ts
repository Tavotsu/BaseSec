import { describe, it, expect, vi, afterEach } from 'vitest';
import { Guard, isNodeSupported } from '../../src/dast/guard';
import { GuardError } from '../../src/dast/types';

const PUBLIC_IP = '93.184.216.34';
const publicResolver = async (): Promise<string[]> => [PUBLIC_IP];

async function expectGuardError(promise: Promise<unknown>, code: string): Promise<void> {
  await expect(promise).rejects.toBeInstanceOf(GuardError);
  await expect(promise).rejects.toMatchObject({ code });
}

function lookupAsync(
  guard: Guard,
  hostname: string,
  options: unknown,
): Promise<{ err: unknown; address?: unknown; family?: unknown }> {
  return new Promise((resolve) => {
    guard.lookup(hostname, options, (err: unknown, address?: unknown, family?: unknown) =>
      resolve({ err, address, family }),
    );
  });
}

describe('isNodeSupported', () => {
  it.each([
    ['22.23.4', true],
    ['22.23.3', false],
    ['24.22.1', true],
    ['24.22.0', false],
    ['20.19.0', false],
    ['18.20.8', false],
    ['21.7.3', false],
    ['23.11.0', false],
    ['25.9.9', false],
    ['26.12.1', true],
    ['26.12.0', false],
    ['27.0.0', true],
  ])('Node %s → supported=%s', (version, expected) => {
    expect(isNodeSupported(version)).toBe(expected);
  });

  it('usa process.versions.node por defecto', () => {
    expect(isNodeSupported()).toBe(isNodeSupported(process.versions.node));
  });

  it('una cadena que no es semver no está soportada', () => {
    expect(isNodeSupported('no-version')).toBe(false);
  });
});

describe('Guard.assertTargetAllowed', () => {
  it('bloquea un host remoto sin allowRemote con remote-blocked', async () => {
    const resolver = vi.fn(publicResolver);
    const guard = new Guard({ resolver });
    await expectGuardError(guard.assertTargetAllowed('http://api.cliente.test/'), 'remote-blocked');
    expect(resolver).toHaveBeenCalledWith('api.cliente.test');
  });

  it('sin TTY y sin BASESEC_ALLOW_REMOTE, allowRemote no basta', async () => {
    const guard = new Guard({ resolver: publicResolver, allowRemote: true });
    await expectGuardError(
      guard.assertTargetAllowed('http://api.cliente.test/', { isTTY: false }),
      'remote-blocked',
    );
  });

  it('sin TTY, allowRemote + allowRemoteEnv permiten el host remoto', async () => {
    const guard = new Guard({ resolver: publicResolver, allowRemote: true, allowRemoteEnv: true });
    await expect(guard.assertTargetAllowed('http://api.cliente.test/', { isTTY: false })).resolves.toEqual([
      PUBLIC_IP,
    ]);
  });

  it('con TTY, allowRemote basta sin la variable de entorno', async () => {
    const guard = new Guard({ resolver: publicResolver, allowRemote: true });
    await expect(guard.assertTargetAllowed('http://api.cliente.test/', { isTTY: true })).resolves.toEqual([
      PUBLIC_IP,
    ]);
  });

  it.each([
    'http://10.1.2.3/',
    'http://192.168.0.5:8080/',
    'http://172.16.0.1/',
    'http://172.31.255.255/',
    'http://127.0.0.1:3000/',
    'http://[::1]:3000/',
    'http://[::ffff:10.1.2.3]:8080/',
  ])('permite loopback y privadas sin flags: %s', async (url) => {
    const guard = new Guard();
    await expect(guard.assertTargetAllowed(url)).resolves.toHaveLength(1);
  });

  it('IPv4 mapeada en IPv6 pública sigue bloqueada sin allowRemote', async () => {
    const guard = new Guard();
    await expectGuardError(guard.assertTargetAllowed('http://[::ffff:93.184.216.34]/'), 'remote-blocked');
  });

  it('172.32.0.1 está fuera del rango privado y se trata como pública', async () => {
    const guard = new Guard();
    await expectGuardError(guard.assertTargetAllowed('http://172.32.0.1/'), 'remote-blocked');
  });

  it('169.254.169.254 es link-local incluso con allowRemote y TTY', async () => {
    const guard = new Guard({ allowRemote: true, allowRemoteEnv: true });
    await expectGuardError(guard.assertTargetAllowed('http://169.254.169.254/', { isTTY: true }), 'link-local');
  });

  it('fe80::1 es link-local', async () => {
    const guard = new Guard({ allowRemote: true, allowRemoteEnv: true });
    await expectGuardError(guard.assertTargetAllowed('http://[fe80::1]/', { isTTY: true }), 'link-local');
  });

  it('un nombre que resuelve a metadata es link-local aunque sea remoto permitido', async () => {
    const guard = new Guard({
      resolver: async () => ['169.254.169.254'],
      allowRemote: true,
      allowRemoteEnv: true,
    });
    await expectGuardError(guard.assertTargetAllowed('http://metadata.test/', { isTTY: true }), 'link-local');
  });

  it.each([
    'http://0177.0.0.1/',
    'http://2130706433/',
    'http://127.1/',
    'http://0x7f.0.0.1/',
    'http://010.0.0.1/',
  ])('IPv4 no canónica en la URL de entrada: %s', async (url) => {
    const guard = new Guard();
    await expectGuardError(guard.assertTargetAllowed(url), 'non-canonical-ip');
  });

  it.each(['not a url', 'ftp://10.0.0.1/', 'file:///etc/passwd'])('URL inválida o protocolo no HTTP: %s', async (url) => {
    const guard = new Guard();
    await expectGuardError(guard.assertTargetAllowed(url), 'invalid-url');
  });

  it('un nombre sin resultados DNS da dns', async () => {
    const guard = new Guard({ resolver: async () => [] });
    await expectGuardError(guard.assertTargetAllowed('http://nada.test/'), 'dns');
  });

  it('un resolver que lanza da dns', async () => {
    const guard = new Guard({
      resolver: async () => {
        throw new Error('ENOTFOUND');
      },
    });
    await expectGuardError(guard.assertTargetAllowed('http://nada.test/'), 'dns');
  });

  it('si el nombre mezcla IP privada y link-local, gana link-local', async () => {
    const guard = new Guard({ resolver: async () => ['10.0.0.1', '169.254.1.1'], allowRemote: true, allowRemoteEnv: true });
    await expectGuardError(guard.assertTargetAllowed('http://mixto.test/', { isTTY: true }), 'link-local');
  });
});

describe('Guard.lookup (hook del socket)', () => {
  it('forma all:true devuelve la lista de direcciones validadas', async () => {
    const guard = new Guard({ resolver: async () => ['10.0.0.7'] });
    const result = await lookupAsync(guard, 'app.test', { all: true });
    expect(result.err).toBeNull();
    expect(result).toMatchObject({ address: [{ address: '10.0.0.7', family: 4 }] });
  });

  it('forma simple devuelve address y family', async () => {
    const guard = new Guard({ resolver: async () => ['127.0.0.1'] });
    const result = await lookupAsync(guard, 'app.test', {});
    expect(result).toMatchObject({ err: null, address: '127.0.0.1', family: 4 });
  });

  it('una IP link-local nunca llega al socket', async () => {
    const guard = new Guard({ resolver: async () => ['169.254.169.254'], allowRemote: true, allowRemoteEnv: true });
    const result = await lookupAsync(guard, 'metadata.test', { all: true });
    expect(result.err).toBeInstanceOf(GuardError);
    expect(result.err).toMatchObject({ code: 'link-local' });
  });

  it('una IP pública sin allowRemote devuelve remote-blocked', async () => {
    const guard = new Guard({ resolver: publicResolver });
    const result = await lookupAsync(guard, 'remoto.test', 4);
    expect(result.err).toMatchObject({ code: 'remote-blocked' });
  });
});

describe('Guard.isMethodAllowed', () => {
  it.each(['GET', 'HEAD', 'OPTIONS', 'get'])('%s siempre permitido', (method) => {
    expect(new Guard().isMethodAllowed(method)).toBe(true);
  });

  it.each(['POST', 'PUT', 'PATCH', 'DELETE', 'delete', 'TRACE'])('%s bloqueado sin allowMutations', (method) => {
    expect(new Guard().isMethodAllowed(method)).toBe(false);
  });

  it.each(['POST', 'PUT', 'PATCH', 'DELETE'])('%s permitido con allowMutations', (method) => {
    expect(new Guard({ allowMutations: true }).isMethodAllowed(method)).toBe(true);
  });
});

describe('Guard.canFollowRedirect', () => {
  const base = 'http://127.0.0.1:8080/start';

  it('una ruta relativa del mismo origen se sigue', async () => {
    await expect(new Guard().canFollowRedirect('/otra', base)).resolves.toBe(true);
  });

  it('un Location a metadata no se sigue', async () => {
    await expect(new Guard().canFollowRedirect('http://169.254.169.254/', base)).resolves.toBe(false);
  });

  it('un Location a un host remoto no se sigue sin allowRemote', async () => {
    const guard = new Guard({ resolver: publicResolver });
    await expect(guard.canFollowRedirect('https://ejemplo.test/x', base)).resolves.toBe(false);
  });

  it('un Location con IPv4 no canónica no se sigue', async () => {
    await expect(new Guard().canFollowRedirect('http://0177.0.0.1/', base)).resolves.toBe(false);
  });

  it('un Location a otra IP privada sí se sigue', async () => {
    await expect(new Guard().canFollowRedirect('http://10.0.0.5/x', base)).resolves.toBe(true);
  });

  it('un Location con otro protocolo no se sigue', async () => {
    await expect(new Guard().canFollowRedirect('ftp://127.0.0.1/', base)).resolves.toBe(false);
  });
});

describe('Guard.assertNodeSupported', () => {
  const originalVersion = process.versions.node;

  afterEach(() => {
    Object.defineProperty(process.versions, 'node', { value: originalVersion, configurable: true });
  });

  it('no lanza en la versión de Node en ejecución (parcheada en CI)', () => {
    expect(() => new Guard().assertNodeSupported()).not.toThrow();
  });

  it('lanza node-vulnerable con una versión por debajo del suelo', () => {
    Object.defineProperty(process.versions, 'node', { value: '20.19.0', configurable: true });
    expect(() => new Guard().assertNodeSupported()).toThrow(GuardError);
    expect(() => new Guard().assertNodeSupported()).toThrow(/parches/);
  });

  it('allowVulnerableNode salta la comprobación', () => {
    Object.defineProperty(process.versions, 'node', { value: '20.19.0', configurable: true });
    expect(() => new Guard({ allowVulnerableNode: true }).assertNodeSupported()).not.toThrow();
  });
});

describe('Guard endurecimiento (revisión de seguridad)', () => {
  const allowAll = { allowRemote: true, allowRemoteEnv: true };

  it.each(['172.16.0.1', '172.20.5.5', '172.31.255.254', '10.255.255.255', '192.168.0.1', '127.8.8.8', '0.0.0.0'])(
    '%s es local y se permite',
    async (ip) => {
      await expect(new Guard().assertTargetAllowed(`http://${ip}/`)).resolves.toEqual([ip]);
    },
  );

  it.each(['172.15.255.255', '172.32.0.0', '192.169.0.1', '11.0.0.1'])('%s queda fuera de los rangos privados', async (ip) => {
    await expectGuardError(new Guard().assertTargetAllowed(`http://${ip}/`), 'remote-blocked');
  });

  it.each([
    ['fc00::1'],
    ['fd12:3456::1'],
    ['::1'],
    ['::'],
  ])('IPv6 %s es local', async (ip) => {
    await expect(new Guard({ resolver: async () => [ip] }).assertTargetAllowed('http://v6.test/')).resolves.toEqual([ip]);
  });

  it.each([['fe00::1'], ['fec0::1'], ['2001:db8::1']])('IPv6 %s no es local', async (ip) => {
    await expectGuardError(new Guard({ resolver: async () => [ip] }).assertTargetAllowed('http://v6.test/'), 'remote-blocked');
  });

  it.each([
    '::ffff:169.254.169.254',
    '::ffff:a9fe:a9fe',
    'fe80::1%eth0',
    'febf::1',
    '::169.254.169.254',
    '64:ff9b::a9fe:a9fe',
    '2002:a9fe:a9fe::1',
  ])('%s es link-local/metadata y se bloquea incluso con allowRemote', async (ip) => {
    const guard = new Guard({ ...allowAll, resolver: async () => [ip] });
    await expectGuardError(guard.assertTargetAllowed('http://meta.test/', { isTTY: true }), 'link-local');
  });

  it('metadata como literal IPv6 mapeado en la URL se bloquea', async () => {
    await expectGuardError(new Guard(allowAll).assertTargetAllowed('http://[::ffff:169.254.169.254]/', { isTTY: true }), 'link-local');
  });

  it.each([
    'http://0177.0.0.1\\@evil.test/',
    'http://evil.test@0x7f.0.0.1/',
    'http://a@b@2130706433/',
    '\thttp://0177.0.0.1/',
    'http://%30x7f.1/',
    'http://0x7f000001/',
    'http://127.1./',
    'http://0xa9.0xfe.0xa9.0xfe/',
    'http://2852039166/',
    'http://１２７.1/',
  ])('IPv4 no canónica %j se rechaza', async (url) => {
    await expectGuardError(new Guard(allowAll).assertTargetAllowed(url, { isTTY: true }), 'non-canonical-ip');
  });

  it('un nombre que empieza por dígitos pero no es numérico no es una IPv4 no canónica', async () => {
    const guard = new Guard({ resolver: async () => ['127.0.0.1'] });
    await expect(guard.assertTargetAllowed('http://1password.test/')).resolves.toEqual(['127.0.0.1']);
  });

  it('un nombre que resuelve a una lista mixta privada+pública se bloquea sin allowRemote', async () => {
    const guard = new Guard({ resolver: async () => ['10.0.0.1', PUBLIC_IP] });
    await expectGuardError(guard.assertTargetAllowed('http://mixto.test/'), 'remote-blocked');
  });

  it('lookup valida TODAS las IPs, no solo la primera (all:true y forma simple)', async () => {
    const guard = new Guard({ resolver: async () => ['10.0.0.1', PUBLIC_IP] });
    expect((await lookupAsync(guard, 'mixto.test', { all: true })).err).toMatchObject({ code: 'remote-blocked' });
    expect((await lookupAsync(guard, 'mixto.test', {})).err).toMatchObject({ code: 'remote-blocked' });
    const meta = new Guard({ ...allowAll, resolver: async () => [PUBLIC_IP, '169.254.169.254'] });
    expect((await lookupAsync(meta, 'mixto.test', { all: true })).err).toMatchObject({ code: 'link-local' });
  });

  it('lookup respeta la familia pedida y falla si no hay direcciones de esa familia', async () => {
    const guard = new Guard({ resolver: async () => ['::1', '127.0.0.1'] });
    expect(await lookupAsync(guard, 'dual.test', { family: 4 })).toMatchObject({ err: null, address: '127.0.0.1', family: 4 });
    expect(await lookupAsync(guard, 'dual.test', 6)).toMatchObject({ err: null, address: '::1', family: 6 });
    const v4only = new Guard({ resolver: async () => ['127.0.0.1'] });
    expect((await lookupAsync(v4only, 'v4.test', { family: 6 })).err).toMatchObject({ code: 'dns' });
  });

  it('lookup invoca el callback una sola vez aunque el callback lance', async () => {
    const guard = new Guard({ resolver: async () => ['127.0.0.1'] });
    const calls: number[] = [];
    const handler = (e: Error): void => {
      calls.push(1);
      void e;
    };
    process.once('uncaughtException', handler);
    guard.lookup('x.test', {}, () => {
      calls.push(0);
      throw new Error('boom en el callback');
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    process.removeListener('uncaughtException', handler);
    expect(calls).toEqual([0, 1]);
  });

  it.each([
    '//169.254.169.254/x',
    '\\\\169.254.169.254/x',
    '/\\169.254.169.254/x',
    '/\t/169.254.169.254/x',
    ' \thttp://169.254.169.254/',
    'http://169.254.169.254:80/',
    '//[::ffff:169.254.169.254]/',
  ])('canFollowRedirect rechaza el Location %j hacia metadata', async (location) => {
    await expect(new Guard(allowAll).canFollowRedirect(location, 'http://127.0.0.1:8080/start')).resolves.toBe(false);
  });

  it('un Location protocol-relative a un host remoto se valida (no cambia de host sin pasar por el guard)', async () => {
    const guard = new Guard({ resolver: publicResolver });
    await expect(guard.canFollowRedirect('//evil.test/x', 'http://127.0.0.1/')).resolves.toBe(false);
    const allowed = new Guard({ resolver: publicResolver, ...allowAll });
    await expect(allowed.canFollowRedirect('//evil.test/x', 'http://127.0.0.1/')).resolves.toBe(true);
  });

  it('un Location relativo con ruta rara sigue en el mismo host', async () => {
    const resolver = vi.fn(async () => ['127.0.0.1']);
    const guard = new Guard({ resolver });
    await expect(guard.canFollowRedirect('../a/b?x=1#f', 'http://app.test/c/d')).resolves.toBe(true);
    expect(resolver).toHaveBeenCalledWith('app.test');
  });
});
