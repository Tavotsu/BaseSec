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
