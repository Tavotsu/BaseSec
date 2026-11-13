import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createVulnerableApp } from '../fixtures/vulnerable-app/server.mjs';
import { HttpClient } from '../../src/dast/http';
import { Guard } from '../../src/dast/guard';

const app = createVulnerableApp();
let origin: string;

beforeAll(async () => {
  origin = await app.start();
});

afterAll(async () => {
  await app.stop();
});

describe('HttpClient.elapsedMs (the timing oracle reads it)', () => {
  it('does not count the wait imposed by the rate limiter', async () => {
    // 2 req/s: la segunda petición espera ~500 ms al limitador. Esa espera no es latencia del servidor.
    const client = new HttpClient({ guard: new Guard(), rps: 2, concurrency: 1, requestTimeout: 5000 });
    const started = Date.now();
    const first = await client.request('GET', `${origin}/users?id=1`);
    const second = await client.request('GET', `${origin}/users?id=1`);
    const wall = Date.now() - started;

    expect(wall).toBeGreaterThanOrEqual(450);
    expect(first.elapsedMs).toBeLessThan(300);
    expect(second.elapsedMs).toBeLessThan(300);
  });

  it('still reflects a slow server', async () => {
    const client = new HttpClient({ guard: new Guard(), rps: 100, requestTimeout: 5000 });
    const response = await client.request('GET', `${origin}/slow?x=1`);
    expect(response.elapsedMs).toBeGreaterThanOrEqual(1100);
  });
});
