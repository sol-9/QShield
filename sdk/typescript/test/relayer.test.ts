import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseEnvelope } from '../src/envelope.js';
import { RelayerClient } from '../src/relayer.js';

const V = JSON.parse(readFileSync(new URL('../../../tests/vectors/sdk/interop-v1.json', import.meta.url), 'utf8'));

/** A fake relayer implementing the documented API. */
function fakeRelayer() {
  const calls: { url: string; body?: any }[] = [];
  let polls = 0;
  const impl = (async (url: string, init?: RequestInit) => {
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ url, body });
    const reply = (code: number, v: unknown) => new Response(JSON.stringify(v), { status: code });
    if (url.endsWith('/v1/submit')) {
      if (body.transport === 'buffered') return reply(400, { error: 'buffered transport disabled on this relayer' });
      return reply(202, { request_id: 'ab'.repeat(32), status: 'pending' });
    }
    if (url.includes('/v1/status/')) {
      polls++;
      return polls < 3
        ? reply(200, { request_id: 'ab'.repeat(32), status: 'submitting' })
        : reply(200, { request_id: 'ab'.repeat(32), status: 'confirmed', signatures: ['sig1'] });
    }
    return reply(404, { error: 'not found' });
  }) as typeof fetch;
  return { impl, calls };
}

describe('RelayerClient', () => {
  it('submits the signed envelope verbatim and polls to completion', async () => {
    const f = fakeRelayer();
    const rc = new RelayerClient('https://relayer.example/', f.impl);
    const env = parseEnvelope(JSON.stringify(V.envelope));
    const id = await rc.submit(env);
    expect(f.calls[0]!.url).toBe('https://relayer.example/v1/submit');
    expect(f.calls[0]!.body.envelope.auth_hex).toBe(V.envelope.auth_hex);
    expect(f.calls[0]!.body.envelope.signature_hex).toBe(V.envelope.signature_hex);
    expect(f.calls[0]!.body.transport).toBe('inline');
    const s = await rc.wait(id, 5_000, 1);
    expect(s).toEqual({ request_id: 'ab'.repeat(32), status: 'confirmed', signatures: ['sig1'] });
    await expect(rc.submit(env, 'buffered')).rejects.toThrow(/400.*disabled/);
    const unsigned = { ...env, signature_hex: undefined };
    await expect(rc.submit(unsigned)).rejects.toThrow(/not signed/);
  });
});
