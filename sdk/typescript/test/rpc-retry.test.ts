import { afterEach, describe, expect, it, vi } from 'vitest';
import { JsonRpc } from '../src/client.js';

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

describe('JsonRpc retries public-RPC rate limits', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('retries 429 and 5xx with backoff, then returns the result', async () => {
    const replies = [json(429, {}), json(503, {}), json(200, { jsonrpc: '2.0', id: 1, result: 1234 })];
    const fetchMock = vi.fn(async () => replies.shift()!);
    vi.stubGlobal('fetch', fetchMock);
    await expect(new JsonRpc('https://rpc.test').getMinimumBalanceForRentExemption(10)).resolves.toBe(1234n);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('gives up with a clear message when the limit persists', async () => {
    vi.useFakeTimers();
    vi.stubGlobal('fetch', vi.fn(async () => json(429, {})));
    const p = new JsonRpc('https://rpc.test').getMinimumBalanceForRentExemption(10);
    const check = expect(p).rejects.toThrow(/rate-limiting/);
    await vi.runAllTimersAsync();
    await check;
    vi.useRealTimers();
  });

  it('does not retry ordinary errors', async () => {
    const fetchMock = vi.fn(async () => json(200, { jsonrpc: '2.0', id: 1, error: { message: 'invalid param' } }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(new JsonRpc('https://rpc.test').getMinimumBalanceForRentExemption(10)).rejects.toThrow(/invalid param/);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
