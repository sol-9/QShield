/**
 * Client for a QShield relayer (docs/RELAYER.md). Lets browser and Node apps
 * get a signed authorization on chain without holding SOL or assembling
 * transactions: the relayer pays the fees and gains no authority. Only public
 * data (the signed envelope) is sent.
 */
import { envelopeToJson, type Envelope } from './envelope.js';
import type { Transport } from './client.js';

export type RelayStatus =
  | { status: 'pending' | 'submitting'; request_id: string }
  | { status: 'confirmed'; request_id: string; signatures: string[] }
  | { status: 'failed'; request_id: string; error: string };

export interface RelayerInfo {
  relayer: string;
  program_id: string;
  cluster: string;
  cluster_id: string;
  min_fee_lamports: number;
  /**
   * Rent of a recipient token account the relayer would create (SPL Token,
   * Token-2022). A send that needs one must add it to the signed fee.
   * Absent on relayers that predate this rule (they charge nothing extra).
   */
  token_account_rent_lamports?: { spl_token: number | null; token_2022: number | null };
  /** Longest accepted proposal lifetime (seconds). */
  max_proposal_lifetime_secs?: number;
  transports: Transport[];
  rate_limit_per_minute: number;
}

export class RelayerClient {
  readonly base: string;

  // Browsers require `fetch` to be called with the global as `this`, so the
  // default wraps it instead of storing the bare function.
  constructor(base: string, private readonly fetchImpl: typeof fetch = (input, init) => fetch(input, init)) {
    this.base = base.replace(/\/+$/, '');
  }

  private async json(path: string, init?: RequestInit): Promise<{ code: number; body: any }> {
    const res = await this.fetchImpl(this.base + path, init);
    return { code: res.status, body: await res.json() };
  }

  async info(): Promise<RelayerInfo> {
    return (await this.json('/v1/info')).body as RelayerInfo;
  }

  /** Submits a signed envelope; returns the request id. */
  async submit(signed: Envelope, transport: Transport = 'inline'): Promise<string> {
    if (!signed.signature_hex) throw new Error('envelope is not signed');
    const { code, body } = await this.json('/v1/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ envelope: JSON.parse(envelopeToJson(signed)), transport }),
    });
    if ((code === 200 || code === 202) && typeof body.request_id === 'string') return body.request_id;
    throw new Error(`relayer refused (${code}): ${body.error ?? 'unknown error'}`);
  }

  async status(requestId: string): Promise<RelayStatus> {
    const { code, body } = await this.json(`/v1/status/${encodeURIComponent(requestId)}`);
    if (code !== 200) throw new Error(`relayer status (${code}): ${body.error ?? ''}`);
    return body as RelayStatus;
  }

  /** Polls until confirmed or failed. */
  async wait(requestId: string, timeoutMs = 120_000, intervalMs = 500): Promise<RelayStatus> {
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) {
      const s = await this.status(requestId);
      if (s.status === 'confirmed' || s.status === 'failed') return s;
      await new Promise((r) => setTimeout(r, intervalMs));
    }
    throw new Error(`relayer request ${requestId} not finished after ${timeoutMs} ms`);
  }
}
