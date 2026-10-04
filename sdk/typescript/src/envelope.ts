/**
 * Authorization envelopes (docs/OFFLINE_SIGNING.md): the JSON file passed
 * between the machine that builds an authorization, an offline signer and a
 * submitter. Same format as the Rust SDK/CLI. `auth_hex` is authoritative;
 * `fields` must equal `describe(decode(auth_hex))` exactly.
 */
import { fromHex, isZero, toBase58, toHex } from './bytes.js';
import { verifyAuthorization, type PqSigner } from './keys.js';
import { formatTokenAmount } from './token.js';
import { Action, AssetType, AUTH_LEN, clusterName, decode, encode, keyId, type Authorization } from './qsp1.js';
import { ActionV2, AUTH_V2_LEN, Role, decodeV2, encodeV2, type AuthorizationV2 } from './qsp1v2.js';

export interface Envelope {
  qshield_authorization: 1;
  fields: Record<string, string>;
  auth_hex: string;
  signer_key_id: string;
  signature_hex?: string;
  public_key_hex?: string;
  hints: { new_key_account?: string; destination_owner?: string; source_token_account?: string };
}

/** Lamports rendered as SOL with all 9 decimals. */
export function sol(lamports: bigint): string {
  return `${lamports / 1_000_000_000n}.${(lamports % 1_000_000_000n).toString().padStart(9, '0')} SOL`;
}

/** Human-readable rendering of every field; identical strings to the Rust SDK. */
export function describe(a: Authorization): Record<string, string> {
  const m: Record<string, string> = {};
  const ts = (t: bigint, none: string) => (t === 0n ? none : `${t} (unix seconds)`);
  m.cluster = clusterName(a.clusterId);
  m.program_id = toBase58(a.programId);
  m.vault = toBase58(a.vault);
  m.action = Action[a.action]!;
  m.nonce = a.nonce.toString();
  m.valid_after = ts(a.validAfter, 'immediately');
  m.expires_at = ts(a.expiresAt, 'never');
  switch (a.action) {
    case Action.WithdrawSol:
      m.destination = toBase58(a.destination);
      m.amount = sol(a.amount);
      break;
    case Action.CloseVault:
      m.destination = toBase58(a.destination);
      m.amount = 'entire balance above the rent reserve';
      break;
    case Action.WithdrawSpl:
      renderTransfer(m, a.assetType, a.mint, a.destination, a.amount, a.decimals);
      break;
    case Action.RotateKey:
      m.new_key_id = toHex(a.newKeyId);
      m.new_algorithm = a.newAlgorithm === 1 ? 'ML-DSA-44' : String(a.newAlgorithm);
      break;
    default:
      break;
  }
  m.fee = sol(a.feeLamports);
  if (a.feeLamports > 0n) m.fee_recipient = isZero(a.feeRecipient) ? 'transaction fee payer' : toBase58(a.feeRecipient);
  return m;
}

function renderTransfer(m: Record<string, string>, assetType: AssetType, mint: Uint8Array, destination: Uint8Array, amount: bigint, decimals: number) {
  m.destination = toBase58(destination);
  if (assetType === AssetType.Sol) {
    m.amount = sol(amount);
  } else {
    m.asset = AssetType[assetType]!;
    m.mint = toBase58(mint);
    m.amount = `${formatTokenAmount(amount, decimals)} (${amount} base units, decimals ${decimals})`;
  }
}

/** Rendering of a v2 (guardian policy) authorization; identical strings to the Rust SDK. */
export function describeV2(a: AuthorizationV2): Record<string, string> {
  const m: Record<string, string> = {};
  const ts = (t: bigint, none: string) => (t === 0n ? none : `${t} (unix seconds)`);
  m.cluster = clusterName(a.clusterId);
  m.program_id = toBase58(a.programId);
  m.vault = toBase58(a.vault);
  m.action = ActionV2[a.action]!;
  m.role = a.role === Role.Everyday ? 'everyday key' : 'guardian';
  m.nonce = a.nonce.toString();
  m.valid_after = ts(a.validAfter, 'immediately');
  m.expires_at = ts(a.expiresAt, 'never');
  if ([ActionV2.WithdrawSol, ActionV2.WithdrawSpl, ActionV2.ProposeWithdraw, ActionV2.ApproveWithdraw].includes(a.action)) {
    renderTransfer(m, a.assetType, a.mint, a.destination, a.amount, a.decimals);
  }
  if (a.action === ActionV2.ApproveWithdraw || a.action === ActionV2.CancelProposal) m.proposal = a.refId.toString();
  if ([ActionV2.RotateKey, ActionV2.RotateGuardian, ActionV2.EnablePolicy].includes(a.action)) {
    m.new_key_id = toHex(a.newKeyId);
    m.new_algorithm = a.newAlgorithm === 1 ? 'ML-DSA-44' : String(a.newAlgorithm);
  }
  if (a.action === ActionV2.EnablePolicy || a.action === ActionV2.SetLimit) m.limit = `${sol(a.limitLamports)} per ${a.limitPeriod} seconds`;
  if (a.action === ActionV2.AddAddress || a.action === ActionV2.RemoveAddress) m.address = toBase58(a.destination);
  m.fee = sol(a.feeLamports);
  if (a.feeLamports > 0n) m.fee_recipient = isZero(a.feeRecipient) ? 'transaction fee payer' : toBase58(a.feeRecipient);
  return m;
}

export type AnyAuthorization = { version: 1; auth: Authorization } | { version: 2; auth: AuthorizationV2 };

/** Decodes either version by length (292 = v1, 317 = v2). */
export function decodeAny(b: Uint8Array): AnyAuthorization {
  if (b.length === AUTH_LEN) return { version: 1, auth: decode(b) };
  if (b.length === AUTH_V2_LEN) return { version: 2, auth: decodeV2(b) };
  throw new Error('authorization must be 292 (v1) or 317 (v2) bytes');
}

export function describeAny(a: AnyAuthorization): Record<string, string> {
  return a.version === 1 ? describe(a.auth) : describeV2(a.auth);
}

function sameFields(a: Record<string, string>, b: Record<string, string>): boolean {
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && a[k] === b[k]);
}

/** Creates an unsigned envelope. */
export function createEnvelope(auth: Authorization, signerKeyId: Uint8Array): Envelope {
  return { qshield_authorization: 1, fields: describe(auth), auth_hex: toHex(encode(auth)), signer_key_id: toHex(signerKeyId), hints: {} };
}

/** Creates an unsigned v2 envelope. */
export function createEnvelopeV2(auth: AuthorizationV2, signerKeyId: Uint8Array): Envelope {
  return { qshield_authorization: 1, fields: describeV2(auth), auth_hex: toHex(encodeV2(auth)), signer_key_id: toHex(signerKeyId), hints: {} };
}

/** Parses and checks an envelope (fields match bytes; any signature verifies). */
export function parseEnvelope(json: string): Envelope {
  const e = JSON.parse(json) as Envelope;
  if (e.qshield_authorization !== 1) throw new Error('envelope: unsupported version');
  const a = decodeAny(fromHex(e.auth_hex));
  if (!sameFields(e.fields ?? {}, describeAny(a))) throw new Error('envelope: displayed fields do not match the authorization bytes');
  e.hints ??= {};
  if (e.signature_hex !== undefined) {
    if (e.public_key_hex === undefined) throw new Error('envelope: signature without public key');
    const pk = fromHex(e.public_key_hex);
    if (toHex(keyId(pk)) !== e.signer_key_id) throw new Error('envelope: public key does not match signer_key_id');
    if (!verifyAuthorization(pk, fromHex(e.auth_hex), fromHex(e.signature_hex))) throw new Error('envelope: signature does not verify');
  }
  return e;
}

/** Signs an envelope with `signer` after checking it is the expected signer. */
export async function signEnvelope(e: Envelope, signer: PqSigner): Promise<Envelope> {
  if (toHex(signer.keyId) !== e.signer_key_id) throw new Error('envelope: this key is not the expected signer');
  const auth = fromHex(e.auth_hex);
  decodeAny(auth);
  const sig = await signer.signAuthorization(auth);
  if (!verifyAuthorization(signer.publicKey, auth, sig)) throw new Error('envelope: signer produced an invalid signature');
  return { ...e, signature_hex: toHex(sig), public_key_hex: toHex(signer.publicKey) };
}

/** Serializes like the Rust SDK (2-space indentation, trailing newline). */
export function envelopeToJson(e: Envelope): string {
  return JSON.stringify(e, null, 2) + '\n';
}

