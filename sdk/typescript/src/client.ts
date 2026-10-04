/**
 * High-level client. Reads chain state over JSON-RPC, builds QSP-1
 * authorizations and envelopes, and produces the instructions to submit a
 * signed authorization through either transport. Transaction assembly and
 * fee payment are left to the caller's transaction library or a relayer:
 * the fee payer never needs, and never gets, any authority over the vault.
 */
import { base64 } from '@scure/base';
import { address, equal, fromHex, isZero, toBase58, toHex } from './bytes.js';
import { KEY_ACCOUNT_LEN, KeyState, VAULT_LEN, parseKeyHeader, parseVault, type KeyHeader, type VaultState } from './accounts.js';
import { createEnvelope, createEnvelopeV2, parseEnvelope, type Envelope } from './envelope.js';
import { availableAt, parsePolicy, parseProposal, type PolicyState, type ProposalState } from './accounts.js';
import { ActionV2, AUTH_V2_LEN, Role, decodeV2, type AuthorizationV2 } from './qsp1v2.js';
import { verifyAuthorization } from './keys.js';
import * as ix from './instructions.js';
import { policyAddress, proposalAddress, sigBufferAddress, vaultAddress } from './pda.js';
import { Action, AssetType, CLUSTER, ZERO32, decode, type Authorization } from './qsp1.js';
import { assetTypeFor, associatedTokenAddress, parseMint, parseTokenAccount, tokenProgramFor, type MintInfo, type TokenAccountInfo } from './token.js';

export interface AccountInfo {
  lamports: bigint;
  owner: Uint8Array;
  data: Uint8Array;
}

/** Minimal chain read access. */
export interface RpcLike {
  getAccount(address: Uint8Array): Promise<AccountInfo | null>;
  getMinimumBalanceForRentExemption(len: number): Promise<bigint>;
  getGenesisHash(): Promise<Uint8Array>;
}

/** Chain access needed to send transactions (vault creation, deposits). */
export interface ChainRpc extends RpcLike {
  getLatestBlockhash(): Promise<Uint8Array>;
  /** Sends a serialized transaction and waits for `confirmed`; returns its signature. */
  sendAndConfirm(tx: Uint8Array, timeoutMs?: number): Promise<string>;
  getTokenAccountsByOwner(owner: Uint8Array, tokenProgram: Uint8Array): Promise<{ address: Uint8Array; account: AccountInfo }[]>;
}

/** JSON-RPC over `fetch` (commitment `confirmed`). */
export class JsonRpc implements ChainRpc {
  constructor(readonly url: string) {}

  private async call(method: string, params: unknown[]): Promise<any> {
    const res = await fetch(this.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
    const body = (await res.json()) as { result?: unknown; error?: { message?: string } };
    if (body.error) throw new Error(`rpc ${method}: ${body.error.message ?? 'error'}`);
    return body.result;
  }

  async getAccount(addr: Uint8Array): Promise<AccountInfo | null> {
    const r = await this.call('getAccountInfo', [toBase58(addr), { encoding: 'base64', commitment: 'confirmed' }]);
    if (!r?.value) return null;
    return { lamports: BigInt(r.value.lamports), owner: address(r.value.owner), data: base64.decode(r.value.data[0]) };
  }

  async getMinimumBalanceForRentExemption(len: number): Promise<bigint> {
    return BigInt(await this.call('getMinimumBalanceForRentExemption', [len]));
  }

  async getGenesisHash(): Promise<Uint8Array> {
    return address(await this.call('getGenesisHash', []));
  }

  async getLatestBlockhash(): Promise<Uint8Array> {
    const r = await this.call('getLatestBlockhash', [{ commitment: 'confirmed' }]);
    return address(r.value.blockhash);
  }

  async sendAndConfirm(tx: Uint8Array, timeoutMs = 90_000): Promise<string> {
    const sig: string = await this.call('sendTransaction', [base64.encode(tx), { encoding: 'base64', preflightCommitment: 'confirmed' }]);
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) {
      const st = (await this.call('getSignatureStatuses', [[sig]])).value[0];
      if (st) {
        if (st.err) throw new Error(`transaction ${sig} failed: ${JSON.stringify(st.err)}`);
        if (st.confirmationStatus === 'confirmed' || st.confirmationStatus === 'finalized') return sig;
      }
      await new Promise((r) => setTimeout(r, 400));
    }
    throw new Error(`transaction ${sig} not confirmed within ${timeoutMs} ms`);
  }

  async getTokenAccountsByOwner(owner: Uint8Array, tokenProgram: Uint8Array): Promise<{ address: Uint8Array; account: AccountInfo }[]> {
    const r = await this.call('getTokenAccountsByOwner', [toBase58(owner), { programId: toBase58(tokenProgram) }, { encoding: 'base64', commitment: 'confirmed' }]);
    return (r.value as any[]).map((v) => ({
      address: address(v.pubkey),
      account: { lamports: BigInt(v.account.lamports), owner: address(v.account.owner), data: base64.decode(v.account.data[0]) },
    }));
  }

  /** Test networks only. */
  async requestAirdrop(to: Uint8Array, lamports: bigint): Promise<string> {
    return this.call('requestAirdrop', [toBase58(to), Number(lamports), { commitment: 'confirmed' }]);
  }
}

export interface VaultInfo {
  address: Uint8Array;
  state: VaultState;
  lamports: bigint;
  /** Withdrawable (balance minus rent reserve). */
  available: bigint;
}

export interface AuthOptions {
  /** Unix seconds; 0n = immediately. */
  validAfter?: bigint;
  /** Unix seconds; 0n = never. Default: one hour from now. */
  expiresAt?: bigint;
  feeLamports?: bigint;
  /** Default: whoever pays the transaction fee. */
  feeRecipient?: Uint8Array;
}

export type Transport = 'inline' | 'buffered';

export interface MintAccount {
  address: Uint8Array;
  tokenProgram: Uint8Array;
  assetType: AssetType;
  info: MintInfo;
}

/** One transaction's worth of instructions plus extra signers it needs (besides the fee payer). */
export interface TxPlan {
  instructions: ix.Instruction[];
  /** 'v1' transactions (SIMD-0385) are required for the inline Execute (≈ 3 KB). */
  format: 'legacy' | 'v1';
  computeUnitLimit?: number;
}

const EXECUTE_CU_LIMIT = 1_000_000;
const CHUNK = 900;

export class QShield {
  readonly rpc: RpcLike;
  readonly programId: Uint8Array;
  readonly clusterId: Uint8Array;

  constructor(opts: { rpc: RpcLike; programId: Uint8Array | string; clusterId: Uint8Array }) {
    this.rpc = opts.rpc;
    this.programId = typeof opts.programId === 'string' ? address(opts.programId) : opts.programId;
    this.clusterId = opts.clusterId;
  }

  /** Refuses to proceed if the RPC endpoint serves a different cluster (skipped for localnet). */
  async checkCluster(): Promise<void> {
    if (equal(this.clusterId, CLUSTER.localnet)) return;
    const g = await this.rpc.getGenesisHash();
    if (!equal(g, this.clusterId)) throw new Error(`RPC endpoint is cluster ${toHex(g)}, expected ${toHex(this.clusterId)}`);
  }

  vaultAddress(initialKeyId: Uint8Array, vaultSeed: Uint8Array): Uint8Array {
    return vaultAddress(this.programId, initialKeyId, vaultSeed)[0];
  }

  async getVault(addr: Uint8Array): Promise<VaultInfo> {
    const a = await this.rpc.getAccount(addr);
    if (!a) throw new Error(`vault ${toBase58(addr)} not found`);
    if (!equal(a.owner, this.programId)) throw new Error(`${toBase58(addr)} is not owned by the QShield program`);
    const state = parseVault(a.data);
    const rent = await this.rpc.getMinimumBalanceForRentExemption(VAULT_LEN);
    return { address: addr, state, lamports: a.lamports, available: a.lamports > rent ? a.lamports - rent : 0n };
  }

  /** Use before depositing: checks the vault is controlled by `expectedKeyId`. */
  async getVaultChecked(addr: Uint8Array, expectedKeyId: Uint8Array): Promise<VaultInfo> {
    const v = await this.getVault(addr);
    if (!equal(v.state.keyId, expectedKeyId)) throw new Error(`vault is controlled by key ${toHex(v.state.keyId)}, not ${toHex(expectedKeyId)}`);
    return v;
  }

  async getKeyAccount(addr: Uint8Array): Promise<KeyHeader> {
    const a = await this.rpc.getAccount(addr);
    if (!a) throw new Error(`key account ${toBase58(addr)} not found`);
    if (!equal(a.owner, this.programId) || a.data.length !== KEY_ACCOUNT_LEN) throw new Error(`${toBase58(addr)} is not a QShield key account`);
    return parseKeyHeader(a.data);
  }

  /** Reads a mint and applies the program's mint policy (throws for unsupported mints). */
  async getMint(mint: Uint8Array): Promise<MintAccount> {
    const a = await this.rpc.getAccount(mint);
    if (!a) throw new Error(`mint ${toBase58(mint)} not found`);
    const assetType = assetTypeFor(a.owner);
    if (assetType === null) throw new Error(`${toBase58(mint)} is not owned by the SPL Token or Token-2022 program`);
    return { address: mint, tokenProgram: a.owner, assetType, info: parseMint(a.owner, a.data) };
  }

  /** The vault's associated token account for a mint. */
  vaultTokenAddress(vault: Uint8Array, mint: MintAccount): Uint8Array {
    return associatedTokenAddress(vault, mint.address, mint.tokenProgram);
  }

  async getTokenAccount(addr: Uint8Array, tokenProgram: Uint8Array): Promise<TokenAccountInfo | null> {
    const a = await this.rpc.getAccount(addr);
    if (!a) return null;
    if (!equal(a.owner, tokenProgram)) throw new Error(`${toBase58(addr)} is not a token account of ${toBase58(tokenProgram)}`);
    return parseTokenAccount(tokenProgram, a.data);
  }

  /**
   * Instructions for one legacy transaction depositing `amount` base units
   * from the depositor's associated token account: create the vault's token
   * account if needed, then `DepositSpl` (checked on-chain).
   */
  async planDepositSpl(p: { vault: Uint8Array; depositor: Uint8Array; mint: Uint8Array; amount: bigint }): Promise<TxPlan> {
    if (p.amount <= 0n) throw new Error('amount must be positive');
    await this.getVault(p.vault);
    const m = await this.getMint(p.mint);
    const source = associatedTokenAddress(p.depositor, p.mint, m.tokenProgram);
    const src = await this.getTokenAccount(source, m.tokenProgram);
    if (!src || src.amount < p.amount) throw new Error('depositor token balance too low');
    const vaultTa = this.vaultTokenAddress(p.vault, m);
    return {
      format: 'legacy',
      instructions: [
        ix.createAtaIdempotent(p.depositor, p.vault, p.mint, m.tokenProgram),
        ix.depositSpl(this.programId, p.depositor, source, p.mint, vaultTa, p.vault, m.tokenProgram, p.amount, m.info.decimals),
      ],
    };
  }

  // ------------------------------------------------------------ intents

  private base(vault: Uint8Array, nonce: bigint, action: Action, o: AuthOptions = {}): Authorization {
    const fee = o.feeLamports ?? 0n;
    return {
      clusterId: this.clusterId,
      programId: this.programId,
      vault,
      action,
      assetType: AssetType.None,
      nonce,
      validAfter: o.validAfter ?? 0n,
      expiresAt: o.expiresAt ?? BigInt(Math.floor(Date.now() / 1000) + 3600),
      mint: ZERO32,
      destination: ZERO32,
      amount: 0n,
      decimals: 0,
      feeRecipient: fee > 0n && o.feeRecipient ? o.feeRecipient : ZERO32,
      feeLamports: fee,
      newKeyId: ZERO32,
      newAlgorithm: 0,
    };
  }

  createWithdrawSolIntent(p: { vault: Uint8Array; nonce: bigint; destination: Uint8Array; lamports: bigint } & AuthOptions): Authorization {
    return { ...this.base(p.vault, p.nonce, Action.WithdrawSol, p), assetType: AssetType.Sol, destination: p.destination, amount: p.lamports };
  }
  /** WithdrawSpl to the associated token account of `toOwner` (decimals and program taken from the mint). */
  createWithdrawSplIntent(p: { vault: Uint8Array; nonce: bigint; mint: MintAccount; toOwner: Uint8Array; amount: bigint } & AuthOptions): Authorization {
    return {
      ...this.base(p.vault, p.nonce, Action.WithdrawSpl, p),
      assetType: p.mint.assetType,
      mint: p.mint.address,
      destination: associatedTokenAddress(p.toOwner, p.mint.address, p.mint.tokenProgram),
      amount: p.amount,
      decimals: p.mint.info.decimals,
    };
  }
  createRotateKeyIntent(p: { vault: Uint8Array; nonce: bigint; newKeyId: Uint8Array } & AuthOptions): Authorization {
    return { ...this.base(p.vault, p.nonce, Action.RotateKey, p), newKeyId: p.newKeyId, newAlgorithm: 1 };
  }
  createPauseIntent(p: { vault: Uint8Array; nonce: bigint } & AuthOptions): Authorization {
    return this.base(p.vault, p.nonce, Action.Pause, p);
  }
  createUnpauseIntent(p: { vault: Uint8Array; nonce: bigint } & AuthOptions): Authorization {
    return this.base(p.vault, p.nonce, Action.Unpause, p);
  }
  createCloseVaultIntent(p: { vault: Uint8Array; nonce: bigint; destination: Uint8Array } & AuthOptions): Authorization {
    return { ...this.base(p.vault, p.nonce, Action.CloseVault, p), assetType: AssetType.Sol, destination: p.destination };
  }

  // ------------------------------------------------- guardian policy (v2)

  /** The vault's guardian policy, or null (ADR-0018). */
  async getPolicy(vault: Uint8Array): Promise<PolicyState | null> {
    const a = await this.rpc.getAccount(policyAddress(this.programId, vault)[0]);
    if (!a || !equal(a.owner, this.programId)) return null;
    return parsePolicy(a.data);
  }

  async getProposal(vault: Uint8Array, id: bigint): Promise<ProposalState | null> {
    const a = await this.rpc.getAccount(proposalAddress(this.programId, vault, id)[0]);
    if (!a || !equal(a.owner, this.programId) || a.lamports === 0n) return null;
    return parseProposal(a.data);
  }

  /** Whether a SOL send can go out now with the everyday key alone. */
  solSendPath(p: PolicyState, to: Uint8Array, lamports: bigint, fee = 0n, now = BigInt(Math.floor(Date.now() / 1000))): 'instant' | 'needs-guardian' {
    const saved = p.saved.some((s) => equal(s, to));
    const need = fee + (saved ? 0n : lamports);
    return need <= availableAt(p, now) ? 'instant' : 'needs-guardian';
  }

  v2Base(vault: Uint8Array, role: Role, nonce: bigint, action: ActionV2, o: AuthOptions = {}): AuthorizationV2 {
    const b = this.base(vault, nonce, 0 as Action, o);
    return { ...b, action, role, refId: 0n, limitLamports: 0n, limitPeriod: 0n };
  }

  /** The nonce a role signs with now. */
  async roleNonce(vault: Uint8Array, role: Role): Promise<bigint> {
    if (role === Role.Everyday) return (await this.getVault(vault)).state.nonce;
    const p = await this.getPolicy(vault);
    if (!p?.enabled) throw new Error('the vault has no guardian policy');
    return p.guardianNonce;
  }

  /** Builds an unsigned v2 envelope for the signing role's current nonce. */
  async prepareV2(vault: Uint8Array, role: Role, build: (nonce: bigint) => AuthorizationV2, signerKeyId?: Uint8Array): Promise<Envelope> {
    const nonce = await this.roleNonce(vault, role);
    let kid = signerKeyId;
    if (!kid) {
      if (role === Role.Everyday) kid = (await this.getVault(vault)).state.keyId;
      else kid = (await this.getPolicy(vault))!.guardianKeyId;
    }
    return createEnvelopeV2(build(nonce), kid);
  }

  /** v2 SOL transfer fields (send now, or propose). */
  createV2SolTransfer(p: { vault: Uint8Array; nonce: bigint; action: ActionV2.WithdrawSol | ActionV2.ProposeWithdraw; destination: Uint8Array; lamports: bigint } & AuthOptions): AuthorizationV2 {
    return { ...this.v2Base(p.vault, Role.Everyday, p.nonce, p.action, p), assetType: AssetType.Sol, destination: p.destination, amount: p.lamports };
  }

  /** The guardian approval restating a proposal's exact effect. */
  createApproval(vault: Uint8Array, guardianNonce: bigint, prop: ProposalState, o: AuthOptions = {}): AuthorizationV2 {
    return {
      ...this.v2Base(vault, Role.Guardian, guardianNonce, ActionV2.ApproveWithdraw, o),
      assetType: prop.assetType,
      mint: prop.mint,
      destination: prop.destination,
      amount: prop.amount,
      decimals: prop.decimals,
      refId: prop.id,
    };
  }

  /** Accounts after `[fee_payer, vault, signer_key, policy]` (PROTOCOL §5). */
  private async actionAccountsV2(a: AuthorizationV2, vault: VaultState, hints: Envelope['hints']): Promise<ix.AccountMeta[]> {
    const w = (pubkey: Uint8Array): ix.AccountMeta => ({ pubkey, isSigner: false, isWritable: true });
    const ro = (pubkey: Uint8Array): ix.AccountMeta => ({ pubkey, isSigner: false, isWritable: false });
    const transfer = (): ix.AccountMeta[] => {
      if (a.assetType === AssetType.Sol) return [w(a.destination)];
      const program = tokenProgramFor(a.assetType);
      if (!program) throw new Error('bad asset');
      const source = hints.source_token_account ? address(hints.source_token_account) : associatedTokenAddress(a.vault, a.mint, program);
      return ix.withdrawSplAccounts(source, a.mint, a.destination, program);
    };
    const newKey = () => {
      if (!hints.new_key_account) throw new Error('needs hints.new_key_account');
      return address(hints.new_key_account);
    };
    let accts: ix.AccountMeta[];
    switch (a.action) {
      case ActionV2.WithdrawSol:
      case ActionV2.WithdrawSpl:
        accts = transfer();
        break;
      case ActionV2.ProposeWithdraw:
        accts = [w(proposalAddress(this.programId, a.vault, a.nonce)[0]), ro(ix.SYSTEM_PROGRAM_ID)];
        break;
      case ActionV2.ApproveWithdraw:
      case ActionV2.CancelProposal: {
        const p = await this.getProposal(a.vault, a.refId);
        if (!p) throw new Error(`proposal ${a.refId} not found`);
        accts = [w(proposalAddress(this.programId, a.vault, a.refId)[0]), w(p.rentPayer)];
        if (a.action === ActionV2.ApproveWithdraw) accts.push(...transfer());
        break;
      }
      case ActionV2.RotateKey: {
        const old = await this.getKeyAccount(vault.keyAccount);
        accts = [w(newKey()), w(vault.keyAccount), w(old.creator)];
        break;
      }
      case ActionV2.RotateGuardian: {
        const pol = await this.getPolicy(a.vault);
        const old = await this.getKeyAccount(pol!.guardianKeyAccount);
        accts = [w(newKey()), w(old.creator)];
        break;
      }
      case ActionV2.EnablePolicy:
        accts = [w(newKey()), ro(ix.SYSTEM_PROGRAM_ID)];
        break;
      default:
        accts = [];
    }
    if (a.feeLamports > 0n && !isZero(a.feeRecipient)) accts.push(w(a.feeRecipient));
    return accts;
  }

  /** Builds an unsigned envelope for the vault's current nonce and key. */
  async prepare(vault: Uint8Array, build: (nonce: bigint) => Authorization): Promise<Envelope> {
    const v = await this.getVault(vault);
    return createEnvelope(build(v.state.nonce), v.state.keyId);
  }

  // ------------------------------------------------------------- submission

  /** Accounts after `[fee_payer, vault, key_account]` (docs/PROTOCOL.md §1.1). */
  async actionAccounts(auth: Authorization, vault: VaultState, hints: Envelope['hints']): Promise<ix.AccountMeta[]> {
    const w = (pubkey: Uint8Array): ix.AccountMeta => ({ pubkey, isSigner: false, isWritable: true });
    let accts: ix.AccountMeta[];
    switch (auth.action) {
      case Action.WithdrawSol:
        accts = [w(auth.destination)];
        break;
      case Action.RotateKey: {
        if (!hints.new_key_account) throw new Error('RotateKey needs hints.new_key_account');
        const newKey = address(hints.new_key_account);
        const k = await this.getKeyAccount(newKey);
        if (k.state !== KeyState.Ready || !equal(k.keyId, auth.newKeyId)) throw new Error('new key account is not ready for this key id');
        const old = await this.getKeyAccount(vault.keyAccount);
        accts = [w(newKey), w(old.creator)];
        break;
      }
      case Action.Pause:
      case Action.Unpause:
        accts = [];
        break;
      case Action.CloseVault: {
        const old = await this.getKeyAccount(vault.keyAccount);
        accts = [w(auth.destination), w(old.creator)];
        break;
      }
      case Action.WithdrawSpl: {
        const program = tokenProgramFor(auth.assetType);
        if (!program) throw new Error('WithdrawSpl without a token asset');
        const source = hints.source_token_account ? address(hints.source_token_account) : associatedTokenAddress(auth.vault, auth.mint, program);
        accts = ix.withdrawSplAccounts(source, auth.mint, auth.destination, program);
        break;
      }
      default:
        throw new Error('unknown action');
    }
    if (auth.feeLamports > 0n && !isZero(auth.feeRecipient)) accts.push(w(auth.feeRecipient));
    return accts;
  }

  private async planSubmissionV2(authBytes: Uint8Array, sig: Uint8Array, hints: Envelope['hints'], feePayer: Uint8Array, transport: Transport, bufferId?: bigint): Promise<TxPlan[]> {
    const a = decodeV2(authBytes);
    if (!equal(a.clusterId, this.clusterId) || !equal(a.programId, this.programId)) throw new Error('authorization is for another cluster or program');
    const v = await this.getVault(a.vault);
    const pol = await this.getPolicy(a.vault);
    let signerKey: Uint8Array;
    let nonce: bigint;
    if (a.role === Role.Everyday) {
      signerKey = v.state.keyAccount;
      nonce = v.state.nonce;
    } else {
      if (!pol?.enabled) throw new Error('the vault has no guardian policy');
      signerKey = pol.guardianKeyAccount;
      nonce = pol.guardianNonce;
    }
    if (nonce !== a.nonce) throw new Error(`authorization nonce ${a.nonce}, ${Role[a.role]} nonce ${nonce}`);
    const key = await this.getKeyAccount(signerKey);
    if (!key.publicKey || !verifyAuthorization(key.publicKey, authBytes, sig)) throw new Error(`signature is not valid for the vault's current ${Role[a.role]} key`);
    const accts = await this.actionAccountsV2(a, v.state, hints);
    const pre: ix.Instruction[] = [];
    if ((a.action === ActionV2.WithdrawSpl || a.action === ActionV2.ApproveWithdraw) && a.assetType !== AssetType.Sol && hints.destination_owner) {
      const program = tokenProgramFor(a.assetType)!;
      const owner = address(hints.destination_owner);
      if (!equal(associatedTokenAddress(owner, a.mint, program), a.destination)) throw new Error("destination is not the owner's token account");
      if (!(await this.rpc.getAccount(a.destination))) pre.push(ix.createAtaIdempotent(feePayer, owner, a.mint, program));
    }
    const policy = policyAddress(this.programId, a.vault)[0];
    if (transport === 'inline') {
      return [{ format: 'v1', computeUnitLimit: EXECUTE_CU_LIMIT, instructions: [...pre, ix.executeV2(this.programId, feePayer, a.vault, signerKey, policy, accts, authBytes, sig)] }];
    }
    const id = bufferId ?? BigInt('0x' + toHex(crypto.getRandomValues(new Uint8Array(8))));
    const [buf] = sigBufferAddress(this.programId, a.vault, feePayer, id);
    const plans: TxPlan[] = [{ format: 'legacy', instructions: [ix.createSigBuffer(this.programId, feePayer, buf, a.vault, id)] }];
    for (let off = 0; off < sig.length; off += CHUNK) {
      plans.push({ format: 'legacy', instructions: [ix.writeSigBuffer(this.programId, feePayer, buf, off, off + CHUNK >= sig.length, sig.subarray(off, off + CHUNK))] });
    }
    plans.push({ format: 'legacy', computeUnitLimit: EXECUTE_CU_LIMIT, instructions: [...pre, ix.executeV2WithBuffer(this.programId, feePayer, a.vault, signerKey, policy, buf, feePayer, accts, authBytes)] });
    return plans;
  }

  /** Same local checks as the Rust SDK; returns the destination-ATA creation if needed. */
  private async withdrawSplPrechecks(auth: Authorization, feePayer: Uint8Array, source: Uint8Array, hints: Envelope['hints']): Promise<ix.Instruction[]> {
    const m = await this.getMint(auth.mint);
    if (m.assetType !== auth.assetType) throw new Error('authorization asset type does not match the mint\'s token program');
    if (m.info.decimals !== auth.decimals) throw new Error(`authorization says ${auth.decimals} decimals but the mint has ${m.info.decimals}`);
    const src = await this.getTokenAccount(source, m.tokenProgram);
    if (!src || !equal(src.owner, auth.vault) || !equal(src.mint, auth.mint) || src.frozen) throw new Error(`${toBase58(source)} is not a usable vault token account`);
    if (src.amount < auth.amount) throw new Error('vault token balance too low');
    const dst = await this.getTokenAccount(auth.destination, m.tokenProgram);
    if (dst) {
      if (!equal(dst.mint, auth.mint)) throw new Error('destination holds another mint');
      return [];
    }
    if (!hints.destination_owner) throw new Error('destination token account does not exist (no destination_owner hint to create it)');
    const owner = address(hints.destination_owner);
    if (!equal(associatedTokenAddress(owner, auth.mint, m.tokenProgram), auth.destination)) throw new Error("destination is not the owner's associated token account");
    return [ix.createAtaIdempotent(feePayer, owner, auth.mint, m.tokenProgram)];
  }

  /**
   * Checks a signed envelope against current chain state (nonce, key) and
   * returns the transactions to send, in order, paid by `feePayer`.
   */
  async planSubmission(signed: Envelope | string, feePayer: Uint8Array, transport: Transport = 'inline', bufferId?: bigint): Promise<TxPlan[]> {
    const e = typeof signed === 'string' ? parseEnvelope(signed) : parseEnvelope(JSON.stringify(signed));
    if (!e.signature_hex) throw new Error('envelope is not signed');
    const authBytes = fromHex(e.auth_hex);
    const sig = fromHex(e.signature_hex);
    if (authBytes.length === AUTH_V2_LEN) return this.planSubmissionV2(authBytes, sig, e.hints, feePayer, transport, bufferId);
    const auth = decode(authBytes);
    if (!equal(auth.clusterId, this.clusterId)) throw new Error('authorization is for another cluster');
    if (!equal(auth.programId, this.programId)) throw new Error('authorization is for another program');
    const v = await this.getVault(auth.vault);
    if (v.state.nonce !== auth.nonce) throw new Error(`authorization nonce ${auth.nonce}, vault nonce ${v.state.nonce}`);
    const key = await this.getKeyAccount(v.state.keyAccount);
    if (!key.publicKey || !verifyAuthorization(key.publicKey, authBytes, sig)) throw new Error("signature is not valid for the vault's current key");
    const accts = await this.actionAccounts(auth, v.state, e.hints);
    const pre = auth.action === Action.WithdrawSpl ? await this.withdrawSplPrechecks(auth, feePayer, accts[0]!.pubkey, e.hints) : [];
    if (transport === 'inline') {
      return [{ format: 'v1', computeUnitLimit: EXECUTE_CU_LIMIT, instructions: [...pre, ix.execute(this.programId, feePayer, auth.vault, v.state.keyAccount, accts, authBytes, sig)] }];
    }
    const id = bufferId ?? BigInt('0x' + toHex(crypto.getRandomValues(new Uint8Array(8))));
    const [buf] = sigBufferAddress(this.programId, auth.vault, feePayer, id);
    const plans: TxPlan[] = [{ format: 'legacy', instructions: [ix.createSigBuffer(this.programId, feePayer, buf, auth.vault, id)] }];
    for (let off = 0; off < sig.length; off += CHUNK) {
      const chunk = sig.subarray(off, off + CHUNK);
      plans.push({ format: 'legacy', instructions: [ix.writeSigBuffer(this.programId, feePayer, buf, off, off + CHUNK >= sig.length, chunk)] });
    }
    plans.push({
      format: 'legacy',
      computeUnitLimit: EXECUTE_CU_LIMIT,
      instructions: [...pre, ix.executeWithBuffer(this.programId, feePayer, auth.vault, v.state.keyAccount, buf, feePayer, accts, authBytes)],
    });
    return plans;
  }
}
