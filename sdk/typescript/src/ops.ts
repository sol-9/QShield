/**
 * Operations that send transactions paid by an ordinary Solana wallet:
 * key-account setup, vault creation, deposits, and the key setup half of a
 * rotation. The wallet pays rent and fees and gains no authority over the
 * vault. Withdrawals and other authorizations go through `RelayerClient` or
 * `planSubmission` instead.
 */
import { equal, toBase58, writeU64 } from './bytes.js';
import { KEY_ACCOUNT_LEN, KeyState, VaultStatus } from './accounts.js';
import type { ChainRpc, QShield, VaultInfo } from './client.js';
import * as ix from './instructions.js';
import { keyId } from './qsp1.js';
import { TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, associatedTokenAddress, parseMint, parseTokenAccount, type TokenAccountInfo } from './token.js';
import { LocalKeypair, buildLegacyTransaction, localSigner, setComputeUnitLimit, type TxSigner } from './transaction.js';

export const KEY_CHUNK = 900;
const EXPAND_PER_TX = 10;
const EXPAND_TOTAL = 20;

/** System program `CreateAccount`. */
export function systemCreateAccount(from: Uint8Array, to: Uint8Array, lamports: bigint, space: number, owner: Uint8Array): ix.Instruction {
  const d = new Uint8Array(52);
  writeU64(d, 4, lamports);
  writeU64(d, 12, BigInt(space));
  d.set(owner, 20);
  return { programId: ix.SYSTEM_PROGRAM_ID, keys: [{ pubkey: from, isSigner: true, isWritable: true }, { pubkey: to, isSigner: true, isWritable: true }], data: d };
}

export interface Progress {
  step: number;
  total: number;
  label: string;
  signature?: string;
}

export interface TokenBalance {
  address: Uint8Array;
  tokenProgram: Uint8Array;
  account: TokenAccountInfo;
  /** null if the mint is unsupported or unreadable. */
  decimals: number | null;
}

export class VaultOperations {
  constructor(
    readonly q: QShield,
    readonly rpc: ChainRpc,
  ) {}

  private async send(payer: TxSigner, ixs: ix.Instruction[], extra: TxSigner[] = []): Promise<string> {
    const bh = await this.rpc.getLatestBlockhash();
    return this.rpc.sendAndConfirm(await buildLegacyTransaction(payer, ixs, bh, extra));
  }

  /**
   * Uploads and expands `publicKey` into a new key account bound to `vault`
   * (6 transactions, ≈ 0.154 SOL rent paid by `payer`, refunded on rotation
   * away or close). Returns the key account address.
   */
  async setupKey(payer: TxSigner, vault: Uint8Array, publicKey: Uint8Array, onProgress?: (p: Progress) => void): Promise<Uint8Array> {
    const id = keyId(publicKey);
    const keyKp = LocalKeypair.generate();
    const keyAcct = keyKp.publicKey;
    const rent = await this.rpc.getMinimumBalanceForRentExemption(KEY_ACCOUNT_LEN);
    const pid = this.q.programId;
    const chunks = Math.ceil(publicKey.length / KEY_CHUNK);
    const total = 2 + chunks + EXPAND_TOTAL / EXPAND_PER_TX;
    let step = 0;
    const report = (label: string, signature?: string) => onProgress?.({ step: ++step, total, label, signature });
    report('create key account', await this.send(payer, [systemCreateAccount(payer.publicKey, keyAcct, rent, KEY_ACCOUNT_LEN, pid), ix.createKey(pid, payer.publicKey, keyAcct, vault, id)], [localSigner(keyKp)]));
    for (let off = 0; off < publicKey.length; off += KEY_CHUNK) {
      report('upload public key', await this.send(payer, [ix.writeKey(pid, payer.publicKey, keyAcct, off, publicKey.subarray(off, off + KEY_CHUNK))]));
    }
    report('verify key id', await this.send(payer, [setComputeUnitLimit(300_000), ix.finalizeKey(pid, payer.publicKey, keyAcct)]));
    for (let i = 0; i < EXPAND_TOTAL / EXPAND_PER_TX; i++) {
      report('expand key', await this.send(payer, [setComputeUnitLimit(1_000_000), ix.expandKey(pid, keyAcct, EXPAND_PER_TX)]));
    }
    const k = await this.q.getKeyAccount(keyAcct);
    if (k.state !== KeyState.Ready || !equal(k.keyId, id)) throw new Error('key account did not become ready');
    return keyAcct;
  }

  /** Creates a vault controlled by `publicKey` (7 transactions: 6 key setup + initialize). Returns `[vault, keyAccount]`. */
  async createVault(payer: TxSigner, publicKey: Uint8Array, vaultSeed: Uint8Array, onProgress?: (p: Progress) => void): Promise<[Uint8Array, Uint8Array]> {
    const id = keyId(publicKey);
    const vault = this.q.vaultAddress(id, vaultSeed);
    const existing = await this.rpc.getAccount(vault);
    if (existing && equal(existing.owner, this.q.programId)) throw new Error(`vault ${toBase58(vault)} already exists`);
    let total = 0;
    const keyAcct = await this.setupKey(payer, vault, publicKey, (p) => {
      total = p.total + 1;
      onProgress?.({ ...p, total });
    });
    const sig = await this.send(payer, [ix.initializeVault(this.q.programId, payer.publicKey, vault, keyAcct, vaultSeed)]);
    onProgress?.({ step: total, total, label: 'initialize vault', signature: sig });
    await this.q.getVaultChecked(vault, id);
    return [vault, keyAcct];
  }

  /** Deposits SOL after checking the vault is controlled by `expectedKeyId`. */
  async depositSol(payer: TxSigner, vault: Uint8Array, lamports: bigint, expectedKeyId: Uint8Array): Promise<string> {
    const v = await this.q.getVaultChecked(vault, expectedKeyId);
    if (v.state.status === VaultStatus.Closed) throw new Error('vault is closed');
    return this.send(payer, [ix.depositSol(this.q.programId, payer.publicKey, vault, lamports)]);
  }

  /** Deposits tokens from the payer's associated token account (creates the vault's token account if needed). */
  async depositSpl(payer: TxSigner, vault: Uint8Array, mint: Uint8Array, amount: bigint, expectedKeyId: Uint8Array): Promise<string> {
    const v = await this.q.getVaultChecked(vault, expectedKeyId);
    if (v.state.status === VaultStatus.Closed) throw new Error('vault is closed');
    const plan = await this.q.planDepositSpl({ vault, depositor: payer.publicKey, mint, amount });
    return this.send(payer, plan.instructions);
  }

  /** SOL and token balances of a vault (tokens via getTokenAccountsByOwner). */
  async balances(vault: Uint8Array): Promise<{ vault: VaultInfo; tokens: TokenBalance[] }> {
    const v = await this.q.getVault(vault);
    const tokens: TokenBalance[] = [];
    for (const program of [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID]) {
      for (const { address, account } of await this.rpc.getTokenAccountsByOwner(vault, program)) {
        if (!equal(account.owner, program)) continue;
        let t: TokenAccountInfo;
        try {
          t = parseTokenAccount(program, account.data);
        } catch {
          continue;
        }
        if (!equal(t.owner, vault)) continue;
        let decimals: number | null = null;
        try {
          const m = await this.rpc.getAccount(t.mint);
          if (m && equal(m.owner, program)) decimals = parseMint(program, m.data).decimals;
        } catch {
          decimals = null;
        }
        tokens.push({ address, tokenProgram: program, account: t, decimals });
      }
    }
    return { vault: v, tokens };
  }

  /** The vault's associated token account for a mint and program (for "receive"). */
  vaultTokenAddress(vault: Uint8Array, mint: Uint8Array, tokenProgram: Uint8Array): Uint8Array {
    return associatedTokenAddress(vault, mint, tokenProgram);
  }
}
