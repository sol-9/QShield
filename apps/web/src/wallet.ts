/**
 * Fee-payer wallets. The Solana wallet pays rent and fees for vault creation,
 * deposits and key setup. It never gains authority over the vault.
 *
 * - Wallet Standard wallets (browser extensions) are discovered with the
 *   standard's event protocol and sign whole transactions
 *   (`solana:signTransaction`); the SDK checks they do not alter the message.
 * - A development payer (in-memory Ed25519 key, airdrop-funded) exists for
 *   test networks only and is refused on mainnet.
 */
import { LocalKeypair, localSigner, type TxSigner } from '@qshield/sdk';
import type { ClusterName } from './store.js';

/** Minimal Wallet Standard types (https://github.com/wallet-standard/wallet-standard). */
interface WalletAccount {
  address: string;
  publicKey: Uint8Array;
  chains: readonly string[];
}
export interface StandardWallet {
  name: string;
  icon?: string;
  chains: readonly string[];
  accounts: readonly WalletAccount[];
  features: Record<string, any>;
}

const wallets = new Set<StandardWallet>();
let listener: (() => void) | null = null;

function register(...ws: StandardWallet[]): () => void {
  for (const w of ws) wallets.add(w);
  listener?.();
  return () => {
    for (const w of ws) wallets.delete(w);
    listener?.();
  };
}

/** Starts Wallet Standard discovery; `onChange` runs whenever a wallet registers. */
export function discoverWallets(onChange: () => void): void {
  listener = onChange;
  window.addEventListener('wallet-standard:register-wallet', ((e: CustomEvent) => {
    try {
      e.detail({ register });
    } catch {
      /* ignore misbehaving wallets */
    }
  }) as EventListener);
  window.dispatchEvent(new CustomEvent('wallet-standard:app-ready', { detail: { register } }));
}

export function solanaWallets(): StandardWallet[] {
  return [...wallets].filter((w) => w.features['standard:connect'] && w.features['solana:signTransaction']);
}

export function chainId(c: ClusterName): string {
  return c === 'mainnet' ? 'solana:mainnet' : `solana:${c}`;
}

export interface Payer {
  label: string;
  signer: TxSigner;
  kind: 'wallet' | 'dev';
}

export async function connectWallet(w: StandardWallet, cluster: ClusterName): Promise<Payer> {
  const { accounts } = await w.features['standard:connect'].connect();
  const account: WalletAccount | undefined = accounts[0] ?? w.accounts[0];
  if (!account) throw new Error(`${w.name}: no account`);
  const chain = chainId(cluster);
  const sign = w.features['solana:signTransaction'];
  return {
    label: `${w.name} ${account.address}`,
    kind: 'wallet',
    signer: {
      publicKey: Uint8Array.from(account.publicKey),
      async signTransaction(transaction: Uint8Array): Promise<Uint8Array> {
        const [out] = await sign.signTransaction({ account, transaction, chain });
        if (!out?.signedTransaction) throw new Error('wallet returned no transaction');
        return Uint8Array.from(out.signedTransaction);
      },
    },
  };
}

/** In-memory development payer. Test networks only; lost on reload. */
export function devPayer(cluster: ClusterName): Payer & { keypair: LocalKeypair } {
  if (cluster === 'mainnet') throw new Error('The development payer is disabled on mainnet.');
  const keypair = LocalKeypair.generate();
  return { label: 'development payer (test networks only)', kind: 'dev', signer: localSigner(keypair), keypair };
}
