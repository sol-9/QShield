/** Shared Playwright helpers: a simulated Wallet Standard wallet and the backup flow. */
import { readFileSync } from 'node:fs';
import { expect, type Page } from '@playwright/test';
import { LocalKeypair, toBase58 } from '@qshield/sdk';

/** Signs the wallet's slot of a serialized legacy transaction. */
export function signSlot(kp: LocalKeypair, tx: Uint8Array): Uint8Array {
  const n = tx[0]!; // < 128 signatures: one-byte shortvec
  const msg = tx.subarray(1 + 64 * n);
  const required = msg[0]!;
  const keys = msg.subarray(4); // header (3) + one-byte key count
  const out = Uint8Array.from(tx);
  for (let i = 0; i < required; i++) {
    if (toBase58(keys.subarray(32 * i, 32 * i + 32)) === toBase58(kp.publicKey)) {
      out.set(kp.sign(msg), 1 + 64 * i);
      return out;
    }
  }
  throw new Error('wallet is not a signer of this transaction');
}

export async function installWallet(page: Page, kp: LocalKeypair) {
  await page.exposeFunction('__qshieldTestSign', (txB64: string) => Buffer.from(signSlot(kp, Buffer.from(txB64, 'base64'))).toString('base64'));
  const pk = Array.from(kp.publicKey);
  const addr = toBase58(kp.publicKey);
  await page.addInitScript(
    ({ pk, addr }) => {
      const account = { address: addr, publicKey: new Uint8Array(pk), chains: ['solana:localnet'], features: [] };
      const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
      const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
      const wallet = {
        version: '1.0.0',
        name: 'Test Wallet',
        icon: 'data:image/svg+xml;base64,',
        chains: ['solana:localnet'],
        accounts: [account],
        features: {
          'standard:connect': { version: '1.0.0', connect: async () => ({ accounts: [account] }) },
          'solana:signTransaction': {
            version: '1.0.0',
            signTransaction: async (...inputs: { transaction: Uint8Array }[]) =>
              Promise.all(inputs.map(async (i) => ({ signedTransaction: unb64(await (window as any).__qshieldTestSign(b64(i.transaction))) }))),
          },
        },
      };
      const callback = ({ register }: any) => register(wallet);
      window.addEventListener('wallet-standard:app-ready', (e: any) => callback(e.detail));
      window.dispatchEvent(new CustomEvent('wallet-standard:register-wallet', { detail: callback }));
    },
    { pk, addr },
  );
}

export async function backup(page: Page, password: string) {
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByTestId('backup-download').click()]);
  const path = await dl.path();
  expect(JSON.parse(readFileSync(path, 'utf8')).ciphertext).toBeTruthy();
  await page.getByTestId('backup-file').setInputFiles(path);
  await page.getByTestId('backup-password').fill(password);
  await page.getByTestId('backup-verify').click();
  await expect(page.getByTestId('log')).toContainText('Backup verified');
}


/** Fresh user up to a funded vault: link settings, key + verified backup, wallet, vault, deposit. */
export async function onboard(page: Page, rpc: string, program: string, relayer: string, pw: string, depositSol: string): Promise<string> {
  const qs = new URLSearchParams({ rpc, program, cluster: 'localnet', relayer });
  await page.goto(`/?${qs}`);
  await page.getByTestId('apply-link-settings').click();
  await page.getByTestId('start-create').click();
  await page.getByTestId('new-password').fill(pw);
  await page.getByTestId('new-password2').fill(pw);
  await page.getByTestId('generate-key').click();
  await expect(page.getByTestId('pending-key-id')).toBeVisible();
  await backup(page, pw);
  await page.getByTestId('connect-wallet-0').click();
  await page.getByTestId('create-vault').click();
  await expect(page.getByTestId('vault-address')).toBeVisible({ timeout: 240_000 });
  await page.getByTestId('action-deposit').click();
  await page.getByTestId('deposit-sol').fill(depositSol);
  await page.getByTestId('deposit-sol-btn').click();
  await expect(page.getByTestId('vault-sol')).not.toHaveText('0.00');
  return (await page.getByTestId('vault-address').textContent())!;
}
