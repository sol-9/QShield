/**
 * Browser end to end: key generation and verified backup, a Wallet Standard
 * wallet (simulated; it signs in Node) creating the vault and depositing,
 * a relayed withdrawal signed with the PQ key, and a key rotation.
 */
import { expect, test } from '@playwright/test';
import { backup, installWallet } from './helpers.js';
import { JsonRpc, LocalKeypair, address, toBase58 } from '@qshield/sdk';

const RPC = process.env.QSHIELD_E2E_RPC;
const PROGRAM = process.env.QSHIELD_E2E_PROGRAM;
const RELAYER = process.env.QSHIELD_E2E_RELAYER;

test.skip(!RPC || !PROGRAM || !RELAYER, 'needs QSHIELD_E2E_RPC, QSHIELD_E2E_PROGRAM, QSHIELD_E2E_RELAYER');

test('generate, back up, create vault, deposit, send via relayer, rotate', async ({ page, browser }) => {
  const rpc = new JsonRpc(RPC!);
  const walletKp = LocalKeypair.generate();
  await rpc.requestAirdrop(walletKp.publicKey, 3_000_000_000n);
  for (let i = 0; i < 60 && !(await rpc.getAccount(walletKp.publicKey)); i++) await new Promise((r) => setTimeout(r, 500));
  await installWallet(page, walletKp);
  page.on('pageerror', (e) => console.error('page error:', e.message));

  const qs = new URLSearchParams({ rpc: RPC!, program: PROGRAM!, cluster: 'localnet', relayer: RELAYER! });
  await page.goto(`/?${qs}`);
  await expect(page.getByText('Research preview, unaudited')).toBeVisible();
  // Link settings are only proposed; they apply after explicit confirmation.
  await expect(page.getByText('This link wants to change your settings')).toBeVisible();
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem('qshield.wallet.v1')!).settings.programId)).toBe('');
  await page.getByTestId('apply-link-settings').click();
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem('qshield.wallet.v1')!).settings.programId)).toBe(PROGRAM);

  // 1. Key: weak passwords refused; then generate (real Argon2id parameters).
  await expect(page.getByTestId('start-create')).toBeVisible();
  await page.getByTestId('start-create').click();
  await expect(page.getByText('Step 1 of 4')).toBeVisible();
  const pw = 'correct horse battery staple';
  await page.getByTestId('new-password').fill('short');
  await page.getByTestId('new-password2').fill('short');
  await page.getByTestId('generate-key').click();
  await expect(page.getByTestId('log')).toContainText('at least 12');
  await page.getByTestId('new-password').fill(pw);
  await page.getByTestId('new-password2').fill(pw);
  await page.getByTestId('generate-key').click();
  const keyId = (await page.getByTestId('pending-key-id').textContent())!;
  expect(keyId).toMatch(/^[0-9a-f]{64}$/);

  // 2. Backup must be verified with the downloaded file and its password.
  await backup(page, pw);
  await expect(page.getByTestId('active-key-id')).toHaveText(keyId);
  // The secret never appears in storage unencrypted.
  const stored = await page.evaluate(() => localStorage.getItem('qshield.wallet.v1')!);
  expect(stored).toContain(keyId);
  expect(stored).not.toMatch(/"seed"|secret/i);

  // 3. Wallet (Wallet Standard) pays for vault creation.
  await page.getByTestId('connect-wallet-0').click();
  await expect(page.getByTestId('payer')).toContainText(toBase58(walletKp.publicKey));
  await page.getByTestId('create-vault').click();
  await expect(page.getByTestId('vault-address')).toBeVisible({ timeout: 240_000 });
  const vault = (await page.getByTestId('vault-address').textContent())!;
  await page.getByTestId('nav-security').click();
  await expect(page.getByTestId('vault-key-id')).toHaveText(keyId);
  await page.getByTestId('nav-home').click();

  // 4. Deposit and balance display.
  await page.getByTestId('action-deposit').click();
  await page.getByTestId('deposit-sol').fill('0.25');
  await page.getByTestId('deposit-sol-btn').click();
  await expect(page.getByTestId('vault-sol')).toHaveText('0.25');

  // 5. Send 0.05 SOL: review shows every field, then sign and relay.
  const dest = LocalKeypair.generate().publicKey;
  await page.getByTestId('action-send').click();
  await page.getByTestId('send-to').fill(toBase58(dest));
  await page.getByTestId('send-amount').fill('0.05');
  await page.getByTestId('review-send').click();
  await expect(page.getByTestId('field-destination')).toHaveText(toBase58(dest));
  await expect(page.getByTestId('field-amount')).toHaveText('0.050000000 SOL');
  await expect(page.getByTestId('field-vault')).toHaveText(vault);
  await page.getByTestId('send-password').fill('wrong password!!');
  await page.getByTestId('sign-send').click();
  await expect(page.getByTestId('log')).toContainText('wrong password');
  await page.getByTestId('send-password').fill(pw);
  await page.getByTestId('sign-send').click();
  await expect(page.getByTestId('vault-sol')).toHaveText('0.20', { timeout: 120_000 });
  expect((await rpc.getAccount(dest))!.lamports).toBe(50_000_000n);

  // 6. Freeze, then unfreeze with the vault key (single-key vault: no guardian).
  await page.getByTestId('nav-security').click();
  await page.getByTestId('freeze-password').fill(pw);
  await page.getByTestId('freeze').click();
  await expect(page.getByTestId('unfreeze')).toBeVisible({ timeout: 120_000 });
  await page.getByTestId('nav-home').click();
  await expect(page.getByTestId('vault-status')).toHaveText('Frozen');
  await expect(page.getByTestId('action-send')).toBeDisabled();
  await page.getByTestId('open-unfreeze').click();
  await page.getByTestId('unfreeze-password').fill(pw);
  await page.getByTestId('unfreeze').click();
  await expect(page.getByTestId('freeze')).toBeVisible({ timeout: 120_000 });
  await page.getByTestId('nav-home').click();
  await expect(page.getByTestId('vault-status')).toHaveText('Active');

  // 7. Rotate: new key, verified backup, wallet pays for the key account, old key signs.
  await page.getByTestId('nav-security').click();
  const pw2 = 'another long passphrase';
  await page.getByTestId('rot-password').fill(pw2);
  await page.getByTestId('rot-password2').fill(pw2);
  await page.getByTestId('rotate-start').click();
  await expect(page.getByText('Step 2 of 3')).toBeVisible();
  // Cancelling discards the half-made key; the vault never changed.
  await page.getByTestId('rotate-cancel').click();
  await expect(page.getByText('Step 1 of 3')).toBeVisible();
  await page.getByTestId('rot-password').fill(pw2);
  await page.getByTestId('rot-password2').fill(pw2);
  await page.getByTestId('rotate-start').click();
  const newId = (await page.getByTestId('pending-key-id').textContent())!;
  await backup(page, pw2);
  await expect(page.getByText('Step 3 of 3')).toBeVisible();
  await expect(page.getByTestId('rotation-key-id')).toHaveText(newId);
  await page.getByTestId('rot-current-password').fill(pw);
  await page.getByTestId('rotate-complete').click();
  await expect(page.getByTestId('vault-key-id')).toHaveText(newId, { timeout: 240_000 });
  await page.getByTestId('nav-settings').click();
  await expect(page.getByTestId('active-key-id')).toHaveText(newId);

  // 8. The new key sends.
  await page.getByTestId('nav-home').click();
  await page.getByTestId('action-send').click();
  await page.getByTestId('send-to').fill(toBase58(dest));
  await page.getByTestId('send-amount').fill('0.01');
  await page.getByTestId('review-send').click();
  await page.getByTestId('send-password').fill(pw2);
  await page.getByTestId('sign-send').click();
  await expect(page.getByTestId('vault-sol')).toHaveText('0.19', { timeout: 120_000 });
  expect((await rpc.getAccount(dest))!.lamports).toBe(60_000_000n);

  // 9. Change password: same key, new lock. The backup must be redone; the old password stops working here.
  const pw3 = 'third passphrase, longer';
  await page.getByTestId('nav-settings').click();
  await page.getByTestId('pw-current').fill('not my password');
  await page.getByTestId('pw-new').fill(pw3);
  await page.getByTestId('pw-new2').fill(pw3);
  await page.getByTestId('change-password').click();
  await expect(page.getByTestId('log').locator('li').first()).toContainText('wrong password');
  await page.getByTestId('pw-current').fill(pw2);
  await page.getByTestId('pw-new').fill(pw3);
  await page.getByTestId('pw-new2').fill(pw3);
  await page.getByTestId('change-password').click();
  await expect(page.getByTestId('log').locator('li').first()).toContainText('Password changed');
  await expect(page.getByTestId('backup-status')).toHaveText('Needs a new backup');
  await expect(page.getByTestId('active-key-id')).toHaveText(newId);
  await backup(page, pw3);
  await expect(page.getByTestId('backup-status')).toHaveText('Checked');
  await page.getByTestId('nav-home').click();
  await page.getByTestId('action-send').click();
  await page.getByTestId('send-to').fill(toBase58(dest));
  await page.getByTestId('send-amount').fill('0.01');
  await page.getByTestId('review-send').click();
  await page.getByTestId('send-password').fill(pw2);
  await page.getByTestId('sign-send').click();
  await expect(page.getByTestId('log').locator('li').first()).toContainText('wrong password');
  await page.getByTestId('send-password').fill(pw3);
  await page.getByTestId('sign-send').click();
  await expect(page.getByTestId('vault-sol')).toHaveText('0.18', { timeout: 120_000 });
  expect((await rpc.getAccount(dest))!.lamports).toBe(70_000_000n);

  // 10. Recovery words: shown after the password, confirmed by a quiz, then hidden again.
  await page.getByTestId('nav-settings').click();
  await expect(page.getByTestId('words-status')).toHaveText('Not written down yet');
  await page.getByTestId('words-password').fill(pw3);
  await page.getByTestId('show-words').click();
  const words: string[] = [];
  for (let i = 1; i <= 24; i++) words.push((await page.getByTestId(`recovery-word-${i}`).textContent())!);
  const quiz = page.locator('input[id^="rq-"]');
  await quiz.first().fill('wrong');
  await page.getByTestId('confirm-words').click();
  await expect(page.getByTestId('log').locator('li').first()).toContainText('does not match');
  for (let i = 0; i < (await quiz.count()); i++) {
    const id = (await quiz.nth(i).getAttribute('id'))!;
    await quiz.nth(i).fill(words[Number(id.slice(3)) - 1]!);
  }
  await page.getByTestId('confirm-words').click();
  await expect(page.getByTestId('words-status')).toHaveText('Written down');
  await expect(page.getByTestId('recovery-phrase')).toHaveCount(0);
  expect(await page.evaluate(() => localStorage.getItem('qshield.wallet.v1')!)).not.toContain(words.slice(0, 6).join(' '));

  // 11. Lost computer, no guardian: a fresh browser restores the key from the words alone.
  const laptop = await (await browser.newContext()).newPage();
  await laptop.goto(`/?${qs}`);
  await laptop.getByTestId('apply-link-settings').click();
  await laptop.getByTestId('start-import').click();
  await laptop.getByTestId('restore-mode-words').click();
  await laptop.getByTestId('restore-words').fill(words.slice().reverse().join(' '));
  await laptop.getByTestId('restore-password').fill('laptop passphrase here');
  await laptop.getByTestId('restore-password2').fill('laptop passphrase here');
  await laptop.getByTestId('restore-words-btn').click();
  await expect(laptop.getByTestId('log').locator('li').first()).toContainText(/checksum|not in the word list/);
  await laptop.getByTestId('restore-words').fill(words.join(' '));
  await laptop.getByTestId('restore-password').fill('laptop passphrase here');
  await laptop.getByTestId('restore-password2').fill('laptop passphrase here');
  await laptop.getByTestId('restore-words-btn').click();
  await expect(laptop.getByTestId('active-key-id')).toHaveText(newId);
  await laptop.getByTestId('skip-wallet').click();
  // The key was replaced since the vault was made, so the name alone cannot find it.
  await laptop.getByTestId('open-vault').click();
  await expect(laptop.getByTestId('log').locator('li').first()).toContainText('enter the vault address');
  await laptop.getByTestId('vault-open-address').fill(vault);
  await laptop.getByTestId('open-vault').click();
  await expect(laptop.getByTestId('vault-sol')).toHaveText('0.18', { timeout: 60_000 });
  expect(address(vault)).toHaveLength(32);
});
