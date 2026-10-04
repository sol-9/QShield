/**
 * Guardian protection in the browser: create a guardian on paper (24 words),
 * turn on a 0.1 SOL daily limit, send instantly within it, propose a larger
 * send, approve it on a separate "guardian device" (another browser context
 * with its own storage) after comparing the match code, then freeze from the
 * wallet and unfreeze from the guardian. Finally, a lost computer: a new
 * browser makes a new key, the guardian checks its match words and switches
 * the vault to it, and the new key sends.
 */
import { expect, test } from '@playwright/test';
import { JsonRpc, LocalKeypair, toBase58 } from '@qshield/sdk';
import { backup, installWallet, onboard } from './helpers.js';

const RPC = process.env.QSHIELD_E2E_RPC;
const PROGRAM = process.env.QSHIELD_E2E_PROGRAM;
const RELAYER = process.env.QSHIELD_E2E_RELAYER;

test.skip(!RPC || !PROGRAM || !RELAYER, 'needs QSHIELD_E2E_RPC, QSHIELD_E2E_PROGRAM, QSHIELD_E2E_RELAYER');

test('guardian: instant small sends, approved large sends, freeze and unfreeze, recovery after a lost computer', async ({ page, browser }) => {
  const rpc = new JsonRpc(RPC!);
  const walletKp = LocalKeypair.generate();
  await rpc.requestAirdrop(walletKp.publicKey, 3_000_000_000n);
  for (let i = 0; i < 60 && !(await rpc.getAccount(walletKp.publicKey)); i++) await new Promise((r) => setTimeout(r, 500));
  await installWallet(page, walletKp);
  const pw = 'correct horse battery staple';
  const vault = await onboard(page, RPC!, PROGRAM!, RELAYER!, pw, '0.5');
  await expect(page.getByTestId('vault-sol')).toHaveText('0.50');

  // 1. Guardian on paper: 24 words, confirmed by a quiz, then forgotten by this browser.
  await page.getByTestId('nav-security').click();
  await page.getByTestId('create-guardian').click();
  const words: string[] = [];
  for (let i = 1; i <= 24; i++) words.push((await page.getByTestId(`guardian-word-${i}`).textContent())!);
  const quiz = page.locator('input[id^="quiz-"]');
  await quiz.first().fill('wrong');
  await page.getByTestId('confirm-guardian').click();
  await expect(page.getByTestId('log')).toContainText('does not match');
  for (let i = 0; i < (await quiz.count()); i++) {
    const id = (await quiz.nth(i).getAttribute('id'))!;
    await quiz.nth(i).fill(words[Number(id.slice(5)) - 1]!);
  }
  await page.getByTestId('confirm-guardian').click();
  await expect(page.getByTestId('guardian-key-id')).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem('qshield.wallet.v1')!)).not.toContain(words.join(' '));

  // 2. Turn it on with a 0.1 SOL / 24 h everyday limit.
  await page.getByTestId('guardian-limit').fill('0.1');
  await page.getByTestId('guardian-password').fill(pw);
  await page.getByTestId('enable-guardian').click();
  await expect(page.getByTestId('policy-limit')).toHaveText('0.10 SOL every day', { timeout: 240_000 });

  // 3. Within the limit: instant.
  const dest = LocalKeypair.generate().publicKey;
  await page.getByTestId('nav-home').click();
  await page.getByTestId('action-send').click();
  await page.getByTestId('send-to').fill(toBase58(dest));
  await page.getByTestId('send-amount').fill('0.05');
  await page.getByTestId('review-send').click();
  await expect(page.getByTestId('recipient-status')).toHaveText('New address — never sent here');
  await expect(page.getByTestId('needs-guardian')).toHaveCount(0);
  await page.getByTestId('send-password').fill(pw);
  await page.getByTestId('sign-send').click();
  await expect(page.getByTestId('vault-sol')).toHaveText('0.45', { timeout: 120_000 });

  // 4. Beyond it: a proposal, nothing moves yet.
  await page.getByTestId('action-send').click();
  await page.getByTestId('send-to').fill(toBase58(dest));
  await page.getByTestId('send-amount').fill('0.2');
  await page.getByTestId('review-send').click();
  await expect(page.getByTestId('needs-guardian')).toBeVisible();
  await expect(page.getByTestId('recipient-status')).toHaveText('Used before');
  await page.getByTestId('send-password').fill(pw);
  await page.getByTestId('sign-send').click();
  await expect(page.getByTestId('match-code')).toBeVisible({ timeout: 120_000 });
  const code = (await page.getByTestId('match-code').textContent())!;
  const link = (await page.getByTestId('guardian-link').getAttribute('href'))!;
  expect((await rpc.getAccount(dest))!.lamports).toBe(50_000_000n);

  // 5. The guardian device (separate storage): open the link, unlock with the words, compare, approve.
  const phone = await (await browser.newContext()).newPage();
  await phone.goto(link);
  await phone.getByTestId('apply-link-settings').click();
  await phone.getByTestId('g-load').click();
  await expect(phone.getByTestId('g-amount')).toHaveText('0.20 SOL');
  await expect(phone.getByTestId('g-match-code')).toHaveText(code);
  await phone.getByTestId('g-phrase').fill(words.slice().reverse().join(' '));
  await phone.getByTestId('g-unlock').click();
  await expect(phone.getByTestId('log')).toContainText(/not in the word list|checksum|not this vault/);
  await phone.getByTestId('g-phrase').fill(words.join(' '));
  await phone.getByTestId('g-unlock').click();
  await expect(phone.getByTestId('g-key-id')).toHaveText(/^[0-9a-f]{64}$/);
  await phone.getByTestId('g-approve').click();
  await expect(phone.getByTestId('log')).toContainText('last 4 characters');
  await phone.getByTestId('g-confirm').fill(toBase58(dest).slice(-4));
  await phone.getByTestId('g-approve').click();
  await expect(phone.getByTestId('log')).toContainText('Approved', { timeout: 120_000 });
  expect((await rpc.getAccount(dest))!.lamports).toBe(250_000_000n);

  // 6. Wallet freezes; only the guardian unfreezes.
  await page.getByTestId('done-waiting').click();
  await page.getByTestId('nav-security').click();
  await page.getByTestId('freeze-password').fill(pw);
  await page.getByTestId('freeze').click();
  await expect(page.getByText('Vault is frozen')).toBeVisible({ timeout: 120_000 });
  await page.getByTestId('nav-home').click();
  await expect(page.getByTestId('vault-status')).toHaveText('Frozen');
  await expect(page.getByTestId('action-send')).toBeDisabled();
  // The everyday key cannot unfreeze a guarded vault; the wallet points to the guardian.
  await page.getByTestId('open-unfreeze').click();
  await expect(page.getByTestId('unfreeze')).toHaveCount(0);
  await expect(page.getByTestId('unfreeze-guardian-link')).toBeVisible();
  await page.getByTestId('nav-home').click();
  await phone.getByTestId('g-load').click();
  await expect(phone.getByTestId('g-status')).toHaveText('Frozen');
  await phone.getByTestId('g-unfreeze').click();
  await expect(phone.getByTestId('log')).toContainText('Unfrozen', { timeout: 120_000 });
  await page.getByTestId('refresh').click();
  await expect(page.getByTestId('vault-status')).toHaveText('Active');

  // 7. Lost computer: a new one (empty storage) makes a new key; the guardian switches the vault to it.
  const laptop = await (await browser.newContext()).newPage();
  const qs = new URLSearchParams({ rpc: RPC!, program: PROGRAM!, cluster: 'localnet', relayer: RELAYER! });
  await laptop.goto(`/?${qs}`);
  await laptop.getByTestId('apply-link-settings').click();
  await laptop.getByTestId('start-recover').click();
  await laptop.getByTestId('recover-with-guardian').click();
  await expect(laptop.getByText('Step 1 of 3')).toBeVisible();
  const pwNew = 'new laptop passphrase';
  await laptop.getByTestId('new-password').fill(pwNew);
  await laptop.getByTestId('new-password2').fill(pwNew);
  await laptop.getByTestId('generate-key').click();
  const newKeyId = (await laptop.getByTestId('pending-key-id').textContent())!;
  await backup(laptop, pwNew);
  await expect(laptop.getByText('Step 3 of 3')).toBeVisible();
  await laptop.getByTestId('recover-vault').fill(vault);
  await laptop.getByTestId('dev-payer').click();
  await expect(laptop.getByTestId('payer')).toBeVisible({ timeout: 60_000 });
  await laptop.getByTestId('recover-prepare').click();
  await expect(laptop.getByTestId('recover-code')).toBeVisible({ timeout: 240_000 });
  const matchWords = (await laptop.getByTestId('recover-code').textContent())!;
  const recoverLink = (await laptop.getByTestId('recover-link').getAttribute('href'))!;
  // Not switched yet: the new computer cannot open the vault.
  await laptop.getByTestId('recover-check').click();
  await expect(laptop.getByTestId('log').locator('li').first()).toContainText('not switched the vault');

  await phone.goto(recoverLink);
  // Same settings as before on this device: the link proposes nothing new, so no confirmation card.
  await expect(phone.getByTestId('apply-link-settings')).toHaveCount(0);
  await phone.getByTestId('g-load').click();
  await expect(phone.getByTestId('g-replace-card')).toBeVisible();
  await phone.getByTestId('g-phrase').fill(words.join(' '));
  await phone.getByTestId('g-unlock').click();
  await phone.getByTestId('g-check-key').click();
  await expect(phone.getByTestId('g-new-key-code')).toHaveText(matchWords);
  await phone.getByTestId('g-replace-key').click();
  await expect(phone.getByTestId('log').locator('li').first()).toContainText('Everyday key replaced', { timeout: 120_000 });

  await laptop.getByTestId('recover-check').click();
  await expect(laptop.getByTestId('vault-sol')).toHaveText('0.25', { timeout: 60_000 });
  await laptop.getByTestId('nav-security').click();
  await expect(laptop.getByTestId('vault-key-id')).toHaveText(newKeyId);
  await laptop.getByTestId('nav-home').click();
  await laptop.getByTestId('action-send').click();
  await laptop.getByTestId('send-to').fill(toBase58(dest));
  await laptop.getByTestId('send-amount').fill('0.01');
  await laptop.getByTestId('review-send').click();
  await laptop.getByTestId('send-password').fill(pwNew);
  await laptop.getByTestId('sign-send').click();
  await expect(laptop.getByTestId('vault-sol')).toHaveText('0.24', { timeout: 120_000 });
});
