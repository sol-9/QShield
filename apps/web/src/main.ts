/**
 * QShield web wallet (Phase 5, experimental research preview).
 *
 * Two keys, kept visibly separate:
 *  - the QShield post-quantum key (ML-DSA-44) — generated here, stored only
 *    encrypted, authorizes every withdrawal / rotation;
 *  - an ordinary Solana wallet — pays rent and fees, can deposit, can never
 *    withdraw.
 * Withdrawals and rotations are sent through a relayer, which pays the fees
 * and cannot change what was signed.
 *
 * All text is inserted with textContent (no innerHTML).
 */
import {
  ActionV2,
  AssetType,
  CLUSTER,
  DEFAULT_KDF,
  Role,
  availableAt,
  decodeAny,
  describeAny,
  phraseFromSeed,
  proposalAddress,
  quizPositions,
  seedFromPhrase,
  type AnyAuthorization,
  type PolicyState,
  type ProposalState,
  JsonRpc,
  KeyState,
  LocalKey,
  QShield,
  RelayerClient,
  VaultOperations,
  VaultStatus,
  address,
  associatedTokenAddress,
  decryptKey,
  encryptKey,
  formatTokenAmount,
  fromHex,
  parseTokenAmount,
  signEnvelope,
  toBase58,
  toHex,
  vaultSeedFromLabel,
  type Envelope,
  type KdfParams,
  type KeystoreFile,
  type RelayerInfo,
  type TokenBalance,
  type VaultInfo,
} from '@qshield/sdk';
import {
  activeKey,
  load,
  passwordProblem,
  pendingKey,
  proposedSettings,
  save,
  verifyBackupFile,
  type AppState,
  type ClusterName,
  type Pinned,
  type Settings,
  type StoredKey,
} from './store.js';
import { chunkAddress, fingerprint, lookalike, proposalCode, proposalRecipient } from './safety.js';
import { connectWallet, devPayer, discoverWallets, solanaWallets, type Payer } from './wallet.js';

// ------------------------------------------------------------------ state

const query = new URLSearchParams(location.search);
/** Build-time pins (production builds set at least program id and cluster). */
const env = import.meta.env;
const pinned: Pinned = {
  programId: env.VITE_QSHIELD_PROGRAM_ID || undefined,
  cluster: (env.VITE_QSHIELD_CLUSTER as ClusterName) || undefined,
  rpcUrl: env.VITE_QSHIELD_RPC_URL || undefined,
  relayerUrl: env.VITE_QSHIELD_RELAYER_URL || undefined,
};
const state: AppState = load(localStorage, pinned);
save(localStorage, state);
/** Settings proposed by the link this page was opened with; applied only on confirmation. */
let linkSettings: Settings | null = proposedSettings(state.settings, query, pinned);
/** Key files always use the full KDF cost (no test shortcut in the app). */
const kdf: KdfParams = DEFAULT_KDF;
/** Largest relayer fee the app will ever sign (0.001 SOL); a relayer asking more is refused. */
const MAX_RELAYER_FEE_LAMPORTS = 1_000_000n;

let payer: Payer | null = null;
let balances: { vault: VaultInfo; tokens: TokenBalance[] } | null = null;
let relayerInfo: RelayerInfo | null = null;
let busy = '';
const log: { text: string; kind: 'info' | 'ok' | 'error' }[] = [];
/** Flow state for the send and rotate forms. */
let review: { env: Envelope; auth: AnyAuthorization; proposal: boolean; to: string; amountText: string } | null = null;
/** The vault's guardian policy (null = single-key vault). */
let policy: PolicyState | null = null;
/** Guardian key being created on this device: shown once as 24 words, never stored. */
let guardianDraft: { key: LocalKey; phrase: string; quiz: number[] } | null = null;
/** The vault key's 24 recovery words while they are shown: memory only, never stored. */
let wordsDraft: { keyId: string; phrase: string; quiz: number[] } | null = null;
/** How the restore screen reads the key. */
let restoreMode: 'file' | 'words' = 'file';
/** A proposal waiting for the guardian. */
let waiting: { id: bigint; link: string; code: string } | null = null;
const GUARDIAN_MODE = query.get('guardian') === '1';

/** Main-app screens. Home, Activity, Security and Settings sit on the tab bar. */
type Screen = 'home' | 'send' | 'receive' | 'deposit' | 'waiting' | 'security' | 'activity' | 'settings';
let screen: Screen = 'home';
/** First-run path chosen on the welcome screen. */
let onboardingPath: 'welcome' | 'create' | 'import' | 'recover-choice' = 'welcome';
/** Skips the wallet step when opening an existing vault (no rent to pay). */
let skipWallet = false;
/** When the newest log entry arrived (drives the toast). */
let noteAt = 0;

/** Appearance, a per-browser display preference ('auto' follows the device). */
type Theme = 'auto' | 'light' | 'dark';
const THEME_KEY = 'qshield.theme';
function storedTheme(): Theme {
  try {
    const t = localStorage.getItem(THEME_KEY);
    return t === 'light' || t === 'dark' ? t : 'auto';
  } catch {
    return 'auto';
  }
}
let theme: Theme = storedTheme();
const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');
function applyTheme() {
  const root = document.documentElement;
  if (theme === 'auto') delete root.dataset.theme;
  else root.dataset.theme = theme;
  const dark = theme === 'dark' || (theme === 'auto' && darkQuery.matches);
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', dark ? '#0d1015' : '#f6f7f9');
}
function setTheme(t: Theme) {
  theme = t;
  try {
    if (t === 'auto') localStorage.removeItem(THEME_KEY);
    else localStorage.setItem(THEME_KEY, t);
  } catch {
    // Storage unavailable (private mode): the choice lasts for this page only.
  }
  applyTheme();
}
applyTheme();
darkQuery.addEventListener('change', applyTheme);

const clusterIds: Record<ClusterName, Uint8Array> = {
  mainnet: CLUSTER.mainnetBeta,
  devnet: CLUSTER.devnet,
  testnet: CLUSTER.testnet,
  localnet: CLUSTER.localnet,
};

function sdk() {
  if (!state.settings.programId) throw new Error('Set the QShield program id in Settings first.');
  const rpc = new JsonRpc(state.settings.rpcUrl);
  const q = new QShield({ rpc, programId: state.settings.programId, clusterId: clusterIds[state.settings.cluster] });
  return { rpc, q, ops: new VaultOperations(q, rpc), relayer: new RelayerClient(state.settings.relayerUrl) };
}

let clusterChecked = '';
/** Like sdk(), but first checks the RPC endpoint really serves the configured cluster. */
async function chain() {
  const x = sdk();
  const id = `${state.settings.rpcUrl}|${state.settings.cluster}`;
  if (clusterChecked !== id) {
    await x.q.checkCluster();
    clusterChecked = id;
  }
  return x;
}

function persist() {
  save(localStorage, state);
}

function note(text: string, kind: 'info' | 'ok' | 'error' = 'info') {
  log.unshift({ text, kind });
  log.splice(30);
  noteAt = Date.now();
}

async function run(label: string, f: () => Promise<void>) {
  if (busy) return;
  busy = label;
  // Start the action before re-rendering: it reads its inputs (including file
  // pickers, which cannot survive a re-render) synchronously before its first await.
  const pending = f();
  render();
  try {
    await pending;
  } catch (e) {
    note(`${label}: ${(e as Error).message}`, 'error');
  } finally {
    busy = '';
    render();
  }
}

// ------------------------------------------------------------------ DOM helpers

type Child = Node | string | null | undefined | false;
function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, any> = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (k === 'value') (el as HTMLInputElement).value = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children) if (c) el.append(typeof c === 'string' ? document.createTextNode(c) : c);
  return el;
}
const input = (id: string, attrs: Record<string, any> = {}) => h('input', { id, 'data-testid': id, ...attrs });
type ButtonKind = 'primary' | 'secondary' | 'danger' | 'ghost';
const button = (id: string, text: string, onclick: () => void, disabled = false, kind: ButtonKind = 'primary', ico?: IconName) =>
  h('button', { id, 'data-testid': id, class: `btn btn-${kind}`, onclick, disabled: disabled || !!busy }, ico && icon(ico), text);
const val = (id: string) => (document.getElementById(id) as HTMLInputElement | null)?.value.trim() ?? '';
/** A titled group of related controls on a screen. */
const card = (title: string, ...children: Child[]) => h('section', { class: 'panel' }, h('h2', {}, title), ...children);
const row = (k: string, v: Child, testid?: string) => h('div', { class: 'row' }, h('span', { class: 'k' }, k), h('span', { class: 'v', 'data-testid': testid }, v));
const field = (label: string, control: Node, hint?: string) => h('label', { class: 'field' }, h('span', { class: 'field-label' }, label), control, hint && h('span', { class: 'field-hint' }, hint));

// Icons: 24px stroke glyphs drawn with createElementNS (no innerHTML).
type Shape = string | ['c', number, number, number] | ['r', number, number, number, number, number];
const ICONS = {
  home: ['M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z'],
  activity: [['c', 12, 12, 9], 'M12 7v5l3 2'],
  shield: ['M12 3l8 3v6c0 5-3.4 8.2-8 9-4.6-.8-8-4-8-9V6z', 'M9 12l2 2 4-4'],
  settings: ['M4 7h9', 'M17 7h3', ['c', 15, 7, 2], 'M4 17h3', 'M11 17h9', ['c', 9, 17, 2]],
  send: ['M7 17 17 7', 'M8 7h9v9'],
  receive: ['M12 4v11', 'M7 10l5 5 5-5', 'M5 20h14'],
  deposit: ['M12 5v14', 'M5 12h14'],
  copy: [['r', 9, 9, 11, 11, 2], 'M5 15V5a1 1 0 0 1 1-1h9'],
  back: ['M15 18l-6-6 6-6'],
  refresh: ['M20 11a8 8 0 1 0-2.3 5.7', 'M20 4v7h-7'],
  freeze: ['M12 2v20', 'M4.9 7l14.2 10', 'M4.9 17 19.1 7', 'M9 4l3 2 3-2', 'M9 20l3-2 3 2'],
  key: [['c', 8, 15, 4], 'M11 12l9-9', 'M17 6l3 3'],
  wallet: [['r', 3, 6, 18, 14, 2], 'M3 10h18', 'M16 15h2'],
  check: ['M5 12l5 5 9-10'],
  alert: ['M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z', 'M12 9v4', 'M12 17h.01'],
  relay: ['M4 12h12', 'M12 6l6 6-6 6'],
} satisfies Record<string, Shape[]>;
type IconName = keyof typeof ICONS;
const SVG_NS = 'http://www.w3.org/2000/svg';
function icon(name: IconName): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('class', 'icon');
  for (const s of ICONS[name] as Shape[]) {
    let el: SVGElement;
    if (typeof s === 'string') {
      el = document.createElementNS(SVG_NS, 'path');
      el.setAttribute('d', s);
    } else if (s[0] === 'c') {
      el = document.createElementNS(SVG_NS, 'circle');
      el.setAttribute('cx', String(s[1]));
      el.setAttribute('cy', String(s[2]));
      el.setAttribute('r', String(s[3]));
    } else {
      el = document.createElementNS(SVG_NS, 'rect');
      for (const [k, v] of [['x', s[1]], ['y', s[2]], ['width', s[3]], ['height', s[4]], ['rx', s[5]]] as const) el.setAttribute(k, String(v));
    }
    svg.append(el);
  }
  return svg;
}

function download(name: string, text: string) {
  const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: 'application/json' })), download: name });
  document.body.append(a);
  a.click();
  a.remove();
}

function readFile(inputId: string): Promise<string> {
  const f = (document.getElementById(inputId) as HTMLInputElement).files?.[0];
  if (!f) return Promise.reject(new Error('choose a file first'));
  return f.text();
}

// ------------------------------------------------------------------ key flows

async function generateKey(pwId: string, repeatId: string) {
  const problem = passwordProblem(val(pwId), val(repeatId));
  if (problem) throw new Error(problem);
  const key = LocalKey.generate();
  let keystore: KeystoreFile;
  try {
    keystore = await encryptKey(key, val(pwId), kdf);
  } finally {
    key.destroy();
    clearInputs(pwId, repeatId);
  }
  state.keys.push({ keystore, status: 'pending', backupVerified: false, createdAt: Date.now() });
  persist();
  note(`Generated key ${keystore.key_id.slice(0, 16)}… — now back it up.`, 'ok');
}

async function verifyBackup(k: StoredKey) {
  const text = await readFile('backup-file');
  if (!verifyBackupFile(k.keystore, text)) throw new Error('That file is not the backup of this key.');
  (await decryptKey(k.keystore, val('backup-password'))).destroy();
  clearInputs('backup-password');
  k.backupVerified = true;
  if (!activeKey(state)) k.status = 'active';
  persist();
  note('Backup verified: the file and password restore this key.', 'ok');
}

async function importKey() {
  const text = await readFile('import-file');
  const keystore = JSON.parse(text) as KeystoreFile;
  const key = await decryptKey(keystore, val('import-password'));
  clearInputs('import-password');
  const ok = toHex(key.keyId) === keystore.key_id;
  key.destroy();
  if (!ok) throw new Error('key file inconsistent');
  for (const k of state.keys) if (k.status === 'active') k.status = 'retired';
  state.keys = state.keys.filter((k) => k.keystore.key_id !== keystore.key_id);
  state.keys.push({ keystore, status: 'active', backupVerified: true, createdAt: Date.now() });
  persist();
  note(`Imported key ${keystore.key_id.slice(0, 16)}…`, 'ok');
}

/** Shows the 24 recovery words of `k` after checking its password. */
async function showRecoveryWords(k: StoredKey) {
  const key = await unlock(k, 'words-password');
  try {
    const seed = key.exportSeed();
    wordsDraft = { keyId: k.keystore.key_id, phrase: phraseFromSeed(seed), quiz: quizPositions(4) };
    seed.fill(0);
  } finally {
    key.destroy();
  }
}

/** Confirms the words were written down; they then count as a backup of the key. */
function confirmRecoveryWords(k: StoredKey) {
  if (!wordsDraft || wordsDraft.keyId !== k.keystore.key_id) return;
  const words = wordsDraft.phrase.split(' ');
  for (const pos of wordsDraft.quiz) {
    if (val(`rq-${pos}`).toLowerCase() !== words[pos - 1]) throw new Error(`Word ${pos} does not match. Check what you wrote down.`);
  }
  wordsDraft = null;
  k.wordsBackedUp = true;
  k.backupVerified = true;
  if (!activeKey(state)) k.status = 'active';
  persist();
  note('Recovery words confirmed. This browser has hidden them again.', 'ok');
}

/** Rebuilds the key from its 24 words and stores it encrypted under a new password. */
async function restoreFromWords() {
  const phrase = val('restore-words');
  const pw = val('restore-password');
  const problem = passwordProblem(pw, val('restore-password2'));
  clearInputs('restore-words', 'restore-password', 'restore-password2');
  if (problem) throw new Error(problem);
  const seed = seedFromPhrase(phrase);
  const key = LocalKey.fromSeed(seed);
  seed.fill(0);
  let keystore: KeystoreFile;
  try {
    keystore = await encryptKey(key, pw, kdf);
  } finally {
    key.destroy();
  }
  for (const k of state.keys) if (k.status === 'active') k.status = 'retired';
  state.keys = state.keys.filter((k) => k.keystore.key_id !== keystore.key_id);
  state.keys.push({ keystore, status: 'active', backupVerified: true, wordsBackedUp: true, createdAt: Date.now() });
  persist();
  note(`Restored key ${keystore.key_id.slice(0, 16)}… from its recovery words.`, 'ok');
}

/** Decrypts a key for one operation; callers must destroy() it in a finally block. */
async function unlock(k: StoredKey, pwId: string): Promise<LocalKey> {
  try {
    return await decryptKey(k.keystore, val(pwId));
  } finally {
    clearInputs(pwId);
  }
}

function clearInputs(...ids: string[]) {
  for (const id of ids) {
    const el = document.getElementById(id) as HTMLInputElement | null;
    if (el) el.value = '';
  }
}

// ------------------------------------------------------------------ vault flows

async function createVault() {
  const k = activeKey(state);
  if (!k || !k.backupVerified) throw new Error('Back up your key first.');
  if (!payer) throw new Error('Connect a Solana wallet to pay for vault creation.');
  const { ops } = await chain();
  const label = val('vault-label') || 'default';
  const steps = h('ol', { 'data-testid': 'create-progress' });
  document.getElementById('progress')?.replaceChildren(steps);
  const [vault] = await ops.createVault(payer.signer, fromHex(k.keystore.public_key), vaultSeedFromLabel(label), (p) => {
    steps.append(h('li', {}, `${p.step}/${p.total} ${p.label}`));
  });
  state.vault = { address: toBase58(vault), label, initialKeyId: k.keystore.key_id };
  persist();
  note('Vault created. Deposit some SOL to get started.', 'ok');
  screen = 'home';
  await refresh();
}

async function openVault() {
  const k = activeKey(state);
  if (!k) throw new Error('No active key.');
  const { q } = await chain();
  const label = val('vault-label') || 'default';
  const typed = val('vault-open-address');
  // A vault's address comes from the key that created it, so after a key
  // replacement it can only be found by its address.
  const addr = typed ? address(typed) : q.vaultAddress(fromHex(k.keystore.key_id), vaultSeedFromLabel(label));
  try {
    await q.getVaultChecked(addr, fromHex(k.keystore.key_id));
  } catch (e) {
    if (typed) throw e;
    throw new Error(`No vault named "${label}" was created with this key. If the key was replaced since the vault was made, enter the vault address instead.`);
  }
  state.vault = { address: toBase58(addr), label, initialKeyId: k.keystore.key_id };
  persist();
  screen = 'home';
  await refresh();
}

async function refresh() {
  if (!state.vault) return;
  const { ops, relayer } = await chain();
  balances = await ops.balances(address(state.vault.address));
  const p = await sdk().q.getPolicy(address(state.vault.address));
  policy = p?.enabled ? p : null;
  try {
    relayerInfo = await relayer.info();
  } catch {
    relayerInfo = null;
  }
}

async function deposit(kind: 'sol' | 'spl') {
  const k = activeKey(state);
  if (!payer || !state.vault || !balances || !k) throw new Error('Connect a wallet and open a vault first.');
  const { ops } = await chain();
  const vault = address(state.vault.address);
  // Deposit only into a vault controlled by this wallet's key (read fresh
  // from the chain by the SDK, never from the cached balances).
  const mine = fromHex(k.keystore.key_id);
  if (toHex(balances.vault.state.keyId) !== toHex(mine)) {
    throw new Error('This vault is no longer controlled by your active key (it was rotated to another key). Not depositing: check the vault before sending it funds.');
  }
  const current = mine;
  if (kind === 'sol') {
    await ops.depositSol(payer.signer, vault, parseTokenAmount(val('deposit-sol'), 9), current);
  } else {
    const mint = address(val('deposit-mint'));
    const m = await (await chain()).q.getMint(mint);
    await ops.depositSpl(payer.signer, vault, mint, parseTokenAmount(val('deposit-token-amount'), m.info.decimals), current);
  }
  note('Deposit confirmed.', 'ok');
  screen = 'home';
  await refresh();
}

/** Builds the authorization for the send form and shows it for review. */
async function prepareSend() {
  if (!state.vault || !balances) throw new Error('Open a vault first.');
  const { q } = await chain();
  const vault = address(state.vault.address);
  const asset = val('send-asset');
  const toText = val('send-to');
  const to = address(toText);
  // Address poisoning: a new address that looks like one used before.
  const similar = lookalike(toText, state.history ?? []);
  if (similar) throw new Error(`This address looks like ${similar}, which you used before, but it is DIFFERENT. Address-poisoning scams use look-alike addresses: copy the address again from the original source.`);
  const { fee } = await relayFee();
  const feeOpts = feeOptions(fee);
  let hints: Envelope['hints'] = {};
  let env: Envelope;
  let proposal = false;
  let amountText = val('send-amount');
  if (policy) {
    // Guardian policy: instant within the limit / to saved addresses, otherwise a proposal.
    if (asset === 'SOL') {
      const lamports = parseTokenAmount(val('send-amount'), 9);
      proposal = q.solSendPath(policy, to, lamports, fee) === 'needs-guardian';
      const action = proposal ? ActionV2.ProposeWithdraw : ActionV2.WithdrawSol;
      env = await q.prepareV2(vault, Role.Everyday, (nonce) => q.createV2SolTransfer({ vault, nonce, action, destination: to, lamports, ...feeOpts }));
      amountText = `${sol(lamports)} SOL`;
    } else {
      const t = balances.tokens.find((x) => toBase58(x.address) === asset);
      if (!t || t.decimals === null) throw new Error('This token cannot be withdrawn (unsupported mint).');
      const mint = await q.getMint(t.account.mint);
      const amount = parseTokenAmount(val('send-amount'), mint.info.decimals);
      proposal = !policy.saved.some((x) => toBase58(x) === toText);
      const destination = associatedTokenAddress(to, mint.address, mint.tokenProgram);
      // A proposal creates no token account; its approval does (and pays for it).
      const tokenFee = proposal ? feeOpts : feeOptions((await relayFee({ assetType: mint.assetType, destination })).fee);
      env = await q.prepareV2(vault, Role.Everyday, (nonce) => ({
        ...q.v2Base(vault, Role.Everyday, nonce, proposal ? ActionV2.ProposeWithdraw : ActionV2.WithdrawSpl, tokenFee),
        assetType: mint.assetType,
        mint: mint.address,
        destination,
        amount,
        decimals: mint.info.decimals,
      }));
      hints = { destination_owner: toText };
      amountText = `${trimAmount(formatTokenAmount(amount, mint.info.decimals))} tokens`;
    }
  } else if (asset === 'SOL') {
    const lamports = parseTokenAmount(val('send-amount'), 9);
    env = await q.prepare(vault, (nonce) => q.createWithdrawSolIntent({ vault, nonce, destination: to, lamports, ...feeOpts }));
    amountText = `${sol(lamports)} SOL`;
  } else {
    const t = balances.tokens.find((x) => toBase58(x.address) === asset);
    if (!t || t.decimals === null) throw new Error('This token cannot be withdrawn (unsupported mint).');
    const mint = await q.getMint(t.account.mint);
    const amount = parseTokenAmount(val('send-amount'), mint.info.decimals);
    const tokenFee = feeOptions((await relayFee({ assetType: mint.assetType, destination: associatedTokenAddress(to, mint.address, mint.tokenProgram) })).fee);
    env = await q.prepare(vault, (nonce) => q.createWithdrawSplIntent({ vault, nonce, mint, toOwner: to, amount, ...tokenFee }));
    hints = { destination_owner: toBase58(to) };
    if (toBase58(t.address) !== toBase58(associatedTokenAddress(vault, t.account.mint, t.tokenProgram))) hints.source_token_account = toBase58(t.address);
    amountText = `${trimAmount(formatTokenAmount(amount, mint.info.decimals))} tokens`;
  }
  env.hints = hints;
  review = { env, auth: decodeAny(fromHex(env.auth_hex)), proposal, to: toText, amountText };
}

/**
 * Signed fee for a send through the relayer: its minimum fee, plus the rent
 * of the recipient's token account when the relayer would have to create it
 * (it refuses otherwise, since it would never get that rent back).
 */
async function relayFee(token?: { assetType: AssetType; destination: Uint8Array }): Promise<{ fee: bigint; rent: bigint }> {
  const { rpc, relayer } = await chain();
  relayerInfo ??= await relayer.info();
  const min = BigInt(relayerInfo.min_fee_lamports);
  if (min > MAX_RELAYER_FEE_LAMPORTS) throw new Error(`The relayer asks ${min} lamports per send, above this wallet's cap of ${MAX_RELAYER_FEE_LAMPORTS}. Use another relayer.`);
  let rent = 0n;
  if (token && token.assetType !== AssetType.Sol && (await rpc.getAccount(token.destination)) === null) {
    const r = relayerInfo.token_account_rent_lamports;
    rent = BigInt((token.assetType === AssetType.Token2022 ? r?.token_2022 : r?.spl_token) ?? 0);
  }
  return { fee: min + rent, rent };
}

function feeOptions(fee: bigint) {
  return fee > 0n ? { feeLamports: fee, feeRecipient: address(relayerInfo!.relayer) } : {};
}

/** Link that opens the guardian page for this vault (and a proposal) on another device. */
function guardianLink(extra: Record<string, string> = {}, vault = state.vault!.address): string {
  const s = state.settings;
  const q = new URLSearchParams({ guardian: '1', vault, rpc: s.rpcUrl, program: s.programId, cluster: s.cluster, relayer: s.relayerUrl, ...extra });
  return `${location.origin}${location.pathname}?${q}`;
}

/** Signs an envelope with the everyday key and sends it through the relayer. */
async function signAndRelay(env: Envelope, pwId: string): Promise<string[]> {
  const k = activeKey(state)!;
  const key = await unlock(k, pwId);
  let signed: Envelope;
  try {
    signed = await signEnvelope(env, key);
  } finally {
    key.destroy();
  }
  const { relayer } = await chain();
  const id = await relayer.submit(signed);
  note(`Submitted to relayer (request ${id.slice(0, 12)}…)`);
  render();
  const r = await relayer.wait(id);
  if (r.status !== 'confirmed') throw new Error(`relayer: ${'error' in r ? r.error : r.status}`);
  return r.signatures;
}

async function signAndSend() {
  if (!review) return;
  const sigs = await signAndRelay(review.env, 'send-password');
  state.history = [...new Set([...(state.history ?? []), review.to])].slice(-200);
  persist();
  if (review.proposal && review.auth.version === 2) {
    const a = review.auth.auth;
    const extra: Record<string, string> = { proposal: a.nonce.toString() };
    if (a.assetType !== AssetType.Sol) extra.owner = review.to;
    waiting = { id: a.nonce, link: guardianLink(extra), code: proposalCode(a.vault, a.nonce, a.mint, a.destination, a.amount) };
    note(`Proposal ${a.nonce} created: approve it on your guardian device.`, 'ok');
    screen = 'waiting';
  } else {
    note(`Sent ${review.amountText}. Transaction ${sigs[sigs.length - 1]?.slice(0, 12)}…`, 'ok');
    screen = 'home';
  }
  review = null;
  await refresh();
}

/** Everyday-key freeze (v1 Pause, or v2 Pause on a guarded vault). */
async function freezeVault() {
  if (!state.vault) throw new Error('Open a vault first.');
  const { q } = await chain();
  const vault = address(state.vault.address);
  const env = policy
    ? await q.prepareV2(vault, Role.Everyday, (nonce) => q.v2Base(vault, Role.Everyday, nonce, ActionV2.Pause))
    : await q.prepare(vault, (nonce) => q.createPauseIntent({ vault, nonce }));
  await signAndRelay(env, 'freeze-password');
  note(policy ? 'Vault frozen. Only your guardian can unfreeze it.' : 'Vault frozen. Unfreeze it from Security when you are ready.', 'ok');
  await refresh();
}

/** Vault-key unfreeze. Only single-key vaults: with a guardian, only the guardian can unfreeze. */
async function unfreezeVault() {
  if (!state.vault) throw new Error('Open a vault first.');
  if (policy) throw new Error('This vault has a guardian: unfreeze it from the guardian page.');
  const { q } = await chain();
  const vault = address(state.vault.address);
  const { fee } = await relayFee();
  const env = await q.prepare(vault, (nonce) => q.createUnpauseIntent({ vault, nonce, ...feeOptions(fee) }));
  await signAndRelay(env, 'unfreeze-password');
  note('Vault unfrozen. Sends work again.', 'ok');
  await refresh();
}

async function startGuardianDraft() {
  const key = LocalKey.generate();
  const seed = key.exportSeed();
  guardianDraft = { key, phrase: phraseFromSeed(seed), quiz: quizPositions(4) };
  seed.fill(0);
}

async function confirmGuardianDraft() {
  if (!guardianDraft) return;
  const words = guardianDraft.phrase.split(' ');
  for (const pos of guardianDraft.quiz) {
    if (val(`quiz-${pos}`).toLowerCase() !== words[pos - 1]) throw new Error(`Word ${pos} does not match. Check what you wrote down.`);
  }
  state.guardianPublic = { keyId: toHex(guardianDraft.key.keyId), publicKey: toHex(guardianDraft.key.publicKey) };
  guardianDraft.key.destroy();
  guardianDraft = null;
  persist();
  note('Guardian phrase confirmed. This browser has forgotten the guardian secret.', 'ok');
}

async function importGuardianPublic() {
  const f = JSON.parse(await readFile('guardian-public-file')) as { key_id?: string; public_key?: string };
  if (!f.key_id || !f.public_key) throw new Error('Not a QShield key file');
  state.guardianPublic = { keyId: f.key_id, publicKey: f.public_key };
  persist();
}

async function enableGuardian() {
  const g = state.guardianPublic;
  if (!g || !state.vault || !payer) throw new Error('Choose a guardian and connect a wallet first.');
  const cur = activeKey(state)!;
  if (g.keyId === cur.keystore.key_id) throw new Error('The guardian must be a different key.');
  const lamports = parseTokenAmount(val('guardian-limit') || '1', 9);
  const hours = BigInt(val('guardian-period') || '24');
  const { q, ops } = await chain();
  const vault = address(state.vault.address);
  const pw = val('guardian-password');
  clearInputs('guardian-password');
  (await decryptKey(cur.keystore, pw)).destroy();
  note('Setting up the guardian key account (6 transactions)…');
  render();
  const acct = await ops.setupKey(payer.signer, vault, fromHex(g.publicKey));
  const env = await q.prepareV2(vault, Role.Everyday, (nonce) => ({
    ...q.v2Base(vault, Role.Everyday, nonce, ActionV2.EnablePolicy),
    newKeyId: fromHex(g.keyId),
    newAlgorithm: 1,
    limitLamports: lamports,
    limitPeriod: hours * 3600n,
  }));
  env.hints = { new_key_account: toBase58(acct) };
  const key = await decryptKey(cur.keystore, pw);
  let signed: Envelope;
  try {
    signed = await signEnvelope(env, key);
  } finally {
    key.destroy();
  }
  const { relayer } = await chain();
  const r = await relayer.wait(await relayer.submit(signed));
  if (r.status !== 'confirmed') throw new Error(`relayer: ${'error' in r ? r.error : r.status}`);
  state.guardianPublic = null;
  persist();
  note('Guardian attached: large sends and new addresses now need its approval.', 'ok');
  await refresh();
}

async function removeSaved(addr: string) {
  const { q } = await chain();
  const vault = address(state.vault!.address);
  const env = await q.prepareV2(vault, Role.Everyday, (nonce) => ({ ...q.v2Base(vault, Role.Everyday, nonce, ActionV2.RemoveAddress), destination: address(addr) }));
  await signAndRelay(env, 'policy-password');
  await refresh();
}

async function startRotation() {
  await generateKey('rot-password', 'rot-password2');
}

/** Drops a key made for a replacement that was never completed (nothing on chain refers to it). */
function cancelRotation() {
  state.keys = state.keys.filter((k) => k.status !== 'pending');
  persist();
  note('Key replacement cancelled. Your current key is unchanged.', 'ok');
}

/**
 * Re-encrypts the active key under a new password. The key itself, and so the
 * vault, are unchanged; nothing is sent to the chain. Older backups still open
 * with the old password, so the backup must be redone.
 */
async function changePassword() {
  const k = activeKey(state);
  if (!k) throw new Error('No active key.');
  const current = val('pw-current');
  const next = val('pw-new');
  const problem = passwordProblem(next, val('pw-new2'));
  clearInputs('pw-current', 'pw-new', 'pw-new2');
  if (problem) throw new Error(problem);
  if (next === current) throw new Error('Choose a password different from the current one.');
  const key = await decryptKey(k.keystore, current);
  let keystore: KeystoreFile;
  try {
    keystore = await encryptKey(key, next, kdf);
  } finally {
    key.destroy();
  }
  if (keystore.key_id !== k.keystore.key_id) throw new Error('Re-encryption produced a different key; nothing was changed.');
  k.keystore = keystore;
  // Recovery words do not depend on the password, so they stay a valid backup.
  k.backupVerified = !!k.wordsBackedUp;
  persist();
  note(k.wordsBackedUp ? 'Password changed. Your recovery words still restore the key; old key files still open with the old password.' : 'Password changed. Download the new key file and check it: your old backup still opens with the old password.', 'ok');
}

async function completeRotation() {
  const cur = activeKey(state);
  const next = pendingKey(state);
  if (!cur || !next || !next.backupVerified) throw new Error('Back up the new key first.');
  if (!payer || !state.vault) throw new Error('Connect a wallet (it pays for the new key account).');
  const { q, ops, relayer } = await chain();
  const vault = address(state.vault.address);
  // Check the password first, but hold the decrypted key only for the signature itself.
  // (The DOM is re-rendered below, so keep the password in a local variable.)
  const pw = val('rot-current-password');
  clearInputs('rot-current-password');
  (await decryptKey(cur.keystore, pw)).destroy();
  note('Setting up the new key account (6 transactions)…');
  render();
  const newAcct = await ops.setupKey(payer.signer, vault, fromHex(next.keystore.public_key));
  const env = await q.prepare(vault, (nonce) => q.createRotateKeyIntent({ vault, nonce, newKeyId: fromHex(next.keystore.key_id) }));
  env.hints = { new_key_account: toBase58(newAcct) };
  const oldKey = await decryptKey(cur.keystore, pw);
  let signed: Envelope;
  try {
    signed = await signEnvelope(env, oldKey);
  } finally {
    oldKey.destroy();
  }
  const id = await relayer.submit(signed);
  const r = await relayer.wait(id);
  if (r.status !== 'confirmed') throw new Error(`relayer: ${'error' in r ? r.error : r.status}`);
  cur.status = 'retired';
  next.status = 'active';
  persist();
  note(`Vault now controlled by key ${next.keystore.key_id.slice(0, 16)}…; the old key can no longer authorize anything.`, 'ok');
  await refresh();
}

// ------------------------------------------------------------------ recovery with a guardian

/**
 * New device, guarded vault: sets up this browser's new key on the vault (the
 * Solana wallet pays the key account's rent, refunded when it is replaced).
 * The guardian then switches the vault to it from its own device.
 */
async function recoverPrepare() {
  const k = activeKey(state);
  if (!k) throw new Error('Create and back up the new key first.');
  const typed = val('recover-vault');
  if (!typed) throw new Error('Enter your vault address.');
  const vault = address(typed);
  const { q, ops } = await chain();
  const v = await q.getVault(vault);
  const pol = await q.getPolicy(vault);
  if (toHex(v.state.keyId) === k.keystore.key_id) return finishRecovery(typed);
  if (!pol?.enabled) throw new Error('This vault has no guardian, so only its key file can open it. Use "I have my key file" instead.');
  if (!payer) throw new Error('Connect a Solana wallet: it pays about 0.154 SOL of refundable rent for the new key.');
  state.recovery = { vault: typed };
  persist();
  const steps = h('ol', { 'data-testid': 'recover-progress' });
  document.getElementById('progress')?.replaceChildren(steps);
  const acct = await ops.setupKey(payer.signer, vault, fromHex(k.keystore.public_key), (p) => {
    steps.append(h('li', {}, `${p.step}/${p.total} ${p.label}`));
  });
  state.recovery = { vault: typed, keyAccount: toBase58(acct) };
  persist();
  note('New key is ready on the vault. Now approve the switch on your guardian device.', 'ok');
}

/** Opens the vault once the guardian has switched it to this browser's key. */
async function recoverCheck() {
  const vault = state.recovery?.vault;
  const k = activeKey(state);
  if (!vault || !k) throw new Error('Nothing to recover.');
  const { q } = await chain();
  const v = await q.getVault(address(vault));
  if (toHex(v.state.keyId) !== k.keystore.key_id) throw new Error('Your guardian has not switched the vault to this key yet. Approve it on the guardian device, then try again.');
  await finishRecovery(vault);
}

async function finishRecovery(vault: string) {
  state.vault = { address: vault, label: 'default', initialKeyId: '' };
  state.recovery = null;
  persist();
  note("Vault recovered: this browser's key controls it now, and the old key cannot approve anything.", 'ok');
  screen = 'home';
  await refresh();
}

// ------------------------------------------------------------------ formatting

/** `0.250000000` → `0.25`: trailing zeros trimmed, at least two decimals. */
function trimAmount(s: string): string {
  const [i, f = ''] = s.split('.');
  if (f === '') return i!;
  const t = f.replace(/0+$/, '');
  return `${i}.${t.length < 2 ? t.padEnd(2, '0') : t}`;
}
const sol = (lamports: bigint) => trimAmount(formatTokenAmount(lamports, 9));
const shortAddr = (a: string) => `${a.slice(0, 4)}…${a.slice(-4)}`;
const periodText = (seconds: bigint) => (seconds % 86_400n === 0n ? `${seconds / 86_400n === 1n ? '' : `${seconds / 86_400n} `}day${seconds / 86_400n === 1n ? '' : 's'}` : `${seconds / 3600n} h`);

/** A two-colour disc derived from the vault address, so each vault looks different at a glance. */
function avatar(addr: string, size: 'sm' | 'lg' = 'sm') {
  const el = h('div', { class: `avatar avatar-${size}`, 'aria-hidden': 'true' });
  const b = address(addr);
  // Set through the CSSOM: the page's CSP forbids inline style attributes.
  el.style.background = `conic-gradient(from ${b[2]! * 1.4}deg, hsl(${(b[0]! * 360) / 256} 62% 58%), hsl(${(b[1]! * 360) / 256} 58% 42%), hsl(${(b[0]! * 360) / 256} 62% 58%))`;
  return el;
}

function copyButton(id: string, text: string, label = 'Copy') {
  return h(
    'button',
    {
      id,
      'data-testid': id,
      class: 'btn btn-ghost btn-small',
      onclick: () => {
        void navigator.clipboard?.writeText(text);
        note('Copied to the clipboard.', 'ok');
        render();
      },
    },
    icon('copy'),
    label,
  );
}

// ------------------------------------------------------------------ shared pieces

function linkSettingsView() {
  if (!linkSettings) return null;
  const p = linkSettings;
  return h(
    'section',
    { class: 'panel panel-attention' },
    h('h2', {}, 'This link wants to change your settings'),
    h('p', { class: 'muted' }, 'Apply settings only from a source you trust. A malicious link can point the wallet at a fake program or relayer.'),
    row('Network', p.cluster),
    row('RPC', p.rpcUrl),
    row('Program', p.programId),
    row('Relayer', p.relayerUrl),
    h(
      'div',
      { class: 'btn-row' },
      button('apply-link-settings', 'Apply settings', () => {
        state.settings = p;
        linkSettings = null;
        persist();
        keepGuardianParams();
        render();
      }),
      button(
        'ignore-link-settings',
        'Ignore',
        () => {
          linkSettings = null;
          keepGuardianParams();
          render();
        },
        false,
        'secondary',
      ),
    ),
  );
}

/** Drops settings from the URL but keeps the guardian page's own parameters. */
function keepGuardianParams() {
  const keep = new URLSearchParams();
  for (const k of ['guardian', 'vault', 'proposal', 'owner', 'newkey', 'keyaccount']) {
    const v = query.get(k);
    if (v) keep.set(k, v);
  }
  const qs = keep.toString();
  history.replaceState(null, '', location.pathname + (qs ? `?${qs}` : ''));
}

function appearanceCard() {
  const opt = (t: Theme, label: string) =>
    h('button', { class: `seg ${theme === t ? 'on' : ''}`, 'data-testid': `theme-${t}`, 'aria-pressed': theme === t ? 'true' : 'false', onclick: () => (setTheme(t), render()) }, label);
  return card('Appearance', h('div', { class: 'segmented', role: 'group', 'aria-label': 'Theme' }, opt('auto', 'Auto'), opt('light', 'Light'), opt('dark', 'Dark')), h('p', { class: 'muted small' }, 'Auto matches your device. Saved in this browser only.'));
}

function settingsForm() {
  const s = state.settings;
  return card(
    'Network',
    field('Solana RPC URL', input('set-rpc', { value: s.rpcUrl, disabled: !!pinned.rpcUrl, spellcheck: 'false' })),
    field('QShield program id', input('set-program', { value: s.programId, disabled: !!pinned.programId, spellcheck: 'false', placeholder: 'program address' })),
    field(
      'Cluster',
      h('select', { id: 'set-cluster', 'data-testid': 'set-cluster', disabled: !!pinned.cluster }, ...(['devnet', 'testnet', 'localnet', 'mainnet'] as const).map((c) => h('option', { value: c, selected: c === s.cluster }, c))),
    ),
    field('Relayer URL', input('set-relayer', { value: s.relayerUrl, disabled: !!pinned.relayerUrl, spellcheck: 'false' }), 'The relayer delivers your signed sends and pays the network fee. It cannot change what you signed.'),
    button('save-settings', 'Save and reload', () => {
      state.settings = applyPinnedSettings({ rpcUrl: val('set-rpc'), programId: val('set-program'), cluster: val('set-cluster') as ClusterName, relayerUrl: val('set-relayer') });
      persist();
      location.reload();
    }),
  );
}

function applyPinnedSettings(s: Settings): Settings {
  return { ...s, ...Object.fromEntries(Object.entries(pinned).filter(([, v]) => v)) } as Settings;
}

function walletButtons() {
  const ws = solanaWallets();
  return h(
    'div',
    { class: 'stack' },
    ...ws.map((w, i) => button(`connect-wallet-${i}`, `Connect ${w.name}`, () => run('Connect wallet', async () => void (payer = await connectWallet(w, state.settings.cluster))), false, 'primary', 'wallet')),
    ws.length === 0 && h('p', { class: 'muted' }, state.settings.cluster === 'localnet' ? 'No Solana wallet extension found in this browser.' : 'No Solana wallet found. Install Phantom or Solflare, then reload this page.'),
    state.settings.cluster !== 'localnet' && state.settings.cluster !== 'mainnet' && devnetHelp(),
    state.settings.cluster === 'localnet' &&
      button(
        'dev-payer',
        'Use a test wallet (airdropped SOL)',
        () =>
          run('Test wallet', async () => {
            const d = devPayer(state.settings.cluster);
            const { rpc } = sdk();
            await rpc.requestAirdrop(d.signer.publicKey, 2_000_000_000n);
            // The RPC returns once the airdrop is submitted; wait until the SOL has landed.
            for (let i = 0; ; i++) {
              if (((await rpc.getAccount(d.signer.publicKey))?.lamports ?? 0n) > 0n) break;
              if (i >= 60) throw new Error('The airdrop did not arrive within 30 seconds. Try again, or connect a funded wallet.');
              await new Promise((r) => setTimeout(r, 500));
            }
            payer = d;
            note('Test wallet funded with 2 SOL by airdrop.', 'ok');
          }),
        false,
        'secondary',
      ),
  );
}

/** Shows, quizzes and hides the vault key's 24 recovery words. */
function recoveryWordsBlock(k: StoredKey) {
  if (wordsDraft && wordsDraft.keyId === k.keystore.key_id) {
    const words = wordsDraft.phrase.split(' ');
    return h(
      'div',
      { class: 'stack' },
      h('p', { class: 'callout callout-warn' }, icon('alert'), h('span', {}, 'These 24 words ARE your vault key, with no password on top. Write them on paper, in order. No photos, no cloud. Never keep them with your guardian words: anyone with both controls everything.')),
      h('ol', { class: 'phrase', 'data-testid': 'recovery-phrase' }, ...words.map((w, i) => h('li', { 'data-testid': `recovery-word-${i + 1}` }, w))),
      h('p', {}, `Type words ${wordsDraft.quiz.join(', ')} to confirm:`),
      h('div', { class: 'quiz' }, ...wordsDraft.quiz.map((pos) => field(`Word ${pos}`, input(`rq-${pos}`, { autocomplete: 'off', spellcheck: 'false' })))),
      button('confirm-words', 'I wrote them down', () => run('Checking words', async () => confirmRecoveryWords(k))),
      button('hide-words', 'Hide words', () => ((wordsDraft = null), render()), false, 'ghost'),
    );
  }
  return h(
    'div',
    { class: 'stack' },
    h('p', { class: 'muted small' }, 'Your vault key as 24 words on paper. They restore the key on any computer, with no file needed.'),
    field('Vault key password', input('words-password', { type: 'password', autocomplete: 'off' })),
    button('show-words', 'Show recovery words', () => run('Showing words', () => showRecoveryWords(k)), false, 'secondary'),
  );
}

/** Test networks: how to get a wallet on the right network and free test SOL. */
function devnetHelp() {
  const c = state.settings.cluster;
  return h(
    'details',
    { class: 'fields', 'data-testid': 'devnet-help' },
    h('summary', {}, `New to ${c}? Get free test SOL`),
    h(
      'ol',
      { class: 'steps compact' },
      h('li', {}, `In Phantom or Solflare, switch the network to ${c[0]!.toUpperCase() + c.slice(1)} (Settings → Developer settings).`),
      h('li', {}, 'Copy your wallet address, then get free test SOL at ', h('a', { href: 'https://faucet.solana.com', target: '_blank', rel: 'noopener noreferrer' }, 'faucet.solana.com'), '.'),
      h('li', {}, 'Come back and connect. Creating a vault uses about 0.16 test SOL.'),
    ),
    h('p', { class: 'muted small' }, 'Test SOL has no value. Never send real SOL to a devnet address.'),
  );
}

function backupSteps(k: StoredKey) {
  return h(
    'div',
    { class: 'stack' },
    h('p', { class: 'callout callout-warn' }, icon('alert'), h('span', {}, 'If this browser loses its data and you have no backup, the vault is gone for good. QShield cannot recover it.')),
    row('Key id', k.keystore.key_id, 'pending-key-id'),
    h(
      'ol',
      { class: 'steps' },
      h('li', {}, h('strong', {}, 'Download the key file. '), 'It is encrypted with your password. Keep it somewhere offline.', button('backup-download', 'Download key file', () => download(`qshield-key-${k.keystore.key_id.slice(0, 8)}.json`, JSON.stringify(k.keystore, null, 2) + '\n'), false, 'secondary')),
      h(
        'li',
        {},
        h('strong', {}, 'Check that it works. '),
        'Choose the file you just downloaded and enter its password.',
        input('backup-file', { type: 'file', accept: '.json,application/json', class: 'file' }),
        input('backup-password', { type: 'password', placeholder: 'Key file password', autocomplete: 'current-password' }),
        button('backup-verify', 'Check backup', () => run('Check backup', () => verifyBackup(k))),
      ),
    ),
    h('details', { class: 'fields', open: wordsDraft?.keyId === k.keystore.key_id }, h('summary', {}, 'Or back up on paper with 24 recovery words'), recoveryWordsBlock(k)),
  );
}

function logView(visible: boolean) {
  const items = log.map((l) => h('li', { class: `log-${l.kind}` }, l.kind === 'error' ? icon('alert') : l.kind === 'ok' ? icon('check') : icon('relay'), h('span', {}, l.text)));
  return h(
    'ul',
    { class: visible ? 'activity' : 'sr-only', 'data-testid': 'log', 'aria-live': 'polite' },
    ...(visible && items.length === 0 ? [h('li', { class: 'empty' }, 'Nothing yet. Sends, deposits and security changes made in this session show up here.')] : items),
  );
}

/** The newest message, fading out after a few seconds (CSS only: a timer re-render would clear file pickers). */
function toastView() {
  if (busy) return h('div', { class: 'toast toast-busy', 'data-testid': 'busy', role: 'status' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), `${busy}…`);
  const last = log[0];
  const age = Date.now() - noteAt;
  if (!last || age > 8000) return null;
  const t = h('div', { class: `toast toast-${last.kind}`, role: 'status' }, last.kind === 'error' ? icon('alert') : icon('check'), h('span', {}, last.text));
  t.style.animationDelay = `-${age}ms`;
  return t;
}

function topBar(title: string, back: Screen = 'home') {
  return h(
    'header',
    { class: 'topbar' },
    h('button', { class: 'icon-btn', 'aria-label': 'Back', 'data-testid': 'nav-back', onclick: () => go(back) }, icon('back')),
    h('h1', {}, title),
    h('span', { class: 'topbar-spacer' }),
  );
}

function go(s: Screen) {
  screen = s;
  wordsDraft = null;
  if (s !== 'send') review = null;
  render();
  window.scrollTo(0, 0);
}

function networkChip() {
  return h('button', { class: 'chip', 'data-testid': 'network-chip', onclick: () => go('settings'), 'aria-label': `Network: ${state.settings.cluster}. Open settings` }, h('span', { class: 'dot' }), state.settings.cluster);
}

// ------------------------------------------------------------------ onboarding

type Step = 'welcome' | 'create' | 'import' | 'recover-choice' | 'backup' | 'wallet' | 'vault' | 'recover';

function onboardingStep(): Step | null {
  const k = activeKey(state);
  const p = pendingKey(state);
  if (!k) return p && !p.backupVerified ? 'backup' : onboardingPath;
  if (!state.vault) return state.recovery ? 'recover' : payer || skipWallet ? 'vault' : 'wallet';
  return null;
}

/** Numbered steps: setting up a new vault, or recovering one with a guardian. */
function stepPlan(): { number: Partial<Record<Step, number>>; names: string[] } {
  return state.recovery
    ? { number: { create: 1, backup: 2, recover: 3 }, names: ['Create key', 'Back up', 'Guardian approves'] }
    : { number: { create: 1, backup: 2, wallet: 3, vault: 4 }, names: ['Create key', 'Back up', 'Connect wallet', 'Create vault'] };
}

function stepHeader(step: Step, title: string, lead: string) {
  const plan = stepPlan();
  const n = plan.number[step];
  const total = plan.names.length;
  return h(
    'div',
    { class: 'onb-head' },
    !!n && h('div', { class: `progress progress-${total}`, role: 'progressbar', 'aria-valuemin': '1', 'aria-valuemax': String(total), 'aria-valuenow': String(n), 'aria-label': `Step ${n} of ${total}: ${plan.names[n - 1]}` }, ...plan.names.map((_, i) => h('span', { class: i < n ? 'on' : '' }))),
    !!n && h('p', { class: 'step-of' }, `Step ${n} of ${total}`),
    h('h1', {}, title),
    h('p', { class: 'lead' }, lead),
  );
}

/** Shown in place of a step that needs the chain when no QShield program is configured. */
function networkGate() {
  const save = () => {
    const id = val('gate-program');
    try {
      if (address(id).length !== 32) throw new Error();
    } catch {
      throw new Error('That is not a valid program address. Paste the QShield program id exactly as you received it.');
    }
    state.settings = applyPinnedSettings({ ...state.settings, programId: id });
    persist();
    clusterChecked = '';
    note(`Connected to the QShield program on ${state.settings.cluster}.`, 'ok');
  };
  return h(
    'section',
    { class: 'panel panel-attention', 'data-testid': 'network-gate' },
    h('h2', {}, 'Connect to the QShield network'),
    h('p', { class: 'muted' }, `This wallet doesn't know which QShield program to use on ${state.settings.cluster} yet. Paste the program id you were given, or open the setup link again.`),
    field('QShield program id', input('gate-program', { placeholder: 'Program address', spellcheck: 'false', autocomplete: 'off' })),
    button('gate-save', 'Connect', () => run('Connecting', async () => save())),
    button('gate-settings', 'Change network or RPC', () => go('settings'), false, 'ghost'),
  );
}

function welcomeView() {
  const role = (ico: IconName, title: string, text: string) => h('li', {}, h('span', { class: 'role-icon' }, icon(ico)), h('div', {}, h('strong', {}, title), h('p', {}, text)));
  return h(
    'div',
    { class: 'onb' },
    h('div', { class: 'brand-mark', 'aria-hidden': 'true' }, icon('shield')),
    h('h1', { class: 'welcome-title' }, 'QShield'),
    h('p', { class: 'lead' }, 'Keep SOL and tokens in a vault that only your post-quantum key can move.'),
    h(
      'ul',
      { class: 'roles' },
      role('key', 'Your vault key', 'Created in this browser and stored encrypted. It signs every send.'),
      role('wallet', 'Your Solana wallet', 'Pays to set up the vault and to deposit. It can never take anything out.'),
      role('relay', 'A relayer', 'Delivers what you signed and pays the network fee. It cannot change a thing.'),
    ),
    !state.settings.programId && h('p', { class: 'callout callout-warn' }, icon('alert'), h('span', {}, 'No QShield program is set for this network yet. Open Settings and add the program id before creating a vault.')),
    h(
      'div',
      { class: 'stack' },
      button('start-create', 'Create a new vault', () => {
        onboardingPath = 'create';
        render();
      }),
      button(
        'start-import',
        'Restore my key',
        () => {
          onboardingPath = 'import';
          render();
        },
        false,
        'secondary',
      ),
      button(
        'start-recover',
        'Lost your computer? Recover your vault',
        () => {
          onboardingPath = 'recover-choice';
          render();
        },
        false,
        'ghost',
      ),
    ),
    h('p', { class: 'fineprint' }, state.settings.cluster === 'mainnet' ? 'Do not store meaningful funds. ' : `Public beta on ${state.settings.cluster}: free test SOL only, never real money. `, 'Research preview, unaudited. QShield protects what is in its vaults; it does not make Solana itself quantum-resistant.'),
  );
}

function createKeyView() {
  return h(
    'div',
    { class: 'onb' },
    stepHeader('create', 'Create your vault key', 'Pick a password. It encrypts the key on this device, and you will type it to approve every send.'),
    field('Password', input('new-password', { type: 'password', placeholder: 'At least 12 characters', autocomplete: 'new-password' })),
    field('Repeat password', input('new-password2', { type: 'password', autocomplete: 'new-password' })),
    h('p', { class: 'callout' }, icon('alert'), h('span', {}, 'The key lives in this browser. Malware or a malicious extension here could steal it, so use a clean device, and add a guardian once the vault is set up.')),
    button('generate-key', 'Create key', () => run('Creating key', () => generateKey('new-password', 'new-password2'))),
    button('onb-back', 'Back', () => ((onboardingPath = state.recovery ? 'recover-choice' : 'welcome'), (state.recovery = null), persist(), render()), false, 'ghost'),
  );
}

function recoverChoiceView() {
  const option = (id: string, ico: IconName, title: string, text: string, onclick: () => void) =>
    h('button', { class: 'option', 'data-testid': id, onclick }, h('span', { class: 'role-icon' }, icon(ico)), h('span', { class: 'option-text' }, h('strong', {}, title), h('span', {}, text)));
  return h(
    'div',
    { class: 'onb' },
    stepHeader('recover-choice', 'Recover your vault', 'Your vault lives on the blockchain, not on your computer. What you need is a way to prove it is yours.'),
    option('recover-with-file', 'key', 'I have my key file or my 24 recovery words', 'Restore the key on this computer and open the vault.', () => ((onboardingPath = 'import'), render())),
    option('recover-with-guardian', 'shield', 'I have a guardian', 'Make a new key here. Your guardian switches the vault to it, and the lost key stops working.', () => {
      state.recovery = {};
      persist();
      onboardingPath = 'create';
      render();
    }),
    h(
      'details',
      { class: 'fields' },
      h('summary', {}, 'I have neither'),
      h('p', { class: 'muted small' }, 'Then the vault cannot be recovered, by you or by anyone else. Nobody else holds a copy of your key: that is what keeps the vault safe, and also why the backup matters so much.'),
    ),
    button('onb-back', 'Back', () => ((onboardingPath = 'welcome'), render()), false, 'ghost'),
  );
}

function recoverView() {
  const k = activeKey(state)!;
  const r = state.recovery ?? {};
  if (!r.keyAccount) {
    return h(
      'div',
      { class: 'onb' },
      stepHeader('recover', 'Set up the new key on your vault', 'This puts the new key next to the vault. Nothing changes until your guardian approves the switch.'),
      h('div', { class: 'done-line' }, icon('check'), h('span', {}, 'New key ready and backed up'), h('span', { class: 'mono sr-only', 'data-testid': 'active-key-id' }, k.keystore.key_id)),
      field('Vault address', input('recover-vault', { value: r.vault ?? '', placeholder: 'The address you deposit to', spellcheck: 'false', autocomplete: 'off' }), 'Find it in an old deposit, a note you kept, or your guardian page link.'),
      payer ? row('Paid by', payer.label, 'payer') : h('div', { class: 'stack' }, h('p', { class: 'muted small' }, 'A Solana wallet pays about 0.154 SOL of rent for the new key. You get it back when that key is replaced one day.'), walletButtons()),
      button('recover-prepare', 'Set up the new key', () => run('Setting up the new key', recoverPrepare), !payer),
      h('div', { id: 'progress', class: 'progress-list' }),
      button('recover-cancel', 'Cancel recovery', () => ((state.recovery = null), persist(), render()), false, 'ghost'),
    );
  }
  const link = guardianLink({ newkey: k.keystore.key_id, keyaccount: r.keyAccount }, r.vault!);
  return h(
    'div',
    { class: 'onb' },
    stepHeader('recover', 'Ask your guardian to switch', 'The new key is on the vault. Your guardian now makes it the vault key; the lost one stops working at that moment.'),
    h(
      'ol',
      { class: 'steps compact' },
      h('li', {}, 'Open this link on your guardian device.'),
      h('li', {}, 'Unlock with your 24 guardian words.'),
      h('li', {}, 'Check that it shows the same four words as below.'),
      h('li', {}, 'Tap Replace everyday key. If the lost computer could be in someone else\'s hands, freeze first.'),
    ),
    h('div', { class: 'match' }, h('span', { class: 'muted small' }, 'Match words for the new key'), h('p', { class: 'match-code', 'data-testid': 'recover-code' }, fingerprint(fromHex(k.keystore.key_id)))),
    h('a', { href: link, 'data-testid': 'recover-link', target: '_blank', rel: 'noopener', class: 'btn btn-secondary' }, 'Open guardian page'),
    copyButton('copy-recover-link', link, 'Copy link for your guardian device'),
    button('recover-check', 'Done, open my vault', () => run('Checking the vault', recoverCheck)),
  );
}

function importView() {
  const seg = (m: 'file' | 'words', label: string) =>
    h('button', { class: `seg ${restoreMode === m ? 'on' : ''}`, 'data-testid': `restore-mode-${m}`, 'aria-pressed': restoreMode === m ? 'true' : 'false', onclick: () => ((restoreMode = m), render()) }, label);
  return h(
    'div',
    { class: 'onb' },
    stepHeader('import', 'Restore your key', restoreMode === 'file' ? 'Choose a QShield key file you backed up earlier and enter its password.' : 'Type your 24 recovery words in order, then choose a password for this computer.'),
    h('div', { class: 'segmented segmented-2', role: 'group', 'aria-label': 'Restore from' }, seg('file', 'Key file'), seg('words', 'Recovery words')),
    ...(restoreMode === 'file'
      ? [field('Key file', input('import-file', { type: 'file', accept: '.json,application/json', class: 'file' })), field('Password', input('import-password', { type: 'password', autocomplete: 'off' })), button('import-key', 'Restore key', () => run('Restoring key', importKey))]
      : [
          field('Recovery words', h('textarea', { id: 'restore-words', 'data-testid': 'restore-words', rows: 4, placeholder: 'word1 word2 …', autocomplete: 'off', spellcheck: 'false' }), 'Your vault key words, not your guardian words.'),
          field('New password', input('restore-password', { type: 'password', autocomplete: 'new-password', placeholder: 'At least 12 characters' })),
          field('Repeat password', input('restore-password2', { type: 'password', autocomplete: 'new-password' })),
          button('restore-words-btn', 'Restore key', () => run('Restoring key', restoreFromWords)),
        ]),
    button('onb-back', 'Back', () => ((onboardingPath = 'welcome'), render()), false, 'ghost'),
  );
}

function backupStepView(k: StoredKey) {
  return h('div', { class: 'onb' }, stepHeader('backup', 'Back up your key', 'Two quick steps. Nothing else is unlocked until your backup is proven to work.'), backupSteps(k));
}

function walletStepView() {
  const k = activeKey(state)!;
  return h(
    'div',
    { class: 'onb' },
    stepHeader('wallet', 'Connect a Solana wallet', 'It pays about 0.157 SOL of rent to create the vault and funds your deposits. It never gets control of the vault.'),
    h('div', { class: 'done-line' }, icon('check'), h('span', {}, 'Vault key ready and backed up'), h('span', { class: 'mono sr-only', 'data-testid': 'active-key-id' }, k.keystore.key_id)),
    state.settings.programId ? walletButtons() : networkGate(),
    h('p', { class: 'muted center' }, 'Already have a vault with this key?'),
    button('skip-wallet', 'Open my existing vault', () => ((skipWallet = true), render()), false, 'ghost'),
  );
}

function vaultStepView() {
  const k = activeKey(state)!;
  return h(
    'div',
    { class: 'onb' },
    stepHeader('vault', payer ? 'Create your vault' : 'Open your vault', payer ? 'One vault per key and name. Creating it takes 7 quick transactions, all paid by your Solana wallet.' : 'Enter the name you gave the vault when you created it.'),
    !state.settings.programId && networkGate(),
    payer && row('Paid by', payer.label, 'payer'),
    field('Vault name', input('vault-label', { value: 'default', spellcheck: 'false' }), 'Only used to find the vault again. "default" is fine.'),
    payer && button('create-vault', 'Create vault', () => run('Creating vault', createVault), !k.backupVerified || !state.settings.programId),
    h(
      payer ? 'details' : 'div',
      { class: payer ? 'fields' : 'stack' },
      payer && h('summary', {}, 'Open a vault I already have'),
      field('Vault address (if the key was ever replaced)', input('vault-open-address', { placeholder: 'Leave empty to find it by name', spellcheck: 'false', autocomplete: 'off' })),
      button('open-vault', 'Open existing vault', () => run('Opening vault', openVault), !state.settings.programId, payer ? 'secondary' : 'primary'),
    ),
    h('div', { id: 'progress', class: 'progress-list' }),
    skipWallet && !payer && button('back-to-wallet', 'Connect a wallet instead', () => ((skipWallet = false), render()), false, 'ghost'),
  );
}

function onboardingView(step: Step): Child[] {
  const header = h('header', { class: 'onb-top' }, h('span', { class: 'wordmark' }, 'QShield'), networkChip());
  const body =
    step === 'welcome' ? welcomeView()
    : step === 'create' ? createKeyView()
    : step === 'import' ? importView()
    : step === 'recover-choice' ? recoverChoiceView()
    : step === 'recover' ? recoverView()
    : step === 'backup' ? backupStepView(pendingKey(state)!)
    : step === 'wallet' ? walletStepView()
    : vaultStepView();
  return [header, body];
}

// ------------------------------------------------------------------ home

function homeView(): Child[] {
  const b = balances;
  const v = state.vault!;
  const frozen = b?.vault.state.status === VaultStatus.Paused;
  const now = BigInt(Math.floor(Date.now() / 1000));
  const action = (id: string, ico: IconName, label: string, to: Screen, disabled = false) =>
    h('button', { class: 'action', 'data-testid': id, onclick: () => go(to), disabled: disabled || !b }, h('span', { class: 'action-icon' }, icon(ico)), h('span', {}, label));
  const tokenRow = (name: string, sub: string, amount: Child, glyph: string, testid?: string, note2?: string) =>
    h('li', { class: 'token' }, h('span', { class: 'token-glyph', 'aria-hidden': 'true' }, glyph), h('div', { class: 'token-name' }, h('strong', {}, name), h('span', {}, note2 ?? sub)), h('span', { class: 'token-amount', 'data-testid': testid }, amount));
  return [
    h(
      'header',
      { class: 'account' },
      avatar(v.address),
      h('div', { class: 'account-text' }, h('strong', {}, v.label === 'default' ? 'My vault' : v.label), h('span', { class: 'mono addr', 'data-testid': 'vault-address', title: v.address }, v.address)),
      h('button', { class: 'icon-btn', 'aria-label': 'Copy vault address', 'data-testid': 'copy-address', onclick: () => (void navigator.clipboard?.writeText(v.address), note('Vault address copied.', 'ok'), render()) }, icon('copy')),
      networkChip(),
    ),
    h(
      'section',
      { class: 'hero' },
      h('p', { class: 'hero-label' }, 'Available to send'),
      h('p', { class: 'balance' }, h('span', { 'data-testid': 'vault-sol' }, b ? sol(b.vault.available) : '—'), h('span', { class: 'unit' }, 'SOL')),
      h(
        'div',
        { class: 'pills' },
        b && h('span', { class: `pill ${frozen ? 'pill-frozen' : 'pill-ok'}`, 'data-testid': 'vault-status' }, frozen ? 'Frozen' : 'Active'),
        policy ? h('span', { class: 'pill pill-guard' }, icon('shield'), `${sol(availableAt(policy, now))} SOL instant today`) : b && h('span', { class: 'pill' }, 'No guardian'),
        h('button', { class: 'icon-btn icon-btn-small', 'aria-label': 'Refresh balances', 'data-testid': 'refresh', onclick: () => run('Refreshing', refresh), disabled: !!busy }, icon('refresh')),
      ),
    ),
    h('nav', { class: 'actions', 'aria-label': 'Vault actions' }, action('action-send', 'send', 'Send', 'send', frozen), action('action-receive', 'receive', 'Receive', 'receive'), action('action-deposit', 'deposit', 'Deposit', 'deposit'), action('action-security', 'shield', 'Protect', 'security')),
    waiting && h('button', { class: 'banner-btn', 'data-testid': 'open-waiting', onclick: () => go('waiting') }, icon('activity'), h('span', {}, `Proposal ${waiting.id} is waiting for your guardian`)),
    frozen && h('button', { class: 'banner-btn banner-frozen', 'data-testid': 'open-unfreeze', onclick: () => go('security') }, icon('freeze'), h('span', {}, policy ? 'Frozen: nothing can leave. Only your guardian can unfreeze it. See how' : 'Frozen: nothing can leave. Unfreeze in Security')),
    !policy && b && !frozen && h('button', { class: 'banner-btn', 'data-testid': 'nudge-guardian', onclick: () => go('security') }, icon('shield'), h('span', {}, 'Add a guardian so stolen keys can take at most a daily limit')),
    h('h2', { class: 'list-title' }, 'Tokens'),
    h(
      'ul',
      { class: 'tokens' },
      tokenRow('Solana', 'SOL', b ? sol(b.vault.available) : '—', 'S'),
      ...(b?.tokens ?? []).map((t) => {
        const m = toBase58(t.account.mint);
        return t.decimals === null
          ? tokenRow(`Token ${shortAddr(m)}`, '', `${t.account.amount}`, '?', 'vault-token', 'Unsupported mint: cannot be withdrawn')
          : tokenRow(`Token ${shortAddr(m)}`, 'SPL token', trimAmount(formatTokenAmount(t.account.amount, t.decimals)), m.slice(0, 1), 'vault-token');
      }),
    ),
    !!b && b.tokens.length === 0 && h('p', { class: 'muted small' }, 'Tokens you deposit appear here.'),
  ];
}

// ------------------------------------------------------------------ receive, deposit

function receiveView(): Child[] {
  const a = state.vault!.address;
  const groups = a.match(/.{1,4}/g)!;
  return [
    topBar('Receive'),
    h(
      'section',
      { class: 'receive' },
      avatar(a, 'lg'),
      h('p', { class: 'muted' }, `Your vault address on ${state.settings.cluster}`),
      h('p', { class: 'addr-big mono', 'aria-label': a }, ...groups.map((g2) => h('span', {}, g2))),
      copyButton('copy-receive', a, 'Copy address'),
    ),
    h('p', { class: 'callout' }, icon('alert'), h('span', {}, 'Send SOL straight to this address. For tokens, use Deposit: it checks the token is supported. Tokens of unsupported mints sent here cannot be withdrawn.')),
  ];
}

function depositView(): Child[] {
  return [
    topBar('Deposit'),
    h('p', { class: 'lead' }, 'Move funds from your Solana wallet into the vault. The wallet pays; it gains no control over the vault.'),
    payer ? row('From', payer.label, 'payer') : card('Connect a wallet first', walletButtons()),
    card('SOL', field('Amount', input('deposit-sol', { placeholder: '0.5', inputmode: 'decimal', autocomplete: 'off' })), button('deposit-sol-btn', 'Deposit SOL', () => run('Depositing SOL', () => deposit('sol')), !payer)),
    card(
      'Tokens',
      field('Token mint', input('deposit-mint', { placeholder: 'Mint address', spellcheck: 'false' })),
      field('Amount', input('deposit-token-amount', { placeholder: '100', inputmode: 'decimal', autocomplete: 'off' })),
      button('deposit-token-btn', 'Deposit tokens', () => run('Depositing tokens', () => deposit('spl')), !payer, 'secondary'),
    ),
  ];
}

// ------------------------------------------------------------------ send

function sendView(): Child[] {
  if (!balances) return [topBar('Send')];
  if (review) {
    const fields = describeAny(review.auth);
    const saved = policy?.saved.some((x) => toBase58(x) === review!.to) ?? false;
    const known = (state.history ?? []).includes(review.to);
    const short = shortAddr(review.to);
    return [
      topBar('Review send', 'send'),
      h(
        'section',
        { class: 'review' },
        h('p', { class: 'review-amount' }, review.amountText),
        h('p', { class: 'muted' }, 'to'),
        h('p', { class: 'mono review-to', 'data-testid': 'review-recipient' }, chunkAddress(review.to)),
        h('span', { class: `pill ${saved ? 'pill-guard' : known ? 'pill-ok' : 'pill-warn'}`, 'data-testid': 'recipient-status' }, saved ? 'Saved address' : known ? 'Used before' : 'New address — never sent here'),
      ),
      review.proposal
        ? h('p', { class: 'callout callout-guard', 'data-testid': 'needs-guardian' }, icon('shield'), h('span', {}, 'Needs guardian approval: it is above your daily limit or to an unsaved address. Signing creates a proposal; nothing moves until your guardian approves it.'))
        : h('p', { class: 'callout' }, icon('alert'), h('span', {}, 'Check the amount and address. Once you sign, nobody can change them, including the relayer.')),
      h('details', { class: 'fields' }, h('summary', {}, 'Every signed field'), h('div', { 'data-testid': 'review-fields' }, ...Object.entries(fields).map(([k, v]) => row(k, v, `field-${k}`)))),
      field('Vault key password', input('send-password', { type: 'password', autocomplete: 'off' })),
      button('sign-send', review.proposal ? `Sign proposal: ${review.amountText} to ${short}` : `Sign and send ${review.amountText}`, () => run(review!.proposal ? 'Creating proposal' : 'Sending', signAndSend)),
      button('cancel-send', 'Cancel', () => ((review = null), render()), false, 'ghost'),
    ];
  }
  const options = [h('option', { value: 'SOL' }, `SOL (${sol(balances.vault.available)} available)`), ...balances.tokens.filter((t) => t.decimals !== null).map((t) => h('option', { value: toBase58(t.address) }, `Token ${shortAddr(toBase58(t.account.mint))} (${trimAmount(formatTokenAmount(t.account.amount, t.decimals!))})`))];
  const fee = relayerInfo ? BigInt(relayerInfo.min_fee_lamports) : null;
  return [
    topBar('Send'),
    field('Asset', h('select', { id: 'send-asset', 'data-testid': 'send-asset' }, ...options)),
    field('To', input('send-to', { placeholder: 'Recipient wallet address', spellcheck: 'false', autocomplete: 'off' })),
    field('Amount', input('send-amount', { placeholder: '0.00', inputmode: 'decimal', autocomplete: 'off' })),
    h(
      'p',
      { class: 'fee-line' },
      icon('relay'),
      relayerInfo ? h('span', {}, fee === 0n ? 'Network fee paid by the relayer. Free for you.' : `Relayer fee ${sol(fee!)} SOL, signed with your send.`) : h('span', { class: 'warn-text' }, 'Relayer unreachable. Check Settings.'),
    ),
    policy && h('p', { class: 'muted small' }, `Instant up to ${sol(availableAt(policy, BigInt(Math.floor(Date.now() / 1000))))} SOL today or to saved addresses. Anything else goes to your guardian.`),
    button('review-send', 'Review', () => run('Preparing', prepareSend)),
  ];
}

function waitingView(): Child[] {
  if (!waiting) return [topBar('Guardian approval'), h('p', { class: 'muted' }, 'Nothing is waiting.')];
  return [
    topBar('Waiting for your guardian'),
    h('section', { class: 'review' }, h('span', { class: 'big-icon' }, icon('shield')), h('p', { class: 'lead' }, `Proposal ${waiting.id} is ready. Open it on your guardian device, check the amount and address there, and approve.`)),
    h('div', { class: 'match' }, h('span', { class: 'muted small' }, 'Match code: both screens must show the same words'), h('p', { class: 'match-code', 'data-testid': 'match-code' }, waiting.code)),
    h('a', { href: waiting.link, 'data-testid': 'guardian-link', target: '_blank', rel: 'noopener', class: 'btn btn-secondary' }, 'Open guardian page'),
    copyButton('copy-guardian-link', waiting.link, 'Copy link for another device'),
    button('done-waiting', 'Done', () => {
      waiting = null;
      screen = 'home';
      void run('Refreshing', refresh);
    }),
  ];
}

// ------------------------------------------------------------------ security

function guardianSection() {
  if (policy) {
    const now = BigInt(Math.floor(Date.now() / 1000));
    return card(
      'Guardian protection is on',
      h('p', { class: 'muted' }, 'Sends within the limit or to saved addresses are instant. Anything else is proposed here and approved on your guardian device.'),
      row('Daily limit', `${sol(policy.limit)} SOL every ${periodText(policy.period)}`, 'policy-limit'),
      row('Left right now', `${sol(availableAt(policy, now))} SOL`, 'policy-available'),
      row('Guardian key', h('span', { class: 'mono' }, toHex(policy.guardianKeyId)), 'policy-guardian'),
      policy.saved.length > 0 && h('h3', {}, 'Saved addresses'),
      ...policy.saved.map((a, i) => h('div', { class: 'saved' }, h('span', { class: 'mono', 'data-testid': `saved-${i}` }, toBase58(a)), button(`remove-saved-${i}`, 'Remove', () => run('Removing address', () => removeSaved(toBase58(a))), false, 'ghost'))),
      policy.saved.length > 0 && field('Vault key password (to remove)', input('policy-password', { type: 'password', autocomplete: 'off' })),
      h('a', { href: guardianLink(), 'data-testid': 'guardian-page-link', target: '_blank', rel: 'noopener', class: 'btn btn-secondary' }, 'Open the guardian page'),
    );
  }
  if (guardianDraft) {
    const words = guardianDraft.phrase.split(' ');
    return card(
      'Write down your guardian phrase',
      h('p', { class: 'callout callout-warn' }, icon('alert'), h('span', {}, 'Write these 24 words on paper, in order. No photos, cloud or password manager on this computer. This browser forgets them once you confirm. Anyone with them can approve sends.')),
      h('ol', { class: 'phrase', 'data-testid': 'guardian-phrase' }, ...words.map((w, i) => h('li', { 'data-testid': `guardian-word-${i + 1}` }, w))),
      h('p', {}, `Type words ${guardianDraft.quiz.join(', ')} to confirm:`),
      h('div', { class: 'quiz' }, ...guardianDraft.quiz.map((pos) => field(`Word ${pos}`, input(`quiz-${pos}`, { autocomplete: 'off', spellcheck: 'false' })))),
      button('confirm-guardian', 'I wrote them down', () => run('Checking words', confirmGuardianDraft)),
    );
  }
  if (state.guardianPublic) {
    return card(
      'Turn on guardian protection',
      row('Guardian key', h('span', { class: 'mono' }, state.guardianPublic.keyId), 'guardian-key-id'),
      h('div', { class: 'two' }, field('Daily limit (SOL)', input('guardian-limit', { value: '1', inputmode: 'decimal' })), field('Period (hours)', input('guardian-period', { value: '24', inputmode: 'numeric' }))),
      h('p', { class: 'muted small' }, 'Your Solana wallet pays about 0.16 SOL of refundable rent for the guardian key. Your vault key signs.'),
      !payer && h('div', {}, h('p', { class: 'muted small' }, 'Connect a Solana wallet to continue:'), walletButtons()),
      field('Vault key password', input('guardian-password', { type: 'password', autocomplete: 'off' })),
      button('enable-guardian', 'Turn on guardian protection', () => run('Turning on guardian', enableGuardian), !payer),
      button('discard-guardian', 'Discard', () => ((state.guardianPublic = null), persist(), render()), false, 'ghost'),
    );
  }
  return card(
    'Add a guardian',
    h('p', {}, 'A guardian is a second key kept on paper or another device. If malware steals your vault key, it can take at most your daily limit. Only the guardian can unfreeze, save addresses or replace keys. Everyday sends stay instant.'),
    button('create-guardian', 'Create a guardian (24 words on paper)', () => run('Creating guardian', startGuardianDraft)),
    h('details', { class: 'fields' }, h('summary', {}, 'Use a guardian made on another device'), h('p', { class: 'muted small' }, 'Only its public key is read from the file.'), input('guardian-public-file', { type: 'file', accept: '.json,application/json', class: 'file' }), button('import-guardian', 'Use this guardian', () => run('Reading guardian', importGuardianPublic), false, 'secondary')),
  );
}

function freezeSection() {
  if (!balances) return null;
  const frozen = balances.vault.state.status === VaultStatus.Paused;
  if (frozen && policy) {
    return h(
      'section',
      { class: 'panel panel-frozen' },
      h('h2', {}, icon('freeze'), 'Vault is frozen'),
      h('p', {}, 'Nothing can leave. Only your guardian can unfreeze it, so a stolen vault key cannot undo the freeze.'),
      h('p', { class: 'small' }, 'On your guardian device, open the guardian page, unlock it with your 24 words and choose Unfreeze. If you think this key was stolen, have the guardian replace it first.'),
      h('a', { href: guardianLink(), 'data-testid': 'unfreeze-guardian-link', target: '_blank', rel: 'noopener', class: 'btn btn-secondary' }, 'Open the guardian page'),
      copyButton('copy-unfreeze-link', guardianLink(), 'Copy link for your guardian device'),
    );
  }
  if (frozen) {
    return h(
      'section',
      { class: 'panel panel-frozen' },
      h('h2', {}, icon('freeze'), 'Vault is frozen'),
      h('p', {}, 'Nothing can leave until you unfreeze it. If you think your key was stolen, replace it first (below): a thief with the old key could unfreeze too.'),
      field('Vault key password', input('unfreeze-password', { type: 'password', autocomplete: 'off' })),
      button('unfreeze', 'Unfreeze vault', () => run('Unfreezing', unfreezeVault)),
    );
  }
  return h(
    'section',
    { class: 'panel panel-danger' },
    h('h2', {}, 'Think your key is stolen?'),
    h('p', { class: 'muted' }, policy ? 'Freeze the vault now. Nothing can leave, and only your guardian can unfreeze it.' : 'Freeze the vault now. Nothing can leave until it is unfrozen.'),
    field('Vault key password', input('freeze-password', { type: 'password', autocomplete: 'off' })),
    button('freeze', 'Freeze vault', () => run('Freezing', freezeVault), false, 'danger', 'freeze'),
  );
}

function rotateSection() {
  const cur = activeKey(state);
  if (policy || !cur) return null;
  const next = pendingKey(state);
  const step = !next ? 1 : !next.backupVerified ? 2 : 3;
  const head = h(
    'div',
    { class: 'onb-head' },
    h('div', { class: 'progress progress-3', role: 'progressbar', 'aria-valuemin': '1', 'aria-valuemax': '3', 'aria-valuenow': String(step), 'aria-label': `Step ${step} of 3` }, ...[1, 2, 3].map((i) => h('span', { class: i <= step ? 'on' : '' }))),
    h('p', { class: 'step-of' }, `Step ${step} of 3`),
  );
  const cancel = next && button('rotate-cancel', 'Cancel replacement', () => (cancelRotation(), render()), false, 'ghost');
  if (step === 1) {
    return card(
      'Replace your vault key',
      h('p', { class: 'muted' }, 'For when you think the key itself was exposed. You get a brand-new key, and the old one stops working for good.'),
      h(
        'ol',
        { class: 'steps compact' },
        h('li', {}, h('strong', {}, 'Create the new key. '), 'Only in this browser: the vault does not change yet.'),
        h('li', {}, h('strong', {}, 'Back up the new key. '), 'Download its file and prove it opens.'),
        h('li', {}, h('strong', {}, 'Switch. '), 'Your current key signs "only the new key counts from now on". This needs your current password.'),
      ),
      head,
      field('Password for the new key', input('rot-password', { type: 'password', autocomplete: 'new-password', placeholder: 'At least 12 characters' })),
      field('Repeat password', input('rot-password2', { type: 'password', autocomplete: 'new-password' })),
      button('rotate-start', 'Create new key', () => run('Creating key', startRotation), false, 'secondary', 'key'),
      h('p', { class: 'muted small' }, 'Only want a different password for the same key?'),
      button('goto-change-password', 'Change password instead', () => go('settings'), false, 'ghost'),
    );
  }
  if (step === 2) return card('Replace your vault key', head, h('h3', {}, 'Back up the new key'), backupSteps(next!), cancel);
  return card(
    'Replace your vault key',
    head,
    h('h3', {}, 'Switch to the new key'),
    h('p', { class: 'muted small' }, 'Your current key signs the change. After this, only the new key (and its password) can approve anything.'),
    row('New key', h('span', { class: 'mono' }, next!.keystore.key_id), 'rotation-key-id'),
    !payer && h('div', {}, h('p', { class: 'muted small' }, 'Connect a Solana wallet: it pays about 0.154 SOL for the new key account (refunded later).'), walletButtons()),
    field('Current key password', input('rot-current-password', { type: 'password', autocomplete: 'off' }), 'The password of the key you are replacing, not the new one.'),
    button('rotate-complete', 'Switch to the new key', () => run('Replacing key', completeRotation), !payer),
    cancel,
  );
}

function securityView(): Child[] {
  const b = balances;
  return [
    h('header', { class: 'page-head' }, h('h1', {}, 'Security')),
    ...(b?.vault.state.status === VaultStatus.Paused ? [freezeSection(), guardianSection()] : [guardianSection(), freezeSection()]),
    rotateSection(),
    b &&
      card(
        'Vault details',
        row('Address', h('span', { class: 'mono' }, state.vault!.address)),
        row('Controlled by key', h('span', { class: 'mono' }, toHex(b.vault.state.keyId)), 'vault-key-id'),
        row('Authorizations used', b.vault.state.nonce.toString()),
      ),
  ];
}

// ------------------------------------------------------------------ activity, settings

function settingsView(): Child[] {
  const k = activeKey(state);
  return [
    h('header', { class: 'page-head' }, h('h1', {}, 'Settings')),
    k &&
      card(
        'Vault key',
        row('Key id', h('span', { class: 'mono', 'data-testid': 'active-key-id' }, k.keystore.key_id)),
        row('Backup', h('span', { 'data-testid': 'backup-status' }, k.backupVerified ? 'Checked' : 'Needs a new backup')),
        k.backupVerified
          ? button('download-key-again', 'Download key file again', () => download(`qshield-key-${k.keystore.key_id.slice(0, 8)}.json`, JSON.stringify(k.keystore, null, 2) + '\n'), false, 'secondary')
          : backupSteps(k),
      ),
    k &&
      card(
        'Recovery words',
        row('Status', h('span', { 'data-testid': 'words-status' }, k.wordsBackedUp ? 'Written down' : 'Not written down yet')),
        recoveryWordsBlock(k),
      ),
    k &&
      card(
        'Change password',
        h('p', { class: 'muted small' }, 'Locks the same key with a new password. Nothing changes on the blockchain, and the vault keeps the same key.'),
        h('p', { class: 'callout callout-warn' }, icon('alert'), h('span', {}, 'Old backup files still open with the old password, and your recovery words keep working. If someone may have seen your password and copied your key file, or seen your words, replace the key instead (Security).')),
        field('Current password', input('pw-current', { type: 'password', autocomplete: 'current-password' })),
        field('New password', input('pw-new', { type: 'password', autocomplete: 'new-password', placeholder: 'At least 12 characters' })),
        field('Repeat new password', input('pw-new2', { type: 'password', autocomplete: 'new-password' })),
        button('change-password', 'Change password', () => run('Changing password', changePassword), false, 'secondary'),
      ),
    card('Solana wallet', h('p', { class: 'muted small' }, 'Pays for setup and deposits. It cannot withdraw.'), payer ? row('Connected', payer.label, 'payer') : walletButtons()),
    appearanceCard(),
    settingsForm(),
    h('p', { class: 'fineprint' }, 'QShield research preview, unaudited. Do not store meaningful funds. It protects assets in QShield vaults with a post-quantum signature; it does not make Solana itself quantum-resistant.'),
  ];
}

function tabBar() {
  const tab = (s: Screen, ico: IconName, label: string) =>
    h('button', { class: `tab ${screen === s ? 'active' : ''}`, 'data-testid': `nav-${s}`, 'aria-label': label, 'aria-current': screen === s ? 'page' : undefined, onclick: () => go(s) }, icon(ico), h('span', {}, label));
  return h('nav', { class: 'tabbar', 'aria-label': 'Main' }, tab('home', 'home', 'Home'), tab('activity', 'activity', 'Activity'), tab('security', 'shield', 'Security'), tab('settings', 'settings', 'Settings'));
}

function appView(): Child[] {
  const body =
    screen === 'send' ? sendView()
    : screen === 'receive' ? receiveView()
    : screen === 'deposit' ? depositView()
    : screen === 'waiting' ? waitingView()
    : screen === 'security' ? securityView()
    : screen === 'activity' ? [h('header', { class: 'page-head' }, h('h1', {}, 'Activity'))]
    : screen === 'settings' ? settingsView()
    : homeView();
  const tabbed = ['home', 'activity', 'security', 'settings'].includes(screen);
  return [h('main', { class: `screen ${tabbed ? 'with-tabs' : ''}` }, ...body, logView(screen === 'activity')), tabbed && tabBar()];
}

// ------------------------------------------------------------------ guardian page

/** Guardian page state: the guardian key lives in memory only, never in storage. */
const g: {
  key: LocalKey | null;
  vault: VaultInfo | null;
  policy: PolicyState | null;
  proposal: ProposalState | null;
  draft: { key: LocalKey; phrase: string; quiz: number[] } | null;
  /** A replacement everyday key, checked on chain, waiting for the guardian's signature. */
  newKey: { keyId: Uint8Array; account: string; code: string } | null;
} = { key: null, vault: null, policy: null, proposal: null, draft: null, newKey: null };

async function gLoadVault() {
  const { q } = await chain();
  const v = address(val('g-vault'));
  g.vault = await q.getVault(v);
  const p = await q.getPolicy(v);
  g.policy = p?.enabled ? p : null;
  const pid = val('g-proposal');
  g.proposal = pid ? await q.getProposal(v, BigInt(pid)) : null;
  if (pid && !g.proposal) note(`Proposal ${pid} not found: already approved, cancelled, or never made.`);
}

async function gUnlockPhrase() {
  const seed = seedFromPhrase(val('g-phrase'));
  clearInputs('g-phrase');
  const key = LocalKey.fromSeed(seed);
  seed.fill(0);
  if (g.policy && toHex(key.keyId) !== toHex(g.policy.guardianKeyId)) {
    key.destroy();
    throw new Error("These words are not this vault's guardian key.");
  }
  g.key?.destroy();
  g.key = key;
  note('Guardian key loaded (in memory only; reload the page to forget it).', 'ok');
}

async function gSubmit(build: (nonce: bigint) => import('@qshield/sdk').AuthorizationV2, done: string, hints: Envelope['hints'] = {}) {
  if (!g.key || !g.vault) throw new Error('Load the vault and the guardian key first.');
  const { q, relayer } = await chain();
  const env = await q.prepareV2(g.vault.address, Role.Guardian, build, g.key.keyId);
  env.hints = hints;
  const signed = await signEnvelope(env, g.key);
  const r = await relayer.wait(await relayer.submit(signed));
  if (r.status !== 'confirmed') throw new Error(`relayer: ${'error' in r ? r.error : r.status}`);
  note(done, 'ok');
}

async function gApprove() {
  const p = g.proposal;
  if (!p || !g.vault) throw new Error('No proposal loaded.');
  const { shown, owner, mismatch } = proposalRecipient(p, query.get('owner'));
  if (mismatch) throw new Error('The link names a recipient that does not own the token account being paid. Reject this proposal and freeze the vault.');
  const saved = g.policy?.saved.some((x) => toBase58(x) === shown) ?? false;
  if (!saved && val('g-confirm') !== shown.slice(-4)) throw new Error('Type the last 4 characters of the recipient to approve a send to a new address.');
  const { q } = await chain();
  // Creating the recipient's token account costs the relayer rent, which the
  // approval pays as its fee (charged to the everyday allowance).
  const { fee } = owner ? await relayFee(p) : await relayFee();
  await gSubmit((nonce) => q.createApproval(g.vault!.address, nonce, p, feeOptions(fee)), 'Approved: the send is on chain.', owner ? { destination_owner: owner } : {});
  g.proposal = null;
}

/** Checks a replacement everyday key on chain before the guardian signs anything for it. */
async function gCheckNewKey() {
  if (!g.vault) throw new Error('Load the vault first.');
  const idHex = val('g-new-key-id').toLowerCase();
  const acct = val('g-new-key-account');
  if (!/^[0-9a-f]{64}$/.test(idHex)) throw new Error('The new key id must be 64 hex characters. Open the link from the new computer instead of typing it.');
  const { q } = await chain();
  const hdr = await q.getKeyAccount(address(acct));
  if (toBase58(hdr.vault) !== toBase58(g.vault.address)) throw new Error('That key account was set up for a different vault.');
  if (toHex(hdr.keyId) !== idHex) throw new Error('That key account holds a different key than the one named in the link.');
  if (hdr.state !== KeyState.Ready) throw new Error('That key is not fully set up yet. Finish "Set up the new key" on the new computer.');
  if (hdr.inUse) throw new Error('That key is already in use.');
  if (g.policy && idHex === toHex(g.policy.guardianKeyId)) throw new Error('The everyday key cannot be the guardian key.');
  if (idHex === toHex(g.vault.state.keyId)) throw new Error('The vault already uses this key.');
  g.newKey = { keyId: hdr.keyId, account: acct, code: fingerprint(hdr.keyId) };
}

async function gReplaceKey() {
  const nk = g.newKey;
  if (!nk || !g.vault) throw new Error('Check the new key first.');
  const { q } = await chain();
  await gSubmit(
    (n) => ({ ...q.v2Base(g.vault!.address, Role.Guardian, n, ActionV2.RotateKey), newKeyId: nk.keyId, newAlgorithm: 1 }),
    'Everyday key replaced: the old key can no longer approve anything.',
    { new_key_account: nk.account },
  );
  g.newKey = null;
  await gLoadVault();
}

function replaceKeyCard(fromLink: boolean) {
  const nk = g.newKey;
  return h(
    'section',
    { class: `panel ${fromLink ? 'panel-attention' : ''}`, 'data-testid': 'g-replace-card' },
    h('h2', {}, icon('key'), 'Replace the everyday key'),
    h('p', { class: 'muted small' }, 'For when the computer with the everyday key was lost or stolen. On the new computer, choose "Recover your vault": it gives you a link and four match words.'),
    field('New key id', input('g-new-key-id', { value: query.get('newkey') ?? '', spellcheck: 'false', autocomplete: 'off' })),
    field('New key account', input('g-new-key-account', { value: query.get('keyaccount') ?? '', spellcheck: 'false', autocomplete: 'off' })),
    !nk && button('g-check-key', 'Check the new key', () => run('Checking key', gCheckNewKey), false, 'secondary'),
    nk && h('div', { class: 'match' }, h('span', { class: 'muted small' }, 'Must match the words on the new computer'), h('p', { class: 'match-code', 'data-testid': 'g-new-key-code' }, nk.code)),
    nk && g.vault?.state.status !== VaultStatus.Paused && h('p', { class: 'callout callout-warn' }, icon('alert'), h('span', {}, 'If the old computer might be in someone else\'s hands, freeze first (below). The switch works while frozen; unfreeze afterwards.')),
    nk && button('g-replace-key', 'Replace everyday key', () => run('Replacing key', gReplaceKey), !g.key),
    nk && button('g-replace-cancel', 'Not these words', () => ((g.newKey = null), render()), false, 'ghost'),
  );
}

async function gCancel() {
  const p = g.proposal;
  if (!p || !g.vault) return;
  const { q } = await chain();
  await gSubmit((nonce) => ({ ...q.v2Base(g.vault!.address, Role.Guardian, nonce, ActionV2.CancelProposal), refId: p.id }), 'Proposal cancelled.');
  g.proposal = null;
}

function guardianPage(): Child[] {
  const { q } = sdk();
  const p = g.proposal;
  const parts: Child[] = [];
  if (state.keys.length > 0) {
    parts.push(h('p', { class: 'callout callout-warn', 'data-testid': 'same-device-warning' }, icon('alert'), h('span', {}, 'This browser also holds an everyday vault key. Keep your guardian on a different device, or malware here can reach both.')));
  }
  parts.push(
    card(
      'Vault',
      field('Vault address', input('g-vault', { value: query.get('vault') ?? '', placeholder: 'Vault address', spellcheck: 'false' })),
      field('Proposal number', input('g-proposal', { value: query.get('proposal') ?? '', placeholder: 'Optional', inputmode: 'numeric' })),
      button('g-load', g.vault ? 'Reload' : 'Load vault', () => run('Loading', gLoadVault), false, g.vault ? 'secondary' : 'primary'),
      g.vault && row('Status', h('span', { class: `pill ${g.vault.state.status === VaultStatus.Paused ? 'pill-frozen' : 'pill-ok'}`, 'data-testid': 'g-status' }, g.vault.state.status === VaultStatus.Paused ? 'Frozen' : 'Active')),
      g.policy && row('Daily limit', `${sol(g.policy.limit)} SOL every ${periodText(g.policy.period)}`),
      g.vault && !g.policy && h('p', { class: 'callout callout-warn' }, icon('alert'), h('span', {}, 'This vault has no guardian.')),
    ),
    card(
      'Guardian key',
      g.key
        ? h('div', { class: 'done-line' }, icon('check'), h('span', {}, 'Unlocked for this page only. Reload to forget it.'), h('span', { class: 'sr-only', 'data-testid': 'g-key-id' }, toHex(g.key.keyId)))
        : h(
            'div',
            {},
            field('Your 24 guardian words', h('textarea', { id: 'g-phrase', 'data-testid': 'g-phrase', rows: 4, placeholder: 'word1 word2 …', autocomplete: 'off', spellcheck: 'false' })),
            button('g-unlock', 'Unlock guardian', () => run('Unlocking', gUnlockPhrase), false, 'primary', 'key'),
          ),
    ),
  );
  if (p && g.vault) {
    const { shown, mismatch } = proposalRecipient(p, query.get('owner'));
    const saved = g.policy?.saved.some((x) => toBase58(x) === shown) ?? false;
    parts.push(
      h(
        'section',
        { class: 'panel panel-attention' },
        h('h2', {}, `Approve send ${p.id}?`),
        h(
          'div',
          { class: 'review' },
          h('p', { class: 'review-amount', 'data-testid': 'g-amount' }, p.assetType === AssetType.Sol ? `${sol(p.amount)} SOL` : `${trimAmount(formatTokenAmount(p.amount, p.decimals))} tokens`),
          p.assetType !== AssetType.Sol && h('p', { class: 'muted small mono' }, `Mint ${toBase58(p.mint)}`),
          h('p', { class: 'muted' }, 'to'),
          h('p', { class: 'mono review-to', 'data-testid': 'g-recipient' }, chunkAddress(shown)),
          h('p', { class: 'mono small muted wrap' }, shown),
          h('span', { class: `pill ${saved ? 'pill-guard' : 'pill-warn'}`, 'data-testid': 'g-recipient-status' }, saved ? 'Saved address' : 'New address — check it carefully'),
        ),
        mismatch && h('p', { class: 'callout callout-danger', 'data-testid': 'g-owner-mismatch' }, icon('alert'), h('span', {}, 'The link names a different recipient than the token account this proposal pays. The computer that made it may be compromised: reject and freeze.')),
        h('div', { class: 'match' }, h('span', { class: 'muted small' }, 'Match code: must equal the one on the other screen'), h('p', { class: 'match-code', 'data-testid': 'g-match-code' }, proposalCode(g.vault.address, p.id, p.mint, p.destination, p.amount))),
        h('p', { class: 'muted small' }, 'This page reads the proposal from the chain, not from the computer that made it. If anything differs from what you expect, reject it and freeze.'),
        !saved && field('Last 4 characters of the recipient', input('g-confirm', { autocomplete: 'off', spellcheck: 'false', maxlength: '4' })),
        h('div', { class: 'btn-row' }, button('g-approve', `Approve send to ${shortAddr(shown)}`, () => run('Approving', gApprove), !g.key || mismatch), button('g-reject', 'Reject', () => run('Rejecting', gCancel), !g.key, 'secondary')),
      ),
    );
  }
  const fromLink = !!query.get('newkey');
  if (g.vault && g.policy && fromLink) parts.push(replaceKeyCard(true));
  if (g.vault && g.policy) {
    parts.push(
      card(
        'Guardian actions',
        h(
          'div',
          { class: 'btn-row' },
          button('g-freeze', 'Freeze', () => run('Freezing', () => gSubmit((n) => q.v2Base(g.vault!.address, Role.Guardian, n, ActionV2.Pause), 'Frozen: only the guardian can unfreeze.')), !g.key, 'danger', 'freeze'),
          button('g-unfreeze', 'Unfreeze', () => run('Unfreezing', () => gSubmit((n) => q.v2Base(g.vault!.address, Role.Guardian, n, ActionV2.Unpause), 'Unfrozen: the vault is active again.')), !g.key, 'secondary'),
        ),
        h('h3', {}, 'Save an address'),
        h('p', { class: 'muted small' }, 'Sends to saved addresses go out instantly, without approval.'),
        input('g-save-address', { placeholder: 'Wallet address', spellcheck: 'false' }),
        button('g-save', 'Save address', () => run('Saving address', () => gSubmit((n) => ({ ...q.v2Base(g.vault!.address, Role.Guardian, n, ActionV2.AddAddress), destination: address(val('g-save-address')) }), 'Address saved.')), !g.key, 'secondary'),
        h('h3', {}, 'Change the daily limit'),
        h('div', { class: 'two' }, field('Limit (SOL)', input('g-limit', { inputmode: 'decimal' })), field('Period (hours)', input('g-period', { value: '24', inputmode: 'numeric' }))),
        button(
          'g-set-limit',
          'Set limit',
          () => run('Setting limit', () => gSubmit((n) => ({ ...q.v2Base(g.vault!.address, Role.Guardian, n, ActionV2.SetLimit), limitLamports: parseTokenAmount(val('g-limit'), 9), limitPeriod: BigInt(val('g-period')) * 3600n }), 'Limit updated.')),
          !g.key,
          'secondary',
        ),
      ),
    );
    if (!fromLink) parts.push(replaceKeyCard(false));
  }
  return parts;
}

function render() {
  const root = document.getElementById('app')!;
  // Keep what the user typed across re-renders (passwords are cleared explicitly after use).
  const typed = new Map<string, string>();
  for (const el of root.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>('input[id], select[id], textarea[id]')) {
    if ((el as HTMLInputElement).type !== 'file') typed.set(el.id, el.value);
  }
  let parts: Child[];
  if (GUARDIAN_MODE) {
    parts = [
      h(
        'main',
        { class: 'screen' },
        h('header', { class: 'onb-top' }, h('span', { class: 'wordmark' }, icon('shield'), 'QShield guardian'), h('span', { class: 'chip' }, h('span', { class: 'dot' }), state.settings.cluster)),
        h('p', { class: 'lead' }, 'Approve, reject or freeze from this device. QShield never asks for your guardian words anywhere else.'),
        linkSettingsView(),
        ...(state.settings.programId ? guardianPage() : [settingsForm()]),
        logView(false),
      ),
    ];
  } else {
    const step = onboardingStep();
    if (step) {
      parts = [
        h(
          'main',
          { class: 'screen' },
          linkSettingsView(),
          ...(screen === 'settings' ? [topBar('Settings'), appearanceCard(), settingsForm()] : onboardingView(step)),
          logView(false),
        ),
      ];
    } else {
      parts = linkSettings ? [h('main', { class: 'screen' }, linkSettingsView()), ...appView()] : appView();
    }
  }
  parts.push(toastView());
  root.replaceChildren(...parts.filter((p): p is Node => !!p));
  for (const [id, v] of typed) {
    const el = document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null;
    if (el && v !== '' && !el.disabled) el.value = v;
  }
}

discoverWallets(render);
render();
if (!GUARDIAN_MODE && state.vault && state.settings.programId) void run('Loading vault', refresh);
