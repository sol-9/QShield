//! Adversarial test suite (specification §34). Each test names the attack it
//! attempts. Every discovered issue gets a regression test here.

// LiteSVM's FailedTransactionMetadata is large; boxing it in tests buys nothing.
#![allow(clippy::result_large_err)]

mod common;

use common::*;
use qshield_protocol::{cluster, Action, Authorization, AUTH_LEN};
use qshield_vault::error::VaultError;
use qshield_vault::instruction::{build, tag};
use qshield_vault::state::KeyHeader;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

struct Fixture {
    env: Env,
    key: PqKey,
    vault: Pubkey,
    key_acct: Pubkey,
    relayer: Keypair,
    dest: Pubkey,
}

fn fixture(seed: u64) -> Fixture {
    let mut env = Env::new();
    let key = PqKey::from_seed(seed);
    let (vault, key_acct) = env.create_vault(&key, [seed as u8; 32]);
    env.deposit(&vault, 2 * LAMPORTS_PER_SOL);
    let relayer = env.relayer.insecure_clone();
    Fixture {
        env,
        key,
        vault,
        key_acct,
        relayer,
        dest: Pubkey::new_unique(),
    }
}

impl Fixture {
    fn signed_withdraw(&self, nonce: u64, amount: u64) -> (Vec<u8>, Vec<u8>) {
        let a = self
            .env
            .withdraw_auth(&self.vault, nonce, &self.dest, amount)
            .encode()
            .unwrap()
            .to_vec();
        let s = self.key.sign(&a);
        (a, s)
    }
    fn exec(&mut self, accts: &[AccountMeta], a: &[u8], s: &[u8]) -> TxResult {
        let (vault, key_acct) = (self.vault, self.key_acct);
        let relayer = self.relayer.insecure_clone();
        self.env
            .execute_v1(&relayer, &vault, &key_acct, accts, a, s)
    }
    fn untouched(&self, vault_balance: u64) {
        assert_eq!(
            self.env.balance(&self.vault),
            vault_balance,
            "vault balance changed"
        );
        assert_eq!(self.env.vault_state(&self.vault).nonce, 0, "nonce changed");
    }
}

#[test]
fn replay_attack_inline_and_buffered() {
    let mut f = fixture(100);
    let (a, s) = f.signed_withdraw(0, 1_000_000);
    let d = f.dest;
    f.exec(&[w(&d)], &a, &s).unwrap();
    assert_vault_error(&f.exec(&[w(&d)], &a, &s), VaultError::WrongNonce);
    let relayer2 = Keypair::new();
    f.env
        .svm
        .airdrop(&relayer2.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    let (vault, key_acct) = (f.vault, f.key_acct);
    let r = f
        .env
        .execute_buffered(&relayer2, &vault, &key_acct, &[w(&d)], &a, &s, 9);
    assert_vault_error(&r, VaultError::WrongNonce);
    assert_eq!(f.env.balance(&d), 1_000_000);
}

#[test]
fn destination_amount_fee_and_field_substitution() {
    let mut f = fixture(101);
    let before = f.env.balance(&f.vault);
    let (a, s) = f.signed_withdraw(0, 1_000_000);
    // Flip every byte of the authorization in turn: every variant must fail
    // (either non-canonical, or the signature no longer matches).
    for pos in 0..AUTH_LEN {
        let mut m = a.clone();
        m[pos] ^= 0x01;
        let accts = match Authorization::decode(&m) {
            Ok(x) if x.action == Action::WithdrawSol => {
                vec![w(&Pubkey::new_from_array(x.destination))]
            }
            _ => vec![w(&f.dest)],
        };
        let r = f.exec(&accts, &m, &s);
        assert!(r.is_err(), "mutated byte {pos} accepted");
    }
    f.untouched(before);
}

#[test]
fn destination_account_substitution() {
    let mut f = fixture(102);
    let before = f.env.balance(&f.vault);
    let (a, s) = f.signed_withdraw(0, 1_000_000);
    let attacker = Pubkey::new_unique();
    assert_vault_error(
        &f.exec(&[w(&attacker)], &a, &s),
        VaultError::AccountMismatch,
    );
    // Destination passed read-only.
    let d = f.dest;
    assert_vault_error(
        &f.exec(&[AccountMeta::new_readonly(d, false)], &a, &s),
        VaultError::NotWritable,
    );
    assert_vault_error(&f.exec(&[], &a, &s), VaultError::MissingAccount);
    f.untouched(before);
}

#[test]
fn nonce_manipulation() {
    let mut f = fixture(103);
    let before = f.env.balance(&f.vault);
    let d = f.dest;
    // Signed for a future nonce.
    let (a, s) = f.signed_withdraw(5, 1_000_000);
    assert_vault_error(&f.exec(&[w(&d)], &a, &s), VaultError::WrongNonce);
    // Nonce field rewritten to the current nonce: signature breaks.
    let mut m = Authorization::decode(&a).unwrap();
    m.nonce = 0;
    assert_vault_error(
        &f.exec(&[w(&d)], &m.encode().unwrap(), &s),
        VaultError::InvalidSignature,
    );
    f.untouched(before);
}

#[test]
fn wrong_vault_and_pda_substitution() {
    let mut f = fixture(104);
    let key2 = PqKey::from_seed(1104);
    let (vault2, key_acct2) = f.env.create_vault(&key2, [44u8; 32]);
    f.env.deposit(&vault2, LAMPORTS_PER_SOL);
    let before = f.env.balance(&f.vault);
    let (a, s) = f.signed_withdraw(0, 1_000_000);
    let d = f.dest;
    let relayer = f.relayer.insecure_clone();
    // Authorization for vault 1 against vault 2's accounts.
    let r = f
        .env
        .execute_v1(&relayer, &vault2, &key_acct2, &[w(&d)], &a, &s);
    assert_vault_error(&r, VaultError::WrongVault);
    // Vault 1 with vault 2's key account.
    let vault = f.vault;
    let r = f
        .env
        .execute_v1(&relayer, &vault, &key_acct2, &[w(&d)], &a, &s);
    assert_vault_error(&r, VaultError::AccountMismatch);
    // A forged "vault" account: same bytes, but owned by another program.
    let mut fake = f.env.svm.get_account(&vault).unwrap();
    fake.owner = Pubkey::new_unique();
    let fake_addr = Pubkey::new_unique();
    f.env.put_account(fake_addr, fake);
    let r = f
        .env
        .execute_v1(&relayer, &fake_addr, &f.key_acct.clone(), &[w(&d)], &a, &s);
    assert_vault_error(&r, VaultError::InvalidAccount);
    f.untouched(before);
}

#[test]
fn account_type_confusion() {
    let mut f = fixture(105);
    let before = f.env.balance(&f.vault);
    let (a, s) = f.signed_withdraw(0, 1_000_000);
    let d = f.dest;
    let relayer = f.relayer.insecure_clone();
    let (vault, key_acct) = (f.vault, f.key_acct);
    // Key account passed as the vault, vault passed as the key account.
    let r = f
        .env
        .execute_v1(&relayer, &key_acct, &vault, &[w(&d)], &a, &s);
    assert!(r.is_err());
    let r = f.env.execute_v1(&relayer, &vault, &vault, &[w(&d)], &a, &s);
    assert!(r.is_err());
    // A signature buffer passed as the key account.
    let buf = f.env.upload_sig_buffer(&relayer, &vault, &s, 3);
    let r = f.env.execute_v1(&relayer, &vault, &buf, &[w(&d)], &a, &s);
    assert!(r.is_err());
    f.untouched(before);
}

#[test]
fn cross_cluster_replay() {
    let mut f = fixture(106);
    let before = f.env.balance(&f.vault);
    let d = f.dest;
    for c in [
        cluster::DEVNET,
        cluster::MAINNET_BETA,
        cluster::TESTNET,
        [0u8; 32],
    ] {
        let mut x = f.env.withdraw_auth(&f.vault, 0, &d, 1_000_000);
        x.cluster_id = c;
        let a = x.encode().unwrap();
        let s = f.key.sign(&a);
        assert_vault_error(&f.exec(&[w(&d)], &a, &s), VaultError::WrongCluster);
    }
    f.untouched(before);
}

#[test]
fn cross_program_replay() {
    let mut f = fixture(107);
    // Deploy a second QShield instance (program B) holding a vault for the same key.
    let program_b = Pubkey::new_unique();
    f.env
        .svm
        .add_program_from_file(program_b, program_so())
        .unwrap();
    let program_a = f.env.program;
    f.env.program = program_b;
    let (vault_b, key_acct_b) = f.env.create_vault(&f.key, [107u8; 32]);
    f.env.deposit(&vault_b, LAMPORTS_PER_SOL);
    f.env.program = program_a;
    // Authorization for program A presented to program B.
    let d = f.dest;
    let mut x = f.env.withdraw_auth(&vault_b, 0, &d, 1_000_000);
    x.program_id = program_a.to_bytes();
    let a = x.encode().unwrap();
    let s = f.key.sign(&a);
    let relayer = f.relayer.insecure_clone();
    let ix = build::execute(
        &program_b,
        &relayer.pubkey(),
        &vault_b,
        &key_acct_b,
        &[w(&d)],
        &a,
        &s,
    );
    assert_vault_error(&f.env.v1(&[ix], &relayer, &[]), VaultError::WrongProgram);
}

#[test]
fn signature_truncation_and_padding() {
    let mut f = fixture(108);
    let before = f.env.balance(&f.vault);
    let (a, s) = f.signed_withdraw(0, 1_000_000);
    let relayer = f.relayer.insecure_clone();
    let d = f.dest;
    for extra in [-1i32, 1, -2420, 100] {
        let mut data = vec![tag::EXECUTE];
        data.extend_from_slice(&a);
        let mut sig = s.clone();
        if extra < 0 {
            sig.truncate((sig.len() as i32 + extra) as usize);
        } else {
            sig.extend(std::iter::repeat_n(0u8, extra as usize));
        }
        data.extend_from_slice(&sig);
        let ix = Instruction::new_with_bytes(
            f.env.program,
            &data,
            vec![
                AccountMeta::new(relayer.pubkey(), true),
                AccountMeta::new(f.vault, false),
                AccountMeta::new(f.key_acct, false),
                w(&d),
            ],
        );
        assert_vault_error(
            &f.env.v1(&[ix], &relayer, &[]),
            VaultError::InvalidInstruction,
        );
    }
    // Authorization truncated (signature shifted) inside a correctly sized payload.
    let mut data = vec![tag::EXECUTE];
    data.extend_from_slice(&a[..AUTH_LEN - 1]);
    data.extend_from_slice(&s);
    data.push(0);
    let ix = Instruction::new_with_bytes(
        f.env.program,
        &data,
        vec![
            AccountMeta::new(relayer.pubkey(), true),
            AccountMeta::new(f.vault, false),
            AccountMeta::new(f.key_acct, false),
            w(&d),
        ],
    );
    assert!(f.env.v1(&[ix], &relayer, &[]).is_err());
    f.untouched(before);
}

#[test]
fn buffer_chunk_replacement_and_ownership() {
    let mut f = fixture(109);
    let before = f.env.balance(&f.vault);
    let (a, s) = f.signed_withdraw(0, 1_000_000);
    let relayer = f.relayer.insecure_clone();
    let attacker = Keypair::new();
    f.env
        .svm
        .airdrop(&attacker.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    let (vault, key_acct, d, program) = (f.vault, f.key_acct, f.dest, f.env.program);

    // Relayer creates a buffer but has not finalized it.
    let (buf, _) = build::sig_buffer_address(&program, &vault, &relayer.pubkey(), 1);
    f.env
        .legacy(
            &[build::create_sig_buffer(
                &program,
                &relayer.pubkey(),
                &vault,
                1,
            )],
            &relayer,
            &[],
        )
        .unwrap();
    f.env
        .legacy(
            &[build::write_sig_buffer(
                &program,
                &relayer.pubkey(),
                &buf,
                0,
                false,
                &s[..900],
            )],
            &relayer,
            &[],
        )
        .unwrap();
    // Attacker tries to overwrite a chunk.
    let ix = build::write_sig_buffer(&program, &attacker.pubkey(), &buf, 0, false, &[0u8; 900]);
    assert_vault_error(
        &f.env.legacy(&[ix], &attacker, &[]),
        VaultError::AccountMismatch,
    );
    // Attacker tries to close it.
    let ix = build::close_sig_buffer(&program, &attacker.pubkey(), &buf);
    assert_vault_error(
        &f.env.legacy(&[ix], &attacker, &[]),
        VaultError::AccountMismatch,
    );
    // Executing with an unfinalized buffer fails.
    let ix = build::execute_with_buffer(
        &program,
        &relayer.pubkey(),
        &vault,
        &key_acct,
        &buf,
        &relayer.pubkey(),
        &[w(&d)],
        &a,
    );
    assert_vault_error(
        &f.env.legacy(&[ix], &relayer, &[]),
        VaultError::WrongBufferState,
    );
    // Finalize; afterwards even the creator cannot modify it.
    for (i, c) in s.chunks(900).enumerate().skip(1) {
        let fin = i == 2;
        let ix =
            build::write_sig_buffer(&program, &relayer.pubkey(), &buf, (i * 900) as u16, fin, c);
        f.env.legacy(&[ix], &relayer, &[]).unwrap();
    }
    let ix = build::write_sig_buffer(&program, &relayer.pubkey(), &buf, 0, false, &[0u8; 10]);
    assert_vault_error(
        &f.env.legacy(&[ix], &relayer, &[]),
        VaultError::WrongBufferState,
    );
    // Writes past the end are rejected.
    let (buf2, _) = build::sig_buffer_address(&program, &vault, &relayer.pubkey(), 2);
    f.env
        .legacy(
            &[build::create_sig_buffer(
                &program,
                &relayer.pubkey(),
                &vault,
                2,
            )],
            &relayer,
            &[],
        )
        .unwrap();
    let ix = build::write_sig_buffer(&program, &relayer.pubkey(), &buf2, 2000, false, &[0u8; 421]);
    assert_vault_error(&f.env.legacy(&[ix], &relayer, &[]), VaultError::OutOfBounds);
    // Buffer creator account substitution (refund theft).
    let ix = build::execute_with_buffer(
        &program,
        &relayer.pubkey(),
        &vault,
        &key_acct,
        &buf,
        &attacker.pubkey(),
        &[w(&d)],
        &a,
    );
    assert_vault_error(
        &f.env.legacy(&[ix], &relayer, &[]),
        VaultError::AccountMismatch,
    );
    // Buffer bound to a different vault.
    let key2 = PqKey::from_seed(1109);
    let (vault2, _) = f.env.create_vault(&key2, [9u8; 32]);
    let other = f.env.upload_sig_buffer(&relayer, &vault2, &s, 5);
    let ix = build::execute_with_buffer(
        &program,
        &relayer.pubkey(),
        &vault,
        &key_acct,
        &other,
        &relayer.pubkey(),
        &[w(&d)],
        &a,
    );
    assert_vault_error(
        &f.env.legacy(&[ix], &relayer, &[]),
        VaultError::AccountMismatch,
    );
    // A fake buffer (right bytes, wrong owner).
    let mut fake = f.env.svm.get_account(&buf).unwrap();
    fake.owner = attacker.pubkey();
    let fake_addr = Pubkey::new_unique();
    f.env.put_account(fake_addr, fake);
    let ix = build::execute_with_buffer(
        &program,
        &relayer.pubkey(),
        &vault,
        &key_acct,
        &fake_addr,
        &relayer.pubkey(),
        &[w(&d)],
        &a,
    );
    assert_vault_error(
        &f.env.legacy(&[ix], &relayer, &[]),
        VaultError::InvalidAccount,
    );
    // A buffer at a non-PDA address cannot be created.
    let bogus = Pubkey::new_unique();
    let mut ix = build::create_sig_buffer(&program, &attacker.pubkey(), &vault, 7);
    ix.accounts[1] = AccountMeta::new(bogus, false);
    assert_vault_error(
        &f.env.legacy(&[ix], &attacker, &[]),
        VaultError::AccountMismatch,
    );
    f.untouched(before);
    // The legitimate finalized buffer still works.
    let ix = build::execute_with_buffer(
        &program,
        &relayer.pubkey(),
        &vault,
        &key_acct,
        &buf,
        &relayer.pubkey(),
        &[w(&d)],
        &a,
    );
    f.env.legacy(&[ix], &relayer, &[]).expect("legit buffer");
    assert_eq!(f.env.balance(&d), 1_000_000);
}

#[test]
fn key_account_attacks() {
    let mut env = Env::new();
    let key = PqKey::from_seed(110);
    let program = env.program;
    let wallet = env.wallet.insecure_clone();
    let attacker = Keypair::new();
    env.svm
        .airdrop(&attacker.pubkey(), 10 * LAMPORTS_PER_SOL)
        .unwrap();
    let (vault, _) = build::vault_address(&program, &key.key_id, &[1u8; 32]);

    // Allocate a key account, then try to initialize it without its signature (front-run).
    let key_kp = Keypair::new();
    let rent = env.svm.minimum_balance_for_rent_exemption(KeyHeader::LEN);
    let alloc = solana_system_interface::instruction::create_account(
        &wallet.pubkey(),
        &key_kp.pubkey(),
        rent,
        KeyHeader::LEN as u64,
        &program,
    );
    env.legacy(&[alloc], &wallet, &[&key_kp]).unwrap();
    let mut ix = build::create_key(
        &program,
        &attacker.pubkey(),
        &key_kp.pubkey(),
        &vault,
        &key.key_id,
        1,
    );
    ix.accounts[1].is_signer = false;
    assert!(env.legacy(&[ix], &attacker, &[]).is_err());
    // Unsupported algorithm.
    let ix = build::create_key(
        &program,
        &wallet.pubkey(),
        &key_kp.pubkey(),
        &vault,
        &key.key_id,
        2,
    );
    assert_vault_error(
        &env.legacy(&[ix], &wallet, &[&key_kp]),
        VaultError::UnsupportedAlgorithm,
    );
    let ix = build::create_key(
        &program,
        &wallet.pubkey(),
        &key_kp.pubkey(),
        &vault,
        &key.key_id,
        1,
    );
    env.legacy(&[ix], &wallet, &[&key_kp]).unwrap();
    // Double initialization.
    let ix = build::create_key(
        &program,
        &wallet.pubkey(),
        &key_kp.pubkey(),
        &vault,
        &key.key_id,
        1,
    );
    assert_vault_error(
        &env.legacy(&[ix], &wallet, &[&key_kp]),
        VaultError::InvalidAccount,
    );
    // Non-creator writes.
    let ix = build::write_key(
        &program,
        &attacker.pubkey(),
        &key_kp.pubkey(),
        0,
        &[1u8; 32],
    );
    assert_vault_error(
        &env.legacy(&[ix], &attacker, &[]),
        VaultError::AccountMismatch,
    );
    // Out-of-bounds write.
    let ix = build::write_key(
        &program,
        &wallet.pubkey(),
        &key_kp.pubkey(),
        1300,
        &[1u8; 13],
    );
    assert_vault_error(&env.legacy(&[ix], &wallet, &[]), VaultError::OutOfBounds);
    // Expanding before finalization.
    let ix = build::expand_key(&program, &key_kp.pubkey(), 1);
    assert_vault_error(&env.legacy(&[ix], &wallet, &[]), VaultError::WrongKeyState);
    // Upload a *different* public key: finalize must fail.
    let wrong = PqKey::from_seed(9999);
    for (i, c) in wrong.pk.chunks(900).enumerate() {
        env.legacy(
            &[build::write_key(
                &program,
                &wallet.pubkey(),
                &key_kp.pubkey(),
                (i * 900) as u16,
                c,
            )],
            &wallet,
            &[],
        )
        .unwrap();
    }
    let ix = build::finalize_key(&program, &wallet.pubkey(), &key_kp.pubkey());
    assert_vault_error(&env.legacy(&[ix], &wallet, &[]), VaultError::KeyIdMismatch);
    // Vault initialization with a key that is not ready.
    let ix = build::initialize_vault(
        &program,
        &wallet.pubkey(),
        &vault,
        &key_kp.pubkey(),
        &[1u8; 32],
    );
    assert_vault_error(&env.legacy(&[ix], &wallet, &[]), VaultError::WrongKeyState);
    // Creator may abandon (close) an unused key and gets the rent back.
    let before = env.balance(&wallet.pubkey());
    env.legacy(
        &[build::close_key(
            &program,
            &wallet.pubkey(),
            &key_kp.pubkey(),
        )],
        &wallet,
        &[],
    )
    .unwrap();
    assert!(env.balance(&wallet.pubkey()) > before);
    assert_eq!(env.balance(&key_kp.pubkey()), 0);

    // A ready key bound to vault A cannot initialize vault B.
    let key_acct = env.setup_key(&wallet, &vault, &key);
    let (vault_b, _) = build::vault_address(&program, &key.key_id, &[2u8; 32]);
    let ix = build::initialize_vault(&program, &wallet.pubkey(), &vault_b, &key_acct, &[2u8; 32]);
    assert_vault_error(
        &env.legacy(&[ix], &wallet, &[]),
        VaultError::AccountMismatch,
    );
    // Wrong vault address for the seeds.
    let ix = build::initialize_vault(&program, &wallet.pubkey(), &vault, &key_acct, &[3u8; 32]);
    assert_vault_error(
        &env.legacy(&[ix], &wallet, &[]),
        VaultError::AccountMismatch,
    );
    // Fake system program.
    let mut ix = build::initialize_vault(&program, &wallet.pubkey(), &vault, &key_acct, &[1u8; 32]);
    ix.accounts[3] = AccountMeta::new_readonly(Pubkey::new_unique(), false);
    assert_vault_error(&env.legacy(&[ix], &wallet, &[]), VaultError::InvalidAccount);
    // Legit init; then the in-use key cannot be reused or closed.
    env.legacy(
        &[build::initialize_vault(
            &program,
            &wallet.pubkey(),
            &vault,
            &key_acct,
            &[1u8; 32],
        )],
        &wallet,
        &[],
    )
    .unwrap();
    let ix = build::initialize_vault(&program, &wallet.pubkey(), &vault, &key_acct, &[1u8; 32]);
    assert!(env.legacy(&[ix], &wallet, &[]).is_err());
}

#[test]
fn front_running_vault_initialization_is_harmless() {
    // An attacker who copies the user's InitializeVault (or creates the
    // vault first) can only create the vault with the user's own key: the
    // address commits to the initial key id.
    let mut env = Env::new();
    let key = PqKey::from_seed(111);
    let attacker = Keypair::new();
    env.svm
        .airdrop(&attacker.pubkey(), 10 * LAMPORTS_PER_SOL)
        .unwrap();
    let seed = [11u8; 32];
    let (vault, _) = build::vault_address(&env.program, &key.key_id, &seed);
    // Attacker builds a ready key account for *their own* key bound to this vault address.
    let evil = PqKey::from_seed(112);
    let evil_acct = env.setup_key(&attacker, &vault, &evil);
    let ix = build::initialize_vault(&env.program, &attacker.pubkey(), &vault, &evil_acct, &seed);
    assert_vault_error(
        &env.legacy(&[ix], &attacker, &[]),
        VaultError::AccountMismatch,
    );
    // Attacker pre-funds the vault PDA to block CreateAccount: init still works.
    let ix = solana_system_interface::instruction::transfer(&attacker.pubkey(), &vault, 1_000_000);
    env.legacy(&[ix], &attacker, &[]).unwrap();
    let (v, _k) = env.create_vault(&key, seed);
    assert_eq!(v, vault);
    assert_eq!(env.vault_state(&vault).key_id, key.key_id);
}

#[test]
fn integer_overflow_and_underflow() {
    let mut f = fixture(113);
    let before = f.env.balance(&f.vault);
    let d = f.dest;
    let mut x = f.env.withdraw_auth(&f.vault, 0, &d, u64::MAX);
    x.fee_lamports = u64::MAX;
    let a = x.encode().unwrap();
    let s = f.key.sign(&a);
    assert_vault_error(&f.exec(&[w(&d)], &a, &s), VaultError::Overflow);
    let a = f
        .env
        .withdraw_auth(&f.vault, 0, &d, u64::MAX)
        .encode()
        .unwrap();
    let s = f.key.sign(&a);
    assert_vault_error(&f.exec(&[w(&d)], &a, &s), VaultError::InsufficientFunds);
    f.untouched(before);
}

#[test]
fn duplicate_and_aliased_accounts() {
    let mut f = fixture(114);
    let relayer = f.relayer.insecure_clone();
    // Destination == vault is rejected (and would be a no-op anyway).
    let vault = f.vault;
    let mut x = f.env.withdraw_auth(&vault, 0, &vault, 1_000_000);
    x.destination = vault.to_bytes();
    let a = x.encode().unwrap();
    let s = f.key.sign(&a);
    assert_vault_error(&f.exec(&[w(&vault)], &a, &s), VaultError::AccountMismatch);
    // Destination == fee payer == fee recipient works and pays exactly amount + fee.
    let mut x = f.env.withdraw_auth(&vault, 0, &relayer.pubkey(), 1_000_000);
    x.fee_lamports = 5_000;
    x.fee_recipient = relayer.pubkey().to_bytes();
    let a = x.encode().unwrap();
    let s = f.key.sign(&a);
    let vb = f.env.balance(&vault);
    f.exec(&[w(&relayer.pubkey()), w(&relayer.pubkey())], &a, &s)
        .expect("aliased ok");
    assert_eq!(vb - f.env.balance(&vault), 1_005_000);
}

#[test]
fn malicious_remaining_accounts_are_ignored() {
    let mut f = fixture(115);
    let (a, s) = f.signed_withdraw(0, 1_000_000);
    let d = f.dest;
    let extra: Vec<AccountMeta> = (0..8).map(|_| w(&Pubkey::new_unique())).collect();
    let mut accts = vec![w(&d)];
    accts.extend(extra.iter().cloned());
    let vb = f.env.balance(&f.vault);
    f.exec(&accts, &a, &s).expect("ok");
    assert_eq!(f.env.balance(&d), 1_000_000);
    assert_eq!(vb - f.env.balance(&f.vault), 1_000_000);
    for e in extra {
        assert_eq!(f.env.balance(&e.pubkey), 0);
    }
}

#[test]
fn disallowed_actions() {
    let mut f = fixture(116);
    let before = f.env.balance(&f.vault);
    // Unpause while active.
    let a = Authorization {
        action: Action::Unpause,
        ..f.env.auth(&f.vault, 0)
    }
    .encode()
    .unwrap();
    let s = f.key.sign(&a);
    assert_vault_error(&f.exec(&[], &a, &s), VaultError::ActionNotPermitted);
    f.untouched(before);
}

#[test]
fn rotation_attacks() {
    let mut f = fixture(117);
    let wallet = f.env.wallet.insecure_clone();
    let new = PqKey::from_seed(1117);
    let vault = f.vault;
    let new_acct = f.env.setup_key(&wallet, &vault, &new);
    let rot = |env: &Env, id: [u8; 32]| {
        Authorization {
            action: Action::RotateKey,
            new_key_id: id,
            new_algorithm: 1,
            ..env.auth(&vault, 0)
        }
        .encode()
        .unwrap()
    };
    // Authorization names key X but a different ready key account is supplied.
    let other = PqKey::from_seed(2117);
    let a = rot(&f.env, other.key_id);
    let s = f.key.sign(&a);
    let wp = wallet.pubkey();
    assert_vault_error(
        &f.exec(&[w(&new_acct), w(&wp)], &a, &s),
        VaultError::AccountMismatch,
    );
    // Refund of the old key's rent redirected to an attacker.
    let a = rot(&f.env, new.key_id);
    let s = f.key.sign(&a);
    let attacker = Pubkey::new_unique();
    assert_vault_error(
        &f.exec(&[w(&new_acct), w(&attacker)], &a, &s),
        VaultError::AccountMismatch,
    );
    // Rotating to the current key account itself.
    let ka = f.key_acct;
    let cur = rot(&f.env, f.key.key_id);
    let cs = f.key.sign(&cur);
    assert_vault_error(
        &f.exec(&[w(&ka), w(&wp)], &cur, &cs),
        VaultError::AccountMismatch,
    );
    // A ready key account bound to another vault.
    let key2 = PqKey::from_seed(3117);
    let (vault2, _) = f.env.create_vault(&key2, [17u8; 32]);
    let foreign = f.env.setup_key(&wallet, &vault2, &new);
    assert_vault_error(
        &f.exec(&[w(&foreign), w(&wp)], &a, &s),
        VaultError::AccountMismatch,
    );
    // Legit rotation succeeds.
    f.exec(&[w(&new_acct), w(&wp)], &a, &s).expect("rotate");
}

/// Property (§33): random instructions signed only by Ed25519 keys never
/// decrease a vault's balance and never change its nonce.
#[test]
fn random_ed25519_only_instructions_never_move_funds() {
    let mut f = fixture(118);
    let mut rng = ChaCha20Rng::seed_from_u64(118);
    let wallet = f.env.wallet.insecure_clone();
    let before = f.env.balance(&f.vault);
    let program = f.env.program;
    let candidates = [
        f.vault,
        f.key_acct,
        wallet.pubkey(),
        f.dest,
        Pubkey::new_unique(),
        Pubkey::new_from_array([0; 32]),
    ];
    let (a, s) = f.signed_withdraw(0, 1_000_000);
    for i in 0..300 {
        let t: u8 = rng.gen_range(0..14);
        let mut data = vec![t];
        match t {
            tag::EXECUTE => {
                let mut aa = a.clone();
                let mut ss = s.clone();
                let p = rng.gen_range(0..AUTH_LEN + 2420);
                if p < AUTH_LEN {
                    aa[p] ^= 1 << rng.gen_range(0..8);
                } else {
                    ss[p - AUTH_LEN] ^= 1 << rng.gen_range(0..8);
                }
                data.extend(aa);
                data.extend(ss);
            }
            tag::EXECUTE_WITH_BUFFER => {
                let mut aa = a.clone();
                aa[rng.gen_range(0..AUTH_LEN)] ^= 1;
                data.extend(aa);
            }
            _ => {
                let n = rng.gen_range(0..80);
                data.extend((0..n).map(|_| rng.gen::<u8>()));
            }
        }
        let n_acc = rng.gen_range(0..7);
        let mut accounts = vec![AccountMeta::new(wallet.pubkey(), true)];
        for _ in 0..n_acc {
            let k = candidates[rng.gen_range(0..candidates.len())];
            if k != wallet.pubkey() {
                accounts.push(AccountMeta::new(k, false));
            }
        }
        let ix = Instruction::new_with_bytes(program, &data, accounts);
        let _ = f.env.v1(&[ix], &wallet, &[]);
        assert!(
            f.env.balance(&f.vault) >= before,
            "iteration {i}: vault balance decreased"
        );
        assert_eq!(
            f.env.vault_state(&f.vault).nonce,
            0,
            "iteration {i}: nonce changed"
        );
    }
}

/// Property (§33/§51): a valid authorization executed by different relayers
/// produces exactly the same effect on the vault and destination.
#[test]
fn relayer_identity_cannot_change_outcome() {
    use solana_account::ReadableAccount;
    let mut f = fixture(119);
    let (a, s) = f.signed_withdraw(0, 3_000_000);
    let d = f.dest;
    let other_relayer = Keypair::new();
    f.env
        .svm
        .airdrop(&other_relayer.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    // Relayer B: simulate only.
    let ix = build::execute(
        &f.env.program,
        &other_relayer.pubkey(),
        &f.vault,
        &f.key_acct,
        &[w(&d)],
        &a,
        &s,
    );
    let msg = solana_message::v1::Message::try_compile_with_config(
        &other_relayer.pubkey(),
        &[ix],
        f.env.svm.latest_blockhash(),
        solana_message::v1::TransactionConfig::empty()
            .with_compute_unit_limit(1_400_000)
            .with_loaded_accounts_data_size_limit(1 << 20),
    )
    .unwrap();
    let tx = solana_transaction::versioned::VersionedTransaction::try_new(
        solana_message::VersionedMessage::V1(msg),
        &[&other_relayer],
    )
    .unwrap();
    let sim = f.env.svm.simulate_transaction(tx).expect("simulate");
    let post = |k: &Pubkey| {
        sim.post_accounts
            .iter()
            .find(|(a, _)| a == k)
            .map(|(_, acc)| (acc.lamports(), acc.data().to_vec()))
    };
    let (sim_vault_lamports, sim_vault_data) = post(&f.vault).unwrap();
    let (sim_dest_lamports, _) = post(&d).unwrap();
    // Relayer A: execute.
    f.exec(&[w(&d)], &a, &s).unwrap();
    let vault_acct = f.env.svm.get_account(&f.vault).unwrap();
    assert_eq!(vault_acct.lamports, sim_vault_lamports);
    assert_eq!(vault_acct.data, sim_vault_data);
    assert_eq!(f.env.balance(&d), sim_dest_lamports);
}
