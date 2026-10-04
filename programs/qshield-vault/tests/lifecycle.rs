//! End-to-end lifecycle tests, including the MVP demonstration from the
//! project specification (§59) and the main security invariant (§50).

// LiteSVM's FailedTransactionMetadata is large; boxing it in tests buys nothing.
#![allow(clippy::result_large_err)]

mod common;

use common::*;
use qshield_protocol::{Action, AssetType, Authorization, ZERO32};
use qshield_vault::error::VaultError;
use qshield_vault::instruction::build;
use qshield_vault::state::VaultStatus;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

/// Specification §59: the MVP success criteria, step by step.
#[test]
fn mvp_demonstration() {
    let mut env = Env::new();

    // 1. Generate ML-DSA keypair locally.
    let key = PqKey::from_seed(1);
    // 2. Create a QShield vault associated with the PQ public key.
    let (vault, key_acct) = env.create_vault(&key, [7u8; 32]);
    assert_eq!(env.vault_state(&vault).key_id, key.key_id);
    // 3. Deposit SOL.
    env.deposit(&vault, LAMPORTS_PER_SOL / 10);
    let vault_before = env.balance(&vault);

    // 4. Disconnect / ignore the original wallet: from here on only the PQ key
    //    and an unrelated relayer act.
    let relayer = env.relayer.insecure_clone();
    let dest = Pubkey::new_unique();

    // 5-6. Construct and ML-DSA-sign a transfer authorization.
    let auth = env
        .withdraw_auth(&vault, 0, &dest, LAMPORTS_PER_SOL / 100)
        .encode()
        .unwrap();
    let sig = key.sign(&auth);

    // 7-10. An untrusted relayer submits it and pays the fee; the program
    //       verifies and the vault PDA transfers SOL.
    let relayer_before = env.balance(&relayer.pubkey());
    let r = env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &auth, &sig);
    let meta = r.expect("withdrawal");
    eprintln!(
        "withdraw_sol (inline v1) CU: {}",
        meta.compute_units_consumed
    );
    assert_eq!(env.balance(&dest), LAMPORTS_PER_SOL / 100);
    assert_eq!(env.balance(&vault), vault_before - LAMPORTS_PER_SOL / 100);
    assert!(
        env.balance(&relayer.pubkey()) < relayer_before,
        "relayer paid the network fee"
    );

    // 11. Nonce changes.
    assert_eq!(env.vault_state(&vault).nonce, 1);

    // 12. Replaying the identical authorization fails.
    let r = env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &auth, &sig);
    assert_vault_error(&r, VaultError::WrongNonce);

    // 13-15. Editing amount, destination or vault fails (signature mismatch).
    let fresh = env
        .withdraw_auth(&vault, 1, &dest, LAMPORTS_PER_SOL / 100)
        .encode()
        .unwrap();
    let fresh_sig = key.sign(&fresh);
    let mut more = Authorization::decode(&fresh).unwrap();
    more.amount *= 10;
    let r = env.execute_v1(
        &relayer,
        &vault,
        &key_acct,
        &[w(&dest)],
        &more.encode().unwrap(),
        &fresh_sig,
    );
    assert_vault_error(&r, VaultError::InvalidSignature);
    let other = Pubkey::new_unique();
    let mut redirect = Authorization::decode(&fresh).unwrap();
    redirect.destination = other.to_bytes();
    let r = env.execute_v1(
        &relayer,
        &vault,
        &key_acct,
        &[w(&other)],
        &redirect.encode().unwrap(),
        &fresh_sig,
    );
    assert_vault_error(&r, VaultError::InvalidSignature);
    let (vault2, key_acct2) = env.create_vault(&key, [8u8; 32]);
    env.deposit(&vault2, LAMPORTS_PER_SOL / 10);
    let mut wrong_vault = Authorization::decode(&fresh).unwrap();
    wrong_vault.vault = vault2.to_bytes();
    wrong_vault.nonce = 0;
    let r = env.execute_v1(
        &relayer,
        &vault2,
        &key_acct2,
        &[w(&dest)],
        &wrong_vault.encode().unwrap(),
        &fresh_sig,
    );
    assert_vault_error(&r, VaultError::InvalidSignature);
    // The untampered authorization still works.
    env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &fresh, &fresh_sig)
        .expect("valid");

    // 16. The original wallet key alone cannot withdraw (see also
    //     `ed25519_wallet_alone_cannot_withdraw`).
    assert_eq!(env.vault_state(&vault).nonce, 2);
}

/// Specification §50: possession of the user's ordinary Solana Ed25519
/// private key alone must not permit withdrawal from a PQ-only vault.
#[test]
fn ed25519_wallet_alone_cannot_withdraw() {
    let mut env = Env::new();
    let key = PqKey::from_seed(2);
    let (vault, key_acct) = env.create_vault(&key, [1u8; 32]);
    env.deposit(&vault, LAMPORTS_PER_SOL);
    let wallet = env.wallet.insecure_clone(); // attacker has stolen this key
    let thief = Pubkey::new_unique();
    let before = env.balance(&vault);

    // (a) Every instruction the wallet can sign, attempting to move funds.
    let auth = env
        .withdraw_auth(&vault, 0, &thief, LAMPORTS_PER_SOL / 2)
        .encode()
        .unwrap();
    // No PQ signature: zeros, random bytes, or a signature by another PQ key.
    let attacker_key = PqKey::from_seed(666);
    for sig in [vec![0u8; 2420], vec![0xa5; 2420], attacker_key.sign(&auth)] {
        let r = env.execute_v1(&wallet, &vault, &key_acct, &[w(&thief)], &auth, &sig);
        assert_vault_error(&r, VaultError::InvalidSignature);
    }
    // (b) Re-initializing the vault with the attacker's own key.
    let ix = build::initialize_vault(
        &env.program,
        &wallet.pubkey(),
        &vault,
        &key_acct,
        &[1u8; 32],
    );
    assert!(env.legacy(&[ix], &wallet, &[]).is_err());
    // (c) Closing the in-use key account to brick or swap the key.
    let ix = build::close_key(&env.program, &wallet.pubkey(), &key_acct);
    assert_vault_error(&env.legacy(&[ix], &wallet, &[]), VaultError::KeyInUse);
    // (d) Rewriting the key bytes after it is ready.
    let ix = build::write_key(&env.program, &wallet.pubkey(), &key_acct, 0, &[0u8; 32]);
    assert_vault_error(&env.legacy(&[ix], &wallet, &[]), VaultError::WrongKeyState);
    // (e) Rotating to a key the attacker controls, signed by the attacker's key.
    let attacker_key_acct = env.setup_key(&wallet, &vault, &attacker_key);
    let rot = Authorization {
        action: Action::RotateKey,
        new_key_id: attacker_key.key_id,
        new_algorithm: 1,
        ..env.auth(&vault, 0)
    }
    .encode()
    .unwrap();
    let r = env.execute_v1(
        &wallet,
        &vault,
        &key_acct,
        &[w(&attacker_key_acct), w(&wallet.pubkey())],
        &rot,
        &attacker_key.sign(&rot),
    );
    assert_vault_error(&r, VaultError::InvalidSignature);

    assert_eq!(env.balance(&vault), before);
    assert_eq!(env.balance(&thief), 0);
    assert_eq!(env.vault_state(&vault).nonce, 0);
}

#[test]
fn buffered_transport_withdrawal() {
    let mut env = Env::new();
    let key = PqKey::from_seed(3);
    let (vault, key_acct) = env.create_vault(&key, [2u8; 32]);
    env.deposit(&vault, LAMPORTS_PER_SOL);
    let relayer = env.relayer.insecure_clone();
    let dest = Pubkey::new_unique();
    let auth = env
        .withdraw_auth(&vault, 0, &dest, 5_000_000)
        .encode()
        .unwrap();
    let sig = key.sign(&auth);
    let relayer_before = env.balance(&relayer.pubkey());
    let meta = env
        .execute_buffered(&relayer, &vault, &key_acct, &[w(&dest)], &auth, &sig, 1)
        .expect("buffered");
    eprintln!(
        "withdraw_sol (buffered legacy) CU: {}",
        meta.compute_units_consumed
    );
    assert_eq!(env.balance(&dest), 5_000_000);
    // Buffer closed and rent refunded: relayer only lost transaction fees.
    let (buf, _) = build::sig_buffer_address(&env.program, &vault, &relayer.pubkey(), 1);
    assert_eq!(env.balance(&buf), 0);
    assert!(relayer_before - env.balance(&relayer.pubkey()) < 100_000);
}

#[test]
fn explicit_relayer_fee() {
    let mut env = Env::new();
    let key = PqKey::from_seed(4);
    let (vault, key_acct) = env.create_vault(&key, [3u8; 32]);
    env.deposit(&vault, LAMPORTS_PER_SOL);
    let relayer = env.relayer.insecure_clone();
    let dest = Pubkey::new_unique();
    let fee_account = Pubkey::new_unique();
    env.svm.airdrop(&fee_account, 1_000_000).unwrap();

    // Fee to an explicit recipient.
    let mut a = env.withdraw_auth(&vault, 0, &dest, 10_000_000);
    a.fee_lamports = 50_000;
    a.fee_recipient = fee_account.to_bytes();
    let auth = a.encode().unwrap();
    let sig = key.sign(&auth);
    // Omitting or substituting the fee account fails.
    let r = env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &auth, &sig);
    assert_vault_error(&r, VaultError::MissingAccount);
    let r = env.execute_v1(
        &relayer,
        &vault,
        &key_acct,
        &[w(&dest), w(&relayer.pubkey())],
        &auth,
        &sig,
    );
    assert_vault_error(&r, VaultError::AccountMismatch);
    env.execute_v1(
        &relayer,
        &vault,
        &key_acct,
        &[w(&dest), w(&fee_account)],
        &auth,
        &sig,
    )
    .expect("ok");
    assert_eq!(env.balance(&fee_account), 1_050_000);

    // Fee to "whoever pays the transaction fee" (fee_recipient = 0).
    let mut a = env.withdraw_auth(&vault, 1, &dest, 10_000_000);
    a.fee_lamports = 70_000;
    let auth = a.encode().unwrap();
    let sig = key.sign(&auth);
    let before = env.balance(&relayer.pubkey());
    env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &auth, &sig)
        .expect("ok");
    let after = env.balance(&relayer.pubkey());
    assert!(
        after > before,
        "relayer was reimbursed more than the network fee"
    );

    // A relayer cannot raise the fee: changing fee_lamports invalidates the signature.
    let mut a = env.withdraw_auth(&vault, 2, &dest, 10_000_000);
    a.fee_lamports = 70_000;
    let sig = key.sign(&a.encode().unwrap());
    a.fee_lamports = 700_000;
    let r = env.execute_v1(
        &relayer,
        &vault,
        &key_acct,
        &[w(&dest)],
        &a.encode().unwrap(),
        &sig,
    );
    assert_vault_error(&r, VaultError::InvalidSignature);
}

#[test]
fn key_rotation() {
    let mut env = Env::new();
    let old = PqKey::from_seed(10);
    let new = PqKey::from_seed(11);
    let (vault, old_acct) = env.create_vault(&old, [4u8; 32]);
    env.deposit(&vault, LAMPORTS_PER_SOL);
    let relayer = env.relayer.insecure_clone();
    let wallet = env.wallet.insecure_clone();
    let new_acct = env.setup_key(&wallet, &vault, &new);

    let rot = Authorization {
        action: Action::RotateKey,
        new_key_id: new.key_id,
        new_algorithm: 1,
        ..env.auth(&vault, 0)
    }
    .encode()
    .unwrap();
    let wallet_before = env.balance(&wallet.pubkey());
    let meta = env
        .execute_v1(
            &relayer,
            &vault,
            &old_acct,
            &[w(&new_acct), w(&wallet.pubkey())],
            &rot,
            &old.sign(&rot),
        )
        .expect("rotate");
    eprintln!("rotate_key CU: {}", meta.compute_units_consumed);
    let v = env.vault_state(&vault);
    assert_eq!(v.key_id, new.key_id);
    assert_eq!(v.key_account, new_acct.to_bytes());
    assert_eq!(v.nonce, 1);
    // Old key account closed, rent refunded to its creator.
    assert_eq!(env.balance(&old_acct), 0);
    assert!(env.balance(&wallet.pubkey()) > wallet_before);

    let dest = Pubkey::new_unique();
    // Old key => invalid (even with the right nonce and the old key account gone).
    let a = env
        .withdraw_auth(&vault, 1, &dest, 1_000_000)
        .encode()
        .unwrap();
    let r = env.execute_v1(&relayer, &vault, &new_acct, &[w(&dest)], &a, &old.sign(&a));
    assert_vault_error(&r, VaultError::InvalidSignature);
    let r = env.execute_v1(&relayer, &vault, &old_acct, &[w(&dest)], &a, &old.sign(&a));
    assert!(r.is_err());
    // New key => valid.
    env.execute_v1(&relayer, &vault, &new_acct, &[w(&dest)], &a, &new.sign(&a))
        .expect("new key works");
    assert_eq!(env.vault_state(&vault).nonce, 2);
    // Withdraw again after rotation.
    let a = env
        .withdraw_auth(&vault, 2, &dest, 1_000_000)
        .encode()
        .unwrap();
    env.execute_v1(&relayer, &vault, &new_acct, &[w(&dest)], &a, &new.sign(&a))
        .expect("again");
    assert_eq!(env.balance(&dest), 2_000_000);
}

#[test]
fn pause_and_unpause() {
    let mut env = Env::new();
    let key = PqKey::from_seed(20);
    let (vault, key_acct) = env.create_vault(&key, [5u8; 32]);
    env.deposit(&vault, LAMPORTS_PER_SOL);
    let relayer = env.relayer.insecure_clone();
    let dest = Pubkey::new_unique();

    let p = env.auth(&vault, 0).encode().unwrap();
    env.execute_v1(&relayer, &vault, &key_acct, &[], &p, &key.sign(&p))
        .expect("pause");
    assert_eq!(env.vault_state(&vault).status, VaultStatus::Paused);

    let a = env
        .withdraw_auth(&vault, 1, &dest, 1_000_000)
        .encode()
        .unwrap();
    let r = env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &a, &key.sign(&a));
    assert_vault_error(&r, VaultError::ActionNotPermitted);
    let p2 = env.auth(&vault, 1).encode().unwrap();
    let r = env.execute_v1(&relayer, &vault, &key_acct, &[], &p2, &key.sign(&p2));
    assert_vault_error(&r, VaultError::ActionNotPermitted);

    let u = Authorization {
        action: Action::Unpause,
        ..env.auth(&vault, 1)
    }
    .encode()
    .unwrap();
    env.execute_v1(&relayer, &vault, &key_acct, &[], &u, &key.sign(&u))
        .expect("unpause");
    assert_eq!(env.vault_state(&vault).status, VaultStatus::Active);
    let a = env
        .withdraw_auth(&vault, 2, &dest, 1_000_000)
        .encode()
        .unwrap();
    env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &a, &key.sign(&a))
        .expect("withdraw after unpause");
}

#[test]
fn close_vault_is_final() {
    let mut env = Env::new();
    let key = PqKey::from_seed(30);
    let seed = [6u8; 32];
    let (vault, key_acct) = env.create_vault(&key, seed);
    env.deposit(&vault, LAMPORTS_PER_SOL);
    let relayer = env.relayer.insecure_clone();
    let wallet = env.wallet.insecure_clone();
    let dest = Pubkey::new_unique();
    let c = Authorization {
        action: Action::CloseVault,
        asset_type: AssetType::Sol,
        destination: dest.to_bytes(),
        ..env.auth(&vault, 0)
    }
    .encode()
    .unwrap();
    env.execute_v1(
        &relayer,
        &vault,
        &key_acct,
        &[w(&dest), w(&wallet.pubkey())],
        &c,
        &key.sign(&c),
    )
    .expect("close");
    assert_eq!(env.balance(&dest), LAMPORTS_PER_SOL);
    assert_eq!(env.vault_state(&vault).status, VaultStatus::Closed);
    assert_eq!(env.balance(&key_acct), 0);
    // Tombstone: cannot be re-initialized, deposits rejected.
    let key_acct2 = env.setup_key(&wallet, &vault, &key);
    let ix = build::initialize_vault(&env.program, &wallet.pubkey(), &vault, &key_acct2, &seed);
    assert!(env.legacy(&[ix], &wallet, &[]).is_err());
    let ix = build::deposit_sol(&env.program, &wallet.pubkey(), &vault, 1);
    assert_vault_error(
        &env.legacy(&[ix], &wallet, &[]),
        VaultError::ActionNotPermitted,
    );
}

#[test]
fn expiry_and_valid_after_use_clock_unix_timestamp() {
    let mut env = Env::new();
    let key = PqKey::from_seed(40);
    let (vault, key_acct) = env.create_vault(&key, [9u8; 32]);
    env.deposit(&vault, LAMPORTS_PER_SOL);
    let relayer = env.relayer.insecure_clone();
    let dest = Pubkey::new_unique();
    let mut a = env.withdraw_auth(&vault, 0, &dest, 1_000_000);
    a.valid_after = NOW + 100;
    a.expires_at = NOW + 200;
    let b = a.encode().unwrap();
    let s = key.sign(&b);
    let r = env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &b, &s);
    assert_vault_error(&r, VaultError::NotYetValid);
    env.set_time(NOW + 200);
    let r = env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &b, &s);
    assert_vault_error(&r, VaultError::Expired);
    env.set_time(NOW + 199);
    env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &b, &s)
        .expect("inside window");
    // No expiry at all (expires_at = 0) is allowed by QSP-1.
    let mut a = env.withdraw_auth(&vault, 1, &dest, 1_000_000);
    a.expires_at = 0;
    let b = a.encode().unwrap();
    env.set_time(i64::MAX / 2);
    env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &b, &key.sign(&b))
        .expect("no expiry");
}

#[test]
fn cannot_withdraw_below_rent_or_more_than_balance() {
    let mut env = Env::new();
    let key = PqKey::from_seed(50);
    let (vault, key_acct) = env.create_vault(&key, [10u8; 32]);
    env.deposit(&vault, 10_000_000);
    let relayer = env.relayer.insecure_clone();
    let dest = Pubkey::new_unique();
    let a = env
        .withdraw_auth(&vault, 0, &dest, 10_000_001)
        .encode()
        .unwrap();
    let r = env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &a, &key.sign(&a));
    assert_vault_error(&r, VaultError::InsufficientFunds);
    let mut a = env.withdraw_auth(&vault, 0, &dest, 10_000_000);
    a.fee_lamports = 1;
    let a = a.encode().unwrap();
    let r = env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &a, &key.sign(&a));
    assert_vault_error(&r, VaultError::InsufficientFunds);
    let a = env
        .withdraw_auth(&vault, 0, &dest, 10_000_000)
        .encode()
        .unwrap();
    env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &a, &key.sign(&a))
        .expect("exact balance");
    assert_eq!(env.vault_state(&vault).nonce, 1);
    assert!(env.balance(&vault) > 0, "rent reserve stays");
}

#[test]
fn unused_authorization_fields_must_be_zero() {
    // Sanity: the program relies on QSP-1 canonical decoding.
    let env = Env::new();
    let mut a = env.auth(&Keypair::new().pubkey(), 0);
    a.amount = 5;
    assert!(a.encode().is_err());
    a.amount = 0;
    a.destination = [1; 32];
    assert!(a.encode().is_err());
    a.destination = ZERO32;
    assert!(a.encode().is_ok());
}
