//! SPL Token / Token-2022 deposits and withdrawals (Phase 3, ADR-0015), run
//! against the real SPL Token and Token-2022 programs that LiteSVM loads.

// LiteSVM's FailedTransactionMetadata is large; boxing it in tests buys nothing.
#![allow(clippy::result_large_err)]

mod common;

use common::*;
use qshield_protocol::{Action, AssetType, Authorization};
use qshield_vault::error::VaultError;
use qshield_vault::instruction::build;
use qshield_vault::token::{self, ext, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

const DECIMALS: u8 = 6;

/// A Token-2022 mint extension to initialize before `InitializeMint2`:
/// (extension type, value length, initialization instruction data).
type MintExt = (u16, usize, Vec<u8>);

fn ext_close_authority(a: &Pubkey) -> MintExt {
    let mut d = vec![25, 1];
    d.extend_from_slice(a.as_ref());
    (ext::MINT_CLOSE_AUTHORITY, 32, d)
}
fn ext_metadata_pointer(a: &Pubkey, m: &Pubkey) -> MintExt {
    let mut d = vec![39, 0];
    d.extend_from_slice(a.as_ref());
    d.extend_from_slice(m.as_ref());
    (ext::METADATA_POINTER, 64, d)
}
fn ext_permanent_delegate(a: &Pubkey) -> MintExt {
    let mut d = vec![35];
    d.extend_from_slice(a.as_ref());
    (ext::PERMANENT_DELEGATE, 32, d)
}
fn ext_transfer_fee(a: &Pubkey) -> MintExt {
    let mut d = vec![26, 0, 1];
    d.extend_from_slice(a.as_ref());
    d.push(1);
    d.extend_from_slice(a.as_ref());
    d.extend_from_slice(&100u16.to_le_bytes());
    d.extend_from_slice(&1_000_000u64.to_le_bytes());
    (ext::TRANSFER_FEE_CONFIG, 108, d)
}
fn ext_transfer_hook(a: &Pubkey, program: &Pubkey) -> MintExt {
    let mut d = vec![36, 0];
    d.extend_from_slice(a.as_ref());
    d.extend_from_slice(program.as_ref());
    (ext::TRANSFER_HOOK, 64, d)
}
fn ext_non_transferable() -> MintExt {
    (ext::NON_TRANSFERABLE, 0, vec![32])
}

struct Spl {
    env: Env,
    key: PqKey,
    vault: Pubkey,
    key_acct: Pubkey,
    relayer: Keypair,
    /// Mint authority (and freeze authority).
    issuer: Keypair,
}

impl Spl {
    fn new(seed: u64) -> Self {
        let mut env = Env::new();
        let key = PqKey::from_seed(seed);
        let (vault, key_acct) = env.create_vault(&key, [seed as u8; 32]);
        env.deposit(&vault, LAMPORTS_PER_SOL);
        let relayer = env.relayer.insecure_clone();
        let issuer = Keypair::new();
        env.svm
            .airdrop(&issuer.pubkey(), 10 * LAMPORTS_PER_SOL)
            .unwrap();
        Self {
            env,
            key,
            vault,
            key_acct,
            relayer,
            issuer,
        }
    }

    /// Creates a mint (with a freeze authority) under `program`.
    fn mint(&mut self, program: &Pubkey, exts: &[MintExt]) -> Pubkey {
        let mint = Keypair::new();
        let space = if exts.is_empty() {
            token::MINT_LEN
        } else {
            token::ACCOUNT_LEN + 1 + exts.iter().map(|e| 4 + e.1).sum::<usize>()
        };
        let rent = self.env.svm.minimum_balance_for_rent_exemption(space);
        let issuer = self.issuer.insecure_clone();
        let mut ixs = vec![solana_system_interface::instruction::create_account(
            &issuer.pubkey(),
            &mint.pubkey(),
            rent,
            space as u64,
            program,
        )];
        for e in exts {
            ixs.push(Instruction::new_with_bytes(
                *program,
                &e.2,
                vec![AccountMeta::new(mint.pubkey(), false)],
            ));
        }
        let mut d = vec![20, DECIMALS];
        d.extend_from_slice(issuer.pubkey().as_ref());
        d.push(1);
        d.extend_from_slice(issuer.pubkey().as_ref());
        ixs.push(Instruction::new_with_bytes(
            *program,
            &d,
            vec![AccountMeta::new(mint.pubkey(), false)],
        ));
        self.env
            .legacy(&ixs, &issuer, &[&mint])
            .expect("create mint");
        mint.pubkey()
    }

    /// Creates (idempotently) the associated token account of `owner`.
    fn ata(&mut self, owner: &Pubkey, mint: &Pubkey, program: &Pubkey) -> Pubkey {
        let issuer = self.issuer.insecure_clone();
        let ix = build::create_ata_idempotent(&issuer.pubkey(), owner, mint, program);
        self.env.legacy(&[ix], &issuer, &[]).expect("create ata");
        token::associated_token_address(owner, mint, program)
    }

    fn mint_to(&mut self, program: &Pubkey, mint: &Pubkey, dest: &Pubkey, amount: u64) {
        let issuer = self.issuer.insecure_clone();
        let mut d = vec![14];
        d.extend_from_slice(&amount.to_le_bytes());
        d.push(DECIMALS);
        let ix = Instruction::new_with_bytes(
            *program,
            &d,
            vec![
                AccountMeta::new(*mint, false),
                AccountMeta::new(*dest, false),
                AccountMeta::new_readonly(issuer.pubkey(), true),
            ],
        );
        self.env.legacy(&[ix], &issuer, &[]).expect("mint to");
    }

    fn freeze(&mut self, program: &Pubkey, mint: &Pubkey, acct: &Pubkey) {
        let issuer = self.issuer.insecure_clone();
        let ix = Instruction::new_with_bytes(
            *program,
            &[10],
            vec![
                AccountMeta::new(*acct, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new_readonly(issuer.pubkey(), true),
            ],
        );
        self.env.legacy(&[ix], &issuer, &[]).expect("freeze");
    }

    fn token_balance(&self, program: &Pubkey, acct: &Pubkey) -> u64 {
        let a = self.env.svm.get_account(acct).unwrap();
        token::parse_token_account(program, &a.data).unwrap().amount
    }

    /// Deposits through the program from the wallet's ATA.
    fn deposit(
        &mut self,
        program: &Pubkey,
        mint: &Pubkey,
        vault_ta: &Pubkey,
        amount: u64,
        decimals: u8,
    ) -> TxResult {
        let wallet = self.env.wallet.insecure_clone();
        let src = token::associated_token_address(&wallet.pubkey(), mint, program);
        let ix = build::deposit_spl(
            &self.env.program,
            &wallet.pubkey(),
            &src,
            mint,
            vault_ta,
            &self.vault,
            program,
            amount,
            decimals,
        );
        self.env.legacy(&[ix], &wallet, &[])
    }

    /// Funds the wallet with tokens and deposits `amount` into the vault's ATA.
    fn fund_vault(&mut self, program: &Pubkey, mint: &Pubkey, amount: u64) -> Pubkey {
        let wallet = self.env.wallet.pubkey();
        let src = self.ata(&wallet, mint, program);
        self.mint_to(program, mint, &src, amount);
        let vault = self.vault;
        let vault_ta = self.ata(&vault, mint, program);
        self.deposit(program, mint, &vault_ta, amount, DECIMALS)
            .expect("deposit spl");
        vault_ta
    }

    fn withdraw_auth(
        &self,
        program: &Pubkey,
        nonce: u64,
        mint: &Pubkey,
        dest: &Pubkey,
        amount: u64,
    ) -> Authorization {
        Authorization {
            action: Action::WithdrawSpl,
            asset_type: token::asset_for(program).unwrap(),
            mint: mint.to_bytes(),
            destination: dest.to_bytes(),
            amount,
            decimals: DECIMALS,
            ..self.env.auth(&self.vault, nonce)
        }
    }

    fn sign(&self, a: &Authorization) -> (Vec<u8>, Vec<u8>) {
        let b = a.encode().unwrap().to_vec();
        let s = self.key.sign(&b);
        (b, s)
    }

    fn exec(&mut self, accts: &[AccountMeta], a: &[u8], s: &[u8]) -> TxResult {
        let (vault, key_acct) = (self.vault, self.key_acct);
        let relayer = self.relayer.insecure_clone();
        self.env
            .execute_v1(&relayer, &vault, &key_acct, accts, a, s)
    }

    fn nonce(&self) -> u64 {
        self.env.vault_state(&self.vault).nonce
    }
}

fn accts(
    source: &Pubkey,
    mint: &Pubkey,
    dest: &Pubkey,
    program: &Pubkey,
    fee: Option<&Pubkey>,
) -> Vec<AccountMeta> {
    build::withdraw_spl_accounts(source, mint, dest, program, fee)
}

#[test]
fn spl_token_deposit_and_withdraw_inline_and_buffered() {
    let p = TOKEN_PROGRAM;
    let mut t = Spl::new(300);
    let mint = t.mint(&p, &[]);
    let vault_ta = t.fund_vault(&p, &mint, 1_000_000);
    assert_eq!(t.token_balance(&p, &vault_ta), 1_000_000);

    let recipient = Pubkey::new_unique();
    let dest = t.ata(&recipient, &mint, &p);
    let fee_to = Pubkey::new_unique();
    t.env.svm.airdrop(&fee_to, LAMPORTS_PER_SOL).unwrap();
    let vault_sol = t.env.balance(&t.vault);

    // Inline (v1 transaction), with a signed SOL fee to an explicit recipient.
    let a = Authorization {
        fee_recipient: fee_to.to_bytes(),
        fee_lamports: 5_000,
        ..t.withdraw_auth(&p, 0, &mint, &dest, 250_000)
    };
    let (a, s) = t.sign(&a);
    let m = t
        .exec(&accts(&vault_ta, &mint, &dest, &p, Some(&fee_to)), &a, &s)
        .unwrap();
    println!("withdraw_spl inline CU: {}", m.compute_units_consumed);
    assert_eq!(t.token_balance(&p, &dest), 250_000);
    assert_eq!(t.token_balance(&p, &vault_ta), 750_000);
    assert_eq!(t.env.balance(&t.vault), vault_sol - 5_000);
    assert_eq!(t.env.balance(&fee_to), LAMPORTS_PER_SOL + 5_000);
    assert_eq!(t.nonce(), 1);

    // Buffered (legacy transactions), fee to the fee payer.
    let (a, s) = t.sign(&t.withdraw_auth(&p, 1, &mint, &dest, 750_000));
    let (vault, key_acct, relayer) = (t.vault, t.key_acct, t.relayer.insecure_clone());
    let m = t
        .env
        .execute_buffered(
            &relayer,
            &vault,
            &key_acct,
            &accts(&vault_ta, &mint, &dest, &p, None),
            &a,
            &s,
            1,
        )
        .unwrap();
    println!("withdraw_spl buffered CU: {}", m.compute_units_consumed);
    assert_eq!(t.token_balance(&p, &dest), 1_000_000);
    assert_eq!(t.token_balance(&p, &vault_ta), 0);
    assert_eq!(t.nonce(), 2);
}

#[test]
fn token_2022_with_allowed_extensions() {
    let p = TOKEN_2022_PROGRAM;
    let mut t = Spl::new(301);
    let auth = t.issuer.pubkey();
    let mint = t.mint(
        &p,
        &[
            ext_close_authority(&auth),
            ext_metadata_pointer(&auth, &Pubkey::new_unique()),
        ],
    );
    let vault_ta = t.fund_vault(&p, &mint, 500);
    let dest = t.ata(&Pubkey::new_unique(), &mint, &p);
    let (a, s) = t.sign(&t.withdraw_auth(&p, 0, &mint, &dest, 200));
    let m = t
        .exec(&accts(&vault_ta, &mint, &dest, &p, None), &a, &s)
        .unwrap();
    println!(
        "withdraw_spl Token-2022 inline CU: {}",
        m.compute_units_consumed
    );
    assert_eq!(t.token_balance(&p, &dest), 200);
    assert_eq!(t.token_balance(&p, &vault_ta), 300);

    // A plain Token-2022 mint without extensions also works.
    let plain = t.mint(&p, &[]);
    let vault_ta2 = t.fund_vault(&p, &plain, 10);
    let dest2 = t.ata(&Pubkey::new_unique(), &plain, &p);
    let (a, s) = t.sign(&t.withdraw_auth(&p, 1, &plain, &dest2, 10));
    t.exec(&accts(&vault_ta2, &plain, &dest2, &p, None), &a, &s)
        .unwrap();
    assert_eq!(t.token_balance(&p, &dest2), 10);
}

#[test]
fn token_2022_unsupported_extensions_fail_closed() {
    let p = TOKEN_2022_PROGRAM;
    let mut t = Spl::new(302);
    let auth = t.issuer.pubkey();
    let cases: Vec<(&str, MintExt)> = vec![
        ("permanent delegate", ext_permanent_delegate(&auth)),
        ("transfer fee", ext_transfer_fee(&auth)),
        (
            "transfer hook",
            ext_transfer_hook(&auth, &Pubkey::new_unique()),
        ),
        ("non-transferable", ext_non_transferable()),
    ];
    for (name, e) in cases {
        let mint = t.mint(&p, &[e]);
        // Tokens arrive in a vault-owned account without the program (direct mint).
        let vault = t.vault;
        let vault_ta = t.ata(&vault, &mint, &p);
        t.mint_to(&p, &mint, &vault_ta, 100);
        // DepositSpl refuses the mint.
        let wallet = t.env.wallet.pubkey();
        let src = t.ata(&wallet, &mint, &p);
        t.mint_to(&p, &mint, &src, 100);
        assert_vault_error(
            &t.deposit(&p, &mint, &vault_ta, 10, DECIMALS),
            VaultError::UnsupportedTokenExtension,
        );
        // A correctly signed withdrawal is refused and changes nothing.
        let dest = t.ata(&Pubkey::new_unique(), &mint, &p);
        let n = t.nonce();
        let (a, s) = t.sign(&t.withdraw_auth(&p, n, &mint, &dest, 10));
        let r = t.exec(&accts(&vault_ta, &mint, &dest, &p, None), &a, &s);
        assert_vault_error(&r, VaultError::UnsupportedTokenExtension);
        assert_eq!(t.token_balance(&p, &vault_ta), 100, "{name}");
        assert_eq!(t.nonce(), n, "{name}");
    }
}

#[test]
fn withdraw_spl_account_substitution() {
    let p = TOKEN_PROGRAM;
    let mut t = Spl::new(303);
    let mint = t.mint(&p, &[]);
    let other_mint = t.mint(&p, &[]);
    let vault_ta = t.fund_vault(&p, &mint, 1_000);
    let other_vault_ta = t.fund_vault(&p, &other_mint, 1_000);
    let dest = t.ata(&Pubkey::new_unique(), &mint, &p);
    let attacker = Keypair::new();
    let attacker_ta = t.ata(&attacker.pubkey(), &mint, &p);
    let wallet = t.env.wallet.pubkey();
    let wallet_ta = token::associated_token_address(&wallet, &mint, &p);
    t.mint_to(&p, &mint, &wallet_ta, 1_000);
    let (a, s) = t.sign(&t.withdraw_auth(&p, 0, &mint, &dest, 100));

    let cases: Vec<(&str, Vec<AccountMeta>, VaultError)> = vec![
        (
            "destination substituted",
            accts(&vault_ta, &mint, &attacker_ta, &p, None),
            VaultError::AccountMismatch,
        ),
        (
            "mint substituted",
            accts(&other_vault_ta, &other_mint, &dest, &p, None),
            VaultError::AccountMismatch,
        ),
        (
            "token program swapped for Token-2022",
            accts(&vault_ta, &mint, &dest, &TOKEN_2022_PROGRAM, None),
            VaultError::InvalidTokenProgram,
        ),
        (
            "arbitrary program as token program",
            accts(&vault_ta, &mint, &dest, &Pubkey::new_unique(), None),
            VaultError::InvalidTokenProgram,
        ),
        (
            "source not owned by the vault",
            accts(&wallet_ta, &mint, &dest, &p, None),
            VaultError::InvalidTokenAccount,
        ),
        (
            "source of another mint",
            accts(&other_vault_ta, &mint, &dest, &p, None),
            VaultError::InvalidTokenAccount,
        ),
        (
            "source equals destination",
            accts(&dest, &mint, &dest, &p, None),
            VaultError::AccountMismatch,
        ),
        (
            "destination read-only",
            vec![
                w(&vault_ta),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(dest, false),
                AccountMeta::new_readonly(p, false),
            ],
            VaultError::NotWritable,
        ),
        (
            "missing token program",
            vec![
                w(&vault_ta),
                AccountMeta::new_readonly(mint, false),
                w(&dest),
            ],
            VaultError::MissingAccount,
        ),
    ];
    for (name, acc, err) in cases {
        let r = t.exec(&acc, &a, &s);
        assert!(r.is_err(), "{name} accepted");
        assert_eq!(custom_error(&r), Some(err as u32), "{name}: {:?}", r.err());
    }

    // A forged token account (same bytes, not owned by the token program).
    let mut fake = t.env.svm.get_account(&vault_ta).unwrap();
    fake.owner = Pubkey::new_unique();
    let fake_addr = Pubkey::new_unique();
    t.env.put_account(fake_addr, fake);
    assert_vault_error(
        &t.exec(&accts(&fake_addr, &mint, &dest, &p, None), &a, &s),
        VaultError::InvalidTokenAccount,
    );
    // A forged destination not owned by the token program.
    let mut fake = t.env.svm.get_account(&dest).unwrap();
    fake.owner = Pubkey::new_unique();
    t.env.put_account(dest, fake.clone());
    assert_vault_error(
        &t.exec(&accts(&vault_ta, &mint, &dest, &p, None), &a, &s),
        VaultError::InvalidTokenAccount,
    );
    fake.owner = p;
    t.env.put_account(dest, fake);

    assert_eq!(t.token_balance(&p, &vault_ta), 1_000);
    assert_eq!(t.nonce(), 0);

    // Fee recipient substitution.
    let fee_to = Pubkey::new_unique();
    let fa = Authorization {
        fee_recipient: fee_to.to_bytes(),
        fee_lamports: 1_000,
        ..t.withdraw_auth(&p, 0, &mint, &dest, 100)
    };
    let (fa, fs) = t.sign(&fa);
    let thief = Pubkey::new_unique();
    assert_vault_error(
        &t.exec(&accts(&vault_ta, &mint, &dest, &p, Some(&thief)), &fa, &fs),
        VaultError::AccountMismatch,
    );

    // The attacker's Ed25519 key cannot move the vault's tokens directly.
    let mut d = vec![12];
    d.extend_from_slice(&100u64.to_le_bytes());
    d.push(DECIMALS);
    let steal = Instruction::new_with_bytes(
        p,
        &d,
        vec![
            w(&vault_ta),
            AccountMeta::new_readonly(mint, false),
            w(&attacker_ta),
            AccountMeta::new_readonly(attacker.pubkey(), true),
        ],
    );
    t.env
        .svm
        .airdrop(&attacker.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    assert!(t.env.legacy(&[steal], &attacker, &[]).is_err());

    // The original authorization still works with the right accounts.
    t.exec(&accts(&vault_ta, &mint, &dest, &p, None), &a, &s)
        .unwrap();
    assert_eq!(t.token_balance(&p, &dest), 100);
    assert_eq!(t.token_balance(&p, &attacker_ta), 0);
}

#[test]
fn withdraw_spl_field_checks() {
    let p = TOKEN_PROGRAM;
    let mut t = Spl::new(304);
    let mint = t.mint(&p, &[]);
    let vault_ta = t.fund_vault(&p, &mint, 1_000);
    let dest = t.ata(&Pubkey::new_unique(), &mint, &p);
    let ok = accts(&vault_ta, &mint, &dest, &p, None);

    // Decimals signed differently from the mint.
    let a = Authorization {
        decimals: 9,
        ..t.withdraw_auth(&p, 0, &mint, &dest, 100)
    };
    let (a, s) = t.sign(&a);
    assert_vault_error(&t.exec(&ok, &a, &s), VaultError::DecimalsMismatch);

    // Asset type says Token-2022 but the mint is an SPL Token mint.
    let a = Authorization {
        asset_type: AssetType::Token2022,
        ..t.withdraw_auth(&p, 0, &mint, &dest, 100)
    };
    let (a, s) = t.sign(&a);
    assert_vault_error(&t.exec(&ok, &a, &s), VaultError::InvalidTokenProgram);
    let tok22 = accts(&vault_ta, &mint, &dest, &TOKEN_2022_PROGRAM, None);
    assert_vault_error(&t.exec(&tok22, &a, &s), VaultError::InvalidMint);

    // More than the source holds.
    let (a, s) = t.sign(&t.withdraw_auth(&p, 0, &mint, &dest, 1_001));
    assert_vault_error(&t.exec(&ok, &a, &s), VaultError::InsufficientFunds);

    // Fee larger than the vault's spendable SOL.
    let a = Authorization {
        fee_lamports: 2 * LAMPORTS_PER_SOL,
        ..t.withdraw_auth(&p, 0, &mint, &dest, 100)
    };
    let (a, s) = t.sign(&a);
    assert_vault_error(&t.exec(&ok, &a, &s), VaultError::InsufficientFunds);

    // Frozen vault token account.
    t.freeze(&p, &mint, &vault_ta);
    let (a, s) = t.sign(&t.withdraw_auth(&p, 0, &mint, &dest, 100));
    assert_vault_error(&t.exec(&ok, &a, &s), VaultError::InvalidTokenAccount);

    assert_eq!(t.token_balance(&p, &vault_ta), 1_000);
    assert_eq!(t.nonce(), 0);
}

#[test]
fn any_vault_owned_token_account_can_be_the_source() {
    // The source account is not signed: any token account of the mint whose
    // authority is the vault may be debited. The signed effect is unchanged.
    let p = TOKEN_PROGRAM;
    let mut t = Spl::new(305);
    let mint = t.mint(&p, &[]);
    let vault_ata = t.fund_vault(&p, &mint, 100);
    // A second, non-associated token account owned by the vault.
    let second = Keypair::new();
    let rent = t
        .env
        .svm
        .minimum_balance_for_rent_exemption(token::ACCOUNT_LEN);
    let issuer = t.issuer.insecure_clone();
    let mut d = vec![18];
    d.extend_from_slice(t.vault.as_ref());
    let ixs = [
        solana_system_interface::instruction::create_account(
            &issuer.pubkey(),
            &second.pubkey(),
            rent,
            token::ACCOUNT_LEN as u64,
            &p,
        ),
        Instruction::new_with_bytes(
            p,
            &d,
            vec![w(&second.pubkey()), AccountMeta::new_readonly(mint, false)],
        ),
    ];
    t.env.legacy(&ixs, &issuer, &[&second]).unwrap();
    t.mint_to(&p, &mint, &second.pubkey(), 50);

    let dest = t.ata(&Pubkey::new_unique(), &mint, &p);
    let (a, s) = t.sign(&t.withdraw_auth(&p, 0, &mint, &dest, 40));
    t.exec(&accts(&second.pubkey(), &mint, &dest, &p, None), &a, &s)
        .unwrap();
    assert_eq!(t.token_balance(&p, &second.pubkey()), 10);
    assert_eq!(t.token_balance(&p, &vault_ata), 100);
    assert_eq!(t.token_balance(&p, &dest), 40);
}

#[test]
fn deposit_spl_checks() {
    let p = TOKEN_PROGRAM;
    let mut t = Spl::new(306);
    let mint = t.mint(&p, &[]);
    let wallet = t.env.wallet.pubkey();
    let src = t.ata(&wallet, &mint, &p);
    t.mint_to(&p, &mint, &src, 1_000);
    let vault = t.vault;
    let vault_ta = t.ata(&vault, &mint, &p);

    // Destination owned by someone else than the vault.
    let other = t.ata(&Pubkey::new_unique(), &mint, &p);
    assert_vault_error(
        &t.deposit(&p, &mint, &other, 10, DECIMALS),
        VaultError::InvalidTokenAccount,
    );
    // Wrong decimals.
    assert_vault_error(
        &t.deposit(&p, &mint, &vault_ta, 10, DECIMALS + 1),
        VaultError::DecimalsMismatch,
    );
    // Zero amount.
    assert_vault_error(
        &t.deposit(&p, &mint, &vault_ta, 0, DECIMALS),
        VaultError::ZeroAmount,
    );
    // A token account owned by a fake vault (not a program account).
    let fake_vault = Pubkey::new_unique();
    let fake_ta = t.ata(&fake_vault, &mint, &p);
    let wallet_kp = t.env.wallet.insecure_clone();
    let ix = build::deposit_spl(
        &t.env.program,
        &wallet,
        &src,
        &mint,
        &fake_ta,
        &fake_vault,
        &p,
        10,
        DECIMALS,
    );
    assert_vault_error(
        &t.env.legacy(&[ix], &wallet_kp, &[]),
        VaultError::InvalidAccount,
    );

    t.deposit(&p, &mint, &vault_ta, 10, DECIMALS).unwrap();
    assert_eq!(t.token_balance(&p, &vault_ta), 10);

    // Deposits into a closed vault are refused.
    let a = Authorization {
        action: Action::CloseVault,
        asset_type: AssetType::Sol,
        destination: wallet.to_bytes(),
        ..t.env.auth(&vault, 0)
    };
    let (a, s) = t.sign(&a);
    let key_creator = wallet;
    t.exec(&[w(&wallet), w(&key_creator)], &a, &s).unwrap();
    assert_vault_error(
        &t.deposit(&p, &mint, &vault_ta, 10, DECIMALS),
        VaultError::ActionNotPermitted,
    );
}

#[test]
fn withdraw_spl_while_paused_is_refused() {
    let p = TOKEN_2022_PROGRAM;
    let mut t = Spl::new(307);
    let mint = t.mint(&p, &[]);
    let vault_ta = t.fund_vault(&p, &mint, 100);
    let dest = t.ata(&Pubkey::new_unique(), &mint, &p);
    let (a, s) = t.sign(&t.env.auth(&t.vault, 0));
    t.exec(&[], &a, &s).unwrap();
    let (a, s) = t.sign(&t.withdraw_auth(&p, 1, &mint, &dest, 10));
    assert_vault_error(
        &t.exec(&accts(&vault_ta, &mint, &dest, &p, None), &a, &s),
        VaultError::ActionNotPermitted,
    );
    // Deposits are still accepted while paused.
    let wallet = t.env.wallet.pubkey();
    let src = token::associated_token_address(&wallet, &mint, &p);
    t.mint_to(&p, &mint, &src, 5);
    t.deposit(&p, &mint, &vault_ta, 5, DECIMALS).unwrap();
    assert_eq!(t.token_balance(&p, &vault_ta), 105);
}
