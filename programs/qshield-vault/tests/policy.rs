//! Guardian policy (QSP-1 v2, ADR-0018): instant everyday sends within a
//! limit or to saved addresses, guardian approval for everything else, freeze,
//! recovery — and the attacks a stolen everyday key would try.

// LiteSVM's FailedTransactionMetadata is large; boxing it in tests buys nothing.
#![allow(clippy::result_large_err)]

mod common;

use common::*;
use qshield_protocol::v2::{ActionV2, AuthorizationV2, Role};
use qshield_protocol::{cluster, AssetType, Authorization, ZERO32};
use qshield_vault::error::VaultError;
use qshield_vault::instruction::build;
use qshield_vault::state::{KeyHeader, Policy, VaultStatus};
use qshield_vault::token::{self, TOKEN_PROGRAM};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

const LIMIT: u64 = LAMPORTS_PER_SOL;
const DAY: i64 = 86_400;

struct G {
    env: Env,
    hot: PqKey,
    hot_acct: Pubkey,
    guardian: PqKey,
    guardian_acct: Pubkey,
    vault: Pubkey,
    relayer: Keypair,
}

fn ro(k: &Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(*k, false)
}

impl G {
    /// Vault with 10 SOL, guardian policy enabled (1 SOL / day).
    fn new(seed: u64) -> Self {
        let mut env = Env::new();
        let hot = PqKey::from_seed(seed);
        let guardian = PqKey::from_seed(seed + 10_000);
        let (vault, hot_acct) = env.create_vault(&hot, [seed as u8; 32]);
        env.deposit(&vault, 10 * LAMPORTS_PER_SOL);
        let wallet = env.wallet.insecure_clone();
        let guardian_acct = env.setup_key(&wallet, &vault, &guardian);
        let relayer = env.relayer.insecure_clone();
        let mut g = Self {
            env,
            hot,
            hot_acct,
            guardian,
            guardian_acct,
            vault,
            relayer,
        };
        let a = AuthorizationV2 {
            new_key_id: g.guardian.key_id,
            new_algorithm: 1,
            limit_lamports: LIMIT,
            limit_period: DAY,
            ..g.base(ActionV2::EnablePolicy, Role::Everyday, 0)
        };
        let ga = g.guardian_acct;
        g.run(&a, &[w(&ga), ro(&Pubkey::default())])
            .expect("enable policy");
        g
    }

    fn base(&self, action: ActionV2, role: Role, nonce: u64) -> AuthorizationV2 {
        AuthorizationV2 {
            cluster_id: cluster::LOCALNET,
            program_id: self.env.program.to_bytes(),
            vault: self.vault.to_bytes(),
            action,
            asset_type: AssetType::None,
            nonce,
            valid_after: 0,
            expires_at: NOW + 3_600,
            mint: ZERO32,
            destination: ZERO32,
            amount: 0,
            decimals: 0,
            fee_recipient: ZERO32,
            fee_lamports: 0,
            new_key_id: ZERO32,
            new_algorithm: 0,
            role,
            ref_id: 0,
            limit_lamports: 0,
            limit_period: 0,
        }
    }

    fn hot_nonce(&self) -> u64 {
        self.env.vault_state(&self.vault).nonce
    }
    fn policy(&self) -> Policy {
        let (p, _) = build::policy_address(&self.env.program, &self.vault);
        Policy::load(&self.env.svm.get_account(&p).unwrap().data).unwrap()
    }
    fn guardian_nonce(&self) -> u64 {
        self.policy().guardian_nonce
    }

    /// Everyday SOL send.
    fn send(&self, to: &Pubkey, lamports: u64) -> AuthorizationV2 {
        AuthorizationV2 {
            asset_type: AssetType::Sol,
            destination: to.to_bytes(),
            amount: lamports,
            ..self.base(ActionV2::WithdrawSol, Role::Everyday, self.hot_nonce())
        }
    }

    fn guardian_auth(&self, action: ActionV2) -> AuthorizationV2 {
        self.base(action, Role::Guardian, self.guardian_nonce())
    }

    /// Signs with the key of `a.role` and executes with its key account.
    fn run(&mut self, a: &AuthorizationV2, accts: &[AccountMeta]) -> TxResult {
        let (key, acct) = match a.role {
            Role::Everyday => (&self.hot, self.hot_acct),
            Role::Guardian => (&self.guardian, self.guardian_acct),
        };
        let bytes = a.encode().unwrap();
        let sig = key.sign(&bytes);
        self.exec_raw(&bytes, &sig, &acct, accts)
    }

    fn exec_raw(
        &mut self,
        auth: &[u8],
        sig: &[u8],
        key_acct: &Pubkey,
        accts: &[AccountMeta],
    ) -> TxResult {
        let relayer = self.relayer.insecure_clone();
        let ix = build::execute_v2(
            &self.env.program,
            &relayer.pubkey(),
            &self.vault,
            key_acct,
            accts,
            auth,
            sig,
        );
        self.env.v1(&[ix], &relayer, &[])
    }

    fn bal(&self, k: &Pubkey) -> u64 {
        self.env.balance(k)
    }

    fn add_address(&mut self, addr: &Pubkey) {
        let a = AuthorizationV2 {
            destination: addr.to_bytes(),
            ..self.guardian_auth(ActionV2::AddAddress)
        };
        self.run(&a, &[]).expect("add address");
    }

    fn proposal(&self, id: u64) -> Pubkey {
        build::proposal_address(&self.env.program, &self.vault, id).0
    }

    fn propose(&mut self, to: &Pubkey, lamports: u64) -> u64 {
        let id = self.hot_nonce();
        let a = AuthorizationV2 {
            action: ActionV2::ProposeWithdraw,
            ..self.send(to, lamports)
        };
        let p = self.proposal(id);
        self.run(&a, &[w(&p), ro(&Pubkey::default())])
            .expect("propose");
        id
    }

    fn approve_auth(&self, id: u64, to: &Pubkey, lamports: u64) -> AuthorizationV2 {
        AuthorizationV2 {
            asset_type: AssetType::Sol,
            destination: to.to_bytes(),
            amount: lamports,
            ref_id: id,
            ..self.guardian_auth(ActionV2::ApproveWithdraw)
        }
    }

    fn approve(&mut self, id: u64, to: &Pubkey, lamports: u64) -> TxResult {
        let a = self.approve_auth(id, to, lamports);
        let p = self.proposal(id);
        let r = self.relayer.pubkey();
        self.run(&a, &[w(&p), w(&r), w(to)])
    }
}

#[test]
fn everyday_sends_are_instant_within_the_limit_and_to_saved_addresses() {
    let mut g = G::new(400);
    let p = g.policy();
    assert!(p.enabled);
    assert_eq!((p.limit, p.available, p.guardian_nonce), (LIMIT, LIMIT, 0));
    assert_eq!(g.env.vault_state(&g.vault).policy_mode, 1);
    // The guardian key account is marked as guardian and cannot be closed.
    let gh = KeyHeader::load(&g.env.svm.get_account(&g.guardian_acct).unwrap().data).unwrap();
    assert!(gh.in_use && gh.guardian);

    // Within the limit: one transaction, no waiting.
    let stranger = Pubkey::new_unique();
    let a = g.send(&stranger, 600_000_000);
    let m = g.run(&a, &[w(&stranger)]).unwrap();
    println!("everyday send CU: {}", m.compute_units_consumed);
    assert_eq!(g.bal(&stranger), 600_000_000);
    // Beyond the remaining 0.4 SOL: refused, nothing moves.
    let a = g.send(&stranger, 500_000_000);
    assert_vault_error(&g.run(&a, &[w(&stranger)]), VaultError::LimitExceeded);
    assert_eq!(g.hot_nonce(), 2);

    // Saved address: no limit.
    let own = Pubkey::new_unique();
    g.add_address(&own);
    let a = g.send(&own, 5 * LAMPORTS_PER_SOL);
    g.run(&a, &[w(&own)]).unwrap();
    assert_eq!(g.bal(&own), 5 * LAMPORTS_PER_SOL);

    // The allowance refills continuously: half a day later, half the limit.
    g.env.set_time(NOW + DAY / 2);
    let a = AuthorizationV2 {
        expires_at: NOW + DAY,
        ..g.send(&stranger, 900_000_000)
    };
    g.run(&a, &[w(&stranger)]).unwrap();
    let a = AuthorizationV2 {
        expires_at: NOW + DAY,
        ..g.send(&stranger, 1)
    };
    assert_vault_error(&g.run(&a, &[w(&stranger)]), VaultError::LimitExceeded);
}

#[test]
fn stolen_everyday_key_cannot_raise_limits_save_addresses_or_use_fees() {
    let mut g = G::new(401);
    let thief = Pubkey::new_unique();
    // A huge "relayer fee" to the thief counts against the limit.
    let a = AuthorizationV2 {
        fee_lamports: 5 * LAMPORTS_PER_SOL,
        fee_recipient: thief.to_bytes(),
        ..g.send(&thief, 1)
    };
    assert_vault_error(
        &g.run(&a, &[w(&thief), w(&thief)]),
        VaultError::LimitExceeded,
    );
    // Raising the limit or changing the period: guardian only.
    for (lim, per) in [(LIMIT + 1, DAY), (LIMIT, DAY * 2)] {
        let a = AuthorizationV2 {
            limit_lamports: lim,
            limit_period: per,
            ..g.base(ActionV2::SetLimit, Role::Everyday, g.hot_nonce())
        };
        assert_vault_error(&g.run(&a, &[]), VaultError::ActionNotPermitted);
    }
    // Lowering is allowed (tightening never needs the guardian).
    let a = AuthorizationV2 {
        limit_lamports: LIMIT / 10,
        limit_period: DAY,
        ..g.base(ActionV2::SetLimit, Role::Everyday, g.hot_nonce())
    };
    g.run(&a, &[]).unwrap();
    assert_eq!(g.policy().available, LIMIT / 10);

    // Guardian-only actions cannot even be encoded with the everyday role;
    // forged bytes are rejected on-chain.
    let n = g.hot_nonce();
    let forged: Vec<AuthorizationV2> = vec![
        AuthorizationV2 {
            destination: thief.to_bytes(),
            ..g.base(ActionV2::AddAddress, Role::Guardian, n)
        },
        g.base(ActionV2::Unpause, Role::Guardian, n),
        AuthorizationV2 {
            new_key_id: [9; 32],
            new_algorithm: 1,
            ..g.base(ActionV2::RotateKey, Role::Guardian, n)
        },
        AuthorizationV2 {
            new_key_id: [9; 32],
            new_algorithm: 1,
            ..g.base(ActionV2::RotateGuardian, Role::Guardian, n)
        },
        g.base(ActionV2::DisablePolicy, Role::Guardian, n),
        AuthorizationV2 {
            asset_type: AssetType::Sol,
            destination: thief.to_bytes(),
            amount: 1,
            ref_id: 1,
            ..g.base(ActionV2::ApproveWithdraw, Role::Guardian, n)
        },
    ];
    assert_eq!(forged.len(), 6);
    for a in forged {
        let mut bytes = a.encode().expect("valid as guardian").to_vec();
        bytes[qshield_protocol::v2::offsets_v2::ROLE] = Role::Everyday as u8;
        let sig = g.hot.sign(&bytes);
        let hk = g.hot_acct;
        let r = g.exec_raw(&bytes, &sig, &hk, &[w(&thief)]);
        assert_vault_error(&r, VaultError::MalformedAuthorization);
    }
    // A guardian-role message signed by the everyday key, with the everyday
    // key account passed in the signer slot.
    let a = AuthorizationV2 {
        destination: thief.to_bytes(),
        ..g.guardian_auth(ActionV2::AddAddress)
    };
    let bytes = a.encode().unwrap();
    let sig = g.hot.sign(&bytes);
    let (hk, gk) = (g.hot_acct, g.guardian_acct);
    assert_vault_error(
        &g.exec_raw(&bytes, &sig, &hk, &[]),
        VaultError::AccountMismatch,
    );
    assert_vault_error(
        &g.exec_raw(&bytes, &sig, &gk, &[]),
        VaultError::InvalidSignature,
    );
    assert_eq!(g.policy().saved_len, 0);
}

#[test]
fn v1_authorizations_are_refused_once_a_guardian_is_attached() {
    let mut g = G::new(402);
    let dest = Pubkey::new_unique();
    let n = g.hot_nonce();
    for action in [
        qshield_protocol::Action::WithdrawSol,
        qshield_protocol::Action::CloseVault,
    ] {
        let a = Authorization {
            action,
            asset_type: AssetType::Sol,
            destination: dest.to_bytes(),
            amount: if action == qshield_protocol::Action::WithdrawSol {
                1_000_000
            } else {
                0
            },
            ..g.env.auth(&g.vault, n)
        };
        let bytes = a.encode().unwrap();
        let sig = g.hot.sign(&bytes);
        let (vault, hk, relayer) = (g.vault, g.hot_acct, g.relayer.insecure_clone());
        let creator = g.env.wallet.pubkey();
        let r = g.env.execute_v1(
            &relayer,
            &vault,
            &hk,
            &[w(&dest), w(&creator)],
            &bytes,
            &sig,
        );
        assert_vault_error(&r, VaultError::PolicyActive);
    }
    assert_eq!(g.bal(&dest), 0);
}

#[test]
fn large_sends_need_a_guardian_approval_seconds_later() {
    let mut g = G::new(403);
    let dest = Pubkey::new_unique();
    let before = g.bal(&g.relayer.pubkey());
    let id = g.propose(&dest, 3 * LAMPORTS_PER_SOL);
    assert_eq!(g.bal(&dest), 0, "a proposal moves nothing");
    // The guardian must restate the exact effect.
    assert_vault_error(
        &g.approve(id, &dest, 3 * LAMPORTS_PER_SOL + 1),
        VaultError::ProposalMismatch,
    );
    let other = Pubkey::new_unique();
    let a = g.approve_auth(id, &other, 3 * LAMPORTS_PER_SOL);
    let (p, r) = (g.proposal(id), g.relayer.pubkey());
    assert_vault_error(
        &g.run(&a, &[w(&p), w(&r), w(&other)]),
        VaultError::ProposalMismatch,
    );
    // Rent refund only to the original payer.
    let a = g.approve_auth(id, &dest, 3 * LAMPORTS_PER_SOL);
    assert_vault_error(
        &g.run(&a, &[w(&p), w(&other), w(&dest)]),
        VaultError::AccountMismatch,
    );

    let m = g.approve(id, &dest, 3 * LAMPORTS_PER_SOL).unwrap();
    println!("guardian approval CU: {}", m.compute_units_consumed);
    assert_eq!(g.bal(&dest), 3 * LAMPORTS_PER_SOL);
    assert!(g
        .env
        .svm
        .get_account(&g.proposal(id))
        .is_none_or(|a| a.lamports == 0));
    // Five transactions' fees (propose, three rejected approvals, approval);
    // the proposal's rent came back to the relayer that paid it.
    assert_eq!(g.bal(&g.relayer.pubkey()), before - 5 * 5_000);
    // Replays fail: the proposal is gone and the guardian nonce moved.
    assert!(g.approve(id, &dest, 3 * LAMPORTS_PER_SOL).is_err());
    // A guardian approval never touches the everyday limit or nonce lane.
    assert_eq!(g.policy().available, LIMIT);
}

#[test]
fn freeze_and_recovery_after_the_everyday_key_is_stolen() {
    let mut g = G::new(404);
    // A pre-signed guardian freeze stays valid however many nonces the thief burns.
    let freeze = g.guardian_auth(ActionV2::Pause);
    let thief = Pubkey::new_unique();
    for _ in 0..3 {
        let a = g.send(&thief, 100_000_000);
        g.run(&a, &[w(&thief)]).unwrap();
    }
    // The thief also proposes a big send, hoping for a careless approval.
    let id = g.propose(&thief, 5 * LAMPORTS_PER_SOL);
    g.run(&freeze, &[]).unwrap();
    assert_eq!(g.env.vault_state(&g.vault).status, VaultStatus::Paused);
    // Frozen: nothing leaves, the everyday key cannot unfreeze.
    let a = g.send(&thief, 1);
    assert_vault_error(&g.run(&a, &[w(&thief)]), VaultError::ActionNotPermitted);
    assert_vault_error(
        &g.approve(id, &thief, 5 * LAMPORTS_PER_SOL),
        VaultError::ActionNotPermitted,
    );
    // Not even as a "fee" on an action still allowed while frozen.
    let a = AuthorizationV2 {
        limit_lamports: LIMIT,
        limit_period: DAY,
        fee_lamports: 50_000_000,
        fee_recipient: thief.to_bytes(),
        ..g.base(ActionV2::SetLimit, Role::Everyday, g.hot_nonce())
    };
    assert_vault_error(&g.run(&a, &[w(&thief)]), VaultError::ActionNotPermitted);

    // The guardian replaces the everyday key (no delay) and unfreezes.
    let new_hot = PqKey::from_seed(7_404);
    let wallet = g.env.wallet.insecure_clone();
    let vault = g.vault;
    let new_acct = g.env.setup_key(&wallet, &vault, &new_hot);
    let a = AuthorizationV2 {
        new_key_id: new_hot.key_id,
        new_algorithm: 1,
        ..g.guardian_auth(ActionV2::RotateKey)
    };
    let (old, creator) = (g.hot_acct, wallet.pubkey());
    g.run(&a, &[w(&new_acct), w(&old), w(&creator)]).unwrap();
    let a = g.guardian_auth(ActionV2::Unpause);
    g.run(&a, &[]).unwrap();
    assert!(
        g.env.svm.get_account(&old).is_none_or(|a| a.lamports == 0),
        "old key closed"
    );

    // The old key is useless; its proposal is dead and anyone can clean it up.
    let a = g.send(&thief, 1);
    let bytes = a.encode().unwrap();
    let sig = g.hot.sign(&bytes);
    assert!(g.exec_raw(&bytes, &sig, &old, &[w(&thief)]).is_err());
    assert_vault_error(
        &g.approve(id, &thief, 5 * LAMPORTS_PER_SOL),
        VaultError::ProposalStale,
    );
    let p = g.proposal(id);
    let r = g.relayer.pubkey();
    let ix = build::close_proposal(&g.env.program, &g.vault, &p, &r);
    let anyone = Keypair::new();
    g.env
        .svm
        .airdrop(&anyone.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    g.env.legacy(&[ix], &anyone, &[]).unwrap();

    // The thief got at most the limit.
    assert_eq!(g.bal(&thief), 300_000_000);
    g.hot = new_hot;
    g.hot_acct = new_acct;
    let dest = Pubkey::new_unique();
    let a = g.send(&dest, 1_000_000);
    g.run(&a, &[w(&dest)]).unwrap();
    assert_eq!(g.bal(&dest), 1_000_000);
}

#[test]
fn live_proposals_cannot_be_closed_by_others_and_cancel_works() {
    let mut g = G::new(405);
    let dest = Pubkey::new_unique();
    let id = g.propose(&dest, 2 * LAMPORTS_PER_SOL);
    let (p, r) = (g.proposal(id), g.relayer.pubkey());
    let ix = build::close_proposal(&g.env.program, &g.vault, &p, &r);
    let relayer = g.relayer.insecure_clone();
    assert_vault_error(
        &g.env.legacy(&[ix], &relayer, &[]),
        VaultError::ActionNotPermitted,
    );
    let a = AuthorizationV2 {
        ref_id: id,
        ..g.base(ActionV2::CancelProposal, Role::Everyday, g.hot_nonce())
    };
    g.run(&a, &[w(&p), w(&r)]).unwrap();
    assert!(g.approve(id, &dest, 2 * LAMPORTS_PER_SOL).is_err());
    // Expired proposals die on their own.
    let a = AuthorizationV2 {
        action: ActionV2::ProposeWithdraw,
        expires_at: NOW + 60,
        ..g.send(&dest, 2 * LAMPORTS_PER_SOL)
    };
    let id = g.hot_nonce();
    let p = g.proposal(id);
    g.run(&a, &[w(&p), ro(&Pubkey::default())]).unwrap();
    g.env.set_time(NOW + 61);
    assert_vault_error(
        &g.approve(id, &dest, 2 * LAMPORTS_PER_SOL),
        VaultError::ProposalStale,
    );
}

#[test]
fn tokens_move_alone_only_to_saved_addresses() {
    let mut g = G::new(406);
    // Mint, fund the vault's token account.
    let issuer = Keypair::new();
    g.env
        .svm
        .airdrop(&issuer.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    let mint = Keypair::new();
    let rent = g
        .env
        .svm
        .minimum_balance_for_rent_exemption(token::MINT_LEN);
    let mut init = vec![20, 6];
    init.extend_from_slice(issuer.pubkey().as_ref());
    init.push(0);
    let vault = g.vault;
    let vault_ta = token::associated_token_address(&vault, &mint.pubkey(), &TOKEN_PROGRAM);
    let mut mint_to = vec![14];
    mint_to.extend_from_slice(&1_000_000u64.to_le_bytes());
    mint_to.push(6);
    let own = Pubkey::new_unique();
    let stranger = Pubkey::new_unique();
    let ixs = [
        solana_system_interface::instruction::create_account(
            &issuer.pubkey(),
            &mint.pubkey(),
            rent,
            token::MINT_LEN as u64,
            &TOKEN_PROGRAM,
        ),
        Instruction::new_with_bytes(TOKEN_PROGRAM, &init, vec![w(&mint.pubkey())]),
        build::create_ata_idempotent(&issuer.pubkey(), &vault, &mint.pubkey(), &TOKEN_PROGRAM),
        build::create_ata_idempotent(&issuer.pubkey(), &own, &mint.pubkey(), &TOKEN_PROGRAM),
        build::create_ata_idempotent(&issuer.pubkey(), &stranger, &mint.pubkey(), &TOKEN_PROGRAM),
        Instruction::new_with_bytes(
            TOKEN_PROGRAM,
            &mint_to,
            vec![
                w(&mint.pubkey()),
                w(&vault_ta),
                AccountMeta::new_readonly(issuer.pubkey(), true),
            ],
        ),
    ];
    g.env.legacy(&ixs, &issuer, &[&mint]).unwrap();
    let own_ta = token::associated_token_address(&own, &mint.pubkey(), &TOKEN_PROGRAM);
    let stranger_ta = token::associated_token_address(&stranger, &mint.pubkey(), &TOKEN_PROGRAM);
    let spl = |g: &G, dest: &Pubkey, amount: u64| AuthorizationV2 {
        action: ActionV2::WithdrawSpl,
        asset_type: AssetType::SplToken,
        mint: mint.pubkey().to_bytes(),
        destination: dest.to_bytes(),
        amount,
        decimals: 6,
        ..g.base(ActionV2::WithdrawSpl, Role::Everyday, g.hot_nonce())
    };
    let accts = |dest: &Pubkey| {
        build::withdraw_spl_accounts(&vault_ta, &mint.pubkey(), dest, &TOKEN_PROGRAM, None)
    };
    // Unsaved owner: needs the guardian.
    let a = spl(&g, &stranger_ta, 10);
    assert_vault_error(&g.run(&a, &accts(&stranger_ta)), VaultError::LimitExceeded);
    // Saved owner (the wallet address, not the token account): instant.
    g.add_address(&own);
    let a = spl(&g, &own_ta, 400_000);
    g.run(&a, &accts(&own_ta)).unwrap();
    let bal = |g: &G, k: &Pubkey| {
        token::parse_token_account(&TOKEN_PROGRAM, &g.env.svm.get_account(k).unwrap().data)
            .unwrap()
            .amount
    };
    assert_eq!(bal(&g, &own_ta), 400_000);
    // Propose + approve to the stranger.
    let id = g.hot_nonce();
    let a = AuthorizationV2 {
        action: ActionV2::ProposeWithdraw,
        ..spl(&g, &stranger_ta, 250_000)
    };
    let p = g.proposal(id);
    g.run(&a, &[w(&p), ro(&Pubkey::default())]).unwrap();
    let a = AuthorizationV2 {
        asset_type: AssetType::SplToken,
        mint: mint.pubkey().to_bytes(),
        destination: stranger_ta.to_bytes(),
        amount: 250_000,
        decimals: 6,
        ref_id: id,
        ..g.guardian_auth(ActionV2::ApproveWithdraw)
    };
    let r = g.relayer.pubkey();
    let mut acc = vec![w(&p), w(&r)];
    acc.extend(accts(&stranger_ta));
    g.run(&a, &acc).unwrap();
    assert_eq!(bal(&g, &stranger_ta), 250_000);
}

#[test]
fn guardian_rotation_disable_and_reenable() {
    let mut g = G::new(407);
    let wallet = g.env.wallet.insecure_clone();
    let vault = g.vault;
    // The guardian may not become the everyday key, nor the reverse.
    let a = AuthorizationV2 {
        new_key_id: g.hot.key_id,
        new_algorithm: 1,
        ..g.guardian_auth(ActionV2::RotateGuardian)
    };
    let (hk, creator) = (g.hot_acct, wallet.pubkey());
    assert_vault_error(&g.run(&a, &[w(&hk), w(&creator)]), VaultError::KeyConflict);
    // Rotate the guardian.
    let g2 = PqKey::from_seed(8_407);
    let g2_acct = g.env.setup_key(&wallet, &vault, &g2);
    let a = AuthorizationV2 {
        new_key_id: g2.key_id,
        new_algorithm: 1,
        ..g.guardian_auth(ActionV2::RotateGuardian)
    };
    let old_guardian_auth = g.guardian_auth(ActionV2::Pause);
    g.run(&a, &[w(&g2_acct), w(&creator)]).unwrap();
    let old_g = std::mem::replace(&mut g.guardian, g2);
    let old_acct = std::mem::replace(&mut g.guardian_acct, g2_acct);
    // The old guardian key no longer works.
    let bytes = AuthorizationV2 {
        nonce: g.guardian_nonce(),
        ..old_guardian_auth
    }
    .encode()
    .unwrap();
    let sig = old_g.sign(&bytes);
    assert!(g.exec_raw(&bytes, &sig, &old_acct, &[]).is_err());

    // Disable: back to single-key rules; re-enable keeps the guardian nonce.
    let gn = g.guardian_nonce();
    let a = g.guardian_auth(ActionV2::DisablePolicy);
    g.run(&a, &[]).unwrap();
    assert_eq!(g.env.vault_state(&g.vault).policy_mode, 0);
    let dest = Pubkey::new_unique();
    let v1 = g
        .env
        .withdraw_auth(&g.vault, g.hot_nonce(), &dest, 5 * LAMPORTS_PER_SOL)
        .encode()
        .unwrap();
    let sig = g.hot.sign(&v1);
    let relayer = g.relayer.insecure_clone();
    g.env
        .execute_v1(&relayer, &vault, &hk, &[w(&dest)], &v1, &sig)
        .unwrap();
    let a = AuthorizationV2 {
        new_key_id: g.guardian.key_id,
        new_algorithm: 1,
        limit_lamports: LIMIT,
        limit_period: DAY,
        ..g.base(ActionV2::EnablePolicy, Role::Everyday, g.hot_nonce())
    };
    let ga = g.guardian_acct;
    g.run(&a, &[w(&ga), ro(&Pubkey::default())]).unwrap();
    assert_eq!(
        g.guardian_nonce(),
        gn + 1,
        "guardian nonce survives re-enabling"
    );
}

#[test]
fn policy_account_and_role_substitution() {
    let mut g = G::new(408);
    let other = G::new(409);
    // Another vault's policy account.
    let dest = Pubkey::new_unique();
    let a = g.send(&dest, 1);
    let bytes = a.encode().unwrap();
    let sig = g.hot.sign(&bytes);
    let (other_policy, _) = build::policy_address(&other.env.program, &other.vault);
    let mut acct = g
        .env
        .svm
        .get_account(&build::policy_address(&g.env.program, &g.vault).0)
        .unwrap();
    acct.data = other.env.svm.get_account(&other_policy).unwrap().data;
    let fake = Pubkey::new_unique();
    g.env.put_account(fake, acct);
    let relayer = g.relayer.insecure_clone();
    let mut ix = build::execute_v2(
        &g.env.program,
        &relayer.pubkey(),
        &g.vault,
        &g.hot_acct,
        &[w(&dest)],
        &bytes,
        &sig,
    );
    ix.accounts[3] = w(&fake);
    assert_vault_error(&g.env.v1(&[ix], &relayer, &[]), VaultError::PolicyRequired);
    // Enabling twice.
    let a = AuthorizationV2 {
        new_key_id: g.guardian.key_id,
        new_algorithm: 1,
        limit_lamports: LIMIT,
        limit_period: DAY,
        ..g.base(ActionV2::EnablePolicy, Role::Everyday, g.hot_nonce())
    };
    let ga = g.guardian_acct;
    assert_vault_error(
        &g.run(&a, &[w(&ga), ro(&Pubkey::default())]),
        VaultError::PolicyActive,
    );
}

#[test]
fn guardian_fees_count_against_the_allowance() {
    let mut g = G::new(409);
    let x = Pubkey::new_unique();
    let before = g.bal(&g.vault);
    // A "freeze" whose fee would empty the vault: refused.
    let a = AuthorizationV2 {
        fee_lamports: 9 * LAMPORTS_PER_SOL,
        fee_recipient: x.to_bytes(),
        ..g.guardian_auth(ActionV2::Pause)
    };
    assert_vault_error(&g.run(&a, &[w(&x)]), VaultError::LimitExceeded);
    // The same for saving an address.
    let a = AuthorizationV2 {
        destination: x.to_bytes(),
        fee_lamports: LIMIT + 1,
        fee_recipient: x.to_bytes(),
        ..g.guardian_auth(ActionV2::AddAddress)
    };
    assert_vault_error(&g.run(&a, &[w(&x)]), VaultError::LimitExceeded);
    assert_eq!(g.bal(&g.vault), before);
    // A fee within the allowance pays the relayer and is charged to it.
    let a = AuthorizationV2 {
        fee_lamports: 5_000,
        fee_recipient: ZERO32,
        ..g.guardian_auth(ActionV2::Pause)
    };
    g.run(&a, &[]).unwrap();
    assert_eq!(g.policy().available, LIMIT - 5_000);
    assert_eq!(g.bal(&g.vault), before - 5_000);
}
