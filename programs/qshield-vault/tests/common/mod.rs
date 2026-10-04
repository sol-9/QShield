//! Shared test harness: runs the compiled program (`target/deploy/qshield_vault.so`,
//! built with `--features cluster-localnet`) inside LiteSVM with the mainnet
//! feature-set snapshot.
#![allow(dead_code)]

use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer as _};
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use litesvm::LiteSVM;
use qshield_protocol::{
    cluster, key_id, Action, Algorithm, AssetType, Authorization, Bytes32, ML_DSA_CONTEXT, ZERO32,
};
use qshield_vault::instruction::build;
use qshield_vault::state::{KeyHeader, Vault};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use solana_account::Account;
use solana_clock::Clock;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{v1, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::Transaction;

pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
pub const NOW: i64 = 1_790_000_000; // 2026-09-21
/// Signature bytes per legacy buffer-write transaction (fits 1,232 bytes with a compute-budget instruction).
pub const SIG_CHUNK: usize = 900;

pub type TxResult = Result<TransactionMetadata, FailedTransactionMetadata>;

pub fn program_so() -> std::path::PathBuf {
    let p = std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/deploy/qshield_vault.so"
    ));
    assert!(
        p.exists(),
        "build the program first: cargo build-sbf --arch v3 --features cluster-localnet --manifest-path programs/qshield-vault/Cargo.toml"
    );
    p
}

/// A post-quantum keypair held by a "user device".
pub struct PqKey {
    pub pk: Vec<u8>,
    sk: ml_dsa_44::PrivateKey,
    pub key_id: Bytes32,
}

impl PqKey {
    pub fn from_seed(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let xi: [u8; 32] = rng.gen();
        let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&xi);
        let pk = pk.into_bytes().to_vec();
        let key_id = key_id(Algorithm::MlDsa44, &pk);
        Self { pk, sk, key_id }
    }

    /// Hedged ML-DSA signature over QSP-1 bytes with the QSP-1 context.
    pub fn sign(&self, auth: &[u8]) -> Vec<u8> {
        self.sk
            .try_sign(auth, ML_DSA_CONTEXT)
            .expect("sign")
            .to_vec()
    }
}

pub struct Env {
    pub svm: LiteSVM,
    pub program: Pubkey,
    /// The user's ordinary Ed25519 wallet (creates the vault, deposits).
    pub wallet: Keypair,
    /// An untrusted relayer that pays fees for executions.
    pub relayer: Keypair,
}

impl Env {
    pub fn new() -> Self {
        let mut svm = LiteSVM::new().with_mainnet_features().with_sigverify(true);
        let program = Pubkey::new_unique();
        svm.add_program_from_file(program, program_so()).unwrap();
        let wallet = Keypair::new();
        let relayer = Keypair::new();
        svm.airdrop(&wallet.pubkey(), 100 * LAMPORTS_PER_SOL)
            .unwrap();
        svm.airdrop(&relayer.pubkey(), 100 * LAMPORTS_PER_SOL)
            .unwrap();
        let mut env = Self {
            svm,
            program,
            wallet,
            relayer,
        };
        env.set_time(NOW);
        env
    }

    pub fn set_time(&mut self, unix: i64) {
        let mut c: Clock = self.svm.get_sysvar();
        c.unix_timestamp = unix;
        self.svm.set_sysvar(&c);
    }

    pub fn balance(&self, k: &Pubkey) -> u64 {
        self.svm.get_balance(k).unwrap_or(0)
    }

    pub fn legacy(&mut self, ixs: &[Instruction], payer: &Keypair, extra: &[&Keypair]) -> TxResult {
        self.svm.expire_blockhash();
        let mut all = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
        all.extend_from_slice(ixs);
        let msg =
            Message::new_with_blockhash(&all, Some(&payer.pubkey()), &self.svm.latest_blockhash());
        let mut signers = vec![payer];
        signers.extend_from_slice(extra);
        let tx = Transaction::new(&signers, msg, self.svm.latest_blockhash());
        assert!(
            bincode::serialize(&tx).unwrap().len() <= 1232,
            "legacy tx too large"
        );
        self.svm.send_transaction(tx)
    }

    pub fn v1(&mut self, ixs: &[Instruction], payer: &Keypair, extra: &[&Keypair]) -> TxResult {
        self.svm.expire_blockhash();
        let msg = v1::Message::try_compile_with_config(
            &payer.pubkey(),
            ixs,
            self.svm.latest_blockhash(),
            v1::TransactionConfig::empty()
                .with_compute_unit_limit(1_400_000)
                .with_loaded_accounts_data_size_limit(1 << 20),
        )
        .unwrap();
        let mut signers = vec![payer];
        signers.extend_from_slice(extra);
        let tx = VersionedTransaction::try_new(VersionedMessage::V1(msg), &signers).unwrap();
        assert!(
            bincode::serialize(&tx).unwrap().len() <= 4096,
            "v1 tx too large"
        );
        self.svm.send_transaction(tx)
    }

    /// Full key-account setup: allocate, upload (legacy chunks), finalize, expand.
    /// Returns the key account address. `creator` pays rent.
    pub fn setup_key(&mut self, creator: &Keypair, vault: &Pubkey, key: &PqKey) -> Pubkey {
        let key_kp = Keypair::new();
        let rent = self.svm.minimum_balance_for_rent_exemption(KeyHeader::LEN);
        let alloc = solana_system_interface::instruction::create_account(
            &creator.pubkey(),
            &key_kp.pubkey(),
            rent,
            KeyHeader::LEN as u64,
            &self.program,
        );
        let init = build::create_key(
            &self.program,
            &creator.pubkey(),
            &key_kp.pubkey(),
            vault,
            &key.key_id,
            1,
        );
        self.legacy(&[alloc, init], creator, &[&key_kp])
            .expect("create key");
        for (i, chunk) in key.pk.chunks(900).enumerate() {
            let ix = build::write_key(
                &self.program,
                &creator.pubkey(),
                &key_kp.pubkey(),
                (i * 900) as u16,
                chunk,
            );
            self.legacy(&[ix], creator, &[]).expect("write key");
        }
        let ix = build::finalize_key(&self.program, &creator.pubkey(), &key_kp.pubkey());
        self.legacy(&[ix], creator, &[]).expect("finalize key");
        for _ in 0..2 {
            let ix = build::expand_key(&self.program, &key_kp.pubkey(), 10);
            self.legacy(&[ix], creator, &[]).expect("expand key");
        }
        let h = KeyHeader::load(&self.svm.get_account(&key_kp.pubkey()).unwrap().data).unwrap();
        assert_eq!(h.state, qshield_vault::state::KeyState::Ready);
        key_kp.pubkey()
    }

    /// Creates a vault for `key` using the user's wallet. Returns (vault, key_account).
    pub fn create_vault(&mut self, key: &PqKey, vault_seed: Bytes32) -> (Pubkey, Pubkey) {
        let (vault, _) = build::vault_address(&self.program, &key.key_id, &vault_seed);
        let wallet = self.wallet.insecure_clone();
        let key_acct = self.setup_key(&wallet, &vault, key);
        let ix = build::initialize_vault(
            &self.program,
            &wallet.pubkey(),
            &vault,
            &key_acct,
            &vault_seed,
        );
        self.legacy(&[ix], &wallet, &[]).expect("initialize vault");
        (vault, key_acct)
    }

    pub fn deposit(&mut self, vault: &Pubkey, amount: u64) {
        let wallet = self.wallet.insecure_clone();
        let ix = build::deposit_sol(&self.program, &wallet.pubkey(), vault, amount);
        self.legacy(&[ix], &wallet, &[]).expect("deposit");
    }

    pub fn vault_state(&self, vault: &Pubkey) -> Vault {
        Vault::load(&self.svm.get_account(vault).unwrap().data).unwrap()
    }

    pub fn put_account(&mut self, key: Pubkey, acct: Account) {
        self.svm.set_account(key, acct).unwrap();
    }

    /// Base authorization for this env's program and localnet.
    pub fn auth(&self, vault: &Pubkey, nonce: u64) -> Authorization {
        Authorization {
            cluster_id: cluster::LOCALNET,
            program_id: self.program.to_bytes(),
            vault: vault.to_bytes(),
            action: Action::Pause,
            asset_type: AssetType::None,
            nonce,
            valid_after: 0,
            expires_at: NOW + 3600,
            mint: ZERO32,
            destination: ZERO32,
            amount: 0,
            decimals: 0,
            fee_recipient: ZERO32,
            fee_lamports: 0,
            new_key_id: ZERO32,
            new_algorithm: 0,
        }
    }

    pub fn withdraw_auth(
        &self,
        vault: &Pubkey,
        nonce: u64,
        dest: &Pubkey,
        amount: u64,
    ) -> Authorization {
        Authorization {
            action: Action::WithdrawSol,
            asset_type: AssetType::Sol,
            destination: dest.to_bytes(),
            amount,
            ..self.auth(vault, nonce)
        }
    }

    /// Executes inline in a v1 transaction paid by `fee_payer`.
    pub fn execute_v1(
        &mut self,
        fee_payer: &Keypair,
        vault: &Pubkey,
        key_acct: &Pubkey,
        action_accounts: &[AccountMeta],
        auth: &[u8],
        sig: &[u8],
    ) -> TxResult {
        let ix = build::execute(
            &self.program,
            &fee_payer.pubkey(),
            vault,
            key_acct,
            action_accounts,
            auth,
            sig,
        );
        self.v1(&[ix], fee_payer, &[])
    }

    /// Uploads `sig` to a fresh signature buffer (legacy txs) and executes with it.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_buffered(
        &mut self,
        relayer: &Keypair,
        vault: &Pubkey,
        key_acct: &Pubkey,
        action_accounts: &[AccountMeta],
        auth: &[u8],
        sig: &[u8],
        buffer_id: u64,
    ) -> TxResult {
        let buf = self.upload_sig_buffer(relayer, vault, sig, buffer_id);
        let ix = build::execute_with_buffer(
            &self.program,
            &relayer.pubkey(),
            vault,
            key_acct,
            &buf,
            &relayer.pubkey(),
            action_accounts,
            auth,
        );
        self.legacy(&[ix], relayer, &[])
    }

    pub fn upload_sig_buffer(
        &mut self,
        relayer: &Keypair,
        vault: &Pubkey,
        sig: &[u8],
        buffer_id: u64,
    ) -> Pubkey {
        let (buf, _) =
            build::sig_buffer_address(&self.program, vault, &relayer.pubkey(), buffer_id);
        let ix = build::create_sig_buffer(&self.program, &relayer.pubkey(), vault, buffer_id);
        self.legacy(&[ix], relayer, &[]).expect("create sig buffer");
        let n = sig.len().div_ceil(SIG_CHUNK);
        for (i, chunk) in sig.chunks(SIG_CHUNK).enumerate() {
            let ix = build::write_sig_buffer(
                &self.program,
                &relayer.pubkey(),
                &buf,
                (i * SIG_CHUNK) as u16,
                i + 1 == n,
                chunk,
            );
            self.legacy(&[ix], relayer, &[]).expect("write sig buffer");
        }
        buf
    }
}

pub fn w(k: &Pubkey) -> AccountMeta {
    AccountMeta::new(*k, false)
}

/// Extracts the custom error code of a failed transaction, if any.
pub fn custom_error(r: &TxResult) -> Option<u32> {
    let e = format!("{:?}", r.as_ref().err()?.err);
    let i = e.find("Custom(")?;
    e[i + 7..].split(')').next()?.parse().ok()
}

pub fn assert_vault_error(r: &TxResult, e: qshield_vault::error::VaultError) {
    assert!(r.is_err(), "expected failure {e:?}, got success");
    assert_eq!(
        custom_error(r),
        Some(e as u32),
        "expected {e:?}, got {:?}",
        r.as_ref().err().map(|f| &f.err)
    );
}
