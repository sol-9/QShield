//! High-level vault operations.

use qshield_mldsa::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use qshield_protocol::{
    cluster, key_id, Action, Algorithm, AssetType, Authorization, Bytes32, AUTH_LEN, ZERO32,
};
use qshield_vault::instruction::build;
use qshield_vault::state::{
    key_off, KeyHeader, KeyState, SigBuffer, Vault, VaultStatus, EXPAND_TOTAL,
};
use qshield_vault::token::{self, MintInfo, TokenAccountInfo, TokenAccountState};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{v1, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::Transaction;

use crate::envelope::Hints;
use crate::key::verify_authorization;
use crate::rpc::Rpc;
use crate::Error;

/// Compute-unit limit requested for `Execute` (measured ≤ 831k, see docs/BENCHMARKS.md).
pub const EXECUTE_CU_LIMIT: u32 = 1_000_000;
/// Compute-unit limit for `ExpandKey` with 10 polynomials (measured ≤ 780k).
pub const EXPAND_CU_LIMIT: u32 = 1_000_000;
/// Compute-unit limit for `FinalizeKey` (measured ≈ 130k).
pub const FINALIZE_CU_LIMIT: u32 = 300_000;
/// Bytes of public key / signature per legacy write transaction.
pub const CHUNK: usize = 900;

/// How the 2,420-byte signature reaches the program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// One v1 transaction (SIMD-0385) carrying the signature inline.
    Inline,
    /// Signature buffer filled by legacy transactions, then executed (5 transactions).
    Buffered,
}

/// Optional authorization fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthOptions {
    /// Unix seconds; 0 = immediately.
    pub valid_after: i64,
    /// Unix seconds; 0 = never.
    pub expires_at: i64,
    /// Relayer fee paid from the vault.
    pub fee_lamports: u64,
    /// Fee recipient; `None` = whoever pays the transaction fee.
    pub fee_recipient: Option<Pubkey>,
}

/// A vault as read from the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultInfo {
    /// Vault address.
    pub address: Pubkey,
    /// Decoded state.
    pub state: Vault,
    /// Total balance (includes the rent reserve).
    pub lamports: u64,
    /// Withdrawable balance.
    pub available: u64,
}

/// A key account as read from the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyAccountInfo {
    /// Address.
    pub address: Pubkey,
    /// Header.
    pub header: KeyHeader,
    /// Public key bytes.
    pub public_key: Vec<u8>,
}

/// A mint as read from the chain and checked against the program's mint
/// policy (ADR-0015).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintAccount {
    /// Mint address.
    pub address: Pubkey,
    /// Owning token program (SPL Token or Token-2022).
    pub token_program: Pubkey,
    /// QSP-1 asset type for that program.
    pub asset_type: AssetType,
    /// Decimals, supply, freeze authority.
    pub info: MintInfo,
    /// Token-2022 extension types (empty for SPL Token).
    pub extensions: Vec<u16>,
}

/// A token account held by a vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenBalance {
    /// Token account address.
    pub address: Pubkey,
    /// Token program.
    pub token_program: Pubkey,
    /// Parsed fields (mint, owner, amount, state).
    pub account: TokenAccountInfo,
}

/// Formats base units with `decimals` (e.g. `1500000`, 6 → `1.500000`).
pub fn format_token_amount(amount: u64, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let d = decimals as u32;
    match 10u128.checked_pow(d) {
        Some(scale) => {
            let a = amount as u128;
            format!("{}.{:0width$}", a / scale, a % scale, width = d as usize)
        }
        None => format!("{amount}e-{decimals}"),
    }
}

/// Parses a decimal token amount (`"1.5"`) into base units for `decimals`.
/// Rejects more fractional digits than the mint supports and overflow.
pub fn parse_token_amount(s: &str, decimals: u8) -> Result<u64, Error> {
    let bad = || Error::InvalidInput(format!("invalid token amount {s:?}"));
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty() && frac.is_empty()
        || !whole.chars().all(|c| c.is_ascii_digit())
        || !frac.chars().all(|c| c.is_ascii_digit())
    {
        return Err(bad());
    }
    if frac.len() > decimals as usize {
        return Err(Error::InvalidInput(format!(
            "{s} has more than {decimals} decimal places"
        )));
    }
    let scale = 10u128.checked_pow(decimals as u32).ok_or_else(bad)?;
    let w: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| bad())?
    };
    let f: u128 = if frac.is_empty() {
        0
    } else {
        frac.parse::<u128>().map_err(|_| bad())? * 10u128.pow(decimals as u32 - frac.len() as u32)
    };
    let v = w
        .checked_mul(scale)
        .and_then(|x| x.checked_add(f))
        .ok_or_else(bad)?;
    u64::try_from(v).map_err(|_| bad())
}

/// QShield client for one program deployment on one cluster.
pub struct QShieldClient<R: Rpc> {
    /// Chain access.
    pub rpc: R,
    /// QShield program id.
    pub program_id: Pubkey,
    /// Cluster id the program was built for (QSP-1 §8).
    pub cluster_id: Bytes32,
}

impl<R: Rpc> QShieldClient<R> {
    /// Creates a client.
    pub fn new(rpc: R, program_id: Pubkey, cluster_id: Bytes32) -> Self {
        Self {
            rpc,
            program_id,
            cluster_id,
        }
    }

    /// Checks that the RPC endpoint serves the expected cluster (skipped for localnet,
    /// whose genesis hash is random).
    pub fn check_cluster(&self) -> Result<(), Error> {
        if self.cluster_id == cluster::LOCALNET {
            return Ok(());
        }
        let actual = self.rpc.genesis_hash()?;
        if actual != self.cluster_id {
            return Err(Error::WrongCluster {
                expected: self.cluster_id,
                actual,
            });
        }
        Ok(())
    }

    // ----------------------------------------------------------------- reads

    /// Vault PDA for a key id and seed.
    pub fn vault_address(&self, initial_key_id: &Bytes32, vault_seed: &Bytes32) -> Pubkey {
        build::vault_address(&self.program_id, initial_key_id, vault_seed).0
    }

    /// Reads a vault.
    pub fn get_vault(&self, address: &Pubkey) -> Result<VaultInfo, Error> {
        let a = self
            .rpc
            .get_account(address)?
            .ok_or_else(|| Error::Account(format!("vault {address} not found")))?;
        if a.owner != self.program_id {
            return Err(Error::Account(format!(
                "{address} is not owned by the QShield program"
            )));
        }
        let state = Vault::load(&a.data)
            .map_err(|_| Error::Account(format!("{address} is not a vault")))?;
        let rent = self.rpc.minimum_balance_for_rent_exemption(Vault::LEN)?;
        Ok(VaultInfo {
            address: *address,
            state,
            lamports: a.lamports,
            available: a.lamports.saturating_sub(rent),
        })
    }

    /// Reads a vault and checks that it is controlled by `expected_key_id`.
    /// Call this before depositing.
    pub fn get_vault_checked(
        &self,
        address: &Pubkey,
        expected_key_id: &Bytes32,
    ) -> Result<VaultInfo, Error> {
        let v = self.get_vault(address)?;
        if &v.state.key_id != expected_key_id {
            return Err(Error::Account(format!(
                "vault {address} is controlled by key {} not {}",
                hex::encode(v.state.key_id),
                hex::encode(expected_key_id)
            )));
        }
        Ok(v)
    }

    /// Reads a key account.
    pub fn get_key_account(&self, address: &Pubkey) -> Result<KeyAccountInfo, Error> {
        let a = self
            .rpc
            .get_account(address)?
            .ok_or_else(|| Error::Account(format!("key account {address} not found")))?;
        if a.owner != self.program_id {
            return Err(Error::Account(format!(
                "{address} is not owned by the QShield program"
            )));
        }
        let header = KeyHeader::load(&a.data)
            .map_err(|_| Error::Account(format!("{address} is not a key account")))?;
        Ok(KeyAccountInfo {
            address: *address,
            header,
            public_key: a.data[key_off::PK..key_off::TR].to_vec(),
        })
    }

    /// Reads a mint and applies the program's mint policy, so unsupported
    /// mints are reported before anything is signed or sent.
    pub fn get_mint(&self, mint: &Pubkey) -> Result<MintAccount, Error> {
        let a = self
            .rpc
            .get_account(mint)?
            .ok_or_else(|| Error::Account(format!("mint {mint} not found")))?;
        let asset_type = token::asset_for(&a.owner).ok_or_else(|| {
            Error::Account(format!(
                "{mint} is not owned by the SPL Token or Token-2022 program"
            ))
        })?;
        let extensions = token::mint_extensions(&a.data).unwrap_or_default();
        let info = token::parse_mint(&a.owner, &a.data).map_err(|e| {
            let unsupported: Vec<&str> = extensions
                .iter()
                .filter(|t| !token::ext::MINT_ALLOWED.contains(t))
                .map(|&t| token::extension_name(t))
                .collect();
            if unsupported.is_empty() {
                Error::Account(format!("{mint} is not a valid mint ({e:?})"))
            } else {
                Error::Account(format!(
                    "mint {mint} uses Token-2022 extensions QShield does not support: {} (docs/adr/0015)",
                    unsupported.join(", ")
                ))
            }
        })?;
        Ok(MintAccount {
            address: *mint,
            token_program: a.owner,
            asset_type,
            info,
            extensions,
        })
    }

    /// The vault's associated token account for `mint`.
    pub fn vault_token_address(&self, vault: &Pubkey, mint: &MintAccount) -> Pubkey {
        token::associated_token_address(vault, &mint.address, &mint.token_program)
    }

    /// Reads a token account (`None` if it does not exist).
    pub fn get_token_account(
        &self,
        address: &Pubkey,
        token_program: &Pubkey,
    ) -> Result<Option<TokenAccountInfo>, Error> {
        match self.rpc.get_account(address)? {
            None => Ok(None),
            Some(a) if a.owner != *token_program => Err(Error::Account(format!(
                "{address} is not a token account of {token_program}"
            ))),
            Some(a) => token::parse_token_account(token_program, &a.data)
                .map(Some)
                .map_err(|e| Error::Account(format!("{address}: {e:?}"))),
        }
    }

    /// Token accounts owned by `vault` under both token programs (needs an
    /// RPC endpoint that supports `getTokenAccountsByOwner`).
    pub fn token_balances(&self, vault: &Pubkey) -> Result<Vec<TokenBalance>, Error> {
        let mut out = vec![];
        for program in [token::TOKEN_PROGRAM, token::TOKEN_2022_PROGRAM] {
            for (address, a) in self.rpc.get_token_accounts_by_owner(vault, &program)? {
                if a.owner != program {
                    continue;
                }
                if let Ok(account) = token::parse_token_account(&program, &a.data) {
                    if account.owner == vault.to_bytes() {
                        out.push(TokenBalance {
                            address,
                            token_program: program,
                            account,
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    /// Deposits `amount` base units of `mint` from the depositor's associated
    /// token account into the vault's associated token account (created if
    /// needed, rent paid by the depositor), through `DepositSpl`, which checks
    /// on-chain that the destination belongs to a live vault and that the
    /// mint is supported.
    pub fn deposit_spl(
        &self,
        depositor: &Keypair,
        vault: &Pubkey,
        mint: &Pubkey,
        amount: u64,
    ) -> Result<Signature, Error> {
        if amount == 0 {
            return Err(Error::InvalidInput("amount must be positive".into()));
        }
        let v = self.get_vault(vault)?;
        if v.state.status == VaultStatus::Closed {
            return Err(Error::Account(format!("vault {vault} is closed")));
        }
        let m = self.get_mint(mint)?;
        let source = token::associated_token_address(&depositor.pubkey(), mint, &m.token_program);
        let src = self
            .get_token_account(&source, &m.token_program)?
            .ok_or_else(|| Error::Account(format!("depositor has no token account {source}")))?;
        if src.amount < amount {
            return Err(Error::InvalidInput(format!(
                "depositor holds {} but {} requested",
                format_token_amount(src.amount, m.info.decimals),
                format_token_amount(amount, m.info.decimals)
            )));
        }
        let vault_ta = self.vault_token_address(vault, &m);
        let ixs = [
            build::create_ata_idempotent(&depositor.pubkey(), vault, mint, &m.token_program),
            build::deposit_spl(
                &self.program_id,
                &depositor.pubkey(),
                &source,
                mint,
                &vault_ta,
                vault,
                &m.token_program,
                amount,
                m.info.decimals,
            ),
        ];
        self.send_legacy(&ixs, depositor, &[], None)
    }

    // ------------------------------------------------------------ transactions

    pub(crate) fn send_legacy(
        &self,
        ixs: &[Instruction],
        payer: &Keypair,
        extra: &[&Keypair],
        cu: Option<u32>,
    ) -> Result<Signature, Error> {
        let mut all = Vec::with_capacity(ixs.len() + 1);
        if let Some(cu) = cu {
            all.push(ComputeBudgetInstruction::set_compute_unit_limit(cu));
        }
        all.extend_from_slice(ixs);
        let bh = self.rpc.latest_blockhash()?;
        let msg = Message::new_with_blockhash(&all, Some(&payer.pubkey()), &bh);
        let mut signers = vec![payer];
        signers.extend_from_slice(extra);
        let mut tx = Transaction::new_unsigned(msg);
        tx.try_sign(&signers, bh)
            .map_err(|e| Error::Transaction(e.to_string()))?;
        self.rpc.send_and_confirm(&tx.into())
    }

    pub(crate) fn send_v1(
        &self,
        ixs: &[Instruction],
        payer: &Keypair,
        cu: u32,
    ) -> Result<Signature, Error> {
        let bh = self.rpc.latest_blockhash()?;
        let msg = v1::Message::try_compile_with_config(
            &payer.pubkey(),
            ixs,
            bh,
            // The 21,976-byte key account and the program must fit the loaded-data limit.
            v1::TransactionConfig::empty()
                .with_compute_unit_limit(cu)
                .with_loaded_accounts_data_size_limit(1 << 20),
        )
        .map_err(|e| Error::Transaction(e.to_string()))?;
        let tx = VersionedTransaction::try_new(VersionedMessage::V1(msg), &[payer])
            .map_err(|e| Error::Transaction(e.to_string()))?;
        self.rpc.send_and_confirm(&tx)
    }

    // ------------------------------------------------------------- key setup

    /// Uploads and expands `public_key` into a new key account bound to
    /// `vault` (6 legacy transactions). `creator` pays ≈ 0.154 SOL of rent,
    /// refunded when the key is rotated away or the vault closed.
    pub fn setup_key(
        &self,
        creator: &Keypair,
        vault: &Pubkey,
        public_key: &[u8],
    ) -> Result<Pubkey, Error> {
        if public_key.len() != PUBLIC_KEY_LEN {
            return Err(Error::InvalidInput("public key must be 1,312 bytes".into()));
        }
        let id = key_id(Algorithm::MlDsa44, public_key);
        let key_kp = Keypair::new();
        let rent = self
            .rpc
            .minimum_balance_for_rent_exemption(KeyHeader::LEN)?;
        let alloc = solana_system_interface::instruction::create_account(
            &creator.pubkey(),
            &key_kp.pubkey(),
            rent,
            KeyHeader::LEN as u64,
            &self.program_id,
        );
        let init = build::create_key(
            &self.program_id,
            &creator.pubkey(),
            &key_kp.pubkey(),
            vault,
            &id,
            Algorithm::MlDsa44 as u8,
        );
        self.send_legacy(&[alloc, init], creator, &[&key_kp], None)?;
        for (i, chunk) in public_key.chunks(CHUNK).enumerate() {
            let ix = build::write_key(
                &self.program_id,
                &creator.pubkey(),
                &key_kp.pubkey(),
                (i * CHUNK) as u16,
                chunk,
            );
            self.send_legacy(&[ix], creator, &[], None)?;
        }
        let ix = build::finalize_key(&self.program_id, &creator.pubkey(), &key_kp.pubkey());
        self.send_legacy(&[ix], creator, &[], Some(FINALIZE_CU_LIMIT))?;
        let per_tx = 10u8;
        for _ in 0..EXPAND_TOTAL.div_ceil(per_tx) {
            let ix = build::expand_key(&self.program_id, &key_kp.pubkey(), per_tx);
            self.send_legacy(&[ix], creator, &[], Some(EXPAND_CU_LIMIT))?;
        }
        let k = self.get_key_account(&key_kp.pubkey())?;
        if k.header.state != KeyState::Ready || k.header.key_id != id {
            return Err(Error::Account("key account did not become ready".into()));
        }
        Ok(key_kp.pubkey())
    }

    /// Creates a vault controlled by `public_key` (key setup + `InitializeVault`).
    /// Returns `(vault, key_account)`. The payer gains no authority over the vault.
    pub fn create_vault(
        &self,
        payer: &Keypair,
        public_key: &[u8],
        vault_seed: &Bytes32,
    ) -> Result<(Pubkey, Pubkey), Error> {
        let id = key_id(Algorithm::MlDsa44, public_key);
        let vault = self.vault_address(&id, vault_seed);
        if let Some(a) = self.rpc.get_account(&vault)? {
            if a.owner == self.program_id {
                return Err(Error::Account(format!("vault {vault} already exists")));
            }
        }
        let key_account = self.setup_key(payer, &vault, public_key)?;
        let ix = build::initialize_vault(
            &self.program_id,
            &payer.pubkey(),
            &vault,
            &key_account,
            vault_seed,
        );
        self.send_legacy(&[ix], payer, &[], None)?;
        self.get_vault_checked(&vault, &id)?;
        Ok((vault, key_account))
    }

    /// Deposits lamports with the `DepositSol` instruction (rejects closed vaults).
    pub fn deposit_sol(
        &self,
        depositor: &Keypair,
        vault: &Pubkey,
        lamports: u64,
    ) -> Result<Signature, Error> {
        let ix = build::deposit_sol(&self.program_id, &depositor.pubkey(), vault, lamports);
        self.send_legacy(&[ix], depositor, &[], None)
    }

    // -------------------------------------------------------- authorizations

    /// Offline authorization builder for this program and cluster.
    pub fn auth(&self) -> AuthBuilder {
        AuthBuilder {
            program_id: self.program_id,
            cluster_id: self.cluster_id,
        }
    }

    /// WithdrawSol authorization (see [`AuthBuilder::withdraw_sol`]).
    pub fn withdraw_sol(
        &self,
        vault: &Pubkey,
        nonce: u64,
        to: &Pubkey,
        lamports: u64,
        opts: &AuthOptions,
    ) -> Authorization {
        self.auth().withdraw_sol(vault, nonce, to, lamports, opts)
    }

    /// WithdrawSpl authorization paying `amount` base units of `mint` to the
    /// associated token account of `to_owner`. Returns the authorization and
    /// the hints needed to submit it (the destination account is created at
    /// submission if it does not exist yet).
    pub fn withdraw_spl(
        &self,
        vault: &Pubkey,
        nonce: u64,
        mint: &MintAccount,
        to_owner: &Pubkey,
        amount: u64,
        opts: &AuthOptions,
    ) -> (Authorization, Hints) {
        let dest = token::associated_token_address(to_owner, &mint.address, &mint.token_program);
        let a = self.auth().withdraw_spl(
            vault,
            nonce,
            mint.asset_type,
            &mint.address,
            &dest,
            amount,
            mint.info.decimals,
            opts,
        );
        let hints = Hints {
            destination_owner: Some(to_owner.to_string()),
            ..Hints::default()
        };
        (a, hints)
    }

    /// RotateKey authorization.
    pub fn rotate_key(
        &self,
        vault: &Pubkey,
        nonce: u64,
        new_key_id: &Bytes32,
        opts: &AuthOptions,
    ) -> Authorization {
        self.auth().rotate_key(vault, nonce, new_key_id, opts)
    }

    /// Pause authorization.
    pub fn pause(&self, vault: &Pubkey, nonce: u64, opts: &AuthOptions) -> Authorization {
        self.auth().pause(vault, nonce, opts)
    }

    /// Unpause authorization.
    pub fn unpause(&self, vault: &Pubkey, nonce: u64, opts: &AuthOptions) -> Authorization {
        self.auth().unpause(vault, nonce, opts)
    }

    /// CloseVault authorization.
    pub fn close_vault(
        &self,
        vault: &Pubkey,
        nonce: u64,
        to: &Pubkey,
        opts: &AuthOptions,
    ) -> Authorization {
        self.auth().close_vault(vault, nonce, to, opts)
    }

    // --------------------------------------------------------------- submit

    /// Accounts required after `[fee_payer, vault, key_account]` (docs/PROTOCOL.md §1.1).
    pub fn action_accounts(
        &self,
        auth: &Authorization,
        vault: &VaultInfo,
        hints: &Hints,
    ) -> Result<Vec<AccountMeta>, Error> {
        let w = |k: Pubkey| AccountMeta::new(k, false);
        let key_account = Pubkey::new_from_array(vault.state.key_account);
        let mut accts = match auth.action {
            Action::WithdrawSol => vec![w(Pubkey::new_from_array(auth.destination))],
            Action::RotateKey => {
                let new = hints.new_key_account.as_ref().ok_or_else(|| {
                    Error::InvalidInput("RotateKey needs the new key account (hint)".into())
                })?;
                let new: Pubkey = new
                    .parse()
                    .map_err(|_| Error::InvalidInput("bad new key account".into()))?;
                let k = self.get_key_account(&new)?;
                if k.header.key_id != auth.new_key_id || k.header.state != KeyState::Ready {
                    return Err(Error::Account(
                        "new key account is not ready for this key id".into(),
                    ));
                }
                let old = self.get_key_account(&key_account)?;
                vec![w(new), w(Pubkey::new_from_array(old.header.creator))]
            }
            Action::Pause | Action::Unpause => vec![],
            Action::CloseVault => {
                let old = self.get_key_account(&key_account)?;
                vec![
                    w(Pubkey::new_from_array(auth.destination)),
                    w(Pubkey::new_from_array(old.header.creator)),
                ]
            }
            Action::WithdrawSpl => {
                let program = token::program_for(auth.asset_type).ok_or_else(|| {
                    Error::InvalidInput("WithdrawSpl without a token asset".into())
                })?;
                let mint = Pubkey::new_from_array(auth.mint);
                let source = match &hints.source_token_account {
                    Some(s) => s
                        .parse()
                        .map_err(|_| Error::InvalidInput("bad source token account".into()))?,
                    None => token::associated_token_address(&vault.address, &mint, &program),
                };
                build::withdraw_spl_accounts(
                    &source,
                    &mint,
                    &Pubkey::new_from_array(auth.destination),
                    &program,
                    None,
                )
            }
        };
        if auth.fee_lamports > 0 && auth.fee_recipient != ZERO32 {
            accts.push(w(Pubkey::new_from_array(auth.fee_recipient)));
        }
        Ok(accts)
    }

    /// Submits a signed authorization, paying fees from `fee_payer` (who gains
    /// no authority). Checks locally first — cluster, program, vault, nonce,
    /// and the signature against the vault's current key — so that invalid
    /// submissions do not cost fees. Returns the transaction signatures.
    pub fn submit(
        &self,
        fee_payer: &Keypair,
        auth_bytes: &[u8; AUTH_LEN],
        signature: &[u8],
        hints: &Hints,
        transport: Transport,
    ) -> Result<Vec<Signature>, Error> {
        if signature.len() != SIGNATURE_LEN {
            return Err(Error::InvalidInput("signature must be 2,420 bytes".into()));
        }
        let auth = Authorization::decode(auth_bytes).map_err(Error::Protocol)?;
        if auth.cluster_id != self.cluster_id {
            return Err(Error::InvalidInput(
                "authorization is for another cluster".into(),
            ));
        }
        if auth.program_id != self.program_id.to_bytes() {
            return Err(Error::InvalidInput(
                "authorization is for another program".into(),
            ));
        }
        let vault_addr = Pubkey::new_from_array(auth.vault);
        let vault = self.get_vault(&vault_addr)?;
        if vault.state.nonce != auth.nonce {
            return Err(Error::InvalidInput(format!(
                "authorization nonce {} but vault nonce is {}",
                auth.nonce, vault.state.nonce
            )));
        }
        let key_account = Pubkey::new_from_array(vault.state.key_account);
        let key = self.get_key_account(&key_account)?;
        if !verify_authorization(&key.public_key, auth_bytes, signature) {
            return Err(Error::InvalidInput(
                "signature is not valid for the vault's current key".into(),
            ));
        }
        let accts = self.action_accounts(&auth, &vault, hints)?;
        let pre = if auth.action == Action::WithdrawSpl {
            self.withdraw_spl_prechecks(&auth, &fee_payer.pubkey(), &accts, hints)?
        } else {
            vec![]
        };
        match transport {
            Transport::Inline => {
                let ix = build::execute(
                    &self.program_id,
                    &fee_payer.pubkey(),
                    &vault_addr,
                    &key_account,
                    &accts,
                    auth_bytes,
                    signature,
                );
                let mut ixs = pre;
                ixs.push(ix);
                Ok(vec![self.send_v1(&ixs, fee_payer, EXECUTE_CU_LIMIT)?])
            }
            Transport::Buffered => {
                let mut sigs = vec![];
                let mut id = [0u8; 8];
                getrandom::getrandom(&mut id).map_err(|_| Error::RandomnessUnavailable)?;
                let id = u64::from_le_bytes(id);
                let (buf, _) = build::sig_buffer_address(
                    &self.program_id,
                    &vault_addr,
                    &fee_payer.pubkey(),
                    id,
                );
                sigs.push(self.send_legacy(
                    &[build::create_sig_buffer(
                        &self.program_id,
                        &fee_payer.pubkey(),
                        &vault_addr,
                        id,
                    )],
                    fee_payer,
                    &[],
                    None,
                )?);
                let n = signature.len().div_ceil(CHUNK);
                let result = (|| {
                    for (i, chunk) in signature.chunks(CHUNK).enumerate() {
                        let ix = build::write_sig_buffer(
                            &self.program_id,
                            &fee_payer.pubkey(),
                            &buf,
                            (i * CHUNK) as u16,
                            i + 1 == n,
                            chunk,
                        );
                        sigs.push(self.send_legacy(&[ix], fee_payer, &[], None)?);
                    }
                    let ix = build::execute_with_buffer(
                        &self.program_id,
                        &fee_payer.pubkey(),
                        &vault_addr,
                        &key_account,
                        &buf,
                        &fee_payer.pubkey(),
                        &accts,
                        auth_bytes,
                    );
                    let mut ixs = pre.clone();
                    ixs.push(ix);
                    sigs.push(self.send_legacy(&ixs, fee_payer, &[], Some(EXECUTE_CU_LIMIT))?);
                    Ok::<_, Error>(())
                })();
                if let Err(e) = result {
                    // Best effort: recover the buffer's rent.
                    let _ = self.send_legacy(
                        &[build::close_sig_buffer(
                            &self.program_id,
                            &fee_payer.pubkey(),
                            &buf,
                        )],
                        fee_payer,
                        &[],
                        None,
                    );
                    return Err(e);
                }
                Ok(sigs)
            }
        }
    }

    /// Local checks for WithdrawSpl (mint policy, decimals, source balance,
    /// destination). Returns instructions to run before `Execute`: creation
    /// of the destination's associated token account, paid by the fee payer,
    /// when the hints name its owner and it does not exist yet.
    fn withdraw_spl_prechecks(
        &self,
        auth: &Authorization,
        fee_payer: &Pubkey,
        accts: &[AccountMeta],
        hints: &Hints,
    ) -> Result<Vec<Instruction>, Error> {
        let mint = self.get_mint(&Pubkey::new_from_array(auth.mint))?;
        if mint.asset_type != auth.asset_type {
            return Err(Error::InvalidInput(format!(
                "authorization says {:?} but the mint belongs to {:?}",
                auth.asset_type, mint.asset_type
            )));
        }
        if mint.info.decimals != auth.decimals {
            return Err(Error::InvalidInput(format!(
                "authorization says {} decimals but the mint has {}",
                auth.decimals, mint.info.decimals
            )));
        }
        let source = accts[0].pubkey;
        let src = self
            .get_token_account(&source, &mint.token_program)?
            .ok_or_else(|| Error::Account(format!("vault token account {source} not found")))?;
        if src.owner != auth.vault
            || src.mint != auth.mint
            || src.state != TokenAccountState::Initialized
        {
            return Err(Error::Account(format!(
                "{source} is not a usable vault token account"
            )));
        }
        if src.amount < auth.amount {
            return Err(Error::InvalidInput(format!(
                "vault holds {} but the authorization moves {}",
                format_token_amount(src.amount, auth.decimals),
                format_token_amount(auth.amount, auth.decimals)
            )));
        }
        let dest = Pubkey::new_from_array(auth.destination);
        match self.get_token_account(&dest, &mint.token_program)? {
            Some(d) if d.mint == auth.mint => Ok(vec![]),
            Some(_) => Err(Error::Account(format!("{dest} holds another mint"))),
            None => {
                let owner: Pubkey = hints
                    .destination_owner
                    .as_ref()
                    .ok_or_else(|| {
                        Error::Account(format!(
                            "destination token account {dest} does not exist (and no owner hint to create it)"
                        ))
                    })?
                    .parse()
                    .map_err(|_| Error::InvalidInput("bad destination owner".into()))?;
                if token::associated_token_address(&owner, &mint.address, &mint.token_program)
                    != dest
                {
                    return Err(Error::InvalidInput(
                        "destination is not the owner's associated token account".into(),
                    ));
                }
                Ok(vec![build::create_ata_idempotent(
                    fee_payer,
                    &owner,
                    &mint.address,
                    &mint.token_program,
                )])
            }
        }
    }

    /// Submits a signed authorization of either QSP-1 version.
    pub fn submit_any(
        &self,
        fee_payer: &Keypair,
        auth: &[u8],
        signature: &[u8],
        hints: &Hints,
        transport: Transport,
    ) -> Result<Vec<Signature>, Error> {
        match auth.len() {
            AUTH_LEN => self.submit(
                fee_payer,
                auth.try_into().expect("length checked"),
                signature,
                hints,
                transport,
            ),
            _ => self.submit_v2(fee_payer, auth, signature, hints, transport),
        }
    }

    /// Size check helper: the signature buffer's rent (refunded after use).
    pub fn sig_buffer_rent(&self) -> Result<u64, Error> {
        self.rpc.minimum_balance_for_rent_exemption(SigBuffer::LEN)
    }
}

/// Builds QSP-1 authorizations without any network access (offline signing).
#[derive(Clone, Copy, Debug)]
pub struct AuthBuilder {
    /// QShield program id.
    pub program_id: Pubkey,
    /// Cluster id.
    pub cluster_id: Bytes32,
}

impl AuthBuilder {
    fn base(
        &self,
        vault: &Pubkey,
        nonce: u64,
        opts: &AuthOptions,
        action: Action,
    ) -> Authorization {
        Authorization {
            cluster_id: self.cluster_id,
            program_id: self.program_id.to_bytes(),
            vault: vault.to_bytes(),
            action,
            asset_type: AssetType::None,
            nonce,
            valid_after: opts.valid_after,
            expires_at: opts.expires_at,
            mint: ZERO32,
            destination: ZERO32,
            amount: 0,
            decimals: 0,
            fee_recipient: if opts.fee_lamports > 0 {
                opts.fee_recipient.map(|p| p.to_bytes()).unwrap_or(ZERO32)
            } else {
                ZERO32
            },
            fee_lamports: opts.fee_lamports,
            new_key_id: ZERO32,
            new_algorithm: 0,
        }
    }

    /// WithdrawSol authorization.
    pub fn withdraw_sol(
        &self,
        vault: &Pubkey,
        nonce: u64,
        to: &Pubkey,
        lamports: u64,
        opts: &AuthOptions,
    ) -> Authorization {
        Authorization {
            asset_type: AssetType::Sol,
            destination: to.to_bytes(),
            amount: lamports,
            ..self.base(vault, nonce, opts, Action::WithdrawSol)
        }
    }

    /// WithdrawSpl authorization. `destination` is a token account (usually
    /// the recipient's associated token account); `decimals` must equal the
    /// mint's, which the program checks.
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw_spl(
        &self,
        vault: &Pubkey,
        nonce: u64,
        asset_type: AssetType,
        mint: &Pubkey,
        destination: &Pubkey,
        amount: u64,
        decimals: u8,
        opts: &AuthOptions,
    ) -> Authorization {
        Authorization {
            asset_type,
            mint: mint.to_bytes(),
            destination: destination.to_bytes(),
            amount,
            decimals,
            ..self.base(vault, nonce, opts, Action::WithdrawSpl)
        }
    }

    /// RotateKey authorization.
    pub fn rotate_key(
        &self,
        vault: &Pubkey,
        nonce: u64,
        new_key_id: &Bytes32,
        opts: &AuthOptions,
    ) -> Authorization {
        Authorization {
            new_key_id: *new_key_id,
            new_algorithm: Algorithm::MlDsa44 as u8,
            ..self.base(vault, nonce, opts, Action::RotateKey)
        }
    }

    /// Pause authorization.
    pub fn pause(&self, vault: &Pubkey, nonce: u64, opts: &AuthOptions) -> Authorization {
        self.base(vault, nonce, opts, Action::Pause)
    }

    /// Unpause authorization.
    pub fn unpause(&self, vault: &Pubkey, nonce: u64, opts: &AuthOptions) -> Authorization {
        self.base(vault, nonce, opts, Action::Unpause)
    }

    /// CloseVault authorization.
    pub fn close_vault(
        &self,
        vault: &Pubkey,
        nonce: u64,
        to: &Pubkey,
        opts: &AuthOptions,
    ) -> Authorization {
        Authorization {
            asset_type: AssetType::Sol,
            destination: to.to_bytes(),
            ..self.base(vault, nonce, opts, Action::CloseVault)
        }
    }
}
