//! `qshield` — command-line interface for QShield (research preview).
//!
//! Offline commands (`keygen`, `key`, `auth … --nonce`, `sign`, `verify`) never
//! touch the network, so they can run on an air-gapped machine. Online
//! commands talk to a Solana JSON-RPC endpoint. See `docs/CLI.md`.
//!
//! The PQ secret key only ever exists encrypted on disk and decrypted in
//! memory inside `sign`/`withdraw`/`rotate-key`; it is never printed (except
//! by the explicit `key export-seed` command) or sent anywhere.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use qshield_client::envelope::{b58, Hints};
use qshield_client::policy::SendPath;
use qshield_client::protocol::v2::{ActionV2, AuthorizationV2, Role};
use qshield_client::protocol::AssetType;
use qshield_client::protocol::{cluster, Bytes32};
use qshield_client::rpc::JsonRpc;
use qshield_client::{
    format_token_amount, parse_token_amount, AuthBuilder, AuthOptions, Envelope, KdfParams,
    Keystore, LocalKey, PqSigner, QShieldClient, Transport,
};
use qshield_vault::token;
use sha2::{Digest, Sha256};
use solana_keypair::{read_keypair_file, Keypair};
use solana_pubkey::Pubkey;
use zeroize::Zeroizing;

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

#[derive(Parser)]
#[command(
    name = "qshield",
    version,
    about = "QShield post-quantum vaults for Solana (experimental research preview)"
)]
struct Cli {
    /// Solana JSON-RPC URL.
    #[arg(
        long,
        global = true,
        env = "QSHIELD_RPC_URL",
        default_value = "http://127.0.0.1:8899"
    )]
    url: String,
    /// QShield program id.
    #[arg(long, global = true, env = "QSHIELD_PROGRAM_ID")]
    program_id: Option<Pubkey>,
    /// Cluster the program was built for (must match the RPC endpoint).
    #[arg(long, global = true, env = "QSHIELD_CLUSTER", value_enum, default_value_t = ClusterArg::Localnet)]
    cluster: ClusterArg,
    /// Read key-file passwords from this environment variable instead of prompting.
    /// For automation and tests only: environment variables can leak (process
    /// listings, shell history, CI logs).
    #[arg(long, global = true)]
    password_env: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum ClusterArg {
    Mainnet,
    Devnet,
    Testnet,
    Localnet,
}

impl ClusterArg {
    fn id(self) -> Bytes32 {
        match self {
            Self::Mainnet => cluster::MAINNET_BETA,
            Self::Devnet => cluster::DEVNET,
            Self::Testnet => cluster::TESTNET,
            Self::Localnet => cluster::LOCALNET,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum TransportArg {
    /// One v1 transaction (requires SIMD-0385 on the cluster).
    Inline,
    /// Legacy transactions through a signature buffer (5 transactions).
    Buffered,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new ML-DSA-44 key and write it, encrypted, to a key file. Offline.
    Keygen {
        /// Output key file (must not exist).
        #[arg(long)]
        out: PathBuf,
    },
    /// Inspect key files. Offline.
    #[command(subcommand)]
    Key(KeyCmd),
    /// Vault operations.
    #[command(subcommand)]
    Vault(VaultCmd),
    /// Deposit SOL into a vault (your Solana wallet pays; it gains no authority).
    DepositSol {
        #[arg(long)]
        vault: Pubkey,
        /// Solana keypair file of the depositor.
        #[arg(long)]
        payer: PathBuf,
        /// Amount in SOL, e.g. 0.1.
        #[arg(long)]
        amount: String,
        /// Refuse unless the vault is controlled by this key file's key.
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Deposit SPL Token / Token-2022 tokens from your associated token account
    /// (creates the vault's token account if needed; the mint must be supported).
    DepositSpl {
        #[arg(long)]
        vault: Pubkey,
        /// Solana keypair file of the depositor (token owner, pays fees).
        #[arg(long)]
        payer: PathBuf,
        #[arg(long)]
        mint: Pubkey,
        /// Amount in tokens, e.g. 12.5 (converted with the mint's decimals).
        #[arg(long)]
        amount: String,
        /// Refuse unless the vault is controlled by this key file's key.
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Create an unsigned authorization file. Offline if --nonce and --signer-key-id/--key are given.
    #[command(subcommand)]
    Auth(AuthCmd),
    /// Sign an authorization file with a key file (offline). Shows every field first.
    Sign {
        file: PathBuf,
        #[arg(long)]
        key: PathBuf,
        /// Output file (default: overwrite the input).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Check an authorization file (consistency and signature). Offline.
    Verify { file: PathBuf },
    /// Submit a signed authorization file. Any fee payer works; it gains no authority.
    Submit {
        file: PathBuf,
        /// Solana keypair file paying transaction fees.
        #[arg(long, required_unless_present = "relayer", conflicts_with = "relayer")]
        payer: Option<PathBuf>,
        /// Send through a QShield relayer (it pays the fees) instead of submitting directly.
        #[arg(long, env = "QSHIELD_RELAYER_URL")]
        relayer: Option<String>,
        #[arg(long, value_enum, default_value_t = TransportArg::Inline)]
        transport: TransportArg,
    },
    /// Build, sign and submit a SOL withdrawal in one step (online signer).
    Withdraw {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        #[arg(long)]
        to: Pubkey,
        /// Amount in SOL.
        #[arg(long)]
        amount: String,
        #[arg(long)]
        payer: PathBuf,
        #[command(flatten)]
        opts: OptsArgs,
        #[arg(long, value_enum, default_value_t = TransportArg::Inline)]
        transport: TransportArg,
        #[arg(long)]
        yes: bool,
    },
    /// Build, sign and submit a token withdrawal in one step (online signer).
    WithdrawSpl {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        #[arg(long)]
        mint: Pubkey,
        /// Recipient wallet; tokens go to its associated token account (created if missing, paid by --payer).
        #[arg(long)]
        to: Pubkey,
        /// Amount in tokens, e.g. 12.5.
        #[arg(long)]
        amount: String,
        #[arg(long)]
        payer: PathBuf,
        #[command(flatten)]
        opts: OptsArgs,
        #[arg(long, value_enum, default_value_t = TransportArg::Inline)]
        transport: TransportArg,
        #[arg(long)]
        yes: bool,
    },
    /// Set up a new key and rotate the vault to it, signed by the current key.
    RotateKey {
        /// Current key file.
        #[arg(long)]
        key: PathBuf,
        /// New key file (create it with `qshield keygen`).
        #[arg(long)]
        new_key: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        #[arg(long)]
        payer: PathBuf,
        #[command(flatten)]
        opts: OptsArgs,
        #[arg(long, value_enum, default_value_t = TransportArg::Inline)]
        transport: TransportArg,
        #[arg(long)]
        yes: bool,
    },
    /// Guardian policy: a second, offline key and spending limits (ADR-0018).
    #[command(subcommand)]
    Guardian(GuardianCmd),
    /// Send SOL or tokens from a vault. With a guardian policy: instant when
    /// within the limit or to a saved address; otherwise a proposal for the
    /// guardian to approve (`qshield guardian approve`).
    Send {
        /// Everyday key file.
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        /// Recipient wallet.
        #[arg(long)]
        to: Pubkey,
        /// Amount in SOL (or tokens with --mint).
        #[arg(long)]
        amount: String,
        /// Token mint (omit for SOL).
        #[arg(long)]
        mint: Option<Pubkey>,
        #[command(flatten)]
        sub: SubmitArgs,
    },
    /// Measure local key generation, signing and verification speed. Offline.
    Benchmark {
        #[arg(long, default_value_t = 50)]
        iterations: u32,
    },
}

/// How a v2 authorization is delivered.
#[derive(clap::Args)]
struct SubmitArgs {
    /// Solana keypair paying fees (or use --relayer).
    #[arg(long, conflicts_with = "relayer")]
    payer: Option<PathBuf>,
    /// Submit through a relayer (it pays the fees).
    #[arg(long, env = "QSHIELD_RELAYER_URL")]
    relayer: Option<String>,
    #[arg(long, value_enum, default_value_t = TransportArg::Inline)]
    transport: TransportArg,
    /// Write the unsigned authorization to this file instead (sign it
    /// offline with `qshield sign`, then `qshield submit`).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Do not ask for confirmation before signing.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    opts: OptsArgs,
}

#[derive(Subcommand)]
enum GuardianCmd {
    /// Attach a guardian key and a spending limit to a vault (signed by the
    /// everyday key; the payer funds the guardian's key account, ≈ 0.154 SOL).
    Enable {
        /// Everyday (current) key file.
        #[arg(long)]
        key: PathBuf,
        /// Guardian key file (only its public part is read). Keep the guardian
        /// itself off this machine.
        #[arg(long)]
        guardian: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        /// Solana keypair paying for the guardian key account.
        #[arg(long)]
        key_payer: PathBuf,
        /// Everyday limit in SOL per period.
        #[arg(long)]
        limit: String,
        /// Period in hours (1..720).
        #[arg(long, default_value_t = 24)]
        period_hours: u32,
        #[command(flatten)]
        sub: SubmitArgs,
    },
    /// Show a vault's policy.
    Show { vault: Pubkey },
    /// Freeze the vault (everyday key or guardian).
    Freeze {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        /// Sign as the guardian.
        #[arg(long)]
        as_guardian: bool,
        #[command(flatten)]
        sub: SubmitArgs,
    },
    /// Unfreeze (guardian).
    Unfreeze {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        #[command(flatten)]
        sub: SubmitArgs,
    },
    /// Approve a proposed send (guardian). Shows the proposal's exact effect.
    Approve {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        #[arg(long)]
        proposal: u64,
        /// Recipient wallet for token proposals (creates its token account if missing).
        #[arg(long)]
        to_owner: Option<Pubkey>,
        #[command(flatten)]
        sub: SubmitArgs,
    },
    /// Cancel a proposal.
    Cancel {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        #[arg(long)]
        proposal: u64,
        #[arg(long)]
        as_guardian: bool,
        #[command(flatten)]
        sub: SubmitArgs,
    },
    /// Save an address: sends to it need no approval (guardian).
    AddAddress {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        #[arg(long)]
        address: Pubkey,
        #[command(flatten)]
        sub: SubmitArgs,
    },
    /// Remove a saved address (everyday key or guardian).
    RemoveAddress {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        #[arg(long)]
        address: Pubkey,
        #[arg(long)]
        as_guardian: bool,
        #[command(flatten)]
        sub: SubmitArgs,
    },
    /// Change the limit (guardian: any; everyday key: only lower, same period).
    SetLimit {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        #[arg(long)]
        limit: String,
        #[arg(long, default_value_t = 24)]
        period_hours: u32,
        #[arg(long)]
        as_guardian: bool,
        #[command(flatten)]
        sub: SubmitArgs,
    },
    /// Replace the everyday key (guardian), e.g. after theft. Instant.
    ReplaceKey {
        /// Guardian key file.
        #[arg(long)]
        key: PathBuf,
        /// New everyday key file (create with `qshield keygen`).
        #[arg(long)]
        new_key: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        /// Solana keypair paying for the new key account.
        #[arg(long)]
        key_payer: PathBuf,
        #[command(flatten)]
        sub: SubmitArgs,
    },
    /// Replace the guardian key (guardian).
    ReplaceGuardian {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        new_guardian: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        #[arg(long)]
        key_payer: PathBuf,
        #[command(flatten)]
        sub: SubmitArgs,
    },
    /// Remove the policy (guardian): back to single-key rules.
    Disable {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        vault: Pubkey,
        #[command(flatten)]
        sub: SubmitArgs,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Show the 24-word recovery phrase of a key file (write it on paper). Dangerous.
    ExportPhrase {
        file: PathBuf,
        /// Required: anyone who reads the phrase controls the key.
        #[arg(long)]
        i_understand_this_reveals_my_secret_key: bool,
    },
    /// Restore a key file from a 24-word recovery phrase (read from stdin).
    ImportPhrase {
        /// Output key file (must not exist).
        #[arg(long)]
        out: PathBuf,
        /// Refuse unless the restored key has this key id (hex) — e.g. the vault's key.
        #[arg(long)]
        expect_key_id: Option<String>,
    },
    /// Show the key id and public key of a key file (no password needed).
    Info {
        file: PathBuf,
        /// Print the full public key.
        #[arg(long)]
        public_key: bool,
    },
    /// Print the 32-byte secret seed (for offline backup). Dangerous.
    ExportSeed {
        file: PathBuf,
        /// Required: confirms you understand that anyone with the seed controls the vault.
        #[arg(long)]
        i_understand_this_reveals_my_secret_key: bool,
    },
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Compute a vault address. Offline.
    Address {
        #[arg(long)]
        key: PathBuf,
        #[command(flatten)]
        seed: SeedArgs,
    },
    /// Create a vault controlled by a key file's key (≈ 7 transactions; ≈ 0.157 SOL rent).
    Create {
        #[arg(long)]
        key: PathBuf,
        /// Solana keypair file paying rent and fees (gains no authority).
        #[arg(long)]
        payer: PathBuf,
        #[command(flatten)]
        seed: SeedArgs,
    },
    /// Show a vault's state.
    Info {
        vault: Pubkey,
        /// Also check that the vault is controlled by this key file's key.
        #[arg(long)]
        key: Option<PathBuf>,
    },
}

#[derive(clap::Args)]
struct SeedArgs {
    /// Vault seed as 64 hex characters.
    #[arg(long, conflicts_with = "label")]
    seed: Option<String>,
    /// Vault label; the seed is SHA-256("qshield-vault-label:" ‖ label).
    #[arg(long, default_value = "default")]
    label: String,
}

impl SeedArgs {
    fn seed(&self) -> Result<Bytes32> {
        if let Some(h) = &self.seed {
            return hex::decode(h)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| anyhow!("--seed must be 64 hex characters"));
        }
        let mut h = Sha256::new();
        h.update(b"qshield-vault-label:");
        h.update(self.label.as_bytes());
        Ok(h.finalize().into())
    }
}

#[derive(clap::Args, Clone)]
struct OptsArgs {
    /// Seconds until the authorization expires (0 = never).
    #[arg(long, default_value_t = 3600)]
    expires_in: u64,
    /// Seconds until the authorization becomes valid.
    #[arg(long, default_value_t = 0)]
    valid_in: u64,
    /// Relayer fee in lamports, paid from the vault.
    #[arg(long, default_value_t = 0)]
    fee: u64,
    /// Fee recipient (default: whoever pays the transaction fee).
    #[arg(long)]
    fee_recipient: Option<Pubkey>,
}

impl OptsArgs {
    fn options(&self) -> Result<AuthOptions> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        Ok(AuthOptions {
            valid_after: if self.valid_in == 0 {
                0
            } else {
                now + self.valid_in as i64
            },
            expires_at: if self.expires_in == 0 {
                0
            } else {
                now + self.expires_in as i64
            },
            fee_lamports: self.fee,
            fee_recipient: self.fee_recipient,
        })
    }
}

#[derive(Subcommand)]
enum AuthCmd {
    /// Withdraw SOL to a destination.
    WithdrawSol {
        #[command(flatten)]
        common: AuthCommon,
        #[arg(long)]
        to: Pubkey,
        /// Amount in SOL.
        #[arg(long)]
        amount: String,
    },
    /// Withdraw SPL Token / Token-2022 tokens.
    WithdrawSpl {
        #[command(flatten)]
        common: AuthCommon,
        #[arg(long)]
        mint: Pubkey,
        /// Recipient wallet (tokens go to its associated token account).
        #[arg(long, conflicts_with = "to_token_account")]
        to: Option<Pubkey>,
        /// Recipient token account (instead of --to).
        #[arg(long)]
        to_token_account: Option<Pubkey>,
        /// Amount in tokens, e.g. 12.5.
        #[arg(long)]
        amount: String,
        /// Mint decimals (offline mode; read from the mint otherwise).
        #[arg(long)]
        decimals: Option<u8>,
        /// Token program of the mint (offline mode; read from the mint otherwise).
        #[arg(long, value_enum)]
        token_program: Option<TokenProgramArg>,
    },
    /// Rotate to a new key (its key account must already be set up: see `qshield rotate-key`).
    RotateKey {
        #[command(flatten)]
        common: AuthCommon,
        /// New key file (only its public part is read).
        #[arg(long)]
        new_key: PathBuf,
        /// The new key's ready key account (submission hint).
        #[arg(long)]
        new_key_account: Pubkey,
    },
    /// Pause withdrawals.
    Pause {
        #[command(flatten)]
        common: AuthCommon,
    },
    /// Lift a pause.
    Unpause {
        #[command(flatten)]
        common: AuthCommon,
    },
    /// Close the vault, sending everything above the rent reserve to --to. Irreversible.
    /// Tokens still in the vault's token accounts would be lost: withdraw them first.
    Close {
        #[command(flatten)]
        common: AuthCommon,
        #[arg(long)]
        to: Pubkey,
        /// Close even if the vault still holds tokens (they become unrecoverable),
        /// or if its token balances cannot be checked (offline mode).
        #[arg(long)]
        allow_token_loss: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum TokenProgramArg {
    /// SPL Token.
    Spl,
    /// Token-2022.
    Token2022,
}

#[derive(clap::Args)]
struct AuthCommon {
    #[arg(long)]
    vault: Pubkey,
    /// Output file.
    #[arg(long)]
    out: PathBuf,
    /// Vault nonce (offline mode). Fetched from the chain if omitted.
    #[arg(long)]
    nonce: Option<u64>,
    /// Key id expected to sign (hex). Defaults to --key's id, or the vault's current key.
    #[arg(long)]
    signer_key_id: Option<String>,
    /// Key file whose (public) key id is the expected signer.
    #[arg(long)]
    key: Option<PathBuf>,
    #[command(flatten)]
    opts: OptsArgs,
}

// ------------------------------------------------------------------ helpers

fn read_keystore(path: &Path) -> Result<Keystore> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(Keystore::from_json(&s)?)
}

fn password(cli: &Cli, prompt: &str) -> Result<Zeroizing<String>> {
    if let Some(var) = &cli.password_env {
        return Ok(Zeroizing::new(
            std::env::var(var).with_context(|| format!("environment variable {var} not set"))?,
        ));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

fn unlock(cli: &Cli, path: &Path) -> Result<LocalKey> {
    let ks = read_keystore(path)?;
    let pw = password(cli, &format!("Password for {}: ", path.display()))?;
    Ok(ks.decrypt(&pw)?)
}

/// Public key and key id of a key file that is about to control a vault,
/// taken from the decrypted key: the file's plaintext header is not
/// authenticated on its own, and installing a key nobody can sign with would
/// lock the vault.
fn verified_public_key(cli: &Cli, path: &Path) -> Result<(Vec<u8>, Bytes32)> {
    let k = unlock(cli, path)?;
    Ok((k.public_key().to_vec(), k.key_id()))
}

fn payer(path: &Path) -> Result<Keypair> {
    read_keypair_file(path).map_err(|e| anyhow!("reading Solana keypair {}: {e}", path.display()))
}

fn parse_sol(s: &str) -> Result<u64> {
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    if int.is_empty() && frac.is_empty()
        || frac.len() > 9
        || !int.chars().chain(frac.chars()).all(|c| c.is_ascii_digit())
    {
        bail!("invalid SOL amount {s:?} (use up to 9 decimals, e.g. 0.01)");
    }
    let int: u64 = if int.is_empty() { 0 } else { int.parse()? };
    let frac: u64 = format!("{frac:0<9}").parse()?;
    int.checked_mul(LAMPORTS_PER_SOL)
        .and_then(|x| x.checked_add(frac))
        .ok_or_else(|| anyhow!("amount too large"))
}

fn client(cli: &Cli) -> Result<QShieldClient<JsonRpc>> {
    let program = cli
        .program_id
        .ok_or_else(|| anyhow!("--program-id (or QSHIELD_PROGRAM_ID) is required"))?;
    let c = QShieldClient::new(JsonRpc::new(cli.url.clone()), program, cli.cluster.id());
    c.check_cluster()?;
    Ok(c)
}

fn offline_program(cli: &Cli) -> Result<Pubkey> {
    cli.program_id
        .ok_or_else(|| anyhow!("--program-id (or QSHIELD_PROGRAM_ID) is required"))
}

fn show(fields: &std::collections::BTreeMap<String, String>) {
    let order = [
        "cluster",
        "program_id",
        "vault",
        "action",
        "role",
        "asset",
        "mint",
        "destination",
        "amount",
        "new_key_id",
        "new_algorithm",
        "proposal",
        "limit",
        "address",
        "fee",
        "fee_recipient",
        "nonce",
        "valid_after",
        "expires_at",
    ];
    for k in order {
        if let Some(v) = fields.get(k) {
            eprintln!("  {k:<14} {v}");
        }
    }
}

fn confirm(yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    eprint!("Sign this authorization? [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    if line.trim().eq_ignore_ascii_case("y") {
        Ok(())
    } else {
        bail!("not signed")
    }
}

fn write_new(path: &Path, contents: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {} (refusing to overwrite)", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(contents.as_bytes())?;
    Ok(())
}

fn transport(t: TransportArg) -> Transport {
    match t {
        TransportArg::Inline => Transport::Inline,
        TransportArg::Buffered => Transport::Buffered,
    }
}

/// Signs an envelope after showing the fields computed from its bytes.
fn sign_envelope(env: &mut Envelope, key: &LocalKey, yes: bool) -> Result<()> {
    let auth = env.any()?;
    if hex::encode(key.key_id()) != env.signer_key_id {
        bail!(
            "this key ({}) is not the expected signer ({})",
            hex::encode(key.key_id()),
            env.signer_key_id
        );
    }
    eprintln!("Authorization to sign:");
    show(&auth.describe());
    confirm(yes)?;
    let sig = key.sign_authorization(&env.auth_raw()?)?;
    env.attach_signature(key.public_key(), &sig)?;
    Ok(())
}

/// Signs (or writes for offline signing) and submits a v2 authorization.
fn v2_deliver(
    cli: &Cli,
    c: &QShieldClient<JsonRpc>,
    a: &AuthorizationV2,
    hints: Hints,
    key_path: &Path,
    sub: &SubmitArgs,
) -> Result<()> {
    let ks = read_keystore(key_path)?;
    let mut env = Envelope::new_v2(a, &ks.key_id_bytes()?)?;
    env.hints = hints;
    if let Some(out) = &sub.out {
        write_new(out, &env.to_json())?;
        eprintln!(
            "Wrote unsigned authorization to {} (sign it offline with `qshield sign`):",
            out.display()
        );
        show(&env.fields);
        return Ok(());
    }
    let key = unlock(cli, key_path)?;
    sign_envelope(&mut env, &key, sub.yes)?;
    let sig = env.signature()?.unwrap_or_default();
    match (&sub.relayer, &sub.payer) {
        (Some(url), _) => {
            let r = qshield_client::relayer::RelayerClient::new(url);
            let id = r.submit(&env, transport(sub.transport))?;
            match r.wait(&id, std::time::Duration::from_secs(180))? {
                qshield_client::relayer::RelayOutcome::Confirmed(sigs) => {
                    sigs.iter().for_each(|s| println!("{s}"))
                }
                qshield_client::relayer::RelayOutcome::Failed(e) => bail!("relayer: {e}"),
            }
        }
        (None, Some(p)) => {
            for s in c.submit_v2(
                &payer(p)?,
                &env.auth_raw()?,
                &sig,
                &env.hints,
                transport(sub.transport),
            )? {
                println!("{s}");
            }
        }
        (None, None) => bail!("give --payer, --relayer or --out"),
    }
    Ok(())
}

fn parse_period(hours: u32) -> Result<i64> {
    if !(1..=720).contains(&hours) {
        bail!("--period-hours must be between 1 and 720");
    }
    Ok(hours as i64 * 3600)
}

fn guardian_cmd(cli: &Cli, g: &GuardianCmd) -> Result<()> {
    let c = client(cli)?;
    let role_of = |as_guardian: bool| {
        if as_guardian {
            Role::Guardian
        } else {
            Role::Everyday
        }
    };
    let base = |vault: &Pubkey,
                role: Role,
                action: ActionV2,
                sub: &SubmitArgs|
     -> Result<AuthorizationV2> {
        let v = c.get_vault(vault)?;
        let n = c.role_nonce(&v, role)?;
        Ok(c.v2_base(vault, role, n, action, &sub.opts.options()?))
    };
    match g {
        GuardianCmd::Enable {
            key,
            guardian,
            vault,
            key_payer,
            limit,
            period_hours,
            sub,
        } => {
            let (g_pk, g_id) = verified_public_key(cli, guardian)?;
            let ks = read_keystore(key)?;
            c.get_vault_checked(vault, &ks.key_id_bytes()?)?;
            if g_id == ks.key_id_bytes()? {
                bail!("the guardian must be a different key from the everyday key");
            }
            eprintln!("Setting up the guardian key account (6 transactions)...");
            let g_acct = c.setup_key(&payer(key_payer)?, vault, &g_pk)?;
            let mut a = base(vault, Role::Everyday, ActionV2::EnablePolicy, sub)?;
            a.new_key_id = g_id;
            a.new_algorithm = 1;
            a.limit_lamports = parse_sol(limit)?;
            a.limit_period = parse_period(*period_hours)?;
            let hints = Hints {
                new_key_account: Some(g_acct.to_string()),
                ..Hints::default()
            };
            v2_deliver(cli, &c, &a, hints, key, sub)?;
            eprintln!(
                "Guardian {} attached. Store it OFF this computer (paper or another device).",
                hex::encode(g_id)
            );
        }
        GuardianCmd::Show { vault } => {
            let v = c.get_vault(vault)?;
            match c.get_policy(vault)?.filter(|p| p.enabled) {
                None => println!("no guardian policy (single-key vault)"),
                Some(p) => {
                    let mut now_p = p;
                    now_p.refill(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64);
                    println!("status          {:?}", v.state.status);
                    println!("everyday key    {}", hex::encode(v.state.key_id));
                    println!("guardian key    {}", hex::encode(p.guardian_key_id));
                    println!(
                        "limit           {} per {} h",
                        qshield_client::envelope::sol(p.limit),
                        p.period / 3600
                    );
                    println!(
                        "available now   {}",
                        qshield_client::envelope::sol(now_p.available)
                    );
                    println!("everyday nonce  {}", v.state.nonce);
                    println!("guardian nonce  {}", p.guardian_nonce);
                    for a in &p.saved[..p.saved_len as usize] {
                        println!("saved address   {}", b58(a));
                    }
                }
            }
        }
        GuardianCmd::Freeze {
            key,
            vault,
            as_guardian,
            sub,
        } => {
            let a = base(vault, role_of(*as_guardian), ActionV2::Pause, sub)?;
            v2_deliver(cli, &c, &a, Hints::default(), key, sub)?;
        }
        GuardianCmd::Unfreeze { key, vault, sub } => {
            let a = base(vault, Role::Guardian, ActionV2::Unpause, sub)?;
            v2_deliver(cli, &c, &a, Hints::default(), key, sub)?;
        }
        GuardianCmd::Approve {
            key,
            vault,
            proposal,
            to_owner,
            sub,
        } => {
            let p = c.get_proposal(vault, *proposal)?.ok_or_else(|| {
                anyhow!("proposal {proposal} not found (approved, cancelled or never made)")
            })?;
            let v = c.get_vault(vault)?;
            let n = c.role_nonce(&v, Role::Guardian)?;
            let a = c.approval_for(vault, n, &p, &sub.opts.options()?)?;
            let hints = Hints {
                destination_owner: to_owner.map(|o| o.to_string()),
                ..Hints::default()
            };
            v2_deliver(cli, &c, &a, hints, key, sub)?;
        }
        GuardianCmd::Cancel {
            key,
            vault,
            proposal,
            as_guardian,
            sub,
        } => {
            let mut a = base(vault, role_of(*as_guardian), ActionV2::CancelProposal, sub)?;
            a.ref_id = *proposal;
            v2_deliver(cli, &c, &a, Hints::default(), key, sub)?;
        }
        GuardianCmd::AddAddress {
            key,
            vault,
            address,
            sub,
        } => {
            let mut a = base(vault, Role::Guardian, ActionV2::AddAddress, sub)?;
            a.destination = address.to_bytes();
            v2_deliver(cli, &c, &a, Hints::default(), key, sub)?;
        }
        GuardianCmd::RemoveAddress {
            key,
            vault,
            address,
            as_guardian,
            sub,
        } => {
            let mut a = base(vault, role_of(*as_guardian), ActionV2::RemoveAddress, sub)?;
            a.destination = address.to_bytes();
            v2_deliver(cli, &c, &a, Hints::default(), key, sub)?;
        }
        GuardianCmd::SetLimit {
            key,
            vault,
            limit,
            period_hours,
            as_guardian,
            sub,
        } => {
            let mut a = base(vault, role_of(*as_guardian), ActionV2::SetLimit, sub)?;
            a.limit_lamports = parse_sol(limit)?;
            a.limit_period = parse_period(*period_hours)?;
            v2_deliver(cli, &c, &a, Hints::default(), key, sub)?;
        }
        GuardianCmd::ReplaceKey {
            key,
            new_key,
            vault,
            key_payer,
            sub,
        } => {
            let (n_pk, n_id) = verified_public_key(cli, new_key)?;
            eprintln!("Setting up the new key account (6 transactions)...");
            let acct = c.setup_key(&payer(key_payer)?, vault, &n_pk)?;
            let mut a = base(vault, Role::Guardian, ActionV2::RotateKey, sub)?;
            a.new_key_id = n_id;
            a.new_algorithm = 1;
            let hints = Hints {
                new_key_account: Some(acct.to_string()),
                ..Hints::default()
            };
            v2_deliver(cli, &c, &a, hints, key, sub)?;
        }
        GuardianCmd::ReplaceGuardian {
            key,
            new_guardian,
            vault,
            key_payer,
            sub,
        } => {
            let (n_pk, n_id) = verified_public_key(cli, new_guardian)?;
            eprintln!("Setting up the new guardian key account (6 transactions)...");
            let acct = c.setup_key(&payer(key_payer)?, vault, &n_pk)?;
            let mut a = base(vault, Role::Guardian, ActionV2::RotateGuardian, sub)?;
            a.new_key_id = n_id;
            a.new_algorithm = 1;
            let hints = Hints {
                new_key_account: Some(acct.to_string()),
                ..Hints::default()
            };
            v2_deliver(cli, &c, &a, hints, key, sub)?;
        }
        GuardianCmd::Disable { key, vault, sub } => {
            let a = base(vault, Role::Guardian, ActionV2::DisablePolicy, sub)?;
            v2_deliver(cli, &c, &a, Hints::default(), key, sub)?;
        }
    }
    Ok(())
}

fn send_cmd(
    cli: &Cli,
    key: &Path,
    vault: &Pubkey,
    to: &Pubkey,
    amount: &str,
    mint: &Option<Pubkey>,
    sub: &SubmitArgs,
) -> Result<()> {
    let c = client(cli)?;
    let ks = read_keystore(key)?;
    let v = c.get_vault_checked(vault, &ks.key_id_bytes()?)?;
    let opts = sub.opts.options()?;
    let m = mint.map(|m| c.get_mint(&m)).transpose()?;
    let lamports_or_units = match &m {
        None => parse_sol(amount)?,
        Some(m) => parse_token_amount(amount, m.info.decimals)?,
    };
    let Some(policy) = c.get_policy(vault)?.filter(|p| p.enabled) else {
        bail!("this vault has no guardian policy: use `qshield withdraw` / `withdraw-spl`");
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let path = match &m {
        None => c.sol_send_path(&policy, to, lamports_or_units, opts.fee_lamports, now),
        Some(_) if policy.is_saved(&to.to_bytes()) => SendPath::Instant,
        Some(_) => SendPath::NeedsGuardian,
    };
    let action = match path {
        SendPath::Instant => {
            if m.is_some() {
                ActionV2::WithdrawSpl
            } else {
                ActionV2::WithdrawSol
            }
        }
        SendPath::NeedsGuardian => ActionV2::ProposeWithdraw,
    };
    let (a, hints) = c.v2_transfer(
        vault,
        Role::Everyday,
        v.state.nonce,
        action,
        m.as_ref(),
        to,
        lamports_or_units,
        &opts,
    );
    if action == ActionV2::ProposeWithdraw {
        eprintln!("Beyond your everyday limit or to an unsaved address: this creates proposal {} for your guardian.", v.state.nonce);
    }
    v2_deliver(cli, &c, &a, hints, key, sub)?;
    if action == ActionV2::ProposeWithdraw && sub.out.is_none() {
        eprintln!("Approve on the guardian's device: qshield guardian approve --vault {vault} --proposal {} --key <guardian key>{}",
            v.state.nonce,
            if m.is_some() { format!(" --to-owner {to}") } else { String::new() });
    }
    Ok(())
}

// --------------------------------------------------------------------- main

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(&cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<()> {
    match &cli.cmd {
        Cmd::Keygen { out } => {
            let pw = password(cli, "New key-file password: ")?;
            if cli.password_env.is_none() && *pw != *password(cli, "Repeat password: ")? {
                bail!("passwords do not match");
            }
            if pw.chars().count() < 12 {
                bail!("use a password of at least 12 characters (a passphrase of several random words is best): a stolen key file can be guessed offline without limit");
            }
            let key = LocalKey::generate()?;
            let ks = Keystore::encrypt(&key, &pw, KdfParams::DEFAULT)?;
            write_new(out, &ks.to_json())?;
            eprintln!("Wrote encrypted ML-DSA-44 key to {}", out.display());
            eprintln!("EXPERIMENTAL software key storage. Back up this file and its password: losing either loses any vault it controls.");
            println!("{}", hex::encode(key.key_id()));
        }
        Cmd::Key(KeyCmd::Info { file, public_key }) => {
            let ks = read_keystore(file)?;
            println!("key_id     {}", ks.key_id);
            println!("algorithm  ML-DSA-44");
            if *public_key {
                println!("public_key {}", ks.public_key);
            }
        }
        Cmd::Key(KeyCmd::ExportPhrase {
            file,
            i_understand_this_reveals_my_secret_key,
        }) => {
            if !i_understand_this_reveals_my_secret_key {
                bail!("refusing: pass --i-understand-this-reveals-my-secret-key");
            }
            let key = unlock(cli, file)?;
            eprintln!("WARNING: anyone with these words controls this key. Write them on paper; no photos, no cloud.");
            println!(
                "{}",
                qshield_client::recovery::phrase_from_seed(key.seed()).as_str()
            );
        }
        Cmd::Key(KeyCmd::ImportPhrase { out, expect_key_id }) => {
            eprintln!("Enter the 24-word recovery phrase, then press Enter:");
            let mut line = Zeroizing::new(String::new());
            std::io::stdin().lock().read_line(&mut line)?;
            let seed = qshield_client::recovery::seed_from_phrase(&line)?;
            let key = LocalKey::from_seed(&seed);
            let id = hex::encode(key.key_id());
            if let Some(want) = expect_key_id {
                if want.to_lowercase() != id {
                    bail!("the phrase gives key {id}, not {want}: a word is probably wrong");
                }
            }
            let pw = password(cli, "New key-file password: ")?;
            if pw.chars().count() < 12 {
                bail!("use a password of at least 12 characters");
            }
            write_new(
                out,
                &Keystore::encrypt(&key, &pw, KdfParams::DEFAULT)?.to_json(),
            )?;
            eprintln!("Restored key {id} to {}", out.display());
            println!("{id}");
        }
        Cmd::Key(KeyCmd::ExportSeed {
            file,
            i_understand_this_reveals_my_secret_key,
        }) => {
            if !i_understand_this_reveals_my_secret_key {
                bail!("refusing: pass --i-understand-this-reveals-my-secret-key");
            }
            let key = unlock(cli, file)?;
            eprintln!("WARNING: anyone with this seed controls every vault of this key. Store it offline.");
            println!("{}", hex::encode(key.seed()));
        }
        Cmd::Vault(VaultCmd::Address { key, seed }) => {
            let ks = read_keystore(key)?;
            let program = offline_program(cli)?;
            let v = qshield_vault::instruction::build::vault_address(
                &program,
                &ks.key_id_bytes()?,
                &seed.seed()?,
            )
            .0;
            println!("{v}");
        }
        Cmd::Vault(VaultCmd::Create {
            key,
            payer: p,
            seed,
        }) => {
            let (pk, _) = verified_public_key(cli, key)?;
            let c = client(cli)?;
            let payer = payer(p)?;
            eprintln!("Creating vault (key setup ≈ 6 transactions + initialize)...");
            let (vault, key_account) = c.create_vault(&payer, &pk, &seed.seed()?)?;
            eprintln!("key account {key_account}");
            println!("{vault}");
        }
        Cmd::Vault(VaultCmd::Info { vault, key }) => {
            let c = client(cli)?;
            let v = match key {
                Some(k) => c.get_vault_checked(vault, &read_keystore(k)?.key_id_bytes()?)?,
                None => c.get_vault(vault)?,
            };
            println!("vault        {}", v.address);
            println!("status       {:?}", v.state.status);
            println!("nonce        {}", v.state.nonce);
            println!("key_id       {}", hex::encode(v.state.key_id));
            println!("key_account  {}", b58(&v.state.key_account));
            println!("balance      {}", qshield_client::envelope::sol(v.lamports));
            println!(
                "withdrawable {}",
                qshield_client::envelope::sol(v.available)
            );
            match c.token_balances(vault) {
                Ok(b) if b.is_empty() => println!("tokens       none"),
                Ok(b) => {
                    for t in b {
                        let amount = match c.get_mint(&Pubkey::new_from_array(t.account.mint)) {
                            Ok(m) => format_token_amount(t.account.amount, m.info.decimals),
                            Err(_) => format!("{} base units (unsupported mint)", t.account.amount),
                        };
                        println!(
                            "token        {amount} of mint {} in {}{}",
                            b58(&t.account.mint),
                            t.address,
                            if t.account.state == token::TokenAccountState::Frozen {
                                " (FROZEN)"
                            } else {
                                ""
                            }
                        );
                    }
                }
                Err(e) => println!("tokens       unknown ({e})"),
            }
        }
        Cmd::DepositSol {
            vault,
            payer: p,
            amount,
            key,
        } => {
            let c = client(cli)?;
            match key {
                Some(k) => c.get_vault_checked(vault, &read_keystore(k)?.key_id_bytes()?)?,
                None => c.get_vault(vault)?,
            };
            let sig = c.deposit_sol(&payer(p)?, vault, parse_sol(amount)?)?;
            println!("{sig}");
        }
        Cmd::DepositSpl {
            vault,
            payer: p,
            mint,
            amount,
            key,
        } => {
            let c = client(cli)?;
            match key {
                Some(k) => c.get_vault_checked(vault, &read_keystore(k)?.key_id_bytes()?)?,
                None => c.get_vault(vault)?,
            };
            let m = c.get_mint(mint)?;
            if m.info.has_freeze_authority {
                eprintln!(
                    "note: this mint has a freeze authority, which can freeze the vault's tokens."
                );
            }
            let sig = c.deposit_spl(
                &payer(p)?,
                vault,
                mint,
                parse_token_amount(amount, m.info.decimals)?,
            )?;
            eprintln!("vault token account {}", c.vault_token_address(vault, &m));
            println!("{sig}");
        }
        Cmd::Auth(a) => {
            let common = match a {
                AuthCmd::WithdrawSol { common, .. }
                | AuthCmd::WithdrawSpl { common, .. }
                | AuthCmd::RotateKey { common, .. }
                | AuthCmd::Pause { common }
                | AuthCmd::Unpause { common }
                | AuthCmd::Close { common, .. } => common,
            };
            let program = offline_program(cli)?;
            let mut signer_id = match (&common.signer_key_id, &common.key) {
                (Some(h), _) => Some(
                    hex::decode(h)
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .ok_or_else(|| anyhow!("bad --signer-key-id"))?,
                ),
                (None, Some(k)) => Some(read_keystore(k)?.key_id_bytes()?),
                (None, None) => None,
            };
            if let AuthCmd::Close {
                allow_token_loss, ..
            } = a
            {
                if !allow_token_loss {
                    if common.nonce.is_some() {
                        bail!("offline close cannot check the vault's token balances: withdraw all tokens first, then pass --allow-token-loss");
                    }
                    let held: Vec<_> = client(cli)?
                        .token_balances(&common.vault)
                        .context(
                            "checking the vault's token balances (pass --allow-token-loss to skip)",
                        )?
                        .into_iter()
                        .filter(|t| t.account.amount > 0)
                        .collect();
                    if !held.is_empty() {
                        bail!(
                            "the vault still holds tokens in {} token account(s); closing would make them unrecoverable. Withdraw them first or pass --allow-token-loss",
                            held.len()
                        );
                    }
                }
            }
            let nonce = match common.nonce {
                Some(n) => n,
                None => {
                    let v = client(cli)?.get_vault(&common.vault)?;
                    if let Some(id) = signer_id {
                        if id != v.state.key_id {
                            bail!(
                                "the vault is controlled by key {}, not {}",
                                hex::encode(v.state.key_id),
                                hex::encode(id)
                            );
                        }
                    }
                    signer_id = Some(v.state.key_id);
                    v.state.nonce
                }
            };
            let signer_id =
                signer_id.ok_or_else(|| anyhow!("offline mode needs --signer-key-id or --key"))?;
            let b = auth_builder(&program, cli);
            let (vault, opts) = (&common.vault, common.opts.options()?);
            let mut hints = Hints::default();
            let auth = match a {
                AuthCmd::WithdrawSol { to, amount, .. } => {
                    b.withdraw_sol(vault, nonce, to, parse_sol(amount)?, &opts)
                }
                AuthCmd::RotateKey {
                    new_key,
                    new_key_account,
                    ..
                } => {
                    hints.new_key_account = Some(new_key_account.to_string());
                    b.rotate_key(
                        vault,
                        nonce,
                        &read_keystore(new_key)?.key_id_bytes()?,
                        &opts,
                    )
                }
                AuthCmd::Pause { .. } => b.pause(vault, nonce, &opts),
                AuthCmd::Unpause { .. } => b.unpause(vault, nonce, &opts),
                AuthCmd::Close { to, .. } => b.close_vault(vault, nonce, to, &opts),
                AuthCmd::WithdrawSpl {
                    mint,
                    to,
                    to_token_account,
                    amount,
                    decimals,
                    token_program,
                    ..
                } => {
                    let (asset, decimals) = match (common.nonce, decimals, token_program) {
                        (Some(_), Some(d), Some(t)) => (
                            match t {
                                TokenProgramArg::Spl => AssetType::SplToken,
                                TokenProgramArg::Token2022 => AssetType::Token2022,
                            },
                            *d,
                        ),
                        (Some(_), _, _) => {
                            bail!("offline withdraw-spl needs --decimals and --token-program")
                        }
                        (None, _, _) => {
                            let m = client(cli)?.get_mint(mint)?;
                            if decimals.is_some_and(|d| d != m.info.decimals) {
                                bail!("--decimals differs from the mint's {}", m.info.decimals);
                            }
                            (m.asset_type, m.info.decimals)
                        }
                    };
                    let program = token::program_for(asset).expect("token asset");
                    let dest = match (to, to_token_account) {
                        (Some(owner), None) => {
                            hints.destination_owner = Some(owner.to_string());
                            token::associated_token_address(owner, mint, &program)
                        }
                        (None, Some(t)) => *t,
                        _ => bail!("give --to (recipient wallet) or --to-token-account"),
                    };
                    b.withdraw_spl(
                        vault,
                        nonce,
                        asset,
                        mint,
                        &dest,
                        parse_token_amount(amount, decimals)?,
                        decimals,
                        &opts,
                    )
                }
            };
            let mut env = Envelope::new(&auth, &signer_id)?;
            env.hints = hints;
            write_new(&common.out, &env.to_json())?;
            eprintln!("Wrote unsigned authorization to {}:", common.out.display());
            show(&env.fields);
        }
        Cmd::Sign {
            file,
            key,
            out,
            yes,
        } => {
            let mut env = Envelope::from_json(&std::fs::read_to_string(file)?)?;
            if env.signature_hex.is_some() {
                bail!("{} is already signed", file.display());
            }
            let key = unlock(cli, key)?;
            sign_envelope(&mut env, &key, *yes)?;
            std::fs::write(out.as_ref().unwrap_or(file), env.to_json())?;
            eprintln!("Signed.");
        }
        Cmd::Verify { file } => {
            let env = Envelope::from_json(&std::fs::read_to_string(file)?)?;
            show(&env.fields);
            if env.signature_hex.is_none() {
                bail!("not signed (fields are consistent with the authorization bytes)");
            }
            println!("OK: signature valid for key {}", env.signer_key_id);
        }
        Cmd::Submit {
            file,
            payer: p,
            relayer,
            transport: t,
        } => {
            let env = Envelope::from_json(&std::fs::read_to_string(file)?)?;
            let sig = env
                .signature()?
                .ok_or_else(|| anyhow!("{} is not signed", file.display()))?;
            if let Some(url) = relayer {
                let r = qshield_client::relayer::RelayerClient::new(url);
                let id = r.submit(&env, transport(*t))?;
                eprintln!("relayer request {id}");
                match r.wait(&id, std::time::Duration::from_secs(180))? {
                    qshield_client::relayer::RelayOutcome::Confirmed(sigs) => {
                        for s in sigs {
                            println!("{s}");
                        }
                    }
                    qshield_client::relayer::RelayOutcome::Failed(e) => {
                        bail!("relayer: {e}")
                    }
                }
                return Ok(());
            }
            let p = p.as_ref().expect("required unless --relayer");
            let c = client(cli)?;
            for s in c.submit_any(
                &payer(p)?,
                &env.auth_raw()?,
                &sig,
                &env.hints,
                transport(*t),
            )? {
                println!("{s}");
            }
        }
        Cmd::Withdraw {
            key,
            vault,
            to,
            amount,
            payer: p,
            opts,
            transport: t,
            yes,
        } => {
            let c = client(cli)?;
            let k = unlock(cli, key)?;
            let v = c.get_vault_checked(vault, &k.key_id())?;
            let auth = c.withdraw_sol(
                vault,
                v.state.nonce,
                to,
                parse_sol(amount)?,
                &opts.options()?,
            );
            let mut env = Envelope::new(&auth, &k.key_id())?;
            sign_envelope(&mut env, &k, *yes)?;
            for s in c.submit_any(
                &payer(p)?,
                &env.auth_raw()?,
                &env.signature()?.unwrap_or_default(),
                &env.hints,
                transport(*t),
            )? {
                println!("{s}");
            }
        }
        Cmd::WithdrawSpl {
            key,
            vault,
            mint,
            to,
            amount,
            payer: p,
            opts,
            transport: t,
            yes,
        } => {
            let c = client(cli)?;
            let k = unlock(cli, key)?;
            let v = c.get_vault_checked(vault, &k.key_id())?;
            let m = c.get_mint(mint)?;
            let (auth, hints) = c.withdraw_spl(
                vault,
                v.state.nonce,
                &m,
                to,
                parse_token_amount(amount, m.info.decimals)?,
                &opts.options()?,
            );
            let mut env = Envelope::new(&auth, &k.key_id())?;
            env.hints = hints;
            sign_envelope(&mut env, &k, *yes)?;
            for s in c.submit_any(
                &payer(p)?,
                &env.auth_raw()?,
                &env.signature()?.unwrap_or_default(),
                &env.hints,
                transport(*t),
            )? {
                println!("{s}");
            }
        }
        Cmd::RotateKey {
            key,
            new_key,
            vault,
            payer: p,
            opts,
            transport: t,
            yes,
        } => {
            let c = client(cli)?;
            let k = unlock(cli, key)?;
            let (new_pk, new_id) = verified_public_key(cli, new_key)?;
            let v = c.get_vault_checked(vault, &k.key_id())?;
            let payer = payer(p)?;
            eprintln!("Setting up the new key account (6 transactions)...");
            let new_acct = c.setup_key(&payer, vault, &new_pk)?;
            let auth = c.rotate_key(vault, v.state.nonce, &new_id, &opts.options()?);
            let mut env = Envelope::new(&auth, &k.key_id())?;
            env.hints.new_key_account = Some(new_acct.to_string());
            sign_envelope(&mut env, &k, *yes)?;
            for s in c.submit_any(
                &payer,
                &env.auth_raw()?,
                &env.signature()?.unwrap_or_default(),
                &env.hints,
                transport(*t),
            )? {
                println!("{s}");
            }
            eprintln!("Vault now controlled by key {}", hex::encode(new_id));
        }
        Cmd::Guardian(g) => guardian_cmd(cli, g)?,
        Cmd::Send {
            key,
            vault,
            to,
            amount,
            mint,
            sub,
        } => send_cmd(cli, key, vault, to, amount, mint, sub)?,
        Cmd::Benchmark { iterations } => benchmark(*iterations)?,
    }
    Ok(())
}

/// Offline authorization builder.
fn auth_builder(program: &Pubkey, cli: &Cli) -> AuthBuilder {
    AuthBuilder {
        program_id: *program,
        cluster_id: cli.cluster.id(),
    }
}

fn benchmark(iterations: u32) -> Result<()> {
    let t = Instant::now();
    let keys: Vec<LocalKey> = (0..iterations)
        .map(|_| LocalKey::generate())
        .collect::<Result<_, _>>()?;
    let keygen = t.elapsed() / iterations;
    // A canonical authorization (keys only sign valid QSP-1 messages).
    let auth = AuthBuilder {
        program_id: Pubkey::new_from_array([1; 32]),
        cluster_id: cluster::DEVNET,
    }
    .pause(&Pubkey::new_from_array([2; 32]), 0, &AuthOptions::default())
    .encode()
    .map_err(|e| anyhow!("{e:?}"))?;
    let t = Instant::now();
    let sigs: Vec<_> = keys
        .iter()
        .map(|k| k.sign_authorization(&auth))
        .collect::<Result<_, _>>()?;
    let sign = t.elapsed() / iterations;
    let t = Instant::now();
    for (k, s) in keys.iter().zip(&sigs) {
        if !qshield_client::key::verify_authorization(k.public_key(), &auth, s) {
            bail!("verification failed");
        }
    }
    let verify = t.elapsed() / iterations;
    println!("ML-DSA-44 on this machine ({iterations} iterations, release build recommended):");
    println!("  keygen  {keygen:?}");
    println!("  sign    {sign:?}  (hedged)");
    println!("  verify  {verify:?}  (qshield-mldsa, compact key)");
    println!("On-chain verification: ≈ 828k compute units (docs/BENCHMARKS.md).");
    Ok(())
}
