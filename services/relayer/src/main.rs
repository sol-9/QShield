//! `qshield-relayer` — self-hostable QShield relayer (see `docs/RELAYER.md`).

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use qshield_client::protocol::{cluster, Bytes32};
use qshield_client::rpc::JsonRpc;
use qshield_client::QShieldClient;
use qshield_relayer::{Policy, Relayer};
use solana_keypair::{read_keypair_file, Keypair};
use solana_pubkey::Pubkey;
use solana_signer::Signer;

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

/// Untrusted QShield relayer: submits signed authorizations and pays fees.
#[derive(Parser)]
#[command(name = "qshield-relayer", version)]
struct Args {
    /// Address to listen on.
    #[arg(long, env = "QSHIELD_RELAYER_BIND", default_value = "127.0.0.1:8787")]
    bind: String,
    /// Solana JSON-RPC URL.
    #[arg(long, env = "QSHIELD_RPC_URL", default_value = "http://127.0.0.1:8899")]
    url: String,
    /// QShield program id.
    #[arg(long, env = "QSHIELD_PROGRAM_ID")]
    program_id: Pubkey,
    /// Cluster the program was built for.
    #[arg(long, env = "QSHIELD_CLUSTER", value_enum, default_value_t = ClusterArg::Localnet)]
    cluster: ClusterArg,
    /// Fee-payer keypair file (the relayer's only key; keep little SOL in it).
    /// Without it, the keypair is read as a JSON byte array from the
    /// environment variable QSHIELD_RELAYER_KEYPAIR_JSON (for hosted secrets).
    #[arg(long, env = "QSHIELD_RELAYER_KEYPAIR")]
    keypair: Option<PathBuf>,
    /// Minimum signed fee per authorization, in lamports (0 = sponsor all fees).
    #[arg(long, env = "QSHIELD_RELAYER_MIN_FEE", default_value_t = 0)]
    min_fee_lamports: u64,
    /// Disable the buffered (legacy, 5-transaction) transport.
    #[arg(long)]
    no_buffered: bool,
    /// Submissions per client IP per minute.
    #[arg(long, default_value_t = 30)]
    rate_limit: u32,
    /// Maximum queued requests.
    #[arg(long, default_value_t = 64)]
    max_queue: usize,
    /// Rate-limit by the address a single trusted reverse proxy appends to
    /// X-Forwarded-For (only when the relayer is reachable solely through it).
    #[arg(long)]
    trust_proxy: bool,
    /// HTTP worker threads.
    #[arg(long, default_value_t = 4)]
    http_threads: usize,
    /// Longest accepted proposal lifetime, in hours (proposals that never
    /// expire are refused: the relayer pays their rent until they are closed).
    #[arg(long, default_value_t = 168)]
    max_proposal_hours: i64,
}

fn main() -> Result<()> {
    let a = Args::parse();
    let fee_payer = match &a.keypair {
        Some(path) => read_keypair_file(path)
            .map_err(|e| anyhow!("reading keypair {}: {e}", path.display()))?,
        None => {
            let json = std::env::var("QSHIELD_RELAYER_KEYPAIR_JSON").map_err(|_| {
                anyhow!("set --keypair (QSHIELD_RELAYER_KEYPAIR) or QSHIELD_RELAYER_KEYPAIR_JSON")
            })?;
            let bytes: Vec<u8> = serde_json::from_str(&json).map_err(|_| anyhow!("QSHIELD_RELAYER_KEYPAIR_JSON must be a JSON byte array, as written by solana-keygen"))?;
            Keypair::try_from(bytes.as_slice())
                .map_err(|e| anyhow!("QSHIELD_RELAYER_KEYPAIR_JSON: {e}"))?
        }
    };
    let client = QShieldClient::new(JsonRpc::new(a.url.clone()), a.program_id, a.cluster.id());
    client.check_cluster()?;
    let policy = Policy {
        min_fee_lamports: a.min_fee_lamports,
        allow_buffered: !a.no_buffered,
        rate_limit_per_minute: a.rate_limit,
        max_queue: a.max_queue,
        trust_forwarded_for: a.trust_proxy,
        max_proposal_lifetime_secs: a.max_proposal_hours.saturating_mul(3600),
        ..Policy::default()
    };
    let r = Relayer::start(
        &a.bind,
        client,
        fee_payer.insecure_clone(),
        policy,
        a.http_threads,
    )?;
    eprintln!(
        "qshield-relayer listening on http://{} (fee payer {}, program {})",
        r.addr,
        fee_payer.pubkey(),
        a.program_id
    );
    eprintln!("The relayer holds no PQ keys and cannot alter signed authorizations.");
    // Serve until killed.
    loop {
        std::thread::park();
    }
}
