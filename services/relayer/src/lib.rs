//! # qshield-relayer
//!
//! A permissionless, **untrusted** relayer for QShield (Phase 4, ADR-0016).
//! It accepts signed QSP-1 authorization envelopes over HTTP, checks them,
//! submits them to Solana and pays the transaction fees (gas sponsorship).
//!
//! It never holds a PQ key and never has custody of user funds; it cannot
//! modify a signed authorization (every field is signed, invariants I4/I5).
//! The only key it holds is its own Ed25519 fee-payer key. Users can always
//! submit without it (`qshield submit`); the protocol does not depend on it.
//!
//! API (`docs/RELAYER.md`):
//!
//! | Method | Path | Purpose |
//! |--------|------|---------|
//! | `POST` | `/v1/submit` | Submit a signed envelope; returns a request id |
//! | `GET`  | `/v1/status/{request_id}` | Request status and transaction signatures |
//! | `GET`  | `/v1/info` | Relayer public key, program, cluster, fee policy |
//! | `GET`  | `/health` | Liveness, queue depth, fee-payer balance |
//!
//! Abuse protection: request size limit, per-client rate limit, bounded
//! queue, one pending request per vault, duplicate detection, a minimum fee
//! policy, and full local verification (including the ML-DSA signature
//! against the vault's on-chain key) before any fee is spent. Rent the
//! relayer would lose (a recipient token account it creates) must be covered
//! by the signed fee, and proposals, whose rent is refunded only when they
//! are closed, must expire.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::net::IpAddr;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use qshield_client::envelope::{AnyAuth, Hints};
use qshield_client::protocol::v2::{ActionV2, AuthorizationV2};
use qshield_client::protocol::{Action, AssetType, Authorization, Bytes32, AUTH_LEN, ZERO32};
use qshield_client::{Envelope, QShieldClient, Rpc, Transport};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use tiny_http::{Header, Method, Request, Response, Server};

/// Maximum request body (a signed envelope is ≈ 9 KB).
pub const MAX_BODY: usize = 32 * 1024;

/// Relayer policy.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Minimum `fee_lamports` an authorization must pay to this relayer
    /// (0 = fully sponsored). A fee counts only if its recipient is zero
    /// (the fee payer, i.e. this relayer) or this relayer's address.
    pub min_fee_lamports: u64,
    /// Accept `"transport": "buffered"` (5 legacy transactions; the relayer
    /// temporarily funds a ≈ 0.018 SOL signature buffer, refunded on use).
    pub allow_buffered: bool,
    /// Submissions per client IP per minute.
    pub rate_limit_per_minute: u32,
    /// Maximum queued requests.
    pub max_queue: usize,
    /// Request records kept for status queries.
    pub max_records: usize,
    /// Behind one trusted reverse proxy: rate-limit by the last address in
    /// `X-Forwarded-For` (the one the proxy appended) instead of the TCP peer.
    pub trust_forwarded_for: bool,
    /// Longest lifetime (`expires_at` − now, seconds) accepted for a v2
    /// ProposeWithdraw. The relayer pays the proposal's rent and gets it back
    /// only when the proposal is approved, cancelled or closed after expiry,
    /// so proposals that never expire are refused.
    pub max_proposal_lifetime_secs: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_fee_lamports: 0,
            allow_buffered: true,
            rate_limit_per_minute: 30,
            max_queue: 64,
            max_records: 10_000,
            trust_forwarded_for: false,
            max_proposal_lifetime_secs: 7 * 86_400,
        }
    }
}

/// Lifecycle of a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum Status {
    /// Accepted, waiting for the submission worker.
    Pending,
    /// Being checked against chain state and submitted.
    Submitting,
    /// Confirmed on chain.
    Confirmed {
        /// Transaction signatures, in order.
        signatures: Vec<String>,
    },
    /// Rejected by the chain checks or failed on chain. Nothing was changed
    /// in the vault (failed authorizations change nothing).
    Failed {
        /// Reason.
        error: String,
    },
}

impl Status {
    fn done(&self) -> bool {
        matches!(self, Self::Confirmed { .. } | Self::Failed { .. })
    }
}

/// Body of `POST /v1/submit`.
#[derive(Debug, Deserialize)]
pub struct SubmitRequest {
    /// Signed authorization envelope (`docs/OFFLINE_SIGNING.md`).
    pub envelope: Value,
    /// `"inline"` (default) or `"buffered"`.
    #[serde(default)]
    pub transport: Option<String>,
}

struct Job {
    id: String,
    vault: Bytes32,
    /// QSP-1 v1 (292) or v2 (317) bytes.
    auth: Vec<u8>,
    signature: Vec<u8>,
    hints: Hints,
    transport: Transport,
    /// Signed fee payable to this relayer (0 if it goes elsewhere).
    fee_to_relayer: u64,
}

#[derive(Default)]
struct State {
    records: HashMap<String, Status>,
    order: VecDeque<String>,
    pending_vaults: HashMap<Bytes32, String>,
    rate: HashMap<IpAddr, (Instant, u32)>,
    balance: Option<u64>,
    submitted: u64,
    failed: u64,
}

impl State {
    fn record(&mut self, id: &str, s: Status, max: usize) {
        if !self.records.contains_key(id) {
            self.order.push_back(id.to_string());
        }
        self.records.insert(id.to_string(), s);
        // Evict the oldest finished records beyond the cap.
        let mut scanned = 0;
        while self.records.len() > max && scanned < self.order.len() {
            let old = self.order.pop_front().expect("non-empty");
            if self.records.get(&old).is_some_and(Status::done) {
                self.records.remove(&old);
            } else {
                self.order.push_back(old);
            }
            scanned += 1;
        }
    }

    fn allow(&mut self, ip: IpAddr, limit: u32) -> bool {
        let now = Instant::now();
        if self.rate.len() > 100_000 {
            self.rate
                .retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(60));
        }
        let e = self.rate.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= Duration::from_secs(60) {
            *e = (now, 0);
        }
        if e.1 >= limit {
            return false;
        }
        e.1 += 1;
        true
    }
}

struct Common {
    cluster_id: Bytes32,
    program_id: Bytes32,
    vault: Bytes32,
    fee_recipient: Bytes32,
    fee_lamports: u64,
    /// `expires_at` of a v2 ProposeWithdraw.
    proposal_expires_at: Option<i64>,
}

/// Size of an associated token account: SPL Token, or Token-2022 with the
/// ImmutableOwner extension (none of the mint extensions the program accepts
/// adds an account extension, ADR-0015).
const TOKEN_ACCOUNT_LEN: usize = 165;

fn token_account_len(asset: AssetType) -> Option<usize> {
    match asset {
        AssetType::SplToken => Some(TOKEN_ACCOUNT_LEN),
        AssetType::Token2022 => Some(TOKEN_ACCOUNT_LEN + 1 + 4),
        _ => None,
    }
}

/// Rent the fee payer would spend, and never get back, to submit `auth`:
/// the recipient's token account, created when `hints` name its owner and
/// it does not exist yet.
pub fn unrefunded_rent<R: Rpc>(
    client: &QShieldClient<R>,
    auth: &[u8],
    hints: &Hints,
) -> Result<u64, qshield_client::Error> {
    if hints.destination_owner.is_none() {
        return Ok(0);
    }
    let (asset, destination) = if auth.len() == AUTH_LEN {
        let a = Authorization::decode(auth).map_err(qshield_client::Error::Protocol)?;
        if a.action != Action::WithdrawSpl {
            return Ok(0);
        }
        (a.asset_type, a.destination)
    } else {
        let a = AuthorizationV2::decode(auth).map_err(qshield_client::Error::Protocol)?;
        if !matches!(a.action, ActionV2::WithdrawSpl | ActionV2::ApproveWithdraw) {
            return Ok(0);
        }
        (a.asset_type, a.destination)
    };
    let Some(len) = token_account_len(asset) else {
        return Ok(0);
    };
    if client
        .rpc
        .get_account(&Pubkey::new_from_array(destination))?
        .is_some()
    {
        return Ok(0);
    }
    client.rpc.minimum_balance_for_rent_exemption(len)
}

/// Request id: hex SHA-256 of the authorization bytes (identical requests
/// share an id, so resubmissions are deduplicated).
pub fn request_id(auth: &[u8]) -> String {
    hex::encode(Sha256::digest(auth))
}

/// Static facts reported by `/v1/info`.
#[derive(Clone, Debug)]
struct Info {
    relayer: Pubkey,
    program_id: Pubkey,
    cluster_id: Bytes32,
    /// Rent of a new recipient token account (SPL Token, Token-2022).
    token_account_rent: (Option<u64>, Option<u64>),
}

/// A running relayer.
pub struct Relayer {
    /// Address the HTTP server listens on.
    pub addr: std::net::SocketAddr,
    server: Arc<Server>,
    threads: Vec<JoinHandle<()>>,
}

impl Relayer {
    /// Starts the HTTP server on `bind` (use port 0 for an ephemeral port)
    /// with `http_threads` request threads and one submission worker that
    /// owns `client` and the fee-payer key.
    pub fn start<R: Rpc + Send + 'static>(
        bind: &str,
        client: QShieldClient<R>,
        fee_payer: Keypair,
        policy: Policy,
        http_threads: usize,
    ) -> anyhow::Result<Self> {
        let server = Arc::new(Server::http(bind).map_err(|e| anyhow::anyhow!("bind {bind}: {e}"))?);
        let addr = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| anyhow::anyhow!("not an IP listener"))?;
        let state = Arc::new(Mutex::new(State::default()));
        let rent = |a| {
            token_account_len(a).and_then(|n| client.rpc.minimum_balance_for_rent_exemption(n).ok())
        };
        let info = Info {
            relayer: fee_payer.pubkey(),
            program_id: client.program_id,
            cluster_id: client.cluster_id,
            token_account_rent: (rent(AssetType::SplToken), rent(AssetType::Token2022)),
        };
        let (tx, rx) = sync_channel::<Job>(policy.max_queue);
        let mut threads = vec![];
        {
            let state = state.clone();
            let policy = policy.clone();
            threads.push(std::thread::spawn(move || {
                worker(client, fee_payer, rx, state, policy)
            }));
        }
        for _ in 0..http_threads.max(1) {
            let (server, state, tx, info, policy) = (
                server.clone(),
                state.clone(),
                tx.clone(),
                info.clone(),
                policy.clone(),
            );
            threads.push(std::thread::spawn(move || {
                while let Ok(req) = server.recv() {
                    handle(req, &state, &tx, &info, &policy);
                }
            }));
        }
        Ok(Self {
            addr,
            server,
            threads,
        })
    }

    /// Stops accepting requests and waits for the HTTP threads.
    pub fn stop(self) {
        self.server.unblock();
        for _ in 1..self.threads.len() {
            self.server.unblock();
        }
        // The worker exits when every sender (held by HTTP threads) is dropped.
        for t in self.threads {
            let _ = t.join();
        }
    }
}

fn worker<R: Rpc>(
    client: QShieldClient<R>,
    fee_payer: Keypair,
    rx: Receiver<Job>,
    state: Arc<Mutex<State>>,
    policy: Policy,
) {
    let balance = |c: &QShieldClient<R>| {
        c.rpc
            .get_account(&fee_payer.pubkey())
            .ok()
            .flatten()
            .map(|a| a.lamports)
    };
    state.lock().unwrap().balance = balance(&client);
    while let Ok(job) = rx.recv() {
        state
            .lock()
            .unwrap()
            .record(&job.id, Status::Submitting, policy.max_records);
        // Rent this relayer would lose must be paid by the signed fee.
        // `submit` re-checks cluster, program, nonce and the ML-DSA signature
        // against the vault's current on-chain key before sending anything,
        // and the RPC node simulates (preflight) before broadcasting.
        let result = unrefunded_rent(&client, &job.auth, &job.hints).and_then(|rent| {
            let need = policy.min_fee_lamports.saturating_add(rent);
            if rent > 0 && job.fee_to_relayer < need {
                return Err(qshield_client::Error::InvalidInput(format!(
                    "this relayer requires fee_lamports >= {need} payable to it: the minimum fee plus {rent} lamports of rent to open the recipient's token account (or create that account first)"
                )));
            }
            client.submit_any(
                &fee_payer,
                &job.auth,
                &job.signature,
                &job.hints,
                job.transport,
            )
        });
        let status = match result {
            Ok(sigs) => Status::Confirmed {
                signatures: sigs.iter().map(ToString::to_string).collect(),
            },
            Err(e) => Status::Failed {
                error: e.to_string(),
            },
        };
        let bal = balance(&client);
        let mut st = state.lock().unwrap();
        match status {
            Status::Confirmed { .. } => st.submitted += 1,
            _ => st.failed += 1,
        }
        st.record(&job.id, status, policy.max_records);
        st.pending_vaults.remove(&job.vault);
        st.balance = bal;
    }
}

fn json_response(code: u16, v: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(v.to_string())
        .with_status_code(code)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        .with_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap())
        .with_header(Header::from_bytes("Access-Control-Allow-Headers", "content-type").unwrap())
        .with_header(
            Header::from_bytes("Access-Control-Allow-Methods", "GET, POST, OPTIONS").unwrap(),
        )
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
}

fn err(code: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(code, &json!({ "error": msg }))
}

fn handle(
    mut req: Request,
    state: &Mutex<State>,
    tx: &SyncSender<Job>,
    info: &Info,
    policy: &Policy,
) {
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("");
    let resp = match (req.method(), path) {
        (Method::Options, _) => json_response(204, &Value::Null),
        (Method::Get, "/health") => {
            let st = state.lock().unwrap();
            json_response(
                200,
                &json!({
                    "ok": true,
                    "relayer": info.relayer.to_string(),
                    "fee_payer_balance_lamports": st.balance,
                    "pending": st.pending_vaults.len(),
                    "submitted": st.submitted,
                    "failed": st.failed,
                }),
            )
        }
        (Method::Get, "/v1/info") => json_response(
            200,
            &json!({
                "relayer": info.relayer.to_string(),
                "program_id": info.program_id.to_string(),
                "cluster": qshield_client::envelope::cluster_name(&info.cluster_id),
                "cluster_id": hex::encode(info.cluster_id),
                "min_fee_lamports": policy.min_fee_lamports,
                "token_account_rent_lamports": {
                    "spl_token": info.token_account_rent.0,
                    "token_2022": info.token_account_rent.1,
                },
                "max_proposal_lifetime_secs": policy.max_proposal_lifetime_secs,
                "fee_recipient": "zero (transaction fee payer) or the relayer address",
                "transports": if policy.allow_buffered { vec!["inline", "buffered"] } else { vec!["inline"] },
                "rate_limit_per_minute": policy.rate_limit_per_minute,
                "custody": "none: the relayer holds no PQ key and cannot change a signed authorization",
            }),
        ),
        (Method::Get, p) if p.starts_with("/v1/status/") => {
            let id = &p["/v1/status/".len()..];
            match state.lock().unwrap().records.get(id) {
                Some(s) => {
                    let mut v = serde_json::to_value(s).unwrap();
                    v["request_id"] = id.into();
                    json_response(200, &v)
                }
                None => err(404, "unknown request id"),
            }
        }
        (Method::Post, "/v1/submit") => submit(&mut req, state, tx, info, policy),
        _ => err(404, "not found"),
    };
    let _ = req.respond(resp);
}

fn submit(
    req: &mut Request,
    state: &Mutex<State>,
    tx: &SyncSender<Job>,
    info: &Info,
    policy: &Policy,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let peer = req
        .remote_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let forwarded = policy
        .trust_forwarded_for
        .then(|| {
            req.headers()
                .iter()
                .find(|h| h.field.equiv("X-Forwarded-For"))
                .and_then(|h| h.value.as_str().rsplit(',').next())
                .and_then(|v| v.trim().parse::<IpAddr>().ok())
        })
        .flatten();
    let ip = forwarded.unwrap_or(peer);
    if !state
        .lock()
        .unwrap()
        .allow(ip, policy.rate_limit_per_minute)
    {
        return err(429, "rate limit exceeded");
    }
    if req.body_length().is_some_and(|n| n > MAX_BODY) {
        return err(413, "request too large");
    }
    let mut body = Vec::new();
    if req
        .as_reader()
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut body)
        .is_err()
    {
        return err(400, "unreadable body");
    }
    if body.len() > MAX_BODY {
        return err(413, "request too large");
    }
    let r: SubmitRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return err(
                400,
                "body must be {\"envelope\": {...}, \"transport\"?: \"inline\"|\"buffered\"}",
            )
        }
    };
    // Format checks: rendering matches bytes, signature verifies under the
    // embedded public key whose id is `signer_key_id` (Envelope::from_json).
    let env = match Envelope::from_json(&r.envelope.to_string()) {
        Ok(e) => e,
        Err(e) => return err(400, &e.to_string()),
    };
    let (Ok(any), Ok(bytes), Ok(Some(signature))) = (env.any(), env.auth_raw(), env.signature())
    else {
        return err(400, "envelope must be signed");
    };
    // The fields the relayer checks sit at the same offsets in v1 and v2.
    let auth = match any {
        AnyAuth::V1(a) => Common {
            cluster_id: a.cluster_id,
            program_id: a.program_id,
            vault: a.vault,
            fee_recipient: a.fee_recipient,
            fee_lamports: a.fee_lamports,
            proposal_expires_at: None,
        },
        AnyAuth::V2(a) => Common {
            cluster_id: a.cluster_id,
            program_id: a.program_id,
            vault: a.vault,
            fee_recipient: a.fee_recipient,
            fee_lamports: a.fee_lamports,
            proposal_expires_at: (a.action == ActionV2::ProposeWithdraw).then_some(a.expires_at),
        },
    };
    if auth.cluster_id != info.cluster_id {
        return err(400, "authorization is for another cluster");
    }
    if auth.program_id != info.program_id.to_bytes() {
        return err(400, "authorization is for another program");
    }
    let to_relayer = auth.fee_recipient == ZERO32 || auth.fee_recipient == info.relayer.to_bytes();
    if policy.min_fee_lamports > 0 && (!to_relayer || auth.fee_lamports < policy.min_fee_lamports) {
        return err(
            402,
            &format!(
                "this relayer requires fee_lamports >= {} payable to the fee payer (fee_recipient zero or {})",
                policy.min_fee_lamports, info.relayer
            ),
        );
    }
    if let Some(exp) = auth.proposal_expires_at {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        if exp == 0 || exp.saturating_sub(now) > policy.max_proposal_lifetime_secs {
            return err(
                400,
                &format!(
                    "proposals must expire within {} s (this relayer pays their rent until they are closed)",
                    policy.max_proposal_lifetime_secs
                ),
            );
        }
    }
    let transport = match r.transport.as_deref() {
        None | Some("inline") => Transport::Inline,
        Some("buffered") if policy.allow_buffered => Transport::Buffered,
        Some("buffered") => return err(400, "buffered transport disabled on this relayer"),
        Some(_) => return err(400, "transport must be inline or buffered"),
    };
    let id = request_id(&bytes);
    let mut st = state.lock().unwrap();
    if let Some(s) = st.records.get(&id) {
        if !matches!(s, Status::Failed { .. }) {
            let mut v = serde_json::to_value(s).unwrap();
            v["request_id"] = id.clone().into();
            v["duplicate"] = true.into();
            return json_response(200, &v);
        }
    }
    if let Some(other) = st.pending_vaults.get(&auth.vault) {
        return err(
            409,
            &format!("another request for this vault is in progress ({other})"),
        );
    }
    let job = Job {
        id: id.clone(),
        vault: auth.vault,
        auth: bytes,
        signature,
        hints: env.hints.clone(),
        transport,
        fee_to_relayer: if to_relayer { auth.fee_lamports } else { 0 },
    };
    match tx.try_send(job) {
        Ok(()) => {
            st.pending_vaults.insert(auth.vault, id.clone());
            st.record(&id, Status::Pending, policy.max_records);
            json_response(202, &json!({ "request_id": id, "status": "pending" }))
        }
        Err(TrySendError::Full(_)) => err(503, "queue full, retry later"),
        Err(TrySendError::Disconnected(_)) => err(503, "relayer shutting down"),
    }
}
