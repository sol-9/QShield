//! Relayer end to end over HTTP, with the compiled vault program in LiteSVM.
#![allow(clippy::result_large_err)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use litesvm::LiteSVM;
use qshield_client::protocol::{cluster, Bytes32};
use qshield_client::rpc::AccountData;
use qshield_client::{AuthOptions, Envelope, Error, LocalKey, PqSigner, QShieldClient, Rpc};
use qshield_relayer::{request_id, Policy, Relayer};
use serde_json::{json, Value};
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

const SOL: u64 = 1_000_000_000;
const NOW: i64 = 1_790_000_000;

#[derive(Clone)]
struct SvmRpc(Arc<Mutex<LiteSVM>>);

impl Rpc for SvmRpc {
    fn get_account(&self, address: &Pubkey) -> Result<Option<AccountData>, Error> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get_account(address)
            .map(|a| AccountData {
                lamports: a.lamports,
                owner: a.owner,
                data: a.data,
            }))
    }
    fn latest_blockhash(&self) -> Result<Hash, Error> {
        let mut svm = self.0.lock().unwrap();
        svm.expire_blockhash();
        Ok(svm.latest_blockhash())
    }
    fn minimum_balance_for_rent_exemption(&self, len: usize) -> Result<u64, Error> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .minimum_balance_for_rent_exemption(len))
    }
    fn send_and_confirm(&self, tx: &VersionedTransaction) -> Result<Signature, Error> {
        self.0
            .lock()
            .unwrap()
            .send_transaction(tx.clone())
            .map(|m| m.signature)
            .map_err(|f| Error::Transaction(format!("{:?}", f.err)))
    }
    fn genesis_hash(&self) -> Result<[u8; 32], Error> {
        Ok([7u8; 32])
    }
}

struct World {
    rpc: SvmRpc,
    client: QShieldClient<SvmRpc>,
    key: LocalKey,
    vault: Pubkey,
}

fn world() -> World {
    let so = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/deploy/qshield_vault.so"
    );
    assert!(std::path::Path::new(so).exists(), "build the program first");
    let mut svm = LiteSVM::new().with_mainnet_features().with_sigverify(true);
    let program_id = Pubkey::new_unique();
    svm.add_program_from_file(program_id, so).unwrap();
    let mut c: solana_clock::Clock = svm.get_sysvar();
    c.unix_timestamp = NOW;
    svm.set_sysvar(&c);
    let wallet = Keypair::new();
    svm.airdrop(&wallet.pubkey(), 100 * SOL).unwrap();
    let rpc = SvmRpc(Arc::new(Mutex::new(svm)));
    let client = QShieldClient::new(rpc.clone(), program_id, cluster::LOCALNET);
    let key = LocalKey::generate().unwrap();
    let (vault, _) = client
        .create_vault(&wallet, key.public_key(), &[9; 32])
        .unwrap();
    client.deposit_sol(&wallet, &vault, SOL).unwrap();
    World {
        rpc,
        client,
        key,
        vault,
    }
}

impl World {
    fn relayer(&self, policy: Policy) -> (Relayer, Keypair, String) {
        let fee_payer = Keypair::new();
        self.rpc
            .0
            .lock()
            .unwrap()
            .airdrop(&fee_payer.pubkey(), 10 * SOL)
            .unwrap();
        let c = QShieldClient::new(self.rpc.clone(), self.client.program_id, cluster::LOCALNET);
        let r = Relayer::start("127.0.0.1:0", c, fee_payer.insecure_clone(), policy, 2).unwrap();
        let base = format!("http://{}", r.addr);
        (r, fee_payer, base)
    }

    fn signed(&self, nonce: u64, to: &Pubkey, lamports: u64, opts: &AuthOptions) -> Value {
        let a = self
            .client
            .withdraw_sol(&self.vault, nonce, to, lamports, opts);
        let mut env = Envelope::new(&a, &self.key.key_id()).unwrap();
        let sig = self
            .key
            .sign_authorization(&env.auth_bytes().unwrap())
            .unwrap();
        env.attach_signature(self.key.public_key(), &sig).unwrap();
        serde_json::from_str(&env.to_json()).unwrap()
    }

    fn balance(&self, k: &Pubkey) -> u64 {
        self.rpc.0.lock().unwrap().get_balance(k).unwrap_or(0)
    }
}

fn opts() -> AuthOptions {
    AuthOptions {
        expires_at: NOW + 3600,
        ..Default::default()
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into()
}

fn get(url: &str) -> (u16, Value) {
    let mut r = agent().get(url).call().unwrap();
    (r.status().as_u16(), r.body_mut().read_json().unwrap())
}

fn post(url: &str, body: &Value) -> (u16, Value) {
    let mut r = agent().post(url).send_json(body).unwrap();
    (r.status().as_u16(), r.body_mut().read_json().unwrap())
}

fn wait(base: &str, id: &str) -> Value {
    for _ in 0..600 {
        let (code, v) = get(&format!("{base}/v1/status/{id}"));
        assert_eq!(code, 200);
        if v["status"] == "confirmed" || v["status"] == "failed" {
            return v;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("request {id} did not finish");
}

#[test]
fn sponsored_withdrawal_through_http() {
    let w = world();
    let (r, fee_payer, base) = w.relayer(Policy::default());
    let (code, info) = get(&format!("{base}/v1/info"));
    assert_eq!(code, 200);
    assert_eq!(info["relayer"], fee_payer.pubkey().to_string());
    assert_eq!(info["cluster"], "localnet");
    assert_eq!(get(&format!("{base}/health")).1["ok"], true);

    let dest = Pubkey::new_unique();
    let env = w.signed(0, &dest, 50_000_000, &opts());
    let (code, v) = post(&format!("{base}/v1/submit"), &json!({ "envelope": env }));
    assert_eq!(code, 202, "{v}");
    let id = v["request_id"].as_str().unwrap().to_string();
    let done = wait(&base, &id);
    assert_eq!(done["status"], "confirmed", "{done}");
    assert_eq!(done["signatures"].as_array().unwrap().len(), 1);
    assert_eq!(w.balance(&dest), 50_000_000);
    // The relayer paid the fee and gained nothing else.
    assert!(w.balance(&fee_payer.pubkey()) < 10 * SOL);

    // Resubmitting the same authorization is deduplicated.
    let (code, v) = post(&format!("{base}/v1/submit"), &json!({ "envelope": env }));
    assert_eq!(code, 200);
    assert_eq!(v["duplicate"], true);
    assert_eq!(v["request_id"], id);

    // Buffered transport.
    let env = w.signed(1, &dest, 1_000_000, &opts());
    let (code, v) = post(
        &format!("{base}/v1/submit"),
        &json!({ "envelope": env, "transport": "buffered" }),
    );
    assert_eq!(code, 202, "{v}");
    let done = wait(&base, v["request_id"].as_str().unwrap());
    assert_eq!(done["status"], "confirmed", "{done}");
    assert_eq!(done["signatures"].as_array().unwrap().len(), 5);
    assert_eq!(w.balance(&dest), 51_000_000);
    assert_eq!(get(&format!("{base}/health")).1["submitted"], 2);
    r.stop();
}

#[test]
fn malformed_tampered_and_foreign_requests_are_rejected_without_spending() {
    let w = world();
    let (r, fee_payer, base) = w.relayer(Policy::default());
    let before = w.balance(&fee_payer.pubkey());
    let dest = Pubkey::new_unique();
    let url = format!("{base}/v1/submit");

    assert_eq!(post(&url, &json!({"nope": 1})).0, 400);
    // Unsigned.
    let mut env = w.signed(0, &dest, 1_000, &opts());
    let mut unsigned = env.clone();
    unsigned.as_object_mut().unwrap().remove("signature_hex");
    assert_eq!(post(&url, &json!({ "envelope": unsigned })).0, 400);
    // Displayed field edited.
    let mut t = env.clone();
    t["fields"]["amount"] = "0.000000001 SOL".into();
    assert_eq!(post(&url, &json!({ "envelope": t })).0, 400);
    // Signed bytes edited (destination): signature no longer verifies.
    let mut t = env.clone();
    let mut b = hex::decode(t["auth_hex"].as_str().unwrap()).unwrap();
    b[178] ^= 1;
    t["auth_hex"] = hex::encode(&b).into();
    assert_eq!(post(&url, &json!({ "envelope": t })).0, 400);
    // Unknown transport.
    assert_eq!(
        post(
            &url,
            &json!({ "envelope": env, "transport": "carrier-pigeon" })
        )
        .0,
        400
    );
    // Another program.
    let other = QShieldClient::new(w.rpc.clone(), Pubkey::new_unique(), cluster::LOCALNET);
    let a = other.withdraw_sol(&w.vault, 0, &dest, 1_000, &opts());
    let mut e = Envelope::new(&a, &w.key.key_id()).unwrap();
    let sig = w.key.sign_authorization(&e.auth_bytes().unwrap()).unwrap();
    e.attach_signature(w.key.public_key(), &sig).unwrap();
    let ev: Value = serde_json::from_str(&e.to_json()).unwrap();
    assert_eq!(post(&url, &json!({ "envelope": ev })).0, 400);
    // Oversized body.
    let big = json!({ "envelope": env, "pad": "x".repeat(40_000) });
    assert_eq!(post(&url, &big).0, 413);

    // Well-formed and self-consistent, but signed by a key that does not
    // control the vault: accepted for processing, then refused by the local
    // chain check before any transaction is sent.
    let attacker = LocalKey::generate().unwrap();
    let a = w.client.withdraw_sol(&w.vault, 0, &dest, 1_000, &opts());
    let mut e = Envelope::new(&a, &attacker.key_id()).unwrap();
    let sig = attacker
        .sign_authorization(&e.auth_bytes().unwrap())
        .unwrap();
    e.attach_signature(attacker.public_key(), &sig).unwrap();
    let ev: Value = serde_json::from_str(&e.to_json()).unwrap();
    let (code, v) = post(&url, &json!({ "envelope": ev }));
    assert_eq!(code, 202);
    let done = wait(&base, v["request_id"].as_str().unwrap());
    assert_eq!(done["status"], "failed");
    assert!(done["error"]
        .as_str()
        .unwrap()
        .contains("not valid for the vault"));

    // Stale nonce: refused locally too.
    env = w.signed(5, &dest, 1_000, &opts());
    let (_, v) = post(&url, &json!({ "envelope": env }));
    let done = wait(&base, v["request_id"].as_str().unwrap());
    assert_eq!(done["status"], "failed");

    assert_eq!(w.balance(&fee_payer.pubkey()), before, "relayer spent fees");
    assert_eq!(w.balance(&dest), 0);
    assert_eq!(get(&format!("{base}/v1/status/{}", "00".repeat(32))).0, 404);
    r.stop();
}

#[test]
fn fee_policy_and_rate_limit() {
    let w = world();
    let policy = Policy {
        min_fee_lamports: 10_000,
        rate_limit_per_minute: 3,
        ..Policy::default()
    };
    let (r, fee_payer, base) = w.relayer(policy);
    let url = format!("{base}/v1/submit");
    let dest = Pubkey::new_unique();

    // No fee: refused (402).
    let (code, v) = post(
        &url,
        &json!({ "envelope": w.signed(0, &dest, 1_000, &opts()) }),
    );
    assert_eq!(code, 402, "{v}");
    // Enough fee, but payable to someone else: refused.
    let elsewhere = AuthOptions {
        fee_lamports: 10_000,
        fee_recipient: Some(Pubkey::new_unique()),
        ..opts()
    };
    assert_eq!(
        post(
            &url,
            &json!({ "envelope": w.signed(0, &dest, 1_000, &elsewhere) })
        )
        .0,
        402
    );
    // Enough fee to the relayer address: accepted, and the relayer is paid.
    let paid = AuthOptions {
        fee_lamports: 10_000,
        fee_recipient: Some(fee_payer.pubkey()),
        ..opts()
    };
    let before = w.balance(&fee_payer.pubkey());
    let (code, v) = post(
        &url,
        &json!({ "envelope": w.signed(0, &dest, 1_000_000, &paid) }),
    );
    assert_eq!(code, 202, "{v}");
    let done = wait(&base, v["request_id"].as_str().unwrap());
    assert_eq!(done["status"], "confirmed", "{done}");
    // Paid 10,000 lamports, spent the 5,000-lamport transaction fee.
    assert_eq!(w.balance(&fee_payer.pubkey()), before + 10_000 - 5_000);

    // Fourth submission within the minute: rate limited (limit 3).
    let (code, _) = post(
        &url,
        &json!({ "envelope": w.signed(1, &dest, 1_000_000, &paid) }),
    );
    assert_eq!(code, 429);
    r.stop();
}

#[test]
fn one_pending_request_per_vault() {
    let w = world();
    // Hold the chain lock so the worker cannot finish the first request.
    let (r, _, base) = w.relayer(Policy::default());
    let url = format!("{base}/v1/submit");
    let dest = Pubkey::new_unique();
    let guard = w.rpc.0.lock().unwrap();
    let e0 = w_signed_unlocked(&w, 0, &dest);
    let (code, v) = post(&url, &json!({ "envelope": e0 }));
    assert_eq!(code, 202);
    let first = v["request_id"].as_str().unwrap().to_string();
    let e1 = w_signed_unlocked(&w, 1, &dest);
    let (code, v) = post(&url, &json!({ "envelope": e1 }));
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains(&first));
    drop(guard);
    assert_eq!(wait(&base, &first)["status"], "confirmed");
    r.stop();
}

/// Builds a signed envelope without touching the (locked) chain.
fn w_signed_unlocked(w: &World, nonce: u64, dest: &Pubkey) -> Value {
    let a = w
        .client
        .auth()
        .withdraw_sol(&w.vault, nonce, dest, 1_000_000, &opts());
    let mut env = Envelope::new(&a, &w.key.key_id()).unwrap();
    let sig = w
        .key
        .sign_authorization(&env.auth_bytes().unwrap())
        .unwrap();
    env.attach_signature(w.key.public_key(), &sig).unwrap();
    let id = request_id(&env.auth_bytes().unwrap());
    assert_eq!(id.len(), 64);
    let _: Bytes32 = hex::decode(&id).unwrap().try_into().unwrap();
    serde_json::from_str(&env.to_json()).unwrap()
}

#[test]
fn forwarded_for_rate_limit_and_rust_client() {
    let w = world();
    let (r, _, base) = w.relayer(Policy {
        rate_limit_per_minute: 1,
        trust_forwarded_for: true,
        ..Policy::default()
    });
    let send = |xff: &str| {
        agent()
            .post(format!("{base}/v1/submit"))
            .header("X-Forwarded-For", xff)
            .send_json(json!({}))
            .unwrap()
            .status()
            .as_u16()
    };
    // Rate limiting keys on the proxy-appended (last) address.
    assert_eq!(send("1.1.1.1, 10.0.0.1"), 400);
    assert_eq!(send("2.2.2.2, 10.0.0.2"), 400);
    assert_eq!(send("9.9.9.9, 10.0.0.1"), 429);

    // The SDK's relayer client (used by `qshield submit --relayer`).
    let rc = qshield_client::relayer::RelayerClient::new(format!("{base}/"));
    assert_eq!(rc.info().unwrap()["cluster"], "localnet");
    let dest = Pubkey::new_unique();
    let env = Envelope::from_json(&w.signed(0, &dest, 2_000_000, &opts()).to_string()).unwrap();
    // This client's address (127.0.0.1, no proxy header) has its own budget.
    let id = rc.submit(&env, qshield_client::Transport::Inline).unwrap();
    assert_eq!(
        rc.wait(&id, Duration::from_secs(30)).unwrap(),
        qshield_client::relayer::RelayOutcome::Confirmed(
            get(&format!("{base}/v1/status/{id}")).1["signatures"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect()
        )
    );
    assert_eq!(w.balance(&dest), 2_000_000);
    r.stop();
}

#[test]
fn guardian_policy_authorizations_through_the_relayer() {
    use qshield_client::protocol::v2::{ActionV2, Role};
    let w = world();
    let (r, _, base) = w.relayer(Policy::default());
    let wallet = Keypair::new();
    w.rpc
        .0
        .lock()
        .unwrap()
        .airdrop(&wallet.pubkey(), 2 * SOL)
        .unwrap();
    let guardian = LocalKey::generate().unwrap();
    let g_acct = w
        .client
        .setup_key(&wallet, &w.vault, guardian.public_key())
        .unwrap();
    let rc = qshield_client::relayer::RelayerClient::new(base.clone());
    let submit = |a: &qshield_client::protocol::v2::AuthorizationV2,
                  key: &LocalKey,
                  hints: qshield_client::envelope::Hints| {
        let mut env = Envelope::new_v2(a, &key.key_id()).unwrap();
        env.hints = hints;
        let b = env.auth_raw().unwrap();
        env.attach_signature(key.public_key(), &key.sign_authorization(&b).unwrap())
            .unwrap();
        let id = rc.submit(&env, qshield_client::Transport::Inline).unwrap();
        rc.wait(&id, Duration::from_secs(30)).unwrap()
    };
    let n = w.client.get_vault(&w.vault).unwrap().state.nonce;
    let mut a = w
        .client
        .v2_base(&w.vault, Role::Everyday, n, ActionV2::EnablePolicy, &opts());
    a.new_key_id = guardian.key_id();
    a.new_algorithm = 1;
    a.limit_lamports = SOL / 10;
    a.limit_period = 86_400;
    let hints = qshield_client::envelope::Hints {
        new_key_account: Some(g_acct.to_string()),
        ..Default::default()
    };
    assert!(matches!(
        submit(&a, &w.key, hints),
        qshield_client::relayer::RelayOutcome::Confirmed(_)
    ));
    // Within the limit: confirmed. Beyond it: the relayer reports the failure, spending nothing.
    let dest = Pubkey::new_unique();
    let send = |amount: u64| {
        let n = w.client.get_vault(&w.vault).unwrap().state.nonce;
        w.client
            .v2_transfer(
                &w.vault,
                Role::Everyday,
                n,
                ActionV2::WithdrawSol,
                None,
                &dest,
                amount,
                &opts(),
            )
            .0
    };
    assert!(matches!(
        submit(&send(SOL / 20), &w.key, Default::default()),
        qshield_client::relayer::RelayOutcome::Confirmed(_)
    ));
    assert_eq!(w.balance(&dest), SOL / 20);
    match submit(&send(SOL / 2), &w.key, Default::default()) {
        qshield_client::relayer::RelayOutcome::Failed(e) => {
            assert!(e.contains("0x5152") || e.contains("Custom(20818)"), "{e}")
        }
        other => panic!("{other:?}"),
    }
    r.stop();
}

/// Signs `a` with `key` and returns the envelope JSON (with `hints`).
fn envelope_json(
    auth_bytes: &[u8],
    env: &mut Envelope,
    key: &LocalKey,
    hints: qshield_client::envelope::Hints,
) -> Value {
    env.hints = hints;
    let sig = key.sign_authorization(auth_bytes).unwrap();
    env.attach_signature(key.public_key(), &sig).unwrap();
    serde_json::from_str(&env.to_json()).unwrap()
}

#[test]
fn rent_the_relayer_would_lose_must_be_paid_by_the_fee() {
    use qshield_client::protocol::AssetType;
    use qshield_vault::token::{associated_token_address, TOKEN_PROGRAM};
    let w = world();
    let (r, fee_payer, base) = w.relayer(Policy::default());
    let url = format!("{base}/v1/submit");
    let rent = w
        .rpc
        .minimum_balance_for_rent_exemption(qshield_vault::token::ACCOUNT_LEN)
        .unwrap();
    let (_, info) = get(&format!("{base}/v1/info"));
    assert_eq!(info["token_account_rent_lamports"]["spl_token"], rent);

    // A token send to a recipient whose token account does not exist: the
    // relayer would pay its rent, so a fee below it is refused, unspent.
    let mint = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let dest = associated_token_address(&owner, &mint, &TOKEN_PROGRAM);
    let hints = qshield_client::envelope::Hints {
        destination_owner: Some(owner.to_string()),
        ..Default::default()
    };
    let spl = |fee: u64| {
        let o = AuthOptions {
            fee_lamports: fee,
            fee_recipient: (fee > 0).then(|| fee_payer.pubkey()),
            ..opts()
        };
        let a =
            w.client
                .auth()
                .withdraw_spl(&w.vault, 0, AssetType::SplToken, &mint, &dest, 1, 0, &o);
        let mut env = Envelope::new(&a, &w.key.key_id()).unwrap();
        envelope_json(&a.encode().unwrap(), &mut env, &w.key, hints.clone())
    };
    let before = w.balance(&fee_payer.pubkey());
    for fee in [0, rent - 1] {
        let (code, v) = post(&url, &json!({ "envelope": spl(fee) }));
        assert_eq!(code, 202, "{v}");
        let done = wait(&base, v["request_id"].as_str().unwrap());
        assert_eq!(done["status"], "failed", "{done}");
        assert!(done["error"].as_str().unwrap().contains("rent"), "{done}");
    }
    assert_eq!(w.balance(&fee_payer.pubkey()), before);
    // A fee covering the rent passes this check (and then fails on the
    // made-up mint, still before anything is spent).
    let (_, v) = post(&url, &json!({ "envelope": spl(rent) }));
    let done = wait(&base, v["request_id"].as_str().unwrap());
    assert_eq!(done["status"], "failed", "{done}");
    assert!(!done["error"].as_str().unwrap().contains("rent"), "{done}");
    assert_eq!(w.balance(&fee_payer.pubkey()), before);
    r.stop();
}

#[test]
fn proposals_must_expire() {
    use qshield_client::protocol::v2::{ActionV2, Role};
    let w = world();
    let (r, _, base) = w.relayer(Policy::default());
    let url = format!("{base}/v1/submit");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let dest = Pubkey::new_unique();
    let propose = |expires_at: i64| {
        let o = AuthOptions {
            expires_at,
            ..Default::default()
        };
        let (a, h) = w.client.v2_transfer(
            &w.vault,
            Role::Everyday,
            0,
            ActionV2::ProposeWithdraw,
            None,
            &dest,
            SOL,
            &o,
        );
        let mut env = Envelope::new_v2(&a, &w.key.key_id()).unwrap();
        envelope_json(&a.encode().unwrap(), &mut env, &w.key, h)
    };
    for exp in [0, now + 30 * 86_400] {
        let (code, v) = post(&url, &json!({ "envelope": propose(exp) }));
        assert_eq!(code, 400, "{v}");
        assert!(v["error"].as_str().unwrap().contains("expire"), "{v}");
    }
    // Within the limit the request is accepted (it then fails on chain: this
    // vault has no guardian policy).
    let (code, v) = post(&url, &json!({ "envelope": propose(now + 86_400) }));
    assert_eq!(code, 202, "{v}");
    r.stop();
}
