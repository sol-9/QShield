//! End-to-end SDK test: the public `qshield-client` API driving the compiled
//! program (`target/deploy/qshield_vault.so`, cluster-localnet) in LiteSVM
//! through an [`Rpc`] implementation.
#![allow(clippy::result_large_err)]

use std::cell::RefCell;

use litesvm::LiteSVM;
use qshield_client::envelope::Hints;
use qshield_client::protocol::{cluster, Bytes32};
use qshield_client::rpc::AccountData;
use qshield_client::{
    AuthOptions, Envelope, Error, KdfParams, Keystore, LocalKey, PqSigner, QShieldClient, Rpc,
    Transport,
};
use qshield_vault::state::VaultStatus;
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

const SOL: u64 = 1_000_000_000;
const NOW: i64 = 1_790_000_000;

struct SvmRpc(RefCell<LiteSVM>);

impl Rpc for SvmRpc {
    fn get_account(&self, address: &Pubkey) -> Result<Option<AccountData>, Error> {
        Ok(self.0.borrow().get_account(address).map(|a| AccountData {
            lamports: a.lamports,
            owner: a.owner,
            data: a.data,
        }))
    }
    fn latest_blockhash(&self) -> Result<Hash, Error> {
        let mut svm = self.0.borrow_mut();
        svm.expire_blockhash();
        Ok(svm.latest_blockhash())
    }
    fn minimum_balance_for_rent_exemption(&self, len: usize) -> Result<u64, Error> {
        Ok(self.0.borrow().minimum_balance_for_rent_exemption(len))
    }
    fn send_and_confirm(&self, tx: &VersionedTransaction) -> Result<Signature, Error> {
        // Same size rules as the network.
        let size = qshield_client::rpc::serialize_tx(tx)?.len();
        let limit = if matches!(tx.message, solana_message::VersionedMessage::V1(_)) {
            4096
        } else {
            1232
        };
        assert!(size <= limit, "transaction of {size} bytes exceeds {limit}");
        self.0
            .borrow_mut()
            .send_transaction(tx.clone())
            .map(|m| m.signature)
            .map_err(|f| Error::Transaction(format!("{:?} {:?}", f.err, f.meta.logs)))
    }
    fn genesis_hash(&self) -> Result<[u8; 32], Error> {
        Ok([7u8; 32])
    }
}

fn setup() -> (QShieldClient<SvmRpc>, Keypair, Keypair) {
    let so = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/deploy/qshield_vault.so"
    );
    assert!(
        std::path::Path::new(so).exists(),
        "build the program first (cluster-localnet)"
    );
    let mut svm = LiteSVM::new().with_mainnet_features().with_sigverify(true);
    let program_id = Pubkey::new_unique();
    svm.add_program_from_file(program_id, so).unwrap();
    let mut c: solana_clock::Clock = svm.get_sysvar();
    c.unix_timestamp = NOW;
    svm.set_sysvar(&c);
    let wallet = Keypair::new();
    let relayer = Keypair::new();
    svm.airdrop(&wallet.pubkey(), 100 * SOL).unwrap();
    svm.airdrop(&relayer.pubkey(), 100 * SOL).unwrap();
    (
        QShieldClient::new(SvmRpc(RefCell::new(svm)), program_id, cluster::LOCALNET),
        wallet,
        relayer,
    )
}

fn opts() -> AuthOptions {
    AuthOptions {
        expires_at: NOW + 3600,
        ..Default::default()
    }
}

#[test]
fn full_lifecycle_through_the_sdk() {
    let (client, wallet, relayer) = setup();

    // Key generated locally, stored encrypted, reloaded.
    let key = LocalKey::generate().unwrap();
    let ks = Keystore::encrypt(&key, "pw", KdfParams::INSECURE_TEST).unwrap();
    let key = Keystore::from_json(&ks.to_json())
        .unwrap()
        .decrypt("pw")
        .unwrap();

    let seed: Bytes32 = [1; 32];
    let (vault, key_acct) = client
        .create_vault(&wallet, key.public_key(), &seed)
        .unwrap();
    assert_eq!(vault, client.vault_address(&key.key_id(), &seed));
    client.deposit_sol(&wallet, &vault, SOL).unwrap();
    let info = client.get_vault_checked(&vault, &key.key_id()).unwrap();
    assert_eq!(info.state.key_account, key_acct.to_bytes());
    assert!(
        client.get_vault_checked(&vault, &[0; 32]).is_err(),
        "deposit check must catch a foreign key"
    );

    // Inline (v1) withdrawal paid by an untrusted relayer.
    let dest = Pubkey::new_unique();
    let a = client
        .withdraw_sol(&vault, 0, &dest, 10_000_000, &opts())
        .encode()
        .unwrap();
    let sig = key.sign_authorization(&a).unwrap();
    client
        .submit(&relayer, &a, &sig, &Hints::default(), Transport::Inline)
        .unwrap();
    assert_eq!(
        client.rpc.get_account(&dest).unwrap().unwrap().lamports,
        10_000_000
    );

    // Replay is refused locally (nonce) before any transaction is sent.
    assert!(client
        .submit(&relayer, &a, &sig, &Hints::default(), Transport::Inline)
        .is_err());

    // Offline flow: build on the online machine, sign "offline", submit (buffered).
    let auth = client.withdraw_sol(&vault, 1, &dest, 5_000_000, &opts());
    let unsigned = Envelope::new(&auth, &key.key_id()).unwrap().to_json();
    let mut on_signer = Envelope::from_json(&unsigned).unwrap(); // air-gapped machine
    let s = key
        .sign_authorization(&on_signer.auth_bytes().unwrap())
        .unwrap();
    on_signer.attach_signature(key.public_key(), &s).unwrap();
    let signed = on_signer.to_json();
    let back = Envelope::from_json(&signed).unwrap(); // online machine
    let sigs = client
        .submit(
            &relayer,
            &back.auth_bytes().unwrap(),
            &back.signature().unwrap().unwrap(),
            &back.hints,
            Transport::Buffered,
        )
        .unwrap();
    assert_eq!(sigs.len(), 5);
    assert_eq!(
        client.rpc.get_account(&dest).unwrap().unwrap().lamports,
        15_000_000
    );

    // A signature by the wrong key is rejected locally.
    let other = LocalKey::generate().unwrap();
    let a = client.pause(&vault, 2, &opts()).encode().unwrap();
    let bad = other.sign_authorization(&a).unwrap();
    assert!(client
        .submit(&relayer, &a, &bad, &Hints::default(), Transport::Inline)
        .is_err());

    // Pause / unpause.
    client
        .submit(
            &relayer,
            &a,
            &key.sign_authorization(&a).unwrap(),
            &Hints::default(),
            Transport::Inline,
        )
        .unwrap();
    assert_eq!(
        client.get_vault(&vault).unwrap().state.status,
        VaultStatus::Paused
    );
    let a = client.unpause(&vault, 3, &opts()).encode().unwrap();
    client
        .submit(
            &relayer,
            &a,
            &key.sign_authorization(&a).unwrap(),
            &Hints::default(),
            Transport::Inline,
        )
        .unwrap();

    // Rotation to a new key, with a relayer fee to an explicit recipient.
    let new_key = LocalKey::generate().unwrap();
    let new_acct = client
        .setup_key(&wallet, &vault, new_key.public_key())
        .unwrap();
    let fee_to = relayer.pubkey();
    let o = AuthOptions {
        fee_lamports: 20_000,
        fee_recipient: Some(fee_to),
        ..opts()
    };
    let a = client
        .rotate_key(&vault, 4, &new_key.key_id(), &o)
        .encode()
        .unwrap();
    let hints = Hints {
        new_key_account: Some(new_acct.to_string()),
        ..Hints::default()
    };
    client
        .submit(
            &relayer,
            &a,
            &key.sign_authorization(&a).unwrap(),
            &hints,
            Transport::Inline,
        )
        .unwrap();
    assert_eq!(
        client.get_vault(&vault).unwrap().state.key_id,
        new_key.key_id()
    );

    // Old key now useless; new key closes the vault.
    let a = client
        .withdraw_sol(&vault, 5, &dest, 1, &opts())
        .encode()
        .unwrap();
    assert!(client
        .submit(
            &relayer,
            &a,
            &key.sign_authorization(&a).unwrap(),
            &Hints::default(),
            Transport::Inline
        )
        .is_err());
    let a = client
        .close_vault(&vault, 5, &dest, &opts())
        .encode()
        .unwrap();
    client
        .submit(
            &relayer,
            &a,
            &new_key.sign_authorization(&a).unwrap(),
            &Hints::default(),
            Transport::Inline,
        )
        .unwrap();
    assert_eq!(
        client.get_vault(&vault).unwrap().state.status,
        VaultStatus::Closed
    );
    assert!(client
        .create_vault(&wallet, key.public_key(), &seed)
        .is_err());
}

#[test]
fn cluster_check() {
    let (client, _, _) = setup();
    assert!(client.check_cluster().is_ok(), "localnet skips the check");
    let devnet = QShieldClient::new(client.rpc, client.program_id, cluster::DEVNET);
    assert!(matches!(
        devnet.check_cluster(),
        Err(Error::WrongCluster { .. })
    ));
}

/// Creates an SPL Token mint (6 decimals) and mints `amount` to `holder`'s ATA.
fn spl_mint(
    client: &QShieldClient<SvmRpc>,
    issuer: &Keypair,
    holder: &Pubkey,
    amount: u64,
) -> Pubkey {
    use qshield_vault::token::{self, TOKEN_PROGRAM};
    use solana_instruction::{AccountMeta, Instruction};
    let mint = Keypair::new();
    let mut svm = client.rpc.0.borrow_mut();
    let rent = svm.minimum_balance_for_rent_exemption(token::MINT_LEN);
    let mut init = vec![20, 6];
    init.extend_from_slice(issuer.pubkey().as_ref());
    init.push(0);
    let ata = token::associated_token_address(holder, &mint.pubkey(), &TOKEN_PROGRAM);
    let mut mint_to = vec![14];
    mint_to.extend_from_slice(&amount.to_le_bytes());
    mint_to.push(6);
    let ixs = [
        solana_system_interface::instruction::create_account(
            &issuer.pubkey(),
            &mint.pubkey(),
            rent,
            token::MINT_LEN as u64,
            &TOKEN_PROGRAM,
        ),
        Instruction::new_with_bytes(
            TOKEN_PROGRAM,
            &init,
            vec![AccountMeta::new(mint.pubkey(), false)],
        ),
        qshield_vault::instruction::build::create_ata_idempotent(
            &issuer.pubkey(),
            holder,
            &mint.pubkey(),
            &TOKEN_PROGRAM,
        ),
        Instruction::new_with_bytes(
            TOKEN_PROGRAM,
            &mint_to,
            vec![
                AccountMeta::new(mint.pubkey(), false),
                AccountMeta::new(ata, false),
                AccountMeta::new_readonly(issuer.pubkey(), true),
            ],
        ),
    ];
    svm.expire_blockhash();
    let msg = solana_message::Message::new_with_blockhash(
        &ixs,
        Some(&issuer.pubkey()),
        &svm.latest_blockhash(),
    );
    let tx = solana_transaction::Transaction::new(&[issuer, &mint], msg, svm.latest_blockhash());
    svm.send_transaction(tx).unwrap();
    mint.pubkey()
}

#[test]
fn spl_deposit_and_withdraw_through_the_sdk() {
    use qshield_client::{format_token_amount, parse_token_amount};
    use qshield_vault::token::TOKEN_PROGRAM;
    let (client, wallet, relayer) = setup();
    let key = LocalKey::generate().unwrap();
    let (vault, _) = client
        .create_vault(&wallet, key.public_key(), &[3; 32])
        .unwrap();
    client.deposit_sol(&wallet, &vault, SOL / 10).unwrap();
    let mint = spl_mint(&client, &wallet, &wallet.pubkey(), 5_000_000);
    let m = client.get_mint(&mint).unwrap();
    assert_eq!(m.info.decimals, 6);
    assert_eq!(m.token_program, TOKEN_PROGRAM);

    // Deposit creates the vault's token account.
    assert!(client
        .deposit_spl(&wallet, &vault, &mint, 6_000_000)
        .is_err());
    let amount = parse_token_amount("3.5", 6).unwrap();
    client.deposit_spl(&wallet, &vault, &mint, amount).unwrap();
    let vault_ta = client.vault_token_address(&vault, &m);
    let bal = client
        .get_token_account(&vault_ta, &TOKEN_PROGRAM)
        .unwrap()
        .unwrap();
    assert_eq!(format_token_amount(bal.amount, 6), "3.500000");

    // Withdraw to a recipient without a token account: the submitter creates it.
    let recipient = Pubkey::new_unique();
    let (a, hints) = client.withdraw_spl(&vault, 0, &m, &recipient, 1_250_000, &opts());
    let env = Envelope::new(&a, &key.key_id()).unwrap();
    assert_eq!(
        env.fields["amount"],
        "1.250000 (1250000 base units, decimals 6)"
    );
    let bytes = a.encode().unwrap();
    let sig = key.sign_authorization(&bytes).unwrap();
    // Without the owner hint the missing destination is reported before sending.
    assert!(client
        .submit(&relayer, &bytes, &sig, &Hints::default(), Transport::Inline)
        .is_err());
    client
        .submit(&relayer, &bytes, &sig, &hints, Transport::Inline)
        .unwrap();
    let dest = qshield_vault::token::associated_token_address(&recipient, &mint, &TOKEN_PROGRAM);
    assert_eq!(
        client
            .get_token_account(&dest, &TOKEN_PROGRAM)
            .unwrap()
            .unwrap()
            .amount,
        1_250_000
    );

    // Buffered path; and an over-withdrawal is caught locally.
    let (a, hints) = client.withdraw_spl(&vault, 1, &m, &recipient, 2_250_001, &opts());
    let bytes = a.encode().unwrap();
    let sig = key.sign_authorization(&bytes).unwrap();
    assert!(client
        .submit(&relayer, &bytes, &sig, &hints, Transport::Buffered)
        .is_err());
    let (a, hints) = client.withdraw_spl(&vault, 1, &m, &recipient, 2_250_000, &opts());
    let bytes = a.encode().unwrap();
    let sig = key.sign_authorization(&bytes).unwrap();
    client
        .submit(&relayer, &bytes, &sig, &hints, Transport::Buffered)
        .unwrap();
    assert_eq!(
        client
            .get_token_account(&vault_ta, &TOKEN_PROGRAM)
            .unwrap()
            .unwrap()
            .amount,
        0
    );
}

#[test]
fn token_amount_parsing() {
    use qshield_client::{format_token_amount, parse_token_amount};
    assert_eq!(parse_token_amount("1", 6).unwrap(), 1_000_000);
    assert_eq!(parse_token_amount("0.000001", 6).unwrap(), 1);
    assert_eq!(parse_token_amount(".5", 1).unwrap(), 5);
    assert_eq!(parse_token_amount("7", 0).unwrap(), 7);
    assert_eq!(
        parse_token_amount("18446744073709551615", 0).unwrap(),
        u64::MAX
    );
    for bad in [
        "",
        ".",
        "1.2.3",
        "-1",
        "1e6",
        "0.0000001",
        "18446744073709551616",
        " 1",
    ] {
        assert!(parse_token_amount(bad, 6).is_err(), "{bad:?}");
    }
    assert_eq!(format_token_amount(1, 6), "0.000001");
    assert_eq!(format_token_amount(u64::MAX, 0), "18446744073709551615");
    assert_eq!(
        format_token_amount(u64::MAX, 255),
        format!("{}e-255", u64::MAX)
    );
}

#[test]
fn guardian_policy_through_the_sdk() {
    use qshield_client::policy::SendPath;
    use qshield_client::protocol::v2::{ActionV2, Role};
    let (client, wallet, relayer) = setup();
    let everyday = LocalKey::generate().unwrap();
    let guardian = LocalKey::generate().unwrap();
    let (vault, _) = client
        .create_vault(&wallet, everyday.public_key(), &[5; 32])
        .unwrap();
    client.deposit_sol(&wallet, &vault, 5 * SOL).unwrap();
    // Guardian key account (the wallet pays), then EnablePolicy signed by the everyday key.
    let g_acct = client
        .setup_key(&wallet, &vault, guardian.public_key())
        .unwrap();
    let v = client.get_vault(&vault).unwrap();
    let mut a = client.v2_base(
        &vault,
        Role::Everyday,
        v.state.nonce,
        ActionV2::EnablePolicy,
        &opts(),
    );
    a.new_key_id = guardian.key_id();
    a.new_algorithm = 1;
    a.limit_lamports = SOL;
    a.limit_period = 86_400;
    let mut env = Envelope::new_v2(&a, &everyday.key_id()).unwrap();
    env.hints.new_key_account = Some(g_acct.to_string());
    let bytes = env.auth_raw().unwrap();
    env.attach_signature(
        everyday.public_key(),
        &everyday.sign_authorization(&bytes).unwrap(),
    )
    .unwrap();
    // The envelope (with its v2 rendering) survives a JSON round trip.
    let env = Envelope::from_json(&env.to_json()).unwrap();
    assert_eq!(env.fields["role"], "everyday key");
    assert_eq!(env.fields["limit"], "1.000000000 SOL per 86400 seconds");
    client
        .submit_any(
            &relayer,
            &bytes,
            &env.signature().unwrap().unwrap(),
            &env.hints,
            Transport::Inline,
        )
        .unwrap();
    let policy = client.get_policy(&vault).unwrap().unwrap();
    assert!(policy.enabled);

    // Instant send within the limit.
    let dest = Pubkey::new_unique();
    assert_eq!(
        client.sol_send_path(&policy, &dest, SOL / 2, 0, NOW),
        SendPath::Instant
    );
    let v = client.get_vault(&vault).unwrap();
    let (a, h) = client.v2_transfer(
        &vault,
        Role::Everyday,
        v.state.nonce,
        ActionV2::WithdrawSol,
        None,
        &dest,
        SOL / 2,
        &opts(),
    );
    let b = a.encode().unwrap();
    client
        .submit_v2(
            &relayer,
            &b,
            &everyday.sign_authorization(&b).unwrap(),
            &h,
            Transport::Buffered,
        )
        .unwrap();
    assert_eq!(
        client.rpc.get_account(&dest).unwrap().unwrap().lamports,
        SOL / 2
    );

    // Over the limit: propose, then the guardian approves the stored proposal.
    let policy = client.get_policy(&vault).unwrap().unwrap();
    assert_eq!(
        client.sol_send_path(&policy, &dest, 2 * SOL, 0, NOW),
        SendPath::NeedsGuardian
    );
    let v = client.get_vault(&vault).unwrap();
    let id = v.state.nonce;
    let (a, h) = client.v2_transfer(
        &vault,
        Role::Everyday,
        id,
        ActionV2::ProposeWithdraw,
        None,
        &dest,
        2 * SOL,
        &opts(),
    );
    let b = a.encode().unwrap();
    client
        .submit_v2(
            &relayer,
            &b,
            &everyday.sign_authorization(&b).unwrap(),
            &h,
            Transport::Inline,
        )
        .unwrap();
    let p = client.get_proposal(&vault, id).unwrap().unwrap();
    assert_eq!(p.amount, 2 * SOL);
    let gn = client
        .role_nonce(&client.get_vault(&vault).unwrap(), Role::Guardian)
        .unwrap();
    let a = client.approval_for(&vault, gn, &p, &opts()).unwrap();
    let b = a.encode().unwrap();
    // The everyday key's signature is refused locally for a guardian message.
    assert!(client
        .submit_v2(
            &relayer,
            &b,
            &everyday.sign_authorization(&b).unwrap(),
            &Hints::default(),
            Transport::Inline
        )
        .is_err());
    client
        .submit_v2(
            &relayer,
            &b,
            &guardian.sign_authorization(&b).unwrap(),
            &Hints::default(),
            Transport::Inline,
        )
        .unwrap();
    assert_eq!(
        client.rpc.get_account(&dest).unwrap().unwrap().lamports,
        SOL / 2 + 2 * SOL
    );
    assert!(client.get_proposal(&vault, id).unwrap().is_none());

    // Guardian freeze; everyday sends refused locally? No: refused on chain.
    let gn = client
        .role_nonce(&client.get_vault(&vault).unwrap(), Role::Guardian)
        .unwrap();
    let a = client.v2_base(&vault, Role::Guardian, gn, ActionV2::Pause, &opts());
    let b = a.encode().unwrap();
    client
        .submit_v2(
            &relayer,
            &b,
            &guardian.sign_authorization(&b).unwrap(),
            &Hints::default(),
            Transport::Inline,
        )
        .unwrap();
    assert_eq!(
        client.get_vault(&vault).unwrap().state.status,
        VaultStatus::Paused
    );
}
