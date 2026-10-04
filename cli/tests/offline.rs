//! Offline (air-gapped) CLI flows: no RPC endpoint is reachable in these tests.

use assert_cmd::Command;
use serde_json::Value;

const PROGRAM: &str = "QSHie1d111111111111111111111111111111111111";
const VAULT: &str = "Vau1t11111111111111111111111111111111111111";
const DEST: &str = "Dest111111111111111111111111111111111111111";

fn qshield(dir: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("qshield").unwrap();
    c.current_dir(dir)
        .env("PW", "test password")
        .env("WRONG", "nope")
        .env_remove("QSHIELD_PROGRAM_ID")
        // An unroutable endpoint: any accidental network use fails the test.
        .env("QSHIELD_RPC_URL", "http://127.0.0.1:9");
    c
}

fn stdout(c: &mut Command) -> String {
    let out = c.assert().success().get_output().stdout.clone();
    String::from_utf8(out).unwrap()
}

#[test]
fn offline_authorize_sign_verify() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let key_id = stdout(qshield(d).args(["--password-env", "PW", "keygen", "--out", "k.json"]))
        .trim()
        .to_string();
    assert_eq!(key_id.len(), 64);
    // Refuses short passwords (a stolen file can be guessed offline).
    qshield(d)
        .args(["--password-env", "WRONG", "keygen", "--out", "weak.json"])
        .assert()
        .failure();
    assert!(!d.join("weak.json").exists());
    // Refuses to overwrite.
    qshield(d)
        .args(["--password-env", "PW", "keygen", "--out", "k.json"])
        .assert()
        .failure();
    let info = stdout(qshield(d).args(["key", "info", "k.json"]));
    assert!(info.contains(&key_id));
    // The key file never contains the seed in clear.
    let ks: Value =
        serde_json::from_str(&std::fs::read_to_string(d.join("k.json")).unwrap()).unwrap();
    assert!(ks.get("seed").is_none() && ks["kdf"]["name"] == "argon2id");

    // Build an authorization fully offline.
    qshield(d)
        .args([
            "--program-id",
            PROGRAM,
            "--cluster",
            "devnet",
            "auth",
            "withdraw-sol",
            "--vault",
            VAULT,
            "--to",
            DEST,
        ])
        .args([
            "--amount", "0.5", "--nonce", "3", "--key", "k.json", "--out", "a.json",
        ])
        .assert()
        .success();
    let a: Value =
        serde_json::from_str(&std::fs::read_to_string(d.join("a.json")).unwrap()).unwrap();
    assert_eq!(a["fields"]["amount"], "0.500000000 SOL");
    assert_eq!(a["fields"]["cluster"], "devnet");
    assert_eq!(a["fields"]["nonce"], "3");
    qshield(d).args(["verify", "a.json"]).assert().failure(); // unsigned

    // Wrong password, then a correct signature.
    qshield(d)
        .args([
            "--password-env",
            "WRONG",
            "sign",
            "a.json",
            "--key",
            "k.json",
            "--yes",
        ])
        .assert()
        .failure();
    qshield(d)
        .args([
            "--password-env",
            "PW",
            "sign",
            "a.json",
            "--key",
            "k.json",
            "--yes",
        ])
        .assert()
        .success();
    assert!(stdout(qshield(d).args(["verify", "a.json"])).contains("OK"));
    qshield(d)
        .args([
            "--password-env",
            "PW",
            "sign",
            "a.json",
            "--key",
            "k.json",
            "--yes",
        ])
        .assert()
        .failure(); // already signed

    // Tampering with the displayed amount is detected.
    let mut t: Value =
        serde_json::from_str(&std::fs::read_to_string(d.join("a.json")).unwrap()).unwrap();
    t["fields"]["amount"] = "0.000000001 SOL".into();
    std::fs::write(d.join("t1.json"), t.to_string()).unwrap();
    qshield(d).args(["verify", "t1.json"]).assert().failure();
    // Tampering with the signed bytes is detected.
    let mut t: Value =
        serde_json::from_str(&std::fs::read_to_string(d.join("a.json")).unwrap()).unwrap();
    let mut bytes = hex::decode(t["auth_hex"].as_str().unwrap()).unwrap();
    bytes[178] ^= 1; // destination
    t["auth_hex"] = hex::encode(bytes).into();
    std::fs::write(d.join("t2.json"), t.to_string()).unwrap();
    qshield(d).args(["verify", "t2.json"]).assert().failure();

    // A different key cannot sign an authorization meant for k.json.
    qshield(d)
        .args(["--password-env", "PW", "keygen", "--out", "other.json"])
        .assert()
        .success();
    qshield(d)
        .args([
            "--program-id",
            PROGRAM,
            "auth",
            "pause",
            "--vault",
            VAULT,
            "--nonce",
            "4",
            "--key",
            "k.json",
            "--out",
            "p.json",
        ])
        .assert()
        .success();
    qshield(d)
        .args([
            "--password-env",
            "PW",
            "sign",
            "p.json",
            "--key",
            "other.json",
            "--yes",
        ])
        .assert()
        .failure();

    // Without --nonce the CLI needs the network: must fail here.
    qshield(d)
        .args([
            "--program-id",
            PROGRAM,
            "auth",
            "pause",
            "--vault",
            VAULT,
            "--key",
            "k.json",
            "--out",
            "n.json",
        ])
        .assert()
        .failure();
}

#[test]
fn amounts_and_seed_export_guard() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    qshield(d)
        .args(["--password-env", "PW", "keygen", "--out", "k.json"])
        .assert()
        .success();
    for bad in ["", ".", "1.0000000001", "-1", "1e9", "abc"] {
        qshield(d)
            .args([
                "--program-id",
                PROGRAM,
                "auth",
                "withdraw-sol",
                "--vault",
                VAULT,
                "--to",
                DEST,
                "--amount",
                bad,
            ])
            .args(["--nonce", "0", "--key", "k.json", "--out", "x.json"])
            .assert()
            .failure();
    }
    qshield(d)
        .args(["--password-env", "PW", "key", "export-seed", "k.json"])
        .assert()
        .failure();
    let seed = stdout(qshield(d).args([
        "--password-env",
        "PW",
        "key",
        "export-seed",
        "k.json",
        "--i-understand-this-reveals-my-secret-key",
    ]));
    assert_eq!(seed.trim().len(), 64);
}

#[test]
fn offline_withdraw_spl_and_close_guard() {
    const MINT: &str = "Mint111111111111111111111111111111111111111";
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    qshield(d)
        .args(["--password-env", "PW", "keygen", "--out", "k.json"])
        .assert()
        .success();
    let base = [
        "--program-id",
        PROGRAM,
        "auth",
        "withdraw-spl",
        "--vault",
        VAULT,
        "--mint",
        MINT,
        "--to",
        DEST,
        "--amount",
        "2.5",
        "--nonce",
        "7",
        "--key",
        "k.json",
    ];
    // Offline mode needs the mint's decimals and program.
    qshield(d)
        .args(base)
        .args(["--out", "x.json"])
        .assert()
        .failure();
    // More decimals than the mint has.
    qshield(d)
        .args(base)
        .args([
            "--decimals",
            "0",
            "--token-program",
            "spl",
            "--out",
            "x.json",
        ])
        .assert()
        .failure();
    qshield(d)
        .args(base)
        .args([
            "--decimals",
            "6",
            "--token-program",
            "token2022",
            "--out",
            "s.json",
        ])
        .assert()
        .success();
    let a: Value =
        serde_json::from_str(&std::fs::read_to_string(d.join("s.json")).unwrap()).unwrap();
    assert_eq!(a["fields"]["action"], "WithdrawSpl");
    assert_eq!(a["fields"]["asset"], "Token2022");
    assert_eq!(a["fields"]["mint"], MINT);
    assert_eq!(
        a["fields"]["amount"],
        "2.500000 (2500000 base units, decimals 6)"
    );
    assert_eq!(a["hints"]["destination_owner"], DEST);
    // The destination is the recipient's Token-2022 associated token account.
    let ata = qshield_vault::token::associated_token_address(
        &DEST.parse().unwrap(),
        &MINT.parse().unwrap(),
        &qshield_vault::token::TOKEN_2022_PROGRAM,
    );
    assert_eq!(a["fields"]["destination"], ata.to_string());
    qshield(d)
        .args([
            "--password-env",
            "PW",
            "sign",
            "s.json",
            "--key",
            "k.json",
            "--yes",
        ])
        .assert()
        .success();
    assert!(stdout(qshield(d).args(["verify", "s.json"])).contains("OK"));

    // An offline close cannot check token balances: refused unless acknowledged.
    let close = [
        "--program-id",
        PROGRAM,
        "auth",
        "close",
        "--vault",
        VAULT,
        "--to",
        DEST,
        "--nonce",
        "8",
        "--key",
        "k.json",
        "--out",
        "c.json",
    ];
    qshield(d).args(close).assert().failure();
    qshield(d)
        .args(close)
        .arg("--allow-token-loss")
        .assert()
        .success();
}

#[test]
fn recovery_phrase_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let id = stdout(qshield(d).args(["--password-env", "PW", "keygen", "--out", "k.json"]));
    qshield(d)
        .args(["--password-env", "PW", "key", "export-phrase", "k.json"])
        .assert()
        .failure();
    let phrase = stdout(qshield(d).args([
        "--password-env",
        "PW",
        "key",
        "export-phrase",
        "k.json",
        "--i-understand-this-reveals-my-secret-key",
    ]));
    assert_eq!(phrase.split_whitespace().count(), 24);
    // Wrong expected id: refused, no file written.
    qshield(d)
        .args([
            "--password-env",
            "PW",
            "key",
            "import-phrase",
            "--out",
            "x.json",
            "--expect-key-id",
            &"00".repeat(32),
        ])
        .write_stdin(phrase.clone())
        .assert()
        .failure();
    assert!(!d.join("x.json").exists());
    let back = stdout(
        qshield(d)
            .args([
                "--password-env",
                "PW",
                "key",
                "import-phrase",
                "--out",
                "r.json",
                "--expect-key-id",
                id.trim(),
            ])
            .write_stdin(phrase.clone()),
    );
    assert_eq!(back.trim(), id.trim());
    // A valid BIP-39 phrase is not a QShield phrase (deterministic checksum failure).
    let bip39 = format!("{}art", "abandon ".repeat(23));
    qshield(d)
        .args([
            "--password-env",
            "PW",
            "key",
            "import-phrase",
            "--out",
            "y.json",
        ])
        .write_stdin(bip39)
        .assert()
        .failure();
}

#[test]
fn edited_key_file_cannot_take_over_a_new_vault() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    qshield(d)
        .args(["--password-env", "PW", "keygen", "--out", "k.json"])
        .assert()
        .success();
    qshield(d)
        .args(["--password-env", "PW", "keygen", "--out", "attacker.json"])
        .assert()
        .success();
    let read = |f: &str| -> Value {
        serde_json::from_str(&std::fs::read_to_string(d.join(f)).unwrap()).unwrap()
    };
    let attacker = read("attacker.json");
    // Graft the attacker's public fields onto the user's key file: the
    // header alone, or the header and key id together.
    for fields in [&["public_key"][..], &["public_key", "key_id"][..]] {
        let mut ks = read("k.json");
        for f in fields {
            ks[*f] = attacker[*f].clone();
        }
        std::fs::write(d.join("edited.json"), ks.to_string()).unwrap();
        let out = qshield(d)
            .args([
                "--password-env",
                "PW",
                "--program-id",
                PROGRAM,
                "vault",
                "create",
                "--key",
                "edited.json",
                "--payer",
                "missing-wallet.json",
            ])
            .assert()
            .failure()
            .get_output()
            .stderr
            .clone();
        let err = String::from_utf8(out).unwrap();
        assert!(
            err.contains("does not match") || err.contains("corrupted"),
            "{fields:?}: {err}"
        );
    }
}
