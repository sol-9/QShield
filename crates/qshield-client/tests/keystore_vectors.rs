//! Keystore known-answer vector shared with other implementations
//! (`tests/vectors/keystore/keystore-v1.json`). Regenerate with
//! `QSHIELD_REGENERATE=1 cargo test -p qshield-client --test keystore_vectors`.

use qshield_client::{KdfParams, Keystore, LocalKey, PqSigner};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/vectors/keystore/keystore-v1.json"
);
const PASSWORD: &str = "QShield test vector password \u{1F510}";

#[test]
fn keystore_vector() {
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    let key = LocalKey::from_seed(&seed);
    let ks = Keystore::encrypt_with(
        &key,
        PASSWORD,
        KdfParams::INSECURE_TEST,
        [0x11; 16],
        [0x22; 24],
    )
    .unwrap();
    let doc = serde_json::json!({
        "description": "QShield keystore v1 test vector. INSECURE KDF parameters: for tests only.",
        "password": PASSWORD,
        "seed_hex": hex::encode(seed),
        "key_id_hex": hex::encode(key.key_id()),
        "keystore": serde_json::to_value(&ks).unwrap(),
    });
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    if std::env::var("QSHIELD_REGENERATE").is_ok() {
        std::fs::write(PATH, &text).unwrap();
    }
    let committed = std::fs::read_to_string(PATH).expect("vector file");
    assert_eq!(committed, text);
    let v: serde_json::Value = serde_json::from_str(&committed).unwrap();
    let ks: Keystore = serde_json::from_value(v["keystore"].clone()).unwrap();
    assert_eq!(ks.decrypt(PASSWORD).unwrap().seed(), &seed);
    assert!(ks.decrypt("wrong").is_err());
}
