//! NIST ACVP known-answer tests for ML-DSA-44 verification.
//!
//! Source: usnistgov/ACVP-Server `gen-val/json-files/ML-DSA-{sigVer,sigGen}-FIPS204/internalProjection.json`,
//! filtered to the ML-DSA-44 groups. See `tests/vectors/acvp/README.md` for provenance.

use qshield_mldsa::{
    compute_mu_internal, compute_tr, verify, verify_mu, Workspace, MU_LEN, PUBLIC_KEY_LEN,
};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!(
        "{}/../../tests/vectors/acvp/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect("vector file")).expect("json")
}

fn hex_field(t: &Value, k: &str) -> Vec<u8> {
    hex::decode(t[k].as_str().unwrap_or_else(|| panic!("missing {k}"))).expect("hex")
}

/// Runs the verifier on one vector according to its group's interface.
/// Returns `None` for interfaces this crate intentionally does not implement (HashML-DSA).
fn run(group: &Value, t: &Value) -> Option<bool> {
    let pk = hex_field(t, "pk");
    let sig = hex_field(t, "signature");
    let mut ws: Workspace = [[0u32; 256]; 7];
    let iface = group["signatureInterface"].as_str().unwrap();
    let prehash = group["preHash"].as_str().unwrap();
    let external_mu = group["externalMu"].as_bool().unwrap_or(false);
    match (iface, prehash, external_mu) {
        ("external", "pure", _) => {
            let msg = hex_field(t, "message");
            let ctx = hex_field(t, "context");
            Some(verify(&pk, &msg, &ctx, &sig, &mut ws).is_ok())
        }
        ("external", "preHash", _) => None,
        ("internal", _, true) => {
            let mu: [u8; MU_LEN] = hex_field(t, "mu").try_into().unwrap();
            Some(verify_mu(&pk, &mu, &sig, &mut ws).is_ok())
        }
        ("internal", _, false) => {
            let msg = hex_field(t, "message");
            let pk_arr: &[u8; PUBLIC_KEY_LEN] = pk.as_slice().try_into().unwrap();
            let mu = compute_mu_internal(&compute_tr(pk_arr), &msg);
            Some(verify_mu(&pk, &mu, &sig, &mut ws).is_ok())
        }
        other => panic!("unknown interface {other:?}"),
    }
}

#[test]
fn acvp_sigver_ml_dsa_44() {
    let v = load("ML-DSA-44-sigVer.json");
    let (mut checked, mut skipped, mut positives, mut negatives) = (0, 0, 0, 0);
    for group in v["testGroups"].as_array().unwrap() {
        assert_eq!(group["parameterSet"], "ML-DSA-44");
        for t in group["tests"].as_array().unwrap() {
            let expected = t["testPassed"].as_bool().unwrap();
            match run(group, t) {
                Some(got) => {
                    assert_eq!(
                        got, expected,
                        "tgId {} tcId {} ({})",
                        group["tgId"], t["tcId"], t["reason"]
                    );
                    checked += 1;
                    if expected {
                        positives += 1
                    } else {
                        negatives += 1
                    }
                }
                None => skipped += 1,
            }
        }
    }
    eprintln!("sigVer: checked {checked} ({positives} valid, {negatives} invalid), skipped {skipped} HashML-DSA");
    assert_eq!(checked, 45);
    assert!(positives > 0 && negatives > 0);
}

#[test]
fn acvp_siggen_outputs_verify() {
    // Every signature produced in the sigGen known-answer set must verify.
    let v = load("ML-DSA-44-sigGen.json");
    let (mut checked, mut skipped) = (0, 0);
    for group in v["testGroups"].as_array().unwrap() {
        for t in group["tests"].as_array().unwrap() {
            match run(group, t) {
                Some(ok) => {
                    assert!(ok, "tgId {} tcId {}", group["tgId"], t["tcId"]);
                    checked += 1;
                }
                None => skipped += 1,
            }
        }
    }
    eprintln!("sigGen: verified {checked} signatures, skipped {skipped} HashML-DSA");
    assert_eq!(checked, 90);
}

#[test]
fn acvp_keygen_tr_consistency() {
    // tr = H(pk, 64) is embedded in every ML-DSA secret key at offset 64
    // (FIPS 204, Algorithm 24 skEncode: rho || K || tr || ...). Checking it
    // ties our `compute_tr` to NIST's key generation output.
    let v = load("ML-DSA-44-keyGen.json");
    let mut checked = 0;
    for group in v["testGroups"].as_array().unwrap() {
        for t in group["tests"].as_array().unwrap() {
            let pk: [u8; PUBLIC_KEY_LEN] = hex_field(t, "pk").try_into().unwrap();
            let sk = hex_field(t, "sk");
            assert_eq!(&compute_tr(&pk)[..], &sk[64..128]);
            checked += 1;
        }
    }
    assert!(checked > 0);
}
