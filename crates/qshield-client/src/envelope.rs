//! Authorization envelopes: the JSON file exchanged between an online machine
//! (which builds an authorization), an offline signer, and a submitter
//! (`docs/OFFLINE_SIGNING.md`).
//!
//! `auth_hex` (the exact QSP-1 bytes) is authoritative. The `fields` object is
//! a human-readable rendering that is **recomputed from `auth_hex` and must
//! match**, so a file cannot show one thing and sign another. Signers display
//! the rendering they compute themselves, never the file's.

use qshield_protocol::v2::{ActionV2, AuthorizationV2, Role, AUTH_V2_LEN};
use qshield_protocol::{cluster, Action, AssetType, Authorization, Bytes32, AUTH_LEN, ZERO32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::key::verify_authorization;
use crate::Error;

/// Format version.
pub const ENVELOPE_VERSION: u32 = 1;

/// Unsigned helper data needed to submit some actions. Not covered by the
/// signature; the program verifies anything security-relevant on-chain.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hints {
    /// Address of the new key account (RotateKey).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_key_account: Option<String>,
    /// Owner of the WithdrawSpl destination: lets the submitter create the
    /// destination's associated token account if it does not exist yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_owner: Option<String>,
    /// Vault token account to debit for WithdrawSpl (default: the vault's
    /// associated token account for the mint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_token_account: Option<String>,
}

/// An authorization, optionally signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Format version.
    pub qshield_authorization: u32,
    /// Human-readable rendering of `auth_hex` (checked on load).
    pub fields: BTreeMap<String, String>,
    /// QSP-1 bytes (292).
    pub auth_hex: String,
    /// Key id expected to sign (the vault's current key).
    pub signer_key_id: String,
    /// ML-DSA-44 signature, once signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    /// Public key that produced `signature_hex` (lets anyone verify offline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
    /// Submission hints.
    #[serde(default)]
    pub hints: Hints,
}

/// Base58 rendering of a 32-byte address.
pub fn b58(x: &Bytes32) -> String {
    bs58::encode(x).into_string()
}

/// Cluster name for a cluster id, or `unknown(<hex>)`.
pub fn cluster_name(id: &Bytes32) -> String {
    match *id {
        cluster::MAINNET_BETA => "mainnet-beta".into(),
        cluster::DEVNET => "devnet".into(),
        cluster::TESTNET => "testnet".into(),
        cluster::LOCALNET => "localnet".into(),
        other => format!("unknown({})", hex::encode(other)),
    }
}

/// Formats lamports as SOL with full precision.
pub fn sol(lamports: u64) -> String {
    format!(
        "{}.{:09} SOL",
        lamports / 1_000_000_000,
        lamports % 1_000_000_000
    )
}

/// Human-readable rendering of every field (what a signer must show).
pub fn describe(a: &Authorization) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let ts = |t: i64, none: &str| {
        if t == 0 {
            none.to_string()
        } else {
            format!("{t} (unix seconds)")
        }
    };
    m.insert("cluster".into(), cluster_name(&a.cluster_id));
    m.insert("program_id".into(), b58(&a.program_id));
    m.insert("vault".into(), b58(&a.vault));
    m.insert("action".into(), format!("{:?}", a.action));
    m.insert("nonce".into(), a.nonce.to_string());
    m.insert("valid_after".into(), ts(a.valid_after, "immediately"));
    m.insert("expires_at".into(), ts(a.expires_at, "never"));
    match a.action {
        Action::WithdrawSol => {
            m.insert("destination".into(), b58(&a.destination));
            m.insert("amount".into(), sol(a.amount));
        }
        Action::CloseVault => {
            m.insert("destination".into(), b58(&a.destination));
            m.insert(
                "amount".into(),
                "entire balance above the rent reserve".into(),
            );
        }
        Action::WithdrawSpl => {
            m.insert("asset".into(), format!("{:?}", a.asset_type));
            m.insert("mint".into(), b58(&a.mint));
            m.insert("destination".into(), b58(&a.destination));
            m.insert(
                "amount".into(),
                format!(
                    "{} ({} base units, decimals {})",
                    crate::client::format_token_amount(a.amount, a.decimals),
                    a.amount,
                    a.decimals
                ),
            );
        }
        Action::RotateKey => {
            m.insert("new_key_id".into(), hex::encode(a.new_key_id));
            m.insert(
                "new_algorithm".into(),
                if a.new_algorithm == 1 {
                    "ML-DSA-44".into()
                } else {
                    a.new_algorithm.to_string()
                },
            );
        }
        Action::Pause | Action::Unpause => {}
    }
    m.insert("fee".into(), sol(a.fee_lamports));
    if a.fee_lamports > 0 {
        m.insert(
            "fee_recipient".into(),
            if a.fee_recipient == ZERO32 {
                "transaction fee payer".into()
            } else {
                b58(&a.fee_recipient)
            },
        );
    }
    m
}

/// A QSP-1 authorization of either version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnyAuth {
    /// Version 1 (vaults without a guardian policy).
    V1(Authorization),
    /// Version 2 (guardian policy, ADR-0018).
    V2(AuthorizationV2),
}

impl AnyAuth {
    /// Decodes by length: 292 bytes = v1, 317 bytes = v2.
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        match b.len() {
            AUTH_LEN => Authorization::decode(b).map(Self::V1),
            AUTH_V2_LEN => AuthorizationV2::decode(b).map(Self::V2),
            _ => Err(qshield_protocol::Error::Length),
        }
        .map_err(Error::Protocol)
    }
    /// Canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::V1(a) => a.encode().map(|b| b.to_vec()),
            Self::V2(a) => a.encode().map(|b| b.to_vec()),
        }
        .map_err(Error::Protocol)
    }
    /// Vault address.
    pub fn vault(&self) -> Bytes32 {
        match self {
            Self::V1(a) => a.vault,
            Self::V2(a) => a.vault,
        }
    }
    /// Human-readable rendering.
    pub fn describe(&self) -> BTreeMap<String, String> {
        match self {
            Self::V1(a) => describe(a),
            Self::V2(a) => describe_v2(a),
        }
    }
}

fn render_transfer(
    m: &mut BTreeMap<String, String>,
    asset: AssetType,
    mint: &Bytes32,
    destination: &Bytes32,
    amount: u64,
    decimals: u8,
) {
    m.insert("destination".into(), b58(destination));
    if asset == AssetType::Sol {
        m.insert("amount".into(), sol(amount));
    } else {
        m.insert("asset".into(), format!("{asset:?}"));
        m.insert("mint".into(), b58(mint));
        m.insert(
            "amount".into(),
            format!(
                "{} ({} base units, decimals {})",
                crate::client::format_token_amount(amount, decimals),
                amount,
                decimals
            ),
        );
    }
}

/// Rendering of a v2 (guardian policy) authorization; identical strings in
/// every SDK (`docs/OFFLINE_SIGNING.md`).
pub fn describe_v2(a: &AuthorizationV2) -> BTreeMap<String, String> {
    use ActionV2::*;
    let mut m = BTreeMap::new();
    let ts = |t: i64, none: &str| {
        if t == 0 {
            none.to_string()
        } else {
            format!("{t} (unix seconds)")
        }
    };
    m.insert("cluster".into(), cluster_name(&a.cluster_id));
    m.insert("program_id".into(), b58(&a.program_id));
    m.insert("vault".into(), b58(&a.vault));
    m.insert("action".into(), format!("{:?}", a.action));
    m.insert(
        "role".into(),
        match a.role {
            Role::Everyday => "everyday key".into(),
            Role::Guardian => "guardian".into(),
        },
    );
    m.insert("nonce".into(), a.nonce.to_string());
    m.insert("valid_after".into(), ts(a.valid_after, "immediately"));
    m.insert("expires_at".into(), ts(a.expires_at, "never"));
    match a.action {
        WithdrawSol | WithdrawSpl | ProposeWithdraw | ApproveWithdraw => {
            render_transfer(
                &mut m,
                a.asset_type,
                &a.mint,
                &a.destination,
                a.amount,
                a.decimals,
            );
        }
        _ => {}
    }
    if matches!(a.action, ApproveWithdraw | CancelProposal) {
        m.insert("proposal".into(), a.ref_id.to_string());
    }
    if matches!(a.action, RotateKey | RotateGuardian | EnablePolicy) {
        m.insert("new_key_id".into(), hex::encode(a.new_key_id));
        m.insert(
            "new_algorithm".into(),
            if a.new_algorithm == 1 {
                "ML-DSA-44".into()
            } else {
                a.new_algorithm.to_string()
            },
        );
    }
    if matches!(a.action, EnablePolicy | SetLimit) {
        m.insert(
            "limit".into(),
            format!("{} per {} seconds", sol(a.limit_lamports), a.limit_period),
        );
    }
    if matches!(a.action, AddAddress | RemoveAddress) {
        m.insert("address".into(), b58(&a.destination));
    }
    m.insert("fee".into(), sol(a.fee_lamports));
    if a.fee_lamports > 0 {
        m.insert(
            "fee_recipient".into(),
            if a.fee_recipient == ZERO32 {
                "transaction fee payer".into()
            } else {
                b58(&a.fee_recipient)
            },
        );
    }
    m
}

impl Envelope {
    /// Creates an unsigned envelope for a v2 authorization.
    pub fn new_v2(auth: &AuthorizationV2, signer_key_id: &Bytes32) -> Result<Self, Error> {
        let bytes = auth.encode().map_err(Error::Protocol)?;
        Ok(Self {
            qshield_authorization: ENVELOPE_VERSION,
            fields: describe_v2(auth),
            auth_hex: hex::encode(bytes),
            signer_key_id: hex::encode(signer_key_id),
            signature_hex: None,
            public_key_hex: None,
            hints: Hints::default(),
        })
    }

    /// The authorization bytes of either version.
    pub fn auth_raw(&self) -> Result<Vec<u8>, Error> {
        let b = hex::decode(&self.auth_hex).map_err(|_| Error::Envelope("bad auth_hex"))?;
        if b.len() != AUTH_LEN && b.len() != AUTH_V2_LEN {
            return Err(Error::Envelope(
                "auth_hex must be 292 (v1) or 317 (v2) bytes",
            ));
        }
        Ok(b)
    }

    /// The decoded authorization (either version).
    pub fn any(&self) -> Result<AnyAuth, Error> {
        AnyAuth::decode(&self.auth_raw()?)
    }

    /// Creates an unsigned envelope.
    pub fn new(auth: &Authorization, signer_key_id: &Bytes32) -> Result<Self, Error> {
        let bytes = auth.encode().map_err(Error::Protocol)?;
        Ok(Self {
            qshield_authorization: ENVELOPE_VERSION,
            fields: describe(auth),
            auth_hex: hex::encode(bytes),
            signer_key_id: hex::encode(signer_key_id),
            signature_hex: None,
            public_key_hex: None,
            hints: Hints::default(),
        })
    }

    /// Parses JSON and checks internal consistency (`fields` matches `auth_hex`,
    /// any signature verifies under `public_key_hex` whose key id is `signer_key_id`).
    pub fn from_json(s: &str) -> Result<Self, Error> {
        let e: Self = serde_json::from_str(s).map_err(|_| Error::Envelope("invalid JSON"))?;
        if e.qshield_authorization != ENVELOPE_VERSION {
            return Err(Error::Envelope("unsupported envelope version"));
        }
        let a = e.any()?;
        if e.fields != a.describe() {
            return Err(Error::Envelope(
                "displayed fields do not match the authorization bytes",
            ));
        }
        if let Some(sig) = &e.signature_hex {
            let pk = e
                .public_key_hex
                .as_ref()
                .ok_or(Error::Envelope("signature without public key"))?;
            let pk = hex::decode(pk).map_err(|_| Error::Envelope("bad public key hex"))?;
            let sig = hex::decode(sig).map_err(|_| Error::Envelope("bad signature hex"))?;
            if hex::encode(qshield_protocol::key_id(
                qshield_protocol::Algorithm::MlDsa44,
                &pk,
            )) != e.signer_key_id
            {
                return Err(Error::Envelope("public key does not match signer_key_id"));
            }
            if !verify_authorization(&pk, &e.auth_raw()?, &sig) {
                return Err(Error::Envelope("signature does not verify"));
            }
        }
        Ok(e)
    }

    /// Serializes to pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("serializable") + "\n"
    }

    /// The QSP-1 bytes.
    pub fn auth_bytes(&self) -> Result<[u8; AUTH_LEN], Error> {
        hex::decode(&self.auth_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(Error::Envelope(
                "auth_hex must be a 292-byte v1 authorization (use auth_raw for v2)",
            ))
    }

    /// The decoded authorization.
    pub fn authorization(&self) -> Result<Authorization, Error> {
        Authorization::decode(&self.auth_bytes()?).map_err(Error::Protocol)
    }

    /// The signature, if present.
    pub fn signature(&self) -> Result<Option<Vec<u8>>, Error> {
        self.signature_hex
            .as_ref()
            .map(|s| hex::decode(s).map_err(|_| Error::Envelope("bad signature hex")))
            .transpose()
    }

    /// Attaches a signature after verifying it.
    pub fn attach_signature(&mut self, public_key: &[u8], signature: &[u8]) -> Result<(), Error> {
        if hex::encode(qshield_protocol::key_id(
            qshield_protocol::Algorithm::MlDsa44,
            public_key,
        )) != self.signer_key_id
        {
            return Err(Error::Envelope("this key is not the expected signer"));
        }
        if !verify_authorization(public_key, &self.auth_raw()?, signature) {
            return Err(Error::Envelope("signature does not verify"));
        }
        self.signature_hex = Some(hex::encode(signature));
        self.public_key_hex = Some(hex::encode(public_key));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{LocalKey, PqSigner};
    use qshield_protocol::AssetType;

    fn auth() -> Authorization {
        Authorization {
            cluster_id: cluster::DEVNET,
            program_id: [1; 32],
            vault: [2; 32],
            action: Action::WithdrawSol,
            asset_type: AssetType::Sol,
            nonce: 3,
            valid_after: 0,
            expires_at: 1_900_000_000,
            mint: ZERO32,
            destination: [4; 32],
            amount: 1_500_000_000,
            decimals: 0,
            fee_recipient: ZERO32,
            fee_lamports: 5_000,
            new_key_id: ZERO32,
            new_algorithm: 0,
        }
    }

    #[test]
    fn sign_roundtrip_and_tamper_checks() {
        let key = LocalKey::from_seed(&[1; 32]);
        let mut e = Envelope::new(&auth(), &key.key_id()).unwrap();
        assert_eq!(e.fields["amount"], "1.500000000 SOL");
        assert_eq!(e.fields["fee_recipient"], "transaction fee payer");
        let sig = key.sign_authorization(&e.auth_bytes().unwrap()).unwrap();
        e.attach_signature(key.public_key(), &sig).unwrap();
        let back = Envelope::from_json(&e.to_json()).unwrap();
        assert_eq!(back, e);

        // Misleading display: change the rendered amount only.
        let mut bad = e.clone();
        bad.fields.insert("amount".into(), "0.010000000 SOL".into());
        assert!(Envelope::from_json(&bad.to_json()).is_err());
        // Changed bytes: signature no longer verifies (fields recomputed to match).
        let mut a = auth();
        a.amount += 1;
        let mut bad = e.clone();
        bad.auth_hex = hex::encode(a.encode().unwrap());
        bad.fields = describe(&a);
        assert!(Envelope::from_json(&bad.to_json()).is_err());
        // Wrong signer.
        let other = LocalKey::from_seed(&[2; 32]);
        let mut fresh = Envelope::new(&auth(), &key.key_id()).unwrap();
        let s = other
            .sign_authorization(&fresh.auth_bytes().unwrap())
            .unwrap();
        assert!(fresh.attach_signature(other.public_key(), &s).is_err());
    }
}
