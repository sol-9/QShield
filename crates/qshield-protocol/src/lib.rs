//! **QSP-1** — QShield Signing Protocol, version 1.
//!
//! This crate defines the canonical byte encoding of a QShield authorization:
//! the exact message that is signed with ML-DSA-44 and verified on-chain. It
//! is `no_std`, allocation-free and shared by the on-chain program and every
//! client, so all of them produce and parse identical bytes.
//!
//! The normative specification is `docs/QSP-1.md`; this crate is its reference
//! implementation. Any change to the encoding is a protocol change and needs
//! a new protocol version and an ADR.
//!
//! # Encoding summary
//!
//! A QSP-1 authorization is exactly [`AUTH_LEN`] = 292 bytes. All fields are
//! fixed-length; integers are little-endian; there are no variable-length
//! fields, so the encoding is unambiguous and has a single valid form for each
//! value (canonical). Fields that an action does not use **must** be zero.
//!
//! The authorization bytes are signed as the message `M` of *pure* ML-DSA-44
//! (`ML-DSA.Sign(sk, M, ctx)`, FIPS 204 Algorithm 2) with the context string
//! [`ML_DSA_CONTEXT`]. QSP-1 does not use HashML-DSA.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod v2;

/// Domain separation tag at the start of every authorization.
pub const DOMAIN: [u8; 22] = *b"QSHIELD_SOLANA_AUTH_V1";
/// Protocol version encoded in every authorization.
pub const PROTOCOL_VERSION: u16 = 1;
/// FIPS 204 context string passed to ML-DSA sign/verify.
pub const ML_DSA_CONTEXT: &[u8] = b"QSHIELD/QSP-1";
/// Length of an encoded authorization.
pub const AUTH_LEN: usize = 292;
/// Domain tag for key identifiers.
pub const KEY_ID_DOMAIN: [u8; 17] = *b"QSHIELD_KEY_ID_V1";

/// Byte offsets of each field (see `docs/QSP-1.md`, section "Layout").
pub mod offsets {
    /// `domain` (22 bytes)
    pub const DOMAIN: usize = 0;
    /// `version` (u16)
    pub const VERSION: usize = 22;
    /// `cluster_id` (32 bytes)
    pub const CLUSTER_ID: usize = 24;
    /// `program_id` (32 bytes)
    pub const PROGRAM_ID: usize = 56;
    /// `vault` (32 bytes)
    pub const VAULT: usize = 88;
    /// `action` (u8)
    pub const ACTION: usize = 120;
    /// `asset_type` (u8)
    pub const ASSET_TYPE: usize = 121;
    /// `nonce` (u64)
    pub const NONCE: usize = 122;
    /// `valid_after` (i64)
    pub const VALID_AFTER: usize = 130;
    /// `expires_at` (i64)
    pub const EXPIRES_AT: usize = 138;
    /// `mint` (32 bytes)
    pub const MINT: usize = 146;
    /// `destination` (32 bytes)
    pub const DESTINATION: usize = 178;
    /// `amount` (u64)
    pub const AMOUNT: usize = 210;
    /// `decimals` (u8)
    pub const DECIMALS: usize = 218;
    /// `fee_recipient` (32 bytes)
    pub const FEE_RECIPIENT: usize = 219;
    /// `fee_lamports` (u64)
    pub const FEE_LAMPORTS: usize = 251;
    /// `new_key_id` (32 bytes)
    pub const NEW_KEY_ID: usize = 259;
    /// `new_algorithm` (u8)
    pub const NEW_ALGORITHM: usize = 291;
    /// End of the encoding.
    pub const END: usize = 292;
}

const _: () = assert!(offsets::END == AUTH_LEN);

/// 32-byte identifier (Solana address, genesis hash or key id).
pub type Bytes32 = [u8; 32];

/// The all-zero 32-byte value ("unused" / "none").
pub const ZERO32: Bytes32 = [0u8; 32];

/// Cluster identifiers: the genesis hash of each Solana cluster.
///
/// The on-chain program is compiled for exactly one cluster and rejects
/// authorizations carrying any other identifier (prevents cross-cluster replay).
pub mod cluster {
    use super::Bytes32;

    /// mainnet-beta genesis hash `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`.
    pub const MAINNET_BETA: Bytes32 = [
        0x45, 0x29, 0x69, 0x98, 0xa6, 0xf8, 0xe2, 0xa7, 0x84, 0xdb, 0x5d, 0x9f, 0x95, 0xe1, 0x8f,
        0xc2, 0x3f, 0x70, 0x44, 0x1a, 0x10, 0x39, 0x44, 0x68, 0x01, 0x08, 0x98, 0x79, 0xb0, 0x8c,
        0x7e, 0xf0,
    ];
    /// devnet genesis hash `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG`.
    pub const DEVNET: Bytes32 = [
        0xce, 0x59, 0xdb, 0x50, 0x80, 0xfc, 0x2c, 0x6d, 0x3b, 0xcf, 0x7c, 0xa9, 0x07, 0x12, 0xd3,
        0xc2, 0xe5, 0xe6, 0xc2, 0x8f, 0x27, 0xf0, 0xdf, 0xbb, 0x99, 0x53, 0xbd, 0xb0, 0x89, 0x4c,
        0x03, 0xab,
    ];
    /// testnet genesis hash `4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY`.
    pub const TESTNET: Bytes32 = [
        0x3a, 0x13, 0x2e, 0xce, 0x10, 0x30, 0x5e, 0xc1, 0x83, 0x07, 0x25, 0x50, 0x2f, 0xa2, 0xb7,
        0xe7, 0xeb, 0x81, 0x57, 0xe9, 0x12, 0x3d, 0x4c, 0x1f, 0x65, 0x4a, 0x71, 0x78, 0x71, 0x61,
        0xdc, 0x21,
    ];
    /// Sentinel for local test validators (whose genesis hash is random).
    /// Signatures for localnet are only meaningful on throwaway clusters.
    pub const LOCALNET: Bytes32 = *b"QSHIELD-LOCALNET-NOT-A-REAL-NET!";
}

/// Signature algorithm identifiers.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// FIPS 204 ML-DSA-44 (pure), context [`ML_DSA_CONTEXT`].
    MlDsa44 = 1,
}

impl Algorithm {
    /// Parses an algorithm byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::MlDsa44),
            _ => None,
        }
    }
}

/// Authorized actions.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Transfer `amount` lamports from the vault to `destination`.
    WithdrawSol = 1,
    /// Transfer `amount` base units of `mint` to the token account `destination`.
    WithdrawSpl = 2,
    /// Replace the vault's key with the key identified by `new_key_id`.
    RotateKey = 3,
    /// Block withdrawals until an `Unpause` authorization executes.
    Pause = 4,
    /// Lift a pause.
    Unpause = 5,
    /// Send every lamport above the tombstone reserve to `destination` and
    /// permanently close the vault.
    CloseVault = 6,
}

impl Action {
    /// Parses an action byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::WithdrawSol),
            2 => Some(Self::WithdrawSpl),
            3 => Some(Self::RotateKey),
            4 => Some(Self::Pause),
            5 => Some(Self::Unpause),
            6 => Some(Self::CloseVault),
            _ => None,
        }
    }
}

/// Asset classes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetType {
    /// The action moves no asset.
    None = 0,
    /// Native SOL (lamports).
    Sol = 1,
    /// SPL Token program (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`).
    SplToken = 2,
    /// Token-2022 program (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`).
    Token2022 = 3,
}

impl AssetType {
    /// Parses an asset-type byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Sol),
            2 => Some(Self::SplToken),
            3 => Some(Self::Token2022),
            _ => None,
        }
    }
}

/// Decoding / validation failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input is not exactly [`AUTH_LEN`] bytes.
    Length,
    /// Domain tag mismatch.
    Domain,
    /// Unsupported protocol version.
    Version,
    /// Unknown action byte.
    Action,
    /// Unknown asset-type byte.
    AssetType,
    /// Unknown algorithm byte.
    Algorithm,
    /// A field that must be zero for this action is non-zero, or a required
    /// field is zero.
    NonCanonical,
    /// `expires_at` is set and not after `valid_after`.
    Window,
}

/// A decoded QSP-1 authorization.
///
/// Construct with [`Authorization::decode`] (validates) or build the struct
/// and call [`Authorization::encode`] (which re-validates).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authorization {
    /// Genesis hash of the target cluster (see [`cluster`]).
    pub cluster_id: Bytes32,
    /// QShield program address.
    pub program_id: Bytes32,
    /// Vault address.
    pub vault: Bytes32,
    /// Action to perform.
    pub action: Action,
    /// Asset class moved by the action.
    pub asset_type: AssetType,
    /// Must equal the vault's current nonce.
    pub nonce: u64,
    /// Unix timestamp (seconds); the authorization is invalid before it. `0` = no lower bound.
    pub valid_after: i64,
    /// Unix timestamp (seconds); the authorization is invalid at or after it. `0` = no expiry.
    pub expires_at: i64,
    /// Token mint (SPL actions only).
    pub mint: Bytes32,
    /// Recipient system account (SOL) or token account (SPL).
    pub destination: Bytes32,
    /// Amount in lamports (SOL) or token base units (SPL).
    pub amount: u64,
    /// Mint decimals (SPL actions only).
    pub decimals: u8,
    /// Recipient of `fee_lamports`. All-zero means "the transaction fee payer".
    pub fee_recipient: Bytes32,
    /// Lamports paid from the vault to `fee_recipient`. Never implicit.
    pub fee_lamports: u64,
    /// Key identifier of the replacement key (rotation only).
    pub new_key_id: Bytes32,
    /// Algorithm byte of the replacement key (rotation only), 0 otherwise.
    pub new_algorithm: u8,
}

pub(crate) fn rd32_at(b: &[u8], off: usize) -> Bytes32 {
    let mut out = [0u8; 32];
    out.copy_from_slice(&b[off..off + 32]);
    out
}

pub(crate) fn rd_u64_at(b: &[u8], off: usize) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(out)
}

pub(crate) fn rd_i64_at(b: &[u8], off: usize) -> i64 {
    rd_u64_at(b, off) as i64
}

fn rd32(b: &[u8; AUTH_LEN], off: usize) -> Bytes32 {
    let mut out = [0u8; 32];
    out.copy_from_slice(&b[off..off + 32]);
    out
}

fn rd_u64(b: &[u8; AUTH_LEN], off: usize) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(out)
}

fn rd_i64(b: &[u8; AUTH_LEN], off: usize) -> i64 {
    rd_u64(b, off) as i64
}

impl Authorization {
    /// Checks the per-action field rules of `docs/QSP-1.md` §5.
    pub fn validate(&self) -> Result<(), Error> {
        use Action::*;
        let zero = |x: &Bytes32| *x == ZERO32;
        // Fee rules (all actions).
        if self.fee_lamports == 0 && !zero(&self.fee_recipient) {
            return Err(Error::NonCanonical);
        }
        if self.expires_at != 0 && self.expires_at <= self.valid_after {
            return Err(Error::Window);
        }
        if self.valid_after < 0 || self.expires_at < 0 {
            return Err(Error::Window);
        }
        let rotation_fields_zero = zero(&self.new_key_id) && self.new_algorithm == 0;
        let ok = match self.action {
            WithdrawSol => {
                self.asset_type == AssetType::Sol
                    && zero(&self.mint)
                    && !zero(&self.destination)
                    && self.amount > 0
                    && self.decimals == 0
                    && rotation_fields_zero
            }
            WithdrawSpl => {
                matches!(self.asset_type, AssetType::SplToken | AssetType::Token2022)
                    && !zero(&self.mint)
                    && !zero(&self.destination)
                    && self.amount > 0
                    && rotation_fields_zero
            }
            RotateKey => {
                self.asset_type == AssetType::None
                    && zero(&self.mint)
                    && zero(&self.destination)
                    && self.amount == 0
                    && self.decimals == 0
                    && !zero(&self.new_key_id)
                    && Algorithm::from_u8(self.new_algorithm).is_some()
            }
            Pause | Unpause => {
                self.asset_type == AssetType::None
                    && zero(&self.mint)
                    && zero(&self.destination)
                    && self.amount == 0
                    && self.decimals == 0
                    && rotation_fields_zero
            }
            CloseVault => {
                self.asset_type == AssetType::Sol
                    && zero(&self.mint)
                    && !zero(&self.destination)
                    && self.amount == 0
                    && self.decimals == 0
                    && rotation_fields_zero
            }
        };
        if ok {
            Ok(())
        } else {
            Err(Error::NonCanonical)
        }
    }

    /// Encodes into the canonical 292-byte form after validating.
    pub fn encode(&self) -> Result<[u8; AUTH_LEN], Error> {
        self.validate()?;
        let mut b = [0u8; AUTH_LEN];
        b[offsets::DOMAIN..offsets::VERSION].copy_from_slice(&DOMAIN);
        b[offsets::VERSION..offsets::CLUSTER_ID].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        b[offsets::CLUSTER_ID..offsets::PROGRAM_ID].copy_from_slice(&self.cluster_id);
        b[offsets::PROGRAM_ID..offsets::VAULT].copy_from_slice(&self.program_id);
        b[offsets::VAULT..offsets::ACTION].copy_from_slice(&self.vault);
        b[offsets::ACTION] = self.action as u8;
        b[offsets::ASSET_TYPE] = self.asset_type as u8;
        b[offsets::NONCE..offsets::VALID_AFTER].copy_from_slice(&self.nonce.to_le_bytes());
        b[offsets::VALID_AFTER..offsets::EXPIRES_AT]
            .copy_from_slice(&self.valid_after.to_le_bytes());
        b[offsets::EXPIRES_AT..offsets::MINT].copy_from_slice(&self.expires_at.to_le_bytes());
        b[offsets::MINT..offsets::DESTINATION].copy_from_slice(&self.mint);
        b[offsets::DESTINATION..offsets::AMOUNT].copy_from_slice(&self.destination);
        b[offsets::AMOUNT..offsets::DECIMALS].copy_from_slice(&self.amount.to_le_bytes());
        b[offsets::DECIMALS] = self.decimals;
        b[offsets::FEE_RECIPIENT..offsets::FEE_LAMPORTS].copy_from_slice(&self.fee_recipient);
        b[offsets::FEE_LAMPORTS..offsets::NEW_KEY_ID]
            .copy_from_slice(&self.fee_lamports.to_le_bytes());
        b[offsets::NEW_KEY_ID..offsets::NEW_ALGORITHM].copy_from_slice(&self.new_key_id);
        b[offsets::NEW_ALGORITHM] = self.new_algorithm;
        Ok(b)
    }

    /// Decodes and validates a canonical encoding.
    ///
    /// Decoding is strict: `decode(x)` succeeds only if `encode(decode(x)) == x`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let b: &[u8; AUTH_LEN] = bytes.try_into().map_err(|_| Error::Length)?;
        if b[offsets::DOMAIN..offsets::VERSION] != DOMAIN {
            return Err(Error::Domain);
        }
        if u16::from_le_bytes([b[offsets::VERSION], b[offsets::VERSION + 1]]) != PROTOCOL_VERSION {
            return Err(Error::Version);
        }
        let auth = Self {
            cluster_id: rd32(b, offsets::CLUSTER_ID),
            program_id: rd32(b, offsets::PROGRAM_ID),
            vault: rd32(b, offsets::VAULT),
            action: Action::from_u8(b[offsets::ACTION]).ok_or(Error::Action)?,
            asset_type: AssetType::from_u8(b[offsets::ASSET_TYPE]).ok_or(Error::AssetType)?,
            nonce: rd_u64(b, offsets::NONCE),
            valid_after: rd_i64(b, offsets::VALID_AFTER),
            expires_at: rd_i64(b, offsets::EXPIRES_AT),
            mint: rd32(b, offsets::MINT),
            destination: rd32(b, offsets::DESTINATION),
            amount: rd_u64(b, offsets::AMOUNT),
            decimals: b[offsets::DECIMALS],
            fee_recipient: rd32(b, offsets::FEE_RECIPIENT),
            fee_lamports: rd_u64(b, offsets::FEE_LAMPORTS),
            new_key_id: rd32(b, offsets::NEW_KEY_ID),
            new_algorithm: b[offsets::NEW_ALGORITHM],
        };
        auth.validate()?;
        Ok(auth)
    }

    /// Checks the validity window against a clock reading (unix seconds).
    pub fn is_live_at(&self, unix_timestamp: i64) -> bool {
        (self.valid_after == 0 || unix_timestamp >= self.valid_after)
            && (self.expires_at == 0 || unix_timestamp < self.expires_at)
    }
}

/// The byte strings hashed (concatenated, SHA-256) to form a key identifier:
/// `key_id = SHA-256(KEY_ID_DOMAIN || algorithm || public_key)`.
///
/// Exposed as parts so that on-chain code can use the `sol_sha256` syscall.
pub fn key_id_preimage<'a>(
    algorithm: Algorithm,
    alg_byte: &'a [u8; 1],
    public_key: &'a [u8],
) -> [&'a [u8]; 3] {
    debug_assert_eq!(alg_byte[0], algorithm as u8);
    [&KEY_ID_DOMAIN, alg_byte, public_key]
}

/// Computes a key identifier off-chain.
#[cfg(feature = "sha2")]
pub fn key_id(algorithm: Algorithm, public_key: &[u8]) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let alg = [algorithm as u8];
    let mut h = Sha256::new();
    for part in key_id_preimage(algorithm, &alg, public_key) {
        h.update(part);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Authorization {
        Authorization {
            cluster_id: cluster::DEVNET,
            program_id: [1; 32],
            vault: [2; 32],
            action: Action::WithdrawSol,
            asset_type: AssetType::Sol,
            nonce: 10,
            valid_after: 0,
            expires_at: 1_900_000_000,
            mint: ZERO32,
            destination: [3; 32],
            amount: 10_000_000,
            decimals: 0,
            fee_recipient: ZERO32,
            fee_lamports: 0,
            new_key_id: ZERO32,
            new_algorithm: 0,
        }
    }

    #[test]
    fn roundtrip() {
        let a = sample();
        let b = a.encode().unwrap();
        assert_eq!(Authorization::decode(&b).unwrap(), a);
    }

    #[test]
    fn field_offsets_are_contiguous() {
        use offsets::*;
        let ends = [
            (DOMAIN, VERSION, 22),
            (VERSION, CLUSTER_ID, 2),
            (CLUSTER_ID, PROGRAM_ID, 32),
            (PROGRAM_ID, VAULT, 32),
            (VAULT, ACTION, 32),
            (ACTION, ASSET_TYPE, 1),
            (ASSET_TYPE, NONCE, 1),
            (NONCE, VALID_AFTER, 8),
            (VALID_AFTER, EXPIRES_AT, 8),
            (EXPIRES_AT, MINT, 8),
            (MINT, DESTINATION, 32),
            (DESTINATION, AMOUNT, 32),
            (AMOUNT, DECIMALS, 8),
            (DECIMALS, FEE_RECIPIENT, 1),
            (FEE_RECIPIENT, FEE_LAMPORTS, 32),
            (FEE_LAMPORTS, NEW_KEY_ID, 8),
            (NEW_KEY_ID, NEW_ALGORITHM, 32),
            (NEW_ALGORITHM, END, 1),
        ];
        for (start, end, len) in ends {
            assert_eq!(end - start, len);
        }
    }

    #[test]
    fn cluster_ids_match_base58_genesis_hashes() {
        // Decoding check written independently of the constants above.
        fn b58(s: &str) -> [u8; 32] {
            const A: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            let mut n = [0u32; 64];
            let mut len = 0usize;
            for c in s.bytes() {
                let mut carry = A.iter().position(|&x| x == c).unwrap() as u32;
                for d in n.iter_mut().take(len) {
                    carry += *d * 58;
                    *d = carry & 0xff;
                    carry >>= 8;
                }
                while carry > 0 {
                    n[len] = carry & 0xff;
                    len += 1;
                    carry >>= 8;
                }
            }
            let mut out = [0u8; 32];
            for i in 0..32 {
                out[31 - i] = n[i] as u8;
            }
            out
        }
        assert_eq!(
            b58("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"),
            cluster::MAINNET_BETA
        );
        assert_eq!(
            b58("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"),
            cluster::DEVNET
        );
        assert_eq!(
            b58("4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"),
            cluster::TESTNET
        );
    }
}
