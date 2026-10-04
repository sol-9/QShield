//! # qshield-client
//!
//! Rust SDK for QShield (research preview). Provides:
//!
//! * [`key`]: ML-DSA-44 keys generated locally from the OS CSPRNG, and the
//!   [`key::PqSigner`] interface for future hardware/offline signers;
//! * [`keystore`]: password-encrypted key files (Argon2id + XChaCha20-Poly1305);
//! * [`envelope`]: the authorization file used for offline signing;
//! * [`rpc`]: a minimal chain-access trait and a JSON-RPC implementation;
//! * `relayer`: a client for the relayer HTTP API (feature `http`);
//! * [`client`]: key setup, vault creation, SOL and SPL deposits, QSP-1 authorization
//!   builders and submission (v1 inline or legacy buffered).
//!
//! Secret material never leaves [`key::LocalKey`]/[`keystore`]: nothing in this
//! crate logs, prints or transmits it.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod client;
pub mod envelope;
pub mod key;
pub mod keystore;
pub mod policy;
pub mod recovery;
#[cfg(feature = "http")]
pub mod relayer;
pub mod rpc;

pub use client::{
    format_token_amount, parse_token_amount, AuthBuilder, AuthOptions, KeyAccountInfo, MintAccount,
    QShieldClient, TokenBalance, Transport, VaultInfo,
};
pub use envelope::Envelope;
pub use key::{LocalKey, PqSigner};
pub use keystore::{KdfParams, Keystore};
pub use qshield_protocol as protocol;
pub use rpc::{AccountData, Rpc};

/// Client errors. Messages never contain secret material.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The OS CSPRNG is unavailable; nothing was generated.
    #[error("secure randomness unavailable")]
    RandomnessUnavailable,
    /// Keystore problem (wrong password, tampering, unsupported format).
    #[error("keystore: {0}")]
    Keystore(&'static str),
    /// Authorization envelope problem.
    #[error("authorization file: {0}")]
    Envelope(&'static str),
    /// QSP-1 encoding/decoding error.
    #[error("QSP-1: {0:?}")]
    Protocol(qshield_protocol::Error),
    /// RPC failure.
    #[error("rpc: {0}")]
    Rpc(String),
    /// Transaction failed or was not confirmed.
    #[error("transaction: {0}")]
    Transaction(String),
    /// The RPC endpoint serves a different cluster than the program was built for.
    #[error("RPC endpoint is cluster {} but the program expects {}", hex::encode(.actual), hex::encode(.expected))]
    WrongCluster {
        /// Expected genesis hash.
        expected: protocol::Bytes32,
        /// Actual genesis hash.
        actual: protocol::Bytes32,
    },
    /// Unexpected on-chain account.
    #[error("account: {0}")]
    Account(String),
    /// Invalid argument.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}
