//! # QShield vault program (research preview v0.1)
//!
//! A Solana program holding SOL and SPL tokens in program-derived vault accounts whose
//! withdrawals and configuration changes are authorized **only** by FIPS 204
//! ML-DSA-44 signatures over QSP-1 authorizations (`docs/QSP-1.md`). No
//! Ed25519 key — neither the vault creator's wallet nor any administrator —
//! can move funds out of a vault.
//!
//! **Experimental. Unaudited. Do not use with meaningful funds.**
//!
//! See `docs/ARCHITECTURE.md` and `docs/PROTOCOL.md`.
#![allow(unexpected_cfgs)]
#![deny(missing_docs)]

pub mod error;
pub mod instruction;
pub mod processor;
pub mod state;
pub mod token;

use qshield_protocol::{cluster, Bytes32};

// Cluster selection. SBF builds must select exactly one cluster; host builds
// (tests, clients) default to localnet.
#[cfg(all(
    target_os = "solana",
    not(any(
        all(
            feature = "cluster-mainnet",
            not(feature = "cluster-devnet"),
            not(feature = "cluster-testnet"),
            not(feature = "cluster-localnet")
        ),
        all(
            feature = "cluster-devnet",
            not(feature = "cluster-mainnet"),
            not(feature = "cluster-testnet"),
            not(feature = "cluster-localnet")
        ),
        all(
            feature = "cluster-testnet",
            not(feature = "cluster-mainnet"),
            not(feature = "cluster-devnet"),
            not(feature = "cluster-localnet")
        ),
        all(
            feature = "cluster-localnet",
            not(feature = "cluster-mainnet"),
            not(feature = "cluster-devnet"),
            not(feature = "cluster-testnet")
        ),
    ))
))]
compile_error!("select exactly one of the features cluster-mainnet, cluster-devnet, cluster-testnet, cluster-localnet");

/// Genesis hash of the cluster this binary is built for. Every authorization
/// must carry exactly this value (prevents cross-cluster replay).
#[cfg(feature = "cluster-mainnet")]
pub const CLUSTER_ID: Bytes32 = cluster::MAINNET_BETA;
/// Genesis hash of the cluster this binary is built for.
#[cfg(all(feature = "cluster-devnet", not(feature = "cluster-mainnet")))]
pub const CLUSTER_ID: Bytes32 = cluster::DEVNET;
/// Genesis hash of the cluster this binary is built for.
#[cfg(all(
    feature = "cluster-testnet",
    not(any(feature = "cluster-mainnet", feature = "cluster-devnet"))
))]
pub const CLUSTER_ID: Bytes32 = cluster::TESTNET;
/// Cluster identifier this binary is built for (localnet sentinel).
#[cfg(not(any(
    feature = "cluster-mainnet",
    feature = "cluster-devnet",
    feature = "cluster-testnet"
)))]
pub const CLUSTER_ID: Bytes32 = cluster::LOCALNET;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    use solana_account_info::AccountInfo;
    use solana_program_error::ProgramResult;
    use solana_pubkey::Pubkey;

    solana_program_entrypoint::entrypoint!(process_instruction);

    fn process_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        data: &[u8],
    ) -> ProgramResult {
        crate::processor::process(program_id, accounts, data)
    }
}
