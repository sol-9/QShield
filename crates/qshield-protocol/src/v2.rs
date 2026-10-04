//! **QSP-1 version 2** — authorizations for vaults with a guardian policy
//! (ADR-0018, `docs/QSP-1.md` §10).
//!
//! A v2 authorization is the 292-byte v1 layout with domain
//! `QSHIELD_SOLANA_AUTH_V2` and version `2`, followed by 25 bytes:
//!
//! | Offset | Size | Field | Type |
//! |-------:|-----:|-------|------|
//! | 292 | 1 | `role` | u8: 1 = everyday (hot) key, 2 = guardian key |
//! | 293 | 8 | `ref_id` | u64: proposal id (ApproveWithdraw, CancelProposal) |
//! | 301 | 8 | `limit_lamports` | u64: spending limit (EnablePolicy, SetLimit) |
//! | 309 | 8 | `limit_period` | i64: seconds (EnablePolicy, SetLimit) |
//!
//! Total 317 bytes. The domain and version differ from v1, so a v1 message can
//! never be read as v2 or vice versa. The ML-DSA context stays
//! [`crate::ML_DSA_CONTEXT`].
//!
//! Nothing in v2 is delayed: everyday sends within the limit or to saved
//! addresses execute immediately; anything else is proposed by the everyday
//! key and approved by the guardian a moment later.

use crate::{rd32_at, rd_i64_at, rd_u64_at, Algorithm, AssetType, Bytes32, Error, ZERO32};

/// Domain separation tag of v2 authorizations.
pub const DOMAIN_V2: [u8; 22] = *b"QSHIELD_SOLANA_AUTH_V2";
/// Version field of v2 authorizations.
pub const PROTOCOL_VERSION_V2: u16 = 2;
/// Length of a v2 authorization.
pub const AUTH_V2_LEN: usize = 317;

/// Offsets of the fields appended by v2 (the first 292 bytes use
/// [`crate::offsets`]).
pub mod offsets_v2 {
    /// `role` (u8)
    pub const ROLE: usize = 292;
    /// `ref_id` (u64)
    pub const REF_ID: usize = 293;
    /// `limit_lamports` (u64)
    pub const LIMIT_LAMPORTS: usize = 301;
    /// `limit_period` (i64)
    pub const LIMIT_PERIOD: usize = 309;
    /// End.
    pub const END: usize = 317;
}

const _: () = assert!(offsets_v2::END == AUTH_V2_LEN);

/// Smallest allowed limit period (1 hour).
pub const MIN_LIMIT_PERIOD: i64 = 3_600;
/// Largest allowed limit period (30 days).
pub const MAX_LIMIT_PERIOD: i64 = 30 * 86_400;

/// Which key signs.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The everyday ("hot") key: the vault's current key.
    Everyday = 1,
    /// The guardian key, kept on another device or on paper.
    Guardian = 2,
}

impl Role {
    /// Parses a role byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Everyday),
            2 => Some(Self::Guardian),
            _ => None,
        }
    }
}

/// v2 actions.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionV2 {
    /// Everyday: send SOL now — to a saved address, or within the limit.
    WithdrawSol = 1,
    /// Everyday: send tokens now — to a saved address only.
    WithdrawSpl = 2,
    /// Guardian: replace the everyday key with `new_key_id`.
    RotateKey = 3,
    /// Either: freeze the vault (nothing can leave it).
    Pause = 4,
    /// Guardian: lift a freeze.
    Unpause = 5,
    /// Everyday: record a send that needs guardian approval.
    ProposeWithdraw = 7,
    /// Guardian: approve proposal `ref_id`; restates its exact effect.
    ApproveWithdraw = 8,
    /// Either: delete proposal `ref_id`.
    CancelProposal = 9,
    /// Everyday, on a vault without a policy: add the guardian `new_key_id`
    /// and the spending limit.
    EnablePolicy = 10,
    /// Guardian: any limit. Everyday: only a lower limit, same period.
    SetLimit = 11,
    /// Guardian: save `destination` (sends to it need no approval).
    AddAddress = 12,
    /// Either: remove a saved address.
    RemoveAddress = 13,
    /// Guardian: replace the guardian key with `new_key_id`.
    RotateGuardian = 14,
    /// Guardian: remove the policy (the vault returns to single-key v1 rules).
    DisablePolicy = 15,
}

impl ActionV2 {
    /// Parses an action byte. `6` (CloseVault) is not a v2 action: disable
    /// the policy first.
    pub fn from_u8(v: u8) -> Option<Self> {
        use ActionV2::*;
        Some(match v {
            1 => WithdrawSol,
            2 => WithdrawSpl,
            3 => RotateKey,
            4 => Pause,
            5 => Unpause,
            7 => ProposeWithdraw,
            8 => ApproveWithdraw,
            9 => CancelProposal,
            10 => EnablePolicy,
            11 => SetLimit,
            12 => AddAddress,
            13 => RemoveAddress,
            14 => RotateGuardian,
            15 => DisablePolicy,
            _ => return None,
        })
    }

    /// Roles allowed to sign this action (independent of vault state).
    pub fn allowed(self, role: Role) -> bool {
        use ActionV2::*;
        match self {
            WithdrawSol | WithdrawSpl | ProposeWithdraw | EnablePolicy => role == Role::Everyday,
            RotateKey | Unpause | ApproveWithdraw | AddAddress | RotateGuardian | DisablePolicy => {
                role == Role::Guardian
            }
            Pause | CancelProposal | SetLimit | RemoveAddress => true,
        }
    }
}

/// A decoded v2 authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationV2 {
    /// Genesis hash of the target cluster.
    pub cluster_id: Bytes32,
    /// QShield program address.
    pub program_id: Bytes32,
    /// Vault address.
    pub vault: Bytes32,
    /// Action.
    pub action: ActionV2,
    /// Asset class.
    pub asset_type: AssetType,
    /// The signing role's current nonce (everyday: vault nonce; guardian:
    /// the policy's guardian nonce).
    pub nonce: u64,
    /// Not valid before (unix seconds, 0 = no bound).
    pub valid_after: i64,
    /// Not valid at or after (unix seconds, 0 = never).
    pub expires_at: i64,
    /// Token mint.
    pub mint: Bytes32,
    /// Recipient (SOL: system account; SPL: token account) or saved address.
    pub destination: Bytes32,
    /// Lamports or token base units.
    pub amount: u64,
    /// Mint decimals.
    pub decimals: u8,
    /// Fee recipient (zero = transaction fee payer).
    pub fee_recipient: Bytes32,
    /// Fee paid from the vault.
    pub fee_lamports: u64,
    /// New key id (RotateKey, RotateGuardian, EnablePolicy).
    pub new_key_id: Bytes32,
    /// New key algorithm.
    pub new_algorithm: u8,
    /// Signing role.
    pub role: Role,
    /// Proposal id.
    pub ref_id: u64,
    /// Spending limit in lamports per period.
    pub limit_lamports: u64,
    /// Limit period in seconds.
    pub limit_period: i64,
}

impl AuthorizationV2 {
    /// Checks the canonical field rules of `docs/QSP-1.md` §10.
    pub fn validate(&self) -> Result<(), Error> {
        use ActionV2::*;
        let zero = |x: &Bytes32| *x == ZERO32;
        if self.fee_lamports == 0 && !zero(&self.fee_recipient) {
            return Err(Error::NonCanonical);
        }
        if self.valid_after < 0 || self.expires_at < 0 {
            return Err(Error::Window);
        }
        if self.expires_at != 0 && self.expires_at <= self.valid_after {
            return Err(Error::Window);
        }
        if !self.action.allowed(self.role) {
            return Err(Error::NonCanonical);
        }
        let no_asset = self.asset_type == AssetType::None
            && zero(&self.mint)
            && zero(&self.destination)
            && self.amount == 0
            && self.decimals == 0;
        let no_key = zero(&self.new_key_id) && self.new_algorithm == 0;
        let no_ref = self.ref_id == 0;
        let no_limit = self.limit_lamports == 0 && self.limit_period == 0;
        let limit_ok = (MIN_LIMIT_PERIOD..=MAX_LIMIT_PERIOD).contains(&self.limit_period);
        let new_key = !zero(&self.new_key_id) && Algorithm::from_u8(self.new_algorithm).is_some();
        // Asset fields of a transfer: SOL or SPL, as in v1.
        let transfer = match self.asset_type {
            AssetType::Sol => zero(&self.mint) && self.decimals == 0,
            AssetType::SplToken | AssetType::Token2022 => !zero(&self.mint),
            AssetType::None => false,
        } && !zero(&self.destination)
            && self.amount > 0;
        let saved_addr = self.asset_type == AssetType::None
            && zero(&self.mint)
            && !zero(&self.destination)
            && self.amount == 0
            && self.decimals == 0;
        let ok = match self.action {
            WithdrawSol => {
                self.asset_type == AssetType::Sol && transfer && no_key && no_ref && no_limit
            }
            WithdrawSpl => {
                matches!(self.asset_type, AssetType::SplToken | AssetType::Token2022)
                    && transfer
                    && no_key
                    && no_ref
                    && no_limit
            }
            ProposeWithdraw => transfer && no_key && no_ref && no_limit,
            ApproveWithdraw => transfer && no_key && self.ref_id != 0 && no_limit,
            CancelProposal => no_asset && no_key && self.ref_id != 0 && no_limit,
            RotateKey | RotateGuardian => no_asset && new_key && no_ref && no_limit,
            Pause | Unpause | DisablePolicy => no_asset && no_key && no_ref && no_limit,
            EnablePolicy => no_asset && new_key && no_ref && limit_ok,
            SetLimit => no_asset && no_key && no_ref && limit_ok,
            AddAddress | RemoveAddress => saved_addr && no_key && no_ref && no_limit,
        };
        if ok {
            Ok(())
        } else {
            Err(Error::NonCanonical)
        }
    }

    /// Encodes into the canonical 317-byte form after validating.
    pub fn encode(&self) -> Result<[u8; AUTH_V2_LEN], Error> {
        use crate::offsets as o;
        use offsets_v2 as o2;
        self.validate()?;
        let mut b = [0u8; AUTH_V2_LEN];
        b[o::DOMAIN..o::VERSION].copy_from_slice(&DOMAIN_V2);
        b[o::VERSION..o::CLUSTER_ID].copy_from_slice(&PROTOCOL_VERSION_V2.to_le_bytes());
        b[o::CLUSTER_ID..o::PROGRAM_ID].copy_from_slice(&self.cluster_id);
        b[o::PROGRAM_ID..o::VAULT].copy_from_slice(&self.program_id);
        b[o::VAULT..o::ACTION].copy_from_slice(&self.vault);
        b[o::ACTION] = self.action as u8;
        b[o::ASSET_TYPE] = self.asset_type as u8;
        b[o::NONCE..o::VALID_AFTER].copy_from_slice(&self.nonce.to_le_bytes());
        b[o::VALID_AFTER..o::EXPIRES_AT].copy_from_slice(&self.valid_after.to_le_bytes());
        b[o::EXPIRES_AT..o::MINT].copy_from_slice(&self.expires_at.to_le_bytes());
        b[o::MINT..o::DESTINATION].copy_from_slice(&self.mint);
        b[o::DESTINATION..o::AMOUNT].copy_from_slice(&self.destination);
        b[o::AMOUNT..o::DECIMALS].copy_from_slice(&self.amount.to_le_bytes());
        b[o::DECIMALS] = self.decimals;
        b[o::FEE_RECIPIENT..o::FEE_LAMPORTS].copy_from_slice(&self.fee_recipient);
        b[o::FEE_LAMPORTS..o::NEW_KEY_ID].copy_from_slice(&self.fee_lamports.to_le_bytes());
        b[o::NEW_KEY_ID..o::NEW_ALGORITHM].copy_from_slice(&self.new_key_id);
        b[o::NEW_ALGORITHM] = self.new_algorithm;
        b[o2::ROLE] = self.role as u8;
        b[o2::REF_ID..o2::LIMIT_LAMPORTS].copy_from_slice(&self.ref_id.to_le_bytes());
        b[o2::LIMIT_LAMPORTS..o2::LIMIT_PERIOD].copy_from_slice(&self.limit_lamports.to_le_bytes());
        b[o2::LIMIT_PERIOD..o2::END].copy_from_slice(&self.limit_period.to_le_bytes());
        Ok(b)
    }

    /// Decodes and validates; `decode(x)` succeeds only if `encode(decode(x)) == x`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        use crate::offsets as o;
        use offsets_v2 as o2;
        let b: &[u8; AUTH_V2_LEN] = bytes.try_into().map_err(|_| Error::Length)?;
        if b[o::DOMAIN..o::VERSION] != DOMAIN_V2 {
            return Err(Error::Domain);
        }
        if u16::from_le_bytes([b[o::VERSION], b[o::VERSION + 1]]) != PROTOCOL_VERSION_V2 {
            return Err(Error::Version);
        }
        let a = Self {
            cluster_id: rd32_at(b, o::CLUSTER_ID),
            program_id: rd32_at(b, o::PROGRAM_ID),
            vault: rd32_at(b, o::VAULT),
            action: ActionV2::from_u8(b[o::ACTION]).ok_or(Error::Action)?,
            asset_type: AssetType::from_u8(b[o::ASSET_TYPE]).ok_or(Error::AssetType)?,
            nonce: rd_u64_at(b, o::NONCE),
            valid_after: rd_i64_at(b, o::VALID_AFTER),
            expires_at: rd_i64_at(b, o::EXPIRES_AT),
            mint: rd32_at(b, o::MINT),
            destination: rd32_at(b, o::DESTINATION),
            amount: rd_u64_at(b, o::AMOUNT),
            decimals: b[o::DECIMALS],
            fee_recipient: rd32_at(b, o::FEE_RECIPIENT),
            fee_lamports: rd_u64_at(b, o::FEE_LAMPORTS),
            new_key_id: rd32_at(b, o::NEW_KEY_ID),
            new_algorithm: b[o::NEW_ALGORITHM],
            role: Role::from_u8(b[o2::ROLE]).ok_or(Error::NonCanonical)?,
            ref_id: rd_u64_at(b, o2::REF_ID),
            limit_lamports: rd_u64_at(b, o2::LIMIT_LAMPORTS),
            limit_period: rd_i64_at(b, o2::LIMIT_PERIOD),
        };
        a.validate()?;
        Ok(a)
    }

    /// Checks the validity window against a clock reading.
    pub fn is_live_at(&self, unix_timestamp: i64) -> bool {
        (self.valid_after == 0 || unix_timestamp >= self.valid_after)
            && (self.expires_at == 0 || unix_timestamp < self.expires_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cluster, Authorization, AUTH_LEN};

    fn base(action: ActionV2, role: Role) -> AuthorizationV2 {
        AuthorizationV2 {
            cluster_id: cluster::DEVNET,
            program_id: [1; 32],
            vault: [2; 32],
            action,
            asset_type: AssetType::None,
            nonce: 3,
            valid_after: 0,
            expires_at: 1_900_000_000,
            mint: ZERO32,
            destination: ZERO32,
            amount: 0,
            decimals: 0,
            fee_recipient: ZERO32,
            fee_lamports: 0,
            new_key_id: ZERO32,
            new_algorithm: 0,
            role,
            ref_id: 0,
            limit_lamports: 0,
            limit_period: 0,
        }
    }

    fn sol_send(action: ActionV2, role: Role) -> AuthorizationV2 {
        AuthorizationV2 {
            asset_type: AssetType::Sol,
            destination: [3; 32],
            amount: 5,
            ..base(action, role)
        }
    }

    #[test]
    fn roundtrip_every_action() {
        use ActionV2::*;
        let samples = [
            sol_send(WithdrawSol, Role::Everyday),
            AuthorizationV2 {
                asset_type: AssetType::Token2022,
                mint: [4; 32],
                decimals: 6,
                ..sol_send(WithdrawSpl, Role::Everyday)
            },
            sol_send(ProposeWithdraw, Role::Everyday),
            AuthorizationV2 {
                ref_id: 9,
                ..sol_send(ApproveWithdraw, Role::Guardian)
            },
            AuthorizationV2 {
                ref_id: 9,
                ..base(CancelProposal, Role::Everyday)
            },
            AuthorizationV2 {
                new_key_id: [5; 32],
                new_algorithm: 1,
                ..base(RotateKey, Role::Guardian)
            },
            base(Pause, Role::Everyday),
            base(Pause, Role::Guardian),
            base(Unpause, Role::Guardian),
            AuthorizationV2 {
                new_key_id: [5; 32],
                new_algorithm: 1,
                limit_lamports: 1_000_000_000,
                limit_period: 86_400,
                ..base(EnablePolicy, Role::Everyday)
            },
            AuthorizationV2 {
                limit_lamports: 0,
                limit_period: 3_600,
                ..base(SetLimit, Role::Everyday)
            },
            AuthorizationV2 {
                destination: [6; 32],
                ..base(AddAddress, Role::Guardian)
            },
            AuthorizationV2 {
                destination: [6; 32],
                ..base(RemoveAddress, Role::Everyday)
            },
            base(DisablePolicy, Role::Guardian),
        ];
        for a in samples {
            let b = a.encode().unwrap_or_else(|e| panic!("{a:?}: {e:?}"));
            assert_eq!(AuthorizationV2::decode(&b).unwrap(), a);
        }
    }

    #[test]
    fn roles_are_enforced_in_the_message() {
        use ActionV2::*;
        for (a, r) in [
            (
                sol_send(WithdrawSol, Role::Guardian),
                "guardian cannot send directly",
            ),
            (
                sol_send(ProposeWithdraw, Role::Guardian),
                "guardian does not propose",
            ),
            (
                AuthorizationV2 {
                    ref_id: 1,
                    ..sol_send(ApproveWithdraw, Role::Everyday)
                },
                "everyday key cannot approve",
            ),
            (base(Unpause, Role::Everyday), "everyday key cannot unpause"),
            (
                AuthorizationV2 {
                    destination: [6; 32],
                    ..base(AddAddress, Role::Everyday)
                },
                "everyday key cannot save addresses",
            ),
            (
                base(DisablePolicy, Role::Everyday),
                "everyday key cannot disable",
            ),
        ] {
            assert_eq!(a.encode(), Err(Error::NonCanonical), "{r}");
        }
    }

    #[test]
    fn canonical_rules() {
        use ActionV2::*;
        // Unused fields must be zero.
        let mut a = base(Pause, Role::Guardian);
        a.ref_id = 1;
        assert_eq!(a.encode(), Err(Error::NonCanonical));
        let mut a = sol_send(WithdrawSol, Role::Everyday);
        a.limit_period = 3_600;
        assert_eq!(a.encode(), Err(Error::NonCanonical));
        // Approve needs a proposal id.
        assert_eq!(
            sol_send(ApproveWithdraw, Role::Guardian).encode(),
            Err(Error::NonCanonical)
        );
        // Limit period bounds.
        for p in [0, 3_599, MAX_LIMIT_PERIOD + 1, -1] {
            let a = AuthorizationV2 {
                limit_period: p,
                ..base(SetLimit, Role::Guardian)
            };
            assert_eq!(a.encode(), Err(Error::NonCanonical), "period {p}");
        }
        // Fee recipient without fee.
        let mut a = base(Pause, Role::Everyday);
        a.fee_recipient = [7; 32];
        assert_eq!(a.encode(), Err(Error::NonCanonical));
    }

    #[test]
    fn decoding_is_strict_and_versions_are_separate() {
        let a = sol_send(ActionV2::WithdrawSol, Role::Everyday);
        let b = a.encode().unwrap();
        // Unknown role byte.
        let mut x = b;
        x[offsets_v2::ROLE] = 3;
        assert!(AuthorizationV2::decode(&x).is_err());
        // CloseVault (6) is not a v2 action.
        let mut x = b;
        x[crate::offsets::ACTION] = 6;
        assert_eq!(AuthorizationV2::decode(&x), Err(Error::Action));
        // v2 bytes are not v1, and v1 bytes are not v2.
        assert!(Authorization::decode(&b).is_err());
        assert!(Authorization::decode(&b[..AUTH_LEN]).is_err());
        let mut v1ish = [0u8; AUTH_V2_LEN];
        v1ish[..22].copy_from_slice(&crate::DOMAIN);
        assert_eq!(AuthorizationV2::decode(&v1ish), Err(Error::Domain));
        assert_eq!(AuthorizationV2::decode(&b[..316]), Err(Error::Length));
    }
}
