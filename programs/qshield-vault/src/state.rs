//! Account layouts.
//!
//! All accounts use fixed little-endian layouts with an 8-byte discriminator,
//! documented field-by-field in `docs/PROTOCOL.md`. Layouts are parsed with
//! explicit offsets (no serialization framework) so they are easy to audit
//! and identical for every client.

use qshield_mldsa::{ExpandedKey, A_HAT_POLYS, PUBLIC_KEY_LEN, SIGNATURE_LEN, TR_LEN};
use qshield_protocol::Bytes32;
use solana_program_error::ProgramError;

use crate::error::VaultError;

/// Current account layout version.
pub const LAYOUT_VERSION: u8 = 1;

fn rd32(d: &[u8], off: usize) -> Bytes32 {
    let mut o = [0u8; 32];
    o.copy_from_slice(&d[off..off + 32]);
    o
}
fn rd_u64(d: &[u8], off: usize) -> u64 {
    let mut o = [0u8; 8];
    o.copy_from_slice(&d[off..off + 8]);
    u64::from_le_bytes(o)
}
fn rd_i64(d: &[u8], off: usize) -> i64 {
    rd_u64(d, off) as i64
}

// ---------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------

/// Vault lifecycle status.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultStatus {
    /// Normal operation.
    Active = 1,
    /// Withdrawals blocked by a PQ-authorized `Pause`.
    Paused = 2,
    /// Permanently closed; the account remains as a tombstone so the address
    /// (and therefore old authorizations) can never be re-initialized.
    Closed = 3,
}

impl VaultStatus {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Active),
            2 => Some(Self::Paused),
            3 => Some(Self::Closed),
            _ => None,
        }
    }
}

/// Vault account (PDA `["vault", initial_key_id, vault_seed]`).
///
/// | off | len | field            |
/// |-----|-----|------------------|
/// | 0   | 8   | discriminator `QSHVAULT` |
/// | 8   | 1   | layout version   |
/// | 9   | 1   | status           |
/// | 10  | 1   | bump             |
/// | 11  | 1   | pq_algorithm     |
/// | 12  | 1   | threshold (1)    |
/// | 13  | 1   | key_count (1)    |
/// | 14  | 1   | policy_mode (0 = none, 1 = guardian policy; ADR-0018) |
/// | 15  | 1   | reserved         |
/// | 16  | 8   | nonce            |
/// | 24  | 32  | key_id           |
/// | 56  | 32  | key_account      |
/// | 88  | 32  | initial_key_id (PDA seed) |
/// | 120 | 32  | vault_seed (PDA seed) |
/// | 152 | 8   | created_slot     |
/// | 160 | 8   | created_at (unix)|
/// | 168 | 88  | reserved (zero)  |
///
/// `threshold` and `key_count` reserve space for future m-of-n policies.
/// Byte 14 (formerly `recovery_mode`, always 0) is `policy_mode`: 1 when a
/// guardian policy account (`["policy", vault]`) governs the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vault {
    /// Lifecycle status.
    pub status: VaultStatus,
    /// PDA bump.
    pub bump: u8,
    /// Algorithm of the current key.
    pub pq_algorithm: u8,
    /// Next nonce to be consumed.
    pub nonce: u64,
    /// Identifier of the current key.
    pub key_id: Bytes32,
    /// Address of the current key account.
    pub key_account: Bytes32,
    /// Key id used in the PDA seeds (the key at creation).
    pub initial_key_id: Bytes32,
    /// Creator-chosen PDA seed.
    pub vault_seed: Bytes32,
    /// Slot at initialization.
    pub created_slot: u64,
    /// Unix timestamp at initialization.
    pub created_at: i64,
    /// 0 = single-key vault (QSP-1 v1), 1 = guardian policy (QSP-1 v2 only).
    pub policy_mode: u8,
}

impl Vault {
    /// Discriminator.
    pub const DISCRIMINATOR: [u8; 8] = *b"QSHVAULT";
    /// Account size.
    pub const LEN: usize = 256;

    /// Parses a vault account's data.
    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        if d.len() != Self::LEN || d[..8] != Self::DISCRIMINATOR || d[8] != LAYOUT_VERSION {
            return Err(VaultError::InvalidAccount.into());
        }
        Ok(Self {
            status: VaultStatus::from_u8(d[9]).ok_or(VaultError::InvalidAccount)?,
            bump: d[10],
            pq_algorithm: d[11],
            nonce: rd_u64(d, 16),
            key_id: rd32(d, 24),
            key_account: rd32(d, 56),
            initial_key_id: rd32(d, 88),
            vault_seed: rd32(d, 120),
            created_slot: rd_u64(d, 152),
            created_at: rd_i64(d, 160),
            policy_mode: match d[14] {
                v @ (0 | 1) => v,
                _ => return Err(VaultError::InvalidAccount.into()),
            },
        })
    }

    /// Writes the vault into account data (which must be `LEN` bytes).
    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        if d.len() != Self::LEN {
            return Err(VaultError::InvalidAccount.into());
        }
        d.fill(0);
        d[..8].copy_from_slice(&Self::DISCRIMINATOR);
        d[8] = LAYOUT_VERSION;
        d[9] = self.status as u8;
        d[10] = self.bump;
        d[11] = self.pq_algorithm;
        d[12] = 1; // threshold
        d[13] = 1; // key_count
        d[14] = self.policy_mode;
        d[16..24].copy_from_slice(&self.nonce.to_le_bytes());
        d[24..56].copy_from_slice(&self.key_id);
        d[56..88].copy_from_slice(&self.key_account);
        d[88..120].copy_from_slice(&self.initial_key_id);
        d[120..152].copy_from_slice(&self.vault_seed);
        d[152..160].copy_from_slice(&self.created_slot.to_le_bytes());
        d[160..168].copy_from_slice(&self.created_at.to_le_bytes());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Key account
// ---------------------------------------------------------------------------

/// Key account lifecycle.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyState {
    /// The creator is uploading the public key.
    Writing = 1,
    /// Public key verified against `key_id`; expansion in progress.
    Expanding = 2,
    /// Fully expanded; immutable from now on.
    Ready = 3,
}

impl KeyState {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Writing),
            2 => Some(Self::Expanding),
            3 => Some(Self::Ready),
            _ => None,
        }
    }
}

/// Key account (a keypair account allocated by its creator; see
/// `processor::create_key` for why it is not a PDA): an ML-DSA-44 public key
/// plus its on-chain expansion.
///
/// | off   | len   | field |
/// |-------|-------|-------|
/// | 0     | 8     | discriminator `QSHKEY01` |
/// | 8     | 1     | layout version |
/// | 9     | 1     | algorithm |
/// | 10    | 1     | state |
/// | 11    | 1     | reserved (0) |
/// | 12    | 1     | role: 0 free, 1 vault (everyday) key, 2 guardian key |
/// | 13    | 1     | expanded polynomial count (0..=20) |
/// | 14    | 10    | reserved |
/// | 24    | 32    | vault |
/// | 56    | 32    | key_id |
/// | 88    | 32    | creator (rent payer, refunded on close) |
/// | 120   | 1312  | public key |
/// | 1432  | 64    | tr = H(pk, 64) |
/// | 1496  | 16384 | A_hat (16 polys × 256 × u32 LE) |
/// | 17880 | 4096  | t1_hat (4 polys × 256 × u32 LE) |
/// | 21976 |       | end |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyHeader {
    /// Signature algorithm.
    pub algorithm: u8,
    /// Lifecycle state.
    pub state: KeyState,
    /// Reserved (always 0).
    pub bump: u8,
    /// Whether a vault currently uses this key (as its key or its guardian).
    pub in_use: bool,
    /// When `in_use`: this key is the vault's guardian (role byte 2) rather
    /// than its everyday key (role byte 1).
    pub guardian: bool,
    /// Number of expanded polynomials (A_hat then t1_hat).
    pub expanded: u8,
    /// Vault this key belongs to.
    pub vault: Bytes32,
    /// Key identifier.
    pub key_id: Bytes32,
    /// Creator / rent payer.
    pub creator: Bytes32,
}

/// Total number of polynomials to expand (A_hat + t1_hat).
pub const EXPAND_TOTAL: u8 = (A_HAT_POLYS + 4) as u8;

/// Offsets inside a key account.
pub mod key_off {
    /// Public key.
    pub const PK: usize = 120;
    /// tr.
    pub const TR: usize = PK + super::PUBLIC_KEY_LEN;
    /// A_hat.
    pub const A_HAT: usize = TR + super::TR_LEN;
    /// t1_hat.
    pub const T1_HAT: usize = A_HAT + super::A_HAT_POLYS * 1024;
    /// End of account.
    pub const END: usize = T1_HAT + 4 * 1024;
}

const _: () = assert!(key_off::A_HAT % 8 == 0);
const _: () = assert!(key_off::END == 21_976);

impl KeyHeader {
    /// Discriminator.
    pub const DISCRIMINATOR: [u8; 8] = *b"QSHKEY01";
    /// Account size.
    pub const LEN: usize = key_off::END;

    /// Parses the header of a key account.
    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        if d.len() != Self::LEN || d[..8] != Self::DISCRIMINATOR || d[8] != LAYOUT_VERSION {
            return Err(VaultError::InvalidAccount.into());
        }
        Ok(Self {
            algorithm: d[9],
            state: KeyState::from_u8(d[10]).ok_or(VaultError::InvalidAccount)?,
            bump: d[11],
            in_use: d[12] != 0,
            guardian: match d[12] {
                0 | 1 => false,
                2 => true,
                _ => return Err(VaultError::InvalidAccount.into()),
            },
            expanded: d[13],
            vault: rd32(d, 24),
            key_id: rd32(d, 56),
            creator: rd32(d, 88),
        })
    }

    /// Writes the header (bytes `0..120`); the body is left untouched.
    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        if d.len() != Self::LEN {
            return Err(VaultError::InvalidAccount.into());
        }
        d[..key_off::PK].fill(0);
        d[..8].copy_from_slice(&Self::DISCRIMINATOR);
        d[8] = LAYOUT_VERSION;
        d[9] = self.algorithm;
        d[10] = self.state as u8;
        d[11] = self.bump;
        d[12] = match (self.in_use, self.guardian) {
            (false, _) => 0,
            (true, false) => 1,
            (true, true) => 2,
        };
        d[13] = self.expanded;
        d[24..56].copy_from_slice(&self.vault);
        d[56..88].copy_from_slice(&self.key_id);
        d[88..120].copy_from_slice(&self.creator);
        Ok(())
    }
}

/// Zero-copy view of the expansion stored in a `Ready` key account.
///
/// Returns `None` if the account data is not 4-byte aligned in memory (the
/// caller then falls back to copying).
pub fn expanded_key_view(d: &[u8]) -> Option<ExpandedKey<'_>> {
    let a = &d[key_off::A_HAT..key_off::T1_HAT];
    let t = &d[key_off::T1_HAT..key_off::END];
    let tr: &[u8; TR_LEN] = d[key_off::TR..key_off::A_HAT].try_into().ok()?;
    Some(ExpandedKey {
        a_hat: bytemuck::try_from_bytes(a).ok()?,
        t1_hat: bytemuck::try_from_bytes(t).ok()?,
        tr,
    })
}

// ---------------------------------------------------------------------------
// Signature buffer
// ---------------------------------------------------------------------------

/// Signature buffer state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferState {
    /// Being written by its creator.
    Writing = 1,
    /// Immutable; may be consumed by `ExecuteWithBuffer`.
    Finalized = 2,
}

/// Signature buffer (PDA `["sigbuf", vault, creator, buffer_id]`), used when
/// the 2,420-byte signature cannot travel inline (legacy/v0 transactions).
///
/// | off | len  | field |
/// |-----|------|-------|
/// | 0   | 8    | discriminator `QSHSIGB1` |
/// | 8   | 1    | layout version |
/// | 9   | 1    | state |
/// | 10  | 1    | bump |
/// | 11  | 5    | reserved |
/// | 16  | 32   | vault |
/// | 48  | 32   | creator |
/// | 80  | 8    | buffer_id |
/// | 88  | 2420 | signature bytes |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigBuffer {
    /// State.
    pub state: BufferState,
    /// PDA bump.
    pub bump: u8,
    /// Vault the buffer is bound to.
    pub vault: Bytes32,
    /// Creator (only signer allowed to write/close; refunded on close).
    pub creator: Bytes32,
    /// Creator-chosen id.
    pub buffer_id: u64,
}

impl SigBuffer {
    /// Discriminator.
    pub const DISCRIMINATOR: [u8; 8] = *b"QSHSIGB1";
    /// Offset of the signature bytes.
    pub const DATA: usize = 88;
    /// Account size.
    pub const LEN: usize = Self::DATA + SIGNATURE_LEN;

    /// Parses a buffer header.
    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        if d.len() != Self::LEN || d[..8] != Self::DISCRIMINATOR || d[8] != LAYOUT_VERSION {
            return Err(VaultError::InvalidAccount.into());
        }
        let state = match d[9] {
            1 => BufferState::Writing,
            2 => BufferState::Finalized,
            _ => return Err(VaultError::InvalidAccount.into()),
        };
        Ok(Self {
            state,
            bump: d[10],
            vault: rd32(d, 16),
            creator: rd32(d, 48),
            buffer_id: rd_u64(d, 80),
        })
    }

    /// Writes the header (bytes `0..88`).
    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        if d.len() != Self::LEN {
            return Err(VaultError::InvalidAccount.into());
        }
        d[..Self::DATA].fill(0);
        d[..8].copy_from_slice(&Self::DISCRIMINATOR);
        d[8] = LAYOUT_VERSION;
        d[9] = self.state as u8;
        d[10] = self.bump;
        d[16..48].copy_from_slice(&self.vault);
        d[48..80].copy_from_slice(&self.creator);
        d[80..88].copy_from_slice(&self.buffer_id.to_le_bytes());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Guardian policy (ADR-0018)
// ---------------------------------------------------------------------------

/// Maximum number of saved addresses.
pub const MAX_SAVED: usize = 8;

/// Guardian policy (PDA `["policy", vault]`), never closed once created so
/// its guardian nonce is never reused.
///
/// | off | len | field |
/// |-----|-----|-------|
/// | 0   | 8   | discriminator `QSHPOL01` |
/// | 8   | 1   | layout version |
/// | 9   | 1   | bump |
/// | 10  | 1   | enabled (0/1) |
/// | 11  | 1   | saved address count |
/// | 12  | 4   | reserved |
/// | 16  | 32  | vault |
/// | 48  | 32  | guardian key id |
/// | 80  | 32  | guardian key account |
/// | 112 | 8   | guardian nonce |
/// | 120 | 8   | limit (lamports per period) |
/// | 128 | 8   | period (seconds) |
/// | 136 | 8   | available (lamports) |
/// | 144 | 8   | last refill (unix seconds) |
/// | 152 | 8   | reserved |
/// | 160 | 256 | saved addresses (8 × 32) |
/// | 416 | 96  | reserved |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// PDA bump.
    pub bump: u8,
    /// Whether the policy is in force (the vault's `policy_mode` mirrors it).
    pub enabled: bool,
    /// Vault.
    pub vault: Bytes32,
    /// Guardian key id.
    pub guardian_key_id: Bytes32,
    /// Guardian key account.
    pub guardian_key_account: Bytes32,
    /// Next guardian nonce (independent of the vault nonce).
    pub guardian_nonce: u64,
    /// Everyday-key spending limit per period (lamports).
    pub limit: u64,
    /// Limit period (seconds).
    pub period: i64,
    /// Currently spendable without the guardian.
    pub available: u64,
    /// Last refill time.
    pub last_refill: i64,
    /// Saved addresses (first `saved_len` entries are meaningful).
    pub saved: [Bytes32; MAX_SAVED],
    /// Number of saved addresses.
    pub saved_len: u8,
}

impl Policy {
    /// Discriminator.
    pub const DISCRIMINATOR: [u8; 8] = *b"QSHPOL01";
    /// Account size.
    pub const LEN: usize = 512;
    /// PDA seed prefix.
    pub const SEED: &'static [u8] = b"policy";

    /// Parses a policy account.
    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        if d.len() != Self::LEN || d[..8] != Self::DISCRIMINATOR || d[8] != LAYOUT_VERSION {
            return Err(VaultError::InvalidAccount.into());
        }
        let saved_len = d[11];
        if saved_len as usize > MAX_SAVED || d[10] > 1 {
            return Err(VaultError::InvalidAccount.into());
        }
        let mut saved = [[0u8; 32]; MAX_SAVED];
        for (i, s) in saved.iter_mut().enumerate() {
            *s = rd32(d, 160 + 32 * i);
        }
        Ok(Self {
            bump: d[9],
            enabled: d[10] == 1,
            vault: rd32(d, 16),
            guardian_key_id: rd32(d, 48),
            guardian_key_account: rd32(d, 80),
            guardian_nonce: rd_u64(d, 112),
            limit: rd_u64(d, 120),
            period: rd_i64(d, 128),
            available: rd_u64(d, 136),
            last_refill: rd_i64(d, 144),
            saved,
            saved_len,
        })
    }

    /// Writes the policy.
    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        if d.len() != Self::LEN {
            return Err(VaultError::InvalidAccount.into());
        }
        d.fill(0);
        d[..8].copy_from_slice(&Self::DISCRIMINATOR);
        d[8] = LAYOUT_VERSION;
        d[9] = self.bump;
        d[10] = self.enabled as u8;
        d[11] = self.saved_len;
        d[16..48].copy_from_slice(&self.vault);
        d[48..80].copy_from_slice(&self.guardian_key_id);
        d[80..112].copy_from_slice(&self.guardian_key_account);
        d[112..120].copy_from_slice(&self.guardian_nonce.to_le_bytes());
        d[120..128].copy_from_slice(&self.limit.to_le_bytes());
        d[128..136].copy_from_slice(&self.period.to_le_bytes());
        d[136..144].copy_from_slice(&self.available.to_le_bytes());
        d[144..152].copy_from_slice(&self.last_refill.to_le_bytes());
        for i in 0..self.saved_len as usize {
            d[160 + 32 * i..192 + 32 * i].copy_from_slice(&self.saved[i]);
        }
        Ok(())
    }

    /// Whether `addr` is a saved address.
    pub fn is_saved(&self, addr: &Bytes32) -> bool {
        self.saved[..self.saved_len as usize].contains(addr)
    }

    /// Refills the allowance for the time elapsed since the last refill
    /// (token bucket: `limit` per `period`, never above `limit`). A clock that
    /// moved backwards refills nothing.
    pub fn refill(&mut self, now: i64) {
        if self.period > 0 && now > self.last_refill {
            let elapsed = (now - self.last_refill) as u128;
            let add = elapsed.saturating_mul(self.limit as u128) / self.period as u128;
            let avail = (self.available as u128).saturating_add(add);
            self.available = avail.min(self.limit as u128) as u64;
        }
        if now > self.last_refill {
            self.last_refill = now;
        }
    }
}

/// A send proposed by the everyday key, waiting for the guardian (PDA
/// `["proposal", vault, id_le]`, where `id` is the vault nonce the proposal
/// consumed). Nothing waits on a timer: the guardian approves whenever ready.
///
/// | off | len | field |
/// |-----|-----|-------|
/// | 0   | 8   | discriminator `QSHPROP1` |
/// | 8   | 1   | layout version |
/// | 9   | 1   | bump |
/// | 10  | 1   | asset type |
/// | 11  | 1   | decimals |
/// | 12  | 4   | reserved |
/// | 16  | 32  | vault |
/// | 48  | 8   | id |
/// | 56  | 8   | created at |
/// | 64  | 8   | expires at (0 = never) |
/// | 72  | 32  | everyday key id at creation (rotation invalidates) |
/// | 104 | 32  | mint |
/// | 136 | 32  | destination |
/// | 168 | 8   | amount |
/// | 176 | 32  | rent payer (refunded on close) |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proposal {
    /// PDA bump.
    pub bump: u8,
    /// QSP-1 asset type byte.
    pub asset_type: u8,
    /// Decimals (SPL).
    pub decimals: u8,
    /// Vault.
    pub vault: Bytes32,
    /// Id (= the vault nonce consumed by the proposal).
    pub id: u64,
    /// Creation time.
    pub created_at: i64,
    /// Expiry copied from the proposing authorization (0 = never).
    pub expires_at: i64,
    /// Everyday key that proposed it.
    pub proposer_key_id: Bytes32,
    /// Mint (SPL) or zero.
    pub mint: Bytes32,
    /// Recipient.
    pub destination: Bytes32,
    /// Amount.
    pub amount: u64,
    /// Rent payer.
    pub rent_payer: Bytes32,
}

impl Proposal {
    /// Discriminator.
    pub const DISCRIMINATOR: [u8; 8] = *b"QSHPROP1";
    /// Account size.
    pub const LEN: usize = 208;
    /// PDA seed prefix.
    pub const SEED: &'static [u8] = b"proposal";

    /// Parses a proposal.
    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        if d.len() != Self::LEN || d[..8] != Self::DISCRIMINATOR || d[8] != LAYOUT_VERSION {
            return Err(VaultError::InvalidAccount.into());
        }
        Ok(Self {
            bump: d[9],
            asset_type: d[10],
            decimals: d[11],
            vault: rd32(d, 16),
            id: rd_u64(d, 48),
            created_at: rd_i64(d, 56),
            expires_at: rd_i64(d, 64),
            proposer_key_id: rd32(d, 72),
            mint: rd32(d, 104),
            destination: rd32(d, 136),
            amount: rd_u64(d, 168),
            rent_payer: rd32(d, 176),
        })
    }

    /// Writes the proposal.
    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        if d.len() != Self::LEN {
            return Err(VaultError::InvalidAccount.into());
        }
        d.fill(0);
        d[..8].copy_from_slice(&Self::DISCRIMINATOR);
        d[8] = LAYOUT_VERSION;
        d[9] = self.bump;
        d[10] = self.asset_type;
        d[11] = self.decimals;
        d[16..48].copy_from_slice(&self.vault);
        d[48..56].copy_from_slice(&self.id.to_le_bytes());
        d[56..64].copy_from_slice(&self.created_at.to_le_bytes());
        d[64..72].copy_from_slice(&self.expires_at.to_le_bytes());
        d[72..104].copy_from_slice(&self.proposer_key_id);
        d[104..136].copy_from_slice(&self.mint);
        d[136..168].copy_from_slice(&self.destination);
        d[168..176].copy_from_slice(&self.amount.to_le_bytes());
        d[176..208].copy_from_slice(&self.rent_payer);
        Ok(())
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    fn policy(limit: u64, period: i64) -> Policy {
        Policy {
            bump: 1,
            enabled: true,
            vault: [1; 32],
            guardian_key_id: [2; 32],
            guardian_key_account: [3; 32],
            guardian_nonce: 0,
            limit,
            period,
            available: 0,
            last_refill: 1_000,
            saved: [[0; 32]; MAX_SAVED],
            saved_len: 0,
        }
    }

    #[test]
    fn token_bucket_bounds() {
        let mut p = policy(1_000, 100);
        p.refill(1_050);
        assert_eq!(p.available, 500);
        p.refill(10_000);
        assert_eq!(p.available, 1_000, "never above the limit");
        p.available = 0;
        p.refill(9_000); // clock went backwards
        assert_eq!(p.available, 0);
        assert_eq!(p.last_refill, 10_000);
        let mut big = policy(u64::MAX, 3_600);
        big.refill(i64::MAX);
        assert_eq!(big.available, u64::MAX);
    }

    #[test]
    fn roundtrip_and_saved() {
        let mut p = policy(5, 3_600);
        p.saved[0] = [9; 32];
        p.saved_len = 1;
        let mut d = [0u8; Policy::LEN];
        p.store(&mut d).unwrap();
        let q = Policy::load(&d).unwrap();
        assert_eq!(q, p);
        assert!(q.is_saved(&[9; 32]));
        assert!(!q.is_saved(&[0; 32]), "empty slots are never saved");
        d[11] = 9;
        assert!(Policy::load(&d).is_err());
    }
}
