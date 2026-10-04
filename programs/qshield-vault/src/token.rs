//! SPL Token / Token-2022 account parsing and the mint policy (ADR-0015).
//!
//! Pure functions over account bytes, shared by the program and by clients so
//! that both apply exactly the same rules. Nothing here trusts client-provided
//! metadata: every value is read from the account data owned by the token
//! program the authorization names.

use qshield_protocol::{AssetType, Bytes32};
use solana_pubkey::Pubkey;

use crate::error::VaultError;

/// SPL Token program (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`).
pub const TOKEN_PROGRAM: Pubkey =
    Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
/// Token-2022 program (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`).
pub const TOKEN_2022_PROGRAM: Pubkey =
    Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
/// Associated Token Account program (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`).
pub const ASSOCIATED_TOKEN_PROGRAM: Pubkey =
    Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// Size of a base mint (both programs).
pub const MINT_LEN: usize = 82;
/// Size of a base token account (both programs).
pub const ACCOUNT_LEN: usize = 165;
/// Size of a multisig account; never a valid mint or token account.
const MULTISIG_LEN: usize = 355;
/// Token-2022 `AccountType` byte position (right after the base account size).
const ACCOUNT_TYPE_OFFSET: usize = ACCOUNT_LEN;
const ACCOUNT_TYPE_MINT: u8 = 1;
const ACCOUNT_TYPE_ACCOUNT: u8 = 2;
/// `TransferChecked` instruction tag (same in both programs).
pub const TRANSFER_CHECKED: u8 = 12;

/// Token-2022 extension types (`spl-token-2022` `ExtensionType`, u16).
pub mod ext {
    /// End of the initialized TLV entries.
    pub const UNINITIALIZED: u16 = 0;
    /// Transfer fees withheld by the mint.
    pub const TRANSFER_FEE_CONFIG: u16 = 1;
    /// Authority that may close the mint once its supply is zero.
    pub const MINT_CLOSE_AUTHORITY: u16 = 3;
    /// Confidential transfers.
    pub const CONFIDENTIAL_TRANSFER_MINT: u16 = 4;
    /// New accounts start in a configured state (e.g. frozen).
    pub const DEFAULT_ACCOUNT_STATE: u16 = 6;
    /// Tokens cannot be transferred.
    pub const NON_TRANSFERABLE: u16 = 9;
    /// UI amount accrues interest (base units differ from displayed amount).
    pub const INTEREST_BEARING_CONFIG: u16 = 10;
    /// A delegate that can move or burn tokens from every account.
    pub const PERMANENT_DELEGATE: u16 = 12;
    /// Every transfer invokes an arbitrary program.
    pub const TRANSFER_HOOK: u16 = 14;
    /// Pointer to metadata.
    pub const METADATA_POINTER: u16 = 18;
    /// Embedded metadata.
    pub const TOKEN_METADATA: u16 = 19;
    /// Pointer to a group.
    pub const GROUP_POINTER: u16 = 20;
    /// Group configuration.
    pub const TOKEN_GROUP: u16 = 21;
    /// Pointer to group membership.
    pub const GROUP_MEMBER_POINTER: u16 = 22;
    /// Group membership.
    pub const TOKEN_GROUP_MEMBER: u16 = 23;
    /// UI amount scaled by a multiplier.
    pub const SCALED_UI_AMOUNT: u16 = 25;
    /// Mint-wide pause.
    pub const PAUSABLE: u16 = 26;

    /// Mint extensions that do not change who can move tokens, how many base
    /// units arrive, or whether a transfer runs third-party code. Everything
    /// else, including extensions unknown to this program version, is
    /// rejected (ADR-0015).
    pub const MINT_ALLOWED: &[u16] = &[
        MINT_CLOSE_AUTHORITY,
        METADATA_POINTER,
        TOKEN_METADATA,
        GROUP_POINTER,
        TOKEN_GROUP,
        GROUP_MEMBER_POINTER,
        TOKEN_GROUP_MEMBER,
    ];
}

/// Token program for a QSP-1 asset type.
pub fn program_for(asset: AssetType) -> Option<Pubkey> {
    match asset {
        AssetType::SplToken => Some(TOKEN_PROGRAM),
        AssetType::Token2022 => Some(TOKEN_2022_PROGRAM),
        AssetType::None | AssetType::Sol => None,
    }
}

/// QSP-1 asset type for a token program id.
pub fn asset_for(program: &Pubkey) -> Option<AssetType> {
    if *program == TOKEN_PROGRAM {
        Some(AssetType::SplToken)
    } else if *program == TOKEN_2022_PROGRAM {
        Some(AssetType::Token2022)
    } else {
        None
    }
}

/// Validated mint fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MintInfo {
    /// Decimals.
    pub decimals: u8,
    /// Total supply in base units.
    pub supply: u64,
    /// Whether a freeze authority is set (the issuer can freeze any account).
    pub has_freeze_authority: bool,
}

/// Token account state (`AccountState`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenAccountState {
    /// Usable.
    Initialized,
    /// Frozen by the mint's freeze authority.
    Frozen,
}

/// Parsed token account fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenAccountInfo {
    /// Mint.
    pub mint: Bytes32,
    /// Owner (authority).
    pub owner: Bytes32,
    /// Balance in base units.
    pub amount: u64,
    /// Initialized or frozen.
    pub state: TokenAccountState,
}

fn rd32(d: &[u8], off: usize) -> Bytes32 {
    let mut a = [0u8; 32];
    a.copy_from_slice(&d[off..off + 32]);
    a
}

fn rd_u64(d: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&d[off..off + 8]);
    u64::from_le_bytes(a)
}

/// Decodes a `COption` tag (`0` none, `1` some); any other value is malformed.
fn coption(d: &[u8], off: usize) -> Result<bool, VaultError> {
    match u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]]) {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(VaultError::InvalidMint),
    }
}

/// Iterates over the Token-2022 TLV entries starting at `tlv`, calling `f`
/// with each initialized extension type. Malformed data fails.
fn for_each_extension(
    tlv: &[u8],
    mut f: impl FnMut(u16) -> Result<(), VaultError>,
) -> Result<(), VaultError> {
    let mut i = 0usize;
    while i < tlv.len() {
        if tlv.len() - i < 2 {
            // A trailing byte too short to hold a type: end of entries.
            return Ok(());
        }
        let t = u16::from_le_bytes([tlv[i], tlv[i + 1]]);
        if t == ext::UNINITIALIZED {
            return Ok(());
        }
        if tlv.len() - i < 4 {
            return Err(VaultError::InvalidMint);
        }
        let len = u16::from_le_bytes([tlv[i + 2], tlv[i + 3]]) as usize;
        let end = i + 4 + len;
        if end > tlv.len() {
            return Err(VaultError::InvalidMint);
        }
        f(t)?;
        i = end;
    }
    Ok(())
}

/// Parses and validates mint data for `program` and applies the extension
/// policy. `program` must be the account's owner (checked by the caller).
pub fn parse_mint(program: &Pubkey, d: &[u8]) -> Result<MintInfo, VaultError> {
    let base_ok = d.len() == MINT_LEN
        || (*program == TOKEN_2022_PROGRAM
            && d.len() > ACCOUNT_TYPE_OFFSET
            && d.len() != MULTISIG_LEN
            && d[ACCOUNT_TYPE_OFFSET] == ACCOUNT_TYPE_MINT
            && d[MINT_LEN..ACCOUNT_TYPE_OFFSET].iter().all(|&b| b == 0));
    if !base_ok {
        return Err(VaultError::InvalidMint);
    }
    coption(d, 0)?;
    let supply = rd_u64(d, 36);
    let decimals = d[44];
    if d[45] != 1 {
        return Err(VaultError::InvalidMint);
    }
    let has_freeze_authority = coption(d, 46)?;
    if d.len() > MINT_LEN {
        for_each_extension(&d[ACCOUNT_TYPE_OFFSET + 1..], |t| {
            if ext::MINT_ALLOWED.contains(&t) {
                Ok(())
            } else {
                Err(VaultError::UnsupportedTokenExtension)
            }
        })?;
    }
    Ok(MintInfo {
        decimals,
        supply,
        has_freeze_authority,
    })
}

/// Lists the extension types of a Token-2022 mint (empty for a base mint).
/// For client diagnostics; does not apply the policy.
#[cfg(not(target_os = "solana"))]
pub fn mint_extensions(d: &[u8]) -> Result<std::vec::Vec<u16>, VaultError> {
    extern crate std;
    let mut v = std::vec::Vec::new();
    if d.len() > ACCOUNT_TYPE_OFFSET + 1 {
        for_each_extension(&d[ACCOUNT_TYPE_OFFSET + 1..], |t| {
            v.push(t);
            Ok(())
        })?;
    }
    Ok(v)
}

/// Human-readable name of a Token-2022 extension type.
pub fn extension_name(t: u16) -> &'static str {
    match t {
        0 => "Uninitialized",
        1 => "TransferFeeConfig",
        2 => "TransferFeeAmount",
        3 => "MintCloseAuthority",
        4 => "ConfidentialTransferMint",
        5 => "ConfidentialTransferAccount",
        6 => "DefaultAccountState",
        7 => "ImmutableOwner",
        8 => "MemoTransfer",
        9 => "NonTransferable",
        10 => "InterestBearingConfig",
        11 => "CpiGuard",
        12 => "PermanentDelegate",
        13 => "NonTransferableAccount",
        14 => "TransferHook",
        15 => "TransferHookAccount",
        16 => "ConfidentialTransferFeeConfig",
        17 => "ConfidentialTransferFeeAmount",
        18 => "MetadataPointer",
        19 => "TokenMetadata",
        20 => "GroupPointer",
        21 => "TokenGroup",
        22 => "GroupMemberPointer",
        23 => "TokenGroupMember",
        24 => "ConfidentialMintBurn",
        25 => "ScaledUiAmount",
        26 => "Pausable",
        27 => "PausableAccount",
        28 => "PermissionedBurn",
        _ => "Unknown",
    }
}

/// Parses the base fields of a token account owned by `program`.
pub fn parse_token_account(program: &Pubkey, d: &[u8]) -> Result<TokenAccountInfo, VaultError> {
    let base_ok = d.len() == ACCOUNT_LEN
        || (*program == TOKEN_2022_PROGRAM
            && d.len() > ACCOUNT_TYPE_OFFSET
            && d.len() != MULTISIG_LEN
            && d[ACCOUNT_TYPE_OFFSET] == ACCOUNT_TYPE_ACCOUNT);
    if !base_ok {
        return Err(VaultError::InvalidTokenAccount);
    }
    let state = match d[108] {
        1 => TokenAccountState::Initialized,
        2 => TokenAccountState::Frozen,
        _ => return Err(VaultError::InvalidTokenAccount),
    };
    Ok(TokenAccountInfo {
        mint: rd32(d, 0),
        owner: rd32(d, 32),
        amount: rd_u64(d, 64),
        state,
    })
}

/// `TransferChecked` instruction data.
pub fn transfer_checked_data(amount: u64, decimals: u8) -> [u8; 10] {
    let mut d = [0u8; 10];
    d[0] = TRANSFER_CHECKED;
    d[1..9].copy_from_slice(&amount.to_le_bytes());
    d[9] = decimals;
    d
}

/// Associated token account address of `owner` for `mint` under `token_program`.
#[cfg(not(target_os = "solana"))]
pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ASSOCIATED_TOKEN_PROGRAM,
    )
    .0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint(decimals: u8) -> [u8; MINT_LEN] {
        let mut d = [0u8; MINT_LEN];
        d[0] = 1; // mint authority: some
        d[36..44].copy_from_slice(&1_000u64.to_le_bytes());
        d[44] = decimals;
        d[45] = 1;
        d
    }

    fn mint_2022(exts: &[(u16, usize)]) -> std::vec::Vec<u8> {
        extern crate std;
        let mut d = std::vec::Vec::from(&mint(6)[..]);
        d.resize(ACCOUNT_LEN, 0);
        d.push(ACCOUNT_TYPE_MINT);
        for &(t, len) in exts {
            d.extend_from_slice(&t.to_le_bytes());
            d.extend_from_slice(&(len as u16).to_le_bytes());
            d.extend(core::iter::repeat_n(0xAB, len));
        }
        d
    }

    #[test]
    fn program_ids_match_their_base58() {
        assert_eq!(
            TOKEN_PROGRAM.to_string(),
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        );
        assert_eq!(
            TOKEN_2022_PROGRAM.to_string(),
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        );
    }

    #[test]
    fn base_mints() {
        let m = parse_mint(&TOKEN_PROGRAM, &mint(9)).unwrap();
        assert_eq!(m.decimals, 9);
        assert!(!m.has_freeze_authority);
        let mut bad = mint(9);
        bad[45] = 0;
        assert_eq!(
            parse_mint(&TOKEN_PROGRAM, &bad),
            Err(VaultError::InvalidMint)
        );
        let mut bad = mint(9);
        bad[0] = 2;
        assert_eq!(
            parse_mint(&TOKEN_PROGRAM, &bad),
            Err(VaultError::InvalidMint)
        );
        // A Token-2022-sized mint is not a legacy SPL mint.
        assert!(parse_mint(&TOKEN_PROGRAM, &mint_2022(&[])).is_err());
    }

    #[test]
    fn extension_policy() {
        assert!(parse_mint(&TOKEN_2022_PROGRAM, &mint_2022(&[])).is_ok());
        assert!(parse_mint(
            &TOKEN_2022_PROGRAM,
            &mint_2022(&[(ext::METADATA_POINTER, 64), (ext::TOKEN_METADATA, 90)])
        )
        .is_ok());
        for t in [
            ext::TRANSFER_FEE_CONFIG,
            ext::CONFIDENTIAL_TRANSFER_MINT,
            ext::DEFAULT_ACCOUNT_STATE,
            ext::NON_TRANSFERABLE,
            ext::INTEREST_BEARING_CONFIG,
            ext::PERMANENT_DELEGATE,
            ext::TRANSFER_HOOK,
            ext::SCALED_UI_AMOUNT,
            ext::PAUSABLE,
            999,
        ] {
            assert_eq!(
                parse_mint(
                    &TOKEN_2022_PROGRAM,
                    &mint_2022(&[(ext::METADATA_POINTER, 64), (t, 8)])
                ),
                Err(VaultError::UnsupportedTokenExtension),
                "extension {t}"
            );
        }
        // Truncated TLV value.
        let mut d = mint_2022(&[(ext::METADATA_POINTER, 64)]);
        d.truncate(d.len() - 1);
        assert_eq!(
            parse_mint(&TOKEN_2022_PROGRAM, &d),
            Err(VaultError::InvalidMint)
        );
        // Wrong account type byte.
        let mut d = mint_2022(&[]);
        d[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_ACCOUNT;
        assert!(parse_mint(&TOKEN_2022_PROGRAM, &d).is_err());
    }
}
