//! Program error codes (returned as `ProgramError::Custom(code)`).

use solana_program_error::ProgramError;

/// QShield vault errors. Codes are stable and part of the public interface.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    /// Instruction data could not be parsed.
    InvalidInstruction = 0x5100,
    /// A required account is missing.
    MissingAccount = 0x5101,
    /// An account has the wrong owner, type, address or size.
    InvalidAccount = 0x5102,
    /// A required signature is missing.
    MissingSignature = 0x5103,
    /// An account that must be writable is not.
    NotWritable = 0x5104,
    /// The QSP-1 authorization bytes are malformed or non-canonical.
    MalformedAuthorization = 0x5110,
    /// The authorization targets another cluster.
    WrongCluster = 0x5111,
    /// The authorization targets another program.
    WrongProgram = 0x5112,
    /// The authorization targets another vault.
    WrongVault = 0x5113,
    /// The authorization nonce is not the vault's current nonce.
    WrongNonce = 0x5114,
    /// The authorization is not yet valid.
    NotYetValid = 0x5115,
    /// The authorization has expired.
    Expired = 0x5116,
    /// The ML-DSA signature is invalid.
    InvalidSignature = 0x5117,
    /// The action is not permitted in the vault's current status.
    ActionNotPermitted = 0x5118,
    /// The action is defined by QSP-1 but not implemented by this program version.
    UnsupportedAction = 0x5119,
    /// An account passed for the action does not match the authorization.
    AccountMismatch = 0x511a,
    /// The vault cannot pay the requested amount plus fee while staying rent exempt.
    InsufficientFunds = 0x5120,
    /// Arithmetic overflow.
    Overflow = 0x5121,
    /// The key account is not in the state required by the instruction.
    WrongKeyState = 0x5130,
    /// The uploaded public key does not hash to the key id.
    KeyIdMismatch = 0x5131,
    /// The key account is referenced by a vault.
    KeyInUse = 0x5132,
    /// Write outside the bounds of the target buffer.
    OutOfBounds = 0x5133,
    /// The signature buffer is not in the state required by the instruction.
    WrongBufferState = 0x5134,
    /// Unsupported signature algorithm.
    UnsupportedAlgorithm = 0x5135,
    /// Amount must be non-zero.
    ZeroAmount = 0x5136,
    /// The token program is not SPL Token / Token-2022, or does not match the asset type.
    InvalidTokenProgram = 0x5140,
    /// The mint does not match the authorization, is not owned by the token program, or is malformed.
    InvalidMint = 0x5141,
    /// The mint has a Token-2022 extension this program does not support (ADR-0015).
    UnsupportedTokenExtension = 0x5142,
    /// A token account has the wrong program, mint, owner or state.
    InvalidTokenAccount = 0x5143,
    /// The signed decimals differ from the mint's decimals.
    DecimalsMismatch = 0x5144,
    /// The vault has a guardian policy: only QSP-1 v2 authorizations are accepted.
    PolicyActive = 0x5150,
    /// The action needs a guardian policy (or the policy account is invalid).
    PolicyRequired = 0x5151,
    /// Beyond the everyday key's limit or to an unsaved address: propose it
    /// and have the guardian approve.
    LimitExceeded = 0x5152,
    /// The approval does not match the proposal.
    ProposalMismatch = 0x5153,
    /// The proposal expired or was made by a key that has since been replaced.
    ProposalStale = 0x5154,
    /// No room for another saved address.
    PolicyFull = 0x5155,
    /// The address is already saved.
    AlreadySaved = 0x5156,
    /// The address is not saved.
    NotSaved = 0x5157,
    /// The guardian and the everyday key must be different keys.
    KeyConflict = 0x5158,
}

impl From<VaultError> for ProgramError {
    fn from(e: VaultError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
