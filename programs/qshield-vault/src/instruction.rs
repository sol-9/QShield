//! Instruction encoding.
//!
//! Instruction data is `tag:u8 ‖ payload` with fixed-size little-endian
//! fields. The account lists below are normative; see `docs/PROTOCOL.md` for
//! the authorization rules of each instruction.

use qshield_mldsa::SIGNATURE_LEN;
use qshield_protocol::v2::AUTH_V2_LEN;
use qshield_protocol::{Bytes32, AUTH_LEN};

use crate::error::VaultError;

/// Instruction tags.
pub mod tag {
    /// Create a key account.
    pub const CREATE_KEY: u8 = 0;
    /// Write public-key bytes into a key account.
    pub const WRITE_KEY: u8 = 1;
    /// Check the uploaded key against its id and compute `tr`.
    pub const FINALIZE_KEY: u8 = 2;
    /// Expand up to N polynomials of the key.
    pub const EXPAND_KEY: u8 = 3;
    /// Close an unused key account.
    pub const CLOSE_KEY: u8 = 4;
    /// Create a vault bound to a ready key.
    pub const INITIALIZE_VAULT: u8 = 5;
    /// Deposit SOL.
    pub const DEPOSIT_SOL: u8 = 6;
    /// Execute a QSP-1 authorization with the signature inline.
    pub const EXECUTE: u8 = 7;
    /// Create a signature buffer.
    pub const CREATE_SIG_BUFFER: u8 = 8;
    /// Write signature bytes into a buffer.
    pub const WRITE_SIG_BUFFER: u8 = 9;
    /// Close a signature buffer.
    pub const CLOSE_SIG_BUFFER: u8 = 10;
    /// Execute a QSP-1 authorization whose signature is in a buffer.
    pub const EXECUTE_WITH_BUFFER: u8 = 11;
    /// Deposit SPL Token / Token-2022 tokens into a vault-owned token account.
    pub const DEPOSIT_SPL: u8 = 12;
    /// Execute a QSP-1 v2 (guardian policy) authorization, signature inline.
    pub const EXECUTE_V2: u8 = 13;
    /// Execute a QSP-1 v2 authorization whose signature is in a buffer.
    pub const EXECUTE_V2_WITH_BUFFER: u8 = 14;
    /// Close a dead proposal (permissionless; rent to its payer).
    pub const CLOSE_PROPOSAL: u8 = 15;
}

/// Decoded instruction.
#[derive(Debug, PartialEq, Eq)]
pub enum VaultInstruction<'a> {
    /// `[creator (s,w), key_account (s,w)]` — key account pre-allocated by the creator.
    CreateKey {
        /// Vault address the key will belong to.
        vault: Bytes32,
        /// Key identifier (`SHA-256(KEY_ID_DOMAIN ‖ alg ‖ pk)`).
        key_id: Bytes32,
        /// Algorithm byte.
        algorithm: u8,
    },
    /// `[creator (s), key_account (w)]`
    WriteKey {
        /// Byte offset into the public key.
        offset: u16,
        /// Bytes to write.
        bytes: &'a [u8],
    },
    /// `[creator (s), key_account (w)]`
    FinalizeKey,
    /// `[key_account (w)]` — permissionless (deterministic computation).
    ExpandKey {
        /// Maximum number of polynomials to expand in this instruction.
        max_polys: u8,
    },
    /// `[creator (s,w), key_account (w)]`
    CloseKey,
    /// `[payer (s,w), vault (w), key_account (w), system_program]`
    InitializeVault {
        /// Creator-chosen seed.
        vault_seed: Bytes32,
    },
    /// `[depositor (s,w), vault (w), system_program]`
    DepositSol {
        /// Lamports.
        amount: u64,
    },
    /// `[fee_payer (s,w), vault (w), key_account, ...action accounts]`
    Execute {
        /// QSP-1 authorization bytes.
        auth: &'a [u8; AUTH_LEN],
        /// ML-DSA-44 signature.
        signature: &'a [u8; SIGNATURE_LEN],
    },
    /// `[creator (s,w), buffer (w), system_program]`
    CreateSigBuffer {
        /// Vault the buffer is bound to.
        vault: Bytes32,
        /// Creator-chosen id.
        buffer_id: u64,
    },
    /// `[creator (s), buffer (w)]`
    WriteSigBuffer {
        /// Byte offset into the signature.
        offset: u16,
        /// Finalize after writing.
        finalize: bool,
        /// Bytes to write.
        bytes: &'a [u8],
    },
    /// `[creator (s,w), buffer (w)]`
    CloseSigBuffer,
    /// `[fee_payer (s,w), vault (w), key_account, buffer (w), buffer_creator (w), ...action accounts]`
    ExecuteWithBuffer {
        /// QSP-1 authorization bytes.
        auth: &'a [u8; AUTH_LEN],
    },
    /// `[fee_payer (s,w), vault (w), signer_key (w*), policy (w), ...action accounts]`
    ExecuteV2 {
        /// QSP-1 v2 authorization bytes.
        auth: &'a [u8; AUTH_V2_LEN],
        /// ML-DSA-44 signature.
        signature: &'a [u8; SIGNATURE_LEN],
    },
    /// `[fee_payer (s,w), vault (w), signer_key (w*), policy (w), buffer (w), buffer_creator (w), ...action accounts]`
    ExecuteV2WithBuffer {
        /// QSP-1 v2 authorization bytes.
        auth: &'a [u8; AUTH_V2_LEN],
    },
    /// `[vault, proposal (w), rent_payer (w)]`
    CloseProposal,
    /// `[depositor (s), source (w), mint, vault_token_account (w), vault, token_program]`
    DepositSpl {
        /// Base units.
        amount: u64,
        /// Mint decimals (checked against the mint).
        decimals: u8,
    },
}

fn arr32(d: &[u8]) -> Result<Bytes32, VaultError> {
    d.try_into().map_err(|_| VaultError::InvalidInstruction)
}

impl<'a> VaultInstruction<'a> {
    /// Decodes instruction data. Trailing bytes are rejected.
    pub fn unpack(data: &'a [u8]) -> Result<Self, VaultError> {
        use VaultError::InvalidInstruction as E;
        let (&t, rest) = data.split_first().ok_or(E)?;
        let exact = |n: usize| if rest.len() == n { Ok(()) } else { Err(E) };
        Ok(match t {
            tag::CREATE_KEY => {
                exact(65)?;
                Self::CreateKey {
                    vault: arr32(&rest[..32])?,
                    key_id: arr32(&rest[32..64])?,
                    algorithm: rest[64],
                }
            }
            tag::WRITE_KEY => {
                if rest.len() < 3 {
                    return Err(E);
                }
                Self::WriteKey {
                    offset: u16::from_le_bytes([rest[0], rest[1]]),
                    bytes: &rest[2..],
                }
            }
            tag::FINALIZE_KEY => {
                exact(0)?;
                Self::FinalizeKey
            }
            tag::EXPAND_KEY => {
                exact(1)?;
                Self::ExpandKey { max_polys: rest[0] }
            }
            tag::CLOSE_KEY => {
                exact(0)?;
                Self::CloseKey
            }
            tag::INITIALIZE_VAULT => {
                exact(32)?;
                Self::InitializeVault {
                    vault_seed: arr32(rest)?,
                }
            }
            tag::DEPOSIT_SOL => {
                exact(8)?;
                Self::DepositSol {
                    amount: u64::from_le_bytes(rest.try_into().map_err(|_| E)?),
                }
            }
            tag::EXECUTE => {
                exact(AUTH_LEN + SIGNATURE_LEN)?;
                let (a, s) = rest.split_at(AUTH_LEN);
                Self::Execute {
                    auth: a.try_into().map_err(|_| E)?,
                    signature: s.try_into().map_err(|_| E)?,
                }
            }
            tag::CREATE_SIG_BUFFER => {
                exact(40)?;
                Self::CreateSigBuffer {
                    vault: arr32(&rest[..32])?,
                    buffer_id: u64::from_le_bytes(rest[32..40].try_into().map_err(|_| E)?),
                }
            }
            tag::WRITE_SIG_BUFFER => {
                if rest.len() < 3 {
                    return Err(E);
                }
                let finalize = match rest[2] {
                    0 => false,
                    1 => true,
                    _ => return Err(E),
                };
                Self::WriteSigBuffer {
                    offset: u16::from_le_bytes([rest[0], rest[1]]),
                    finalize,
                    bytes: &rest[3..],
                }
            }
            tag::CLOSE_SIG_BUFFER => {
                exact(0)?;
                Self::CloseSigBuffer
            }
            tag::EXECUTE_WITH_BUFFER => {
                exact(AUTH_LEN)?;
                Self::ExecuteWithBuffer {
                    auth: rest.try_into().map_err(|_| E)?,
                }
            }
            tag::EXECUTE_V2 => {
                exact(AUTH_V2_LEN + SIGNATURE_LEN)?;
                let (a, s) = rest.split_at(AUTH_V2_LEN);
                Self::ExecuteV2 {
                    auth: a.try_into().map_err(|_| E)?,
                    signature: s.try_into().map_err(|_| E)?,
                }
            }
            tag::EXECUTE_V2_WITH_BUFFER => {
                exact(AUTH_V2_LEN)?;
                Self::ExecuteV2WithBuffer {
                    auth: rest.try_into().map_err(|_| E)?,
                }
            }
            tag::CLOSE_PROPOSAL => {
                exact(0)?;
                Self::CloseProposal
            }
            tag::DEPOSIT_SPL => {
                exact(9)?;
                Self::DepositSpl {
                    amount: u64::from_le_bytes(rest[..8].try_into().map_err(|_| E)?),
                    decimals: rest[8],
                }
            }
            _ => return Err(E),
        })
    }
}

/// Seeds and PDA helpers shared with clients.
pub mod seeds {
    /// Vault PDA prefix: `["vault", initial_key_id, vault_seed]`.
    pub const VAULT: &[u8] = b"vault";
    /// Signature buffer PDA prefix: `["sigbuf", vault, creator, buffer_id_le]`.
    pub const SIG_BUFFER: &[u8] = b"sigbuf";
    /// Guardian policy PDA prefix: `["policy", vault]`.
    pub const POLICY: &[u8] = b"policy";
    /// Proposal PDA prefix: `["proposal", vault, id_le]`.
    pub const PROPOSAL: &[u8] = b"proposal";
}

/// Client-side instruction builders (host only).
#[cfg(not(target_os = "solana"))]
pub mod build {
    extern crate std;
    use std::vec::Vec;

    use qshield_protocol::Bytes32;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_pubkey::Pubkey;

    use super::{seeds, tag};

    /// System program id.
    pub const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0u8; 32]);

    fn data(t: u8, parts: &[&[u8]]) -> Vec<u8> {
        let mut v = std::vec![t];
        for p in parts {
            v.extend_from_slice(p);
        }
        v
    }

    /// Vault PDA.
    pub fn vault_address(
        program: &Pubkey,
        initial_key_id: &Bytes32,
        vault_seed: &Bytes32,
    ) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[seeds::VAULT, initial_key_id, vault_seed], program)
    }

    /// Signature buffer PDA.
    pub fn sig_buffer_address(
        program: &Pubkey,
        vault: &Pubkey,
        creator: &Pubkey,
        id: u64,
    ) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[
                seeds::SIG_BUFFER,
                vault.as_ref(),
                creator.as_ref(),
                &id.to_le_bytes(),
            ],
            program,
        )
    }

    /// Guardian policy PDA.
    pub fn policy_address(program: &Pubkey, vault: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[seeds::POLICY, vault.as_ref()], program)
    }

    /// Proposal PDA (`id` = the vault nonce consumed by the proposal).
    pub fn proposal_address(program: &Pubkey, vault: &Pubkey, id: u64) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[seeds::PROPOSAL, vault.as_ref(), &id.to_le_bytes()],
            program,
        )
    }

    /// `ExecuteV2` (signature inline; needs a v1 transaction).
    pub fn execute_v2(
        program: &Pubkey,
        fee_payer: &Pubkey,
        vault: &Pubkey,
        signer_key: &Pubkey,
        action_accounts: &[AccountMeta],
        auth: &[u8],
        signature: &[u8],
    ) -> Instruction {
        let mut accounts = std::vec![
            AccountMeta::new(*fee_payer, true),
            AccountMeta::new(*vault, false),
            AccountMeta::new(*signer_key, false),
            AccountMeta::new(policy_address(program, vault).0, false),
        ];
        accounts.extend_from_slice(action_accounts);
        Instruction::new_with_bytes(
            *program,
            &data(tag::EXECUTE_V2, &[auth, signature]),
            accounts,
        )
    }

    /// `ExecuteV2WithBuffer`.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_v2_with_buffer(
        program: &Pubkey,
        fee_payer: &Pubkey,
        vault: &Pubkey,
        signer_key: &Pubkey,
        buffer: &Pubkey,
        buffer_creator: &Pubkey,
        action_accounts: &[AccountMeta],
        auth: &[u8],
    ) -> Instruction {
        let mut accounts = std::vec![
            AccountMeta::new(*fee_payer, true),
            AccountMeta::new(*vault, false),
            AccountMeta::new(*signer_key, false),
            AccountMeta::new(policy_address(program, vault).0, false),
            AccountMeta::new(*buffer, false),
            AccountMeta::new(*buffer_creator, false),
        ];
        accounts.extend_from_slice(action_accounts);
        Instruction::new_with_bytes(
            *program,
            &data(tag::EXECUTE_V2_WITH_BUFFER, &[auth]),
            accounts,
        )
    }

    /// `CloseProposal` (permissionless).
    pub fn close_proposal(
        program: &Pubkey,
        vault: &Pubkey,
        proposal: &Pubkey,
        rent_payer: &Pubkey,
    ) -> Instruction {
        Instruction::new_with_bytes(
            *program,
            &[tag::CLOSE_PROPOSAL],
            std::vec![
                AccountMeta::new_readonly(*vault, false),
                AccountMeta::new(*proposal, false),
                AccountMeta::new(*rent_payer, false),
            ],
        )
    }

    /// `CreateKey`. The key account must already be allocated with
    /// [`crate::state::KeyHeader::LEN`] bytes and owned by the program, e.g. by
    /// a system `CreateAccount` instruction earlier in the same transaction.
    pub fn create_key(
        program: &Pubkey,
        creator: &Pubkey,
        key: &Pubkey,
        vault: &Pubkey,
        key_id: &Bytes32,
        algorithm: u8,
    ) -> Instruction {
        Instruction::new_with_bytes(
            *program,
            &data(tag::CREATE_KEY, &[vault.as_ref(), key_id, &[algorithm]]),
            std::vec![
                AccountMeta::new(*creator, true),
                AccountMeta::new(*key, true)
            ],
        )
    }

    /// `WriteKey`.
    pub fn write_key(
        program: &Pubkey,
        creator: &Pubkey,
        key: &Pubkey,
        offset: u16,
        bytes: &[u8],
    ) -> Instruction {
        Instruction::new_with_bytes(
            *program,
            &data(tag::WRITE_KEY, &[&offset.to_le_bytes(), bytes]),
            std::vec![
                AccountMeta::new_readonly(*creator, true),
                AccountMeta::new(*key, false)
            ],
        )
    }

    /// `FinalizeKey`.
    pub fn finalize_key(program: &Pubkey, creator: &Pubkey, key: &Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            *program,
            &[tag::FINALIZE_KEY],
            std::vec![
                AccountMeta::new_readonly(*creator, true),
                AccountMeta::new(*key, false)
            ],
        )
    }

    /// `ExpandKey`.
    pub fn expand_key(program: &Pubkey, key: &Pubkey, max_polys: u8) -> Instruction {
        Instruction::new_with_bytes(
            *program,
            &[tag::EXPAND_KEY, max_polys],
            std::vec![AccountMeta::new(*key, false)],
        )
    }

    /// `CloseKey`.
    pub fn close_key(program: &Pubkey, creator: &Pubkey, key: &Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            *program,
            &[tag::CLOSE_KEY],
            std::vec![
                AccountMeta::new(*creator, true),
                AccountMeta::new(*key, false)
            ],
        )
    }

    /// `InitializeVault`.
    pub fn initialize_vault(
        program: &Pubkey,
        payer: &Pubkey,
        vault: &Pubkey,
        key: &Pubkey,
        vault_seed: &Bytes32,
    ) -> Instruction {
        Instruction::new_with_bytes(
            *program,
            &data(tag::INITIALIZE_VAULT, &[vault_seed]),
            std::vec![
                AccountMeta::new(*payer, true),
                AccountMeta::new(*vault, false),
                AccountMeta::new(*key, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
        )
    }

    /// `DepositSol`.
    pub fn deposit_sol(
        program: &Pubkey,
        depositor: &Pubkey,
        vault: &Pubkey,
        amount: u64,
    ) -> Instruction {
        Instruction::new_with_bytes(
            *program,
            &data(tag::DEPOSIT_SOL, &[&amount.to_le_bytes()]),
            std::vec![
                AccountMeta::new(*depositor, true),
                AccountMeta::new(*vault, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
        )
    }

    /// `DepositSpl`: transfers `amount` base units from the depositor's token
    /// account `source` to `vault_token_account` (owned by `vault`).
    #[allow(clippy::too_many_arguments)]
    pub fn deposit_spl(
        program: &Pubkey,
        depositor: &Pubkey,
        source: &Pubkey,
        mint: &Pubkey,
        vault_token_account: &Pubkey,
        vault: &Pubkey,
        token_program: &Pubkey,
        amount: u64,
        decimals: u8,
    ) -> Instruction {
        Instruction::new_with_bytes(
            *program,
            &data(tag::DEPOSIT_SPL, &[&amount.to_le_bytes(), &[decimals]]),
            std::vec![
                AccountMeta::new_readonly(*depositor, true),
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new(*vault_token_account, false),
                AccountMeta::new_readonly(*vault, false),
                AccountMeta::new_readonly(*token_program, false),
            ],
        )
    }

    /// Associated token account `CreateIdempotent` (creates `owner`'s ATA for
    /// `mint` if it does not exist; `owner` may be a vault PDA).
    pub fn create_ata_idempotent(
        payer: &Pubkey,
        owner: &Pubkey,
        mint: &Pubkey,
        token_program: &Pubkey,
    ) -> Instruction {
        let ata = crate::token::associated_token_address(owner, mint, token_program);
        Instruction::new_with_bytes(
            crate::token::ASSOCIATED_TOKEN_PROGRAM,
            &[1],
            std::vec![
                AccountMeta::new(*payer, true),
                AccountMeta::new(ata, false),
                AccountMeta::new_readonly(*owner, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
                AccountMeta::new_readonly(*token_program, false),
            ],
        )
    }

    /// Action accounts for a WithdrawSpl authorization: `vault_token_account
    /// (w)`, `mint`, `destination (w)`, `token_program`, then the optional
    /// `fee_recipient (w)`.
    pub fn withdraw_spl_accounts(
        vault_token_account: &Pubkey,
        mint: &Pubkey,
        destination: &Pubkey,
        token_program: &Pubkey,
        fee_recipient: Option<&Pubkey>,
    ) -> Vec<AccountMeta> {
        let mut v = std::vec![
            AccountMeta::new(*vault_token_account, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*token_program, false),
        ];
        if let Some(f) = fee_recipient {
            v.push(AccountMeta::new(*f, false));
        }
        v
    }

    /// `Execute` with explicit action accounts (see `docs/PROTOCOL.md`).
    pub fn execute(
        program: &Pubkey,
        fee_payer: &Pubkey,
        vault: &Pubkey,
        key: &Pubkey,
        action_accounts: &[AccountMeta],
        auth: &[u8],
        signature: &[u8],
    ) -> Instruction {
        let mut accounts = std::vec![
            AccountMeta::new(*fee_payer, true),
            AccountMeta::new(*vault, false),
            AccountMeta::new(*key, false)
        ];
        accounts.extend_from_slice(action_accounts);
        Instruction::new_with_bytes(*program, &data(tag::EXECUTE, &[auth, signature]), accounts)
    }

    /// `CreateSigBuffer`.
    pub fn create_sig_buffer(
        program: &Pubkey,
        creator: &Pubkey,
        vault: &Pubkey,
        id: u64,
    ) -> Instruction {
        let (buf, _) = sig_buffer_address(program, vault, creator, id);
        Instruction::new_with_bytes(
            *program,
            &data(tag::CREATE_SIG_BUFFER, &[vault.as_ref(), &id.to_le_bytes()]),
            std::vec![
                AccountMeta::new(*creator, true),
                AccountMeta::new(buf, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
        )
    }

    /// `WriteSigBuffer`.
    pub fn write_sig_buffer(
        program: &Pubkey,
        creator: &Pubkey,
        buffer: &Pubkey,
        offset: u16,
        finalize: bool,
        bytes: &[u8],
    ) -> Instruction {
        Instruction::new_with_bytes(
            *program,
            &data(
                tag::WRITE_SIG_BUFFER,
                &[&offset.to_le_bytes(), &[finalize as u8], bytes],
            ),
            std::vec![
                AccountMeta::new_readonly(*creator, true),
                AccountMeta::new(*buffer, false)
            ],
        )
    }

    /// `CloseSigBuffer`.
    pub fn close_sig_buffer(program: &Pubkey, creator: &Pubkey, buffer: &Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            *program,
            &[tag::CLOSE_SIG_BUFFER],
            std::vec![
                AccountMeta::new(*creator, true),
                AccountMeta::new(*buffer, false)
            ],
        )
    }

    /// `ExecuteWithBuffer`.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_buffer(
        program: &Pubkey,
        fee_payer: &Pubkey,
        vault: &Pubkey,
        key: &Pubkey,
        buffer: &Pubkey,
        buffer_creator: &Pubkey,
        action_accounts: &[AccountMeta],
        auth: &[u8],
    ) -> Instruction {
        let mut accounts = std::vec![
            AccountMeta::new(*fee_payer, true),
            AccountMeta::new(*vault, false),
            AccountMeta::new(*key, false),
            AccountMeta::new(*buffer, false),
            AccountMeta::new(*buffer_creator, false),
        ];
        accounts.extend_from_slice(action_accounts);
        Instruction::new_with_bytes(*program, &data(tag::EXECUTE_WITH_BUFFER, &[auth]), accounts)
    }
}
