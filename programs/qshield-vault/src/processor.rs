//! Instruction handlers.

extern crate alloc;

use qshield_mldsa::{
    compute_tr, expand_a_entry, expand_t1_hat_row, verify_expanded, workspace_vec, ExpandedKey,
    Workspace, A_HAT_POLYS, PUBLIC_KEY_LEN, SIGNATURE_LEN, TR_LEN,
};
use qshield_protocol::v2::{ActionV2, AuthorizationV2, Role, AUTH_V2_LEN};
use qshield_protocol::{
    key_id_preimage, Action, Algorithm, AssetType, Authorization, Bytes32, AUTH_LEN,
    ML_DSA_CONTEXT, ZERO32,
};
use solana_account_info::AccountInfo;
use solana_clock::Clock;
use solana_cpi::invoke_signed;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::{ProgramError, ProgramResult};
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_sysvar::Sysvar;

use crate::error::VaultError;
use crate::instruction::{seeds, VaultInstruction};
use crate::state::{
    expanded_key_view, key_off, BufferState, KeyHeader, KeyState, Policy, Proposal, SigBuffer,
    Vault, VaultStatus, EXPAND_TOTAL, MAX_SAVED,
};
use crate::token::{self, MintInfo, TokenAccountInfo, TokenAccountState};
use crate::CLUSTER_ID;

const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0u8; 32]);

/// Program entry point logic.
pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    match VaultInstruction::unpack(data)? {
        VaultInstruction::CreateKey {
            vault,
            key_id,
            algorithm,
        } => create_key(program_id, accounts, vault, key_id, algorithm),
        VaultInstruction::WriteKey { offset, bytes } => {
            write_key(program_id, accounts, offset, bytes)
        }
        VaultInstruction::FinalizeKey => finalize_key(program_id, accounts),
        VaultInstruction::ExpandKey { max_polys } => expand_key(program_id, accounts, max_polys),
        VaultInstruction::CloseKey => close_key(program_id, accounts),
        VaultInstruction::InitializeVault { vault_seed } => {
            initialize_vault(program_id, accounts, vault_seed)
        }
        VaultInstruction::DepositSol { amount } => deposit_sol(program_id, accounts, amount),
        VaultInstruction::ExecuteV2 { auth, signature } => {
            execute_v2(program_id, accounts, auth, SigSource::Inline(signature))
        }
        VaultInstruction::ExecuteV2WithBuffer { auth } => {
            execute_v2(program_id, accounts, auth, SigSource::Buffer)
        }
        VaultInstruction::CloseProposal => close_proposal(program_id, accounts),
        VaultInstruction::DepositSpl { amount, decimals } => {
            deposit_spl(program_id, accounts, amount, decimals)
        }
        VaultInstruction::Execute { auth, signature } => {
            execute(program_id, accounts, auth, SigSource::Inline(signature))
        }
        VaultInstruction::CreateSigBuffer { vault, buffer_id } => {
            create_sig_buffer(program_id, accounts, vault, buffer_id)
        }
        VaultInstruction::WriteSigBuffer {
            offset,
            finalize,
            bytes,
        } => write_sig_buffer(program_id, accounts, offset, finalize, bytes),
        VaultInstruction::CloseSigBuffer => close_sig_buffer(program_id, accounts),
        VaultInstruction::ExecuteWithBuffer { auth } => {
            execute(program_id, accounts, auth, SigSource::Buffer)
        }
    }
}

// ---------------------------------------------------------------------------
// Account helpers
// ---------------------------------------------------------------------------

fn account<'a, 'b>(
    accounts: &'a [AccountInfo<'b>],
    i: usize,
) -> Result<&'a AccountInfo<'b>, ProgramError> {
    accounts
        .get(i)
        .ok_or_else(|| VaultError::MissingAccount.into())
}

fn require_signer(a: &AccountInfo) -> ProgramResult {
    if a.is_signer {
        Ok(())
    } else {
        Err(VaultError::MissingSignature.into())
    }
}

fn require_writable(a: &AccountInfo) -> ProgramResult {
    if a.is_writable {
        Ok(())
    } else {
        Err(VaultError::NotWritable.into())
    }
}

fn require_owned(a: &AccountInfo, program_id: &Pubkey) -> ProgramResult {
    if a.owner == program_id {
        Ok(())
    } else {
        Err(VaultError::InvalidAccount.into())
    }
}

fn require_key(a: &AccountInfo, expected: &Bytes32) -> ProgramResult {
    if a.key.as_ref() == expected {
        Ok(())
    } else {
        Err(VaultError::AccountMismatch.into())
    }
}

fn require_system_program(a: &AccountInfo) -> ProgramResult {
    if *a.key == SYSTEM_PROGRAM {
        Ok(())
    } else {
        Err(VaultError::InvalidAccount.into())
    }
}

/// Moves lamports out of a program-owned account.
fn move_lamports(from: &AccountInfo, to: &AccountInfo, amount: u64) -> ProgramResult {
    if amount == 0 {
        return Ok(());
    }
    {
        let mut f = from.try_borrow_mut_lamports()?;
        **f = f.checked_sub(amount).ok_or(VaultError::InsufficientFunds)?;
    }
    let mut t = to.try_borrow_mut_lamports()?;
    **t = t.checked_add(amount).ok_or(VaultError::Overflow)?;
    Ok(())
}

/// Closes a program-owned account: transfers all lamports to `recipient`,
/// truncates the data and hands the account back to the system program so it
/// cannot be revived with stale contents later in the same transaction.
fn close_account(acct: &AccountInfo, recipient: &AccountInfo) -> ProgramResult {
    let lamports = acct.lamports();
    move_lamports(acct, recipient, lamports)?;
    acct.try_borrow_mut_data()?.fill(0);
    acct.resize(0)?;
    acct.assign(&SYSTEM_PROGRAM);
    Ok(())
}

// System program instructions, encoded by hand (bincode layout:
// u32 LE discriminant followed by fixed-size fields).
fn sys_create_account(
    from: &Pubkey,
    to: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let mut d = [0u8; 52];
    d[4..12].copy_from_slice(&lamports.to_le_bytes());
    d[12..20].copy_from_slice(&space.to_le_bytes());
    d[20..52].copy_from_slice(owner.as_ref());
    Instruction::new_with_bytes(
        SYSTEM_PROGRAM,
        &d,
        alloc::vec![AccountMeta::new(*from, true), AccountMeta::new(*to, true)],
    )
}

fn sys_transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut d = [0u8; 12];
    d[0] = 2;
    d[4..12].copy_from_slice(&lamports.to_le_bytes());
    Instruction::new_with_bytes(
        SYSTEM_PROGRAM,
        &d,
        alloc::vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
    )
}

fn sys_allocate(acct: &Pubkey, space: u64) -> Instruction {
    let mut d = [0u8; 12];
    d[0] = 8;
    d[4..12].copy_from_slice(&space.to_le_bytes());
    Instruction::new_with_bytes(
        SYSTEM_PROGRAM,
        &d,
        alloc::vec![AccountMeta::new(*acct, true)],
    )
}

fn sys_assign(acct: &Pubkey, owner: &Pubkey) -> Instruction {
    let mut d = [0u8; 36];
    d[0] = 1;
    d[4..36].copy_from_slice(owner.as_ref());
    Instruction::new_with_bytes(
        SYSTEM_PROGRAM,
        &d,
        alloc::vec![AccountMeta::new(*acct, true)],
    )
}

/// Creates a PDA owned by this program. Works even if someone pre-funded the
/// address with lamports (which would make `CreateAccount` fail).
fn create_pda<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    space: usize,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    let rent = Rent::get()?.minimum_balance(space);
    let infos = [payer.clone(), target.clone(), system.clone()];
    let current = target.lamports();
    if current == 0 {
        return invoke_signed(
            &sys_create_account(payer.key, target.key, rent, space as u64, program_id),
            &infos,
            &[signer_seeds],
        );
    }
    // Pre-funded address: it must still be an empty system account.
    if *target.owner != SYSTEM_PROGRAM || !target.data_is_empty() {
        return Err(VaultError::InvalidAccount.into());
    }
    if current < rent {
        invoke_signed(
            &sys_transfer(payer.key, target.key, rent - current),
            &infos,
            &[],
        )?;
    }
    invoke_signed(
        &sys_allocate(target.key, space as u64),
        &infos,
        &[signer_seeds],
    )?;
    invoke_signed(&sys_assign(target.key, program_id), &infos, &[signer_seeds])
}

// ---------------------------------------------------------------------------
// Key accounts
// ---------------------------------------------------------------------------

/// `CreateKey`: initializes a key account that the creator has already
/// allocated (system `CreateAccount` with `space = KeyHeader::LEN`,
/// `owner = program`) in the same or an earlier transaction.
///
/// Accounts: `[creator (s,w), key_account (s,w)]`.
///
/// Key accounts are ordinary keypair accounts rather than PDAs because the
/// runtime limits account growth inside CPI to 10 KiB, and the key account is
/// 21,976 bytes. Requiring the key account's own signature prevents anyone
/// else from initializing an account the creator allocated.
fn create_key(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    vault: Bytes32,
    key_id: Bytes32,
    algorithm: u8,
) -> ProgramResult {
    let creator = account(accounts, 0)?;
    let key = account(accounts, 1)?;
    require_signer(creator)?;
    require_signer(key)?;
    require_writable(key)?;
    require_owned(key, program_id)?;
    if Algorithm::from_u8(algorithm) != Some(Algorithm::MlDsa44) {
        return Err(VaultError::UnsupportedAlgorithm.into());
    }
    let mut d = key.try_borrow_mut_data()?;
    if d.len() != KeyHeader::LEN || d[..8] != [0u8; 8] {
        return Err(VaultError::InvalidAccount.into());
    }
    KeyHeader {
        algorithm,
        state: KeyState::Writing,
        bump: 0,
        in_use: false,
        guardian: false,
        expanded: 0,
        vault,
        key_id,
        creator: creator.key.to_bytes(),
    }
    .store(&mut d)
}

fn load_key_for_creator(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> Result<KeyHeader, ProgramError> {
    let creator = account(accounts, 0)?;
    let key = account(accounts, 1)?;
    require_signer(creator)?;
    require_writable(key)?;
    require_owned(key, program_id)?;
    let h = KeyHeader::load(&key.try_borrow_data()?)?;
    require_key(creator, &h.creator)?;
    Ok(h)
}

/// `WriteKey`: `[creator (s), key_account (w)]`.
fn write_key(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    offset: u16,
    bytes: &[u8],
) -> ProgramResult {
    let h = load_key_for_creator(program_id, accounts)?;
    if h.state != KeyState::Writing {
        return Err(VaultError::WrongKeyState.into());
    }
    let start = offset as usize;
    let end = start
        .checked_add(bytes.len())
        .ok_or(VaultError::OutOfBounds)?;
    if end > PUBLIC_KEY_LEN {
        return Err(VaultError::OutOfBounds.into());
    }
    let key = account(accounts, 1)?;
    key.try_borrow_mut_data()?[key_off::PK + start..key_off::PK + end].copy_from_slice(bytes);
    Ok(())
}

/// `FinalizeKey`: `[creator (s), key_account (w)]`. Checks
/// `SHA-256(KEY_ID_DOMAIN ‖ alg ‖ pk) == key_id` and stores `tr`.
fn finalize_key(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let mut h = load_key_for_creator(program_id, accounts)?;
    if h.state != KeyState::Writing {
        return Err(VaultError::WrongKeyState.into());
    }
    let key = account(accounts, 1)?;
    let mut d = key.try_borrow_mut_data()?;
    let pk: [u8; PUBLIC_KEY_LEN] = d[key_off::PK..key_off::TR]
        .try_into()
        .map_err(|_| VaultError::InvalidAccount)?;
    let alg = Algorithm::from_u8(h.algorithm).ok_or(VaultError::UnsupportedAlgorithm)?;
    let alg_byte = [h.algorithm];
    let id = solana_sha256_hasher::hashv(&key_id_preimage(alg, &alg_byte, &pk)).to_bytes();
    if id != h.key_id {
        return Err(VaultError::KeyIdMismatch.into());
    }
    let tr = compute_tr(&pk);
    d[key_off::TR..key_off::A_HAT].copy_from_slice(&tr);
    h.state = KeyState::Expanding;
    h.store(&mut d)
}

/// `ExpandKey`: `[key_account (w)]`. Permissionless: computes the next
/// `max_polys` polynomials of `A_hat` (then `NTT(t1 * 2^d)`) from the stored
/// public key. When all 20 are done the key becomes `Ready` and immutable.
fn expand_key(program_id: &Pubkey, accounts: &[AccountInfo], max_polys: u8) -> ProgramResult {
    let key = account(accounts, 0)?;
    require_writable(key)?;
    require_owned(key, program_id)?;
    let mut d = key.try_borrow_mut_data()?;
    let mut h = KeyHeader::load(&d)?;
    if h.state != KeyState::Expanding {
        return Err(VaultError::WrongKeyState.into());
    }
    let pk: [u8; PUBLIC_KEY_LEN] = d[key_off::PK..key_off::TR]
        .try_into()
        .map_err(|_| VaultError::InvalidAccount)?;
    let end = h.expanded.saturating_add(max_polys).min(EXPAND_TOTAL);
    let mut poly = alloc::vec![0u32; 256];
    let poly: &mut [u32; 256] = poly
        .as_mut_slice()
        .try_into()
        .map_err(|_| VaultError::Overflow)?;
    for i in h.expanded..end {
        let i = i as usize;
        let off = if i < A_HAT_POLYS {
            expand_a_entry(poly, &pk, i / 4, i % 4);
            key_off::A_HAT + i * 1024
        } else {
            expand_t1_hat_row(poly, &pk, i - A_HAT_POLYS);
            key_off::T1_HAT + (i - A_HAT_POLYS) * 1024
        };
        for (j, c) in poly.iter().enumerate() {
            d[off + 4 * j..off + 4 * j + 4].copy_from_slice(&c.to_le_bytes());
        }
    }
    h.expanded = end;
    if end == EXPAND_TOTAL {
        h.state = KeyState::Ready;
    }
    h.store(&mut d)
}

/// `CloseKey`: `[creator (s,w), key_account (w)]`. Only for keys not in use.
fn close_key(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let h = load_key_for_creator(program_id, accounts)?;
    if h.in_use {
        return Err(VaultError::KeyInUse.into());
    }
    let creator = account(accounts, 0)?;
    require_writable(creator)?;
    close_account(account(accounts, 1)?, creator)
}

// ---------------------------------------------------------------------------
// Vault lifecycle
// ---------------------------------------------------------------------------

/// `InitializeVault`: `[payer (s,w), vault (w), key_account (w), system_program]`.
///
/// Permissionless. The vault address is the PDA
/// `["vault", key_id, vault_seed]`, so it commits to its initial key: whoever
/// initializes it, the vault can only ever be controlled by that key (or keys
/// it later authorizes by rotation). No Ed25519 authority is recorded.
fn initialize_vault(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    vault_seed: Bytes32,
) -> ProgramResult {
    let payer = account(accounts, 0)?;
    let vault = account(accounts, 1)?;
    let key = account(accounts, 2)?;
    let system = account(accounts, 3)?;
    require_signer(payer)?;
    require_writable(payer)?;
    require_writable(vault)?;
    require_writable(key)?;
    require_owned(key, program_id)?;
    require_system_program(system)?;

    let mut h = KeyHeader::load(&key.try_borrow_data()?)?;
    if h.state != KeyState::Ready {
        return Err(VaultError::WrongKeyState.into());
    }
    if h.in_use {
        return Err(VaultError::KeyInUse.into());
    }
    let (expected, bump) =
        Pubkey::find_program_address(&[seeds::VAULT, &h.key_id, &vault_seed], program_id);
    if *vault.key != expected || h.vault != expected.to_bytes() {
        return Err(VaultError::AccountMismatch.into());
    }
    create_pda(
        program_id,
        payer,
        vault,
        system,
        Vault::LEN,
        &[seeds::VAULT, &h.key_id, &vault_seed, &[bump]],
    )?;

    let clock = Clock::get()?;
    Vault {
        status: VaultStatus::Active,
        bump,
        pq_algorithm: h.algorithm,
        nonce: 0,
        key_id: h.key_id,
        key_account: key.key.to_bytes(),
        initial_key_id: h.key_id,
        vault_seed,
        created_slot: clock.slot,
        created_at: clock.unix_timestamp,
        policy_mode: 0,
    }
    .store(&mut vault.try_borrow_mut_data()?)?;

    h.in_use = true;
    h.store(&mut key.try_borrow_mut_data()?)
}

/// `DepositSol`: `[depositor (s,w), vault (w), system_program]`. Anyone may
/// deposit into a vault that is not closed.
fn deposit_sol(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let depositor = account(accounts, 0)?;
    let vault = account(accounts, 1)?;
    let system = account(accounts, 2)?;
    require_signer(depositor)?;
    require_writable(depositor)?;
    require_writable(vault)?;
    require_owned(vault, program_id)?;
    require_system_program(system)?;
    if amount == 0 {
        return Err(VaultError::ZeroAmount.into());
    }
    let v = Vault::load(&vault.try_borrow_data()?)?;
    if v.status == VaultStatus::Closed {
        return Err(VaultError::ActionNotPermitted.into());
    }
    invoke_signed(
        &sys_transfer(depositor.key, vault.key, amount),
        &[depositor.clone(), vault.clone(), system.clone()],
        &[],
    )
}

// ---------------------------------------------------------------------------
// SPL tokens (ADR-0015)
// ---------------------------------------------------------------------------

/// Checks that `ai` is the token program for `asset` and returns its asset type.
fn require_token_program(
    ai: &AccountInfo,
    asset: Option<AssetType>,
) -> Result<AssetType, ProgramError> {
    // The CPI target is this account's address, so matching the address
    // against the two token program ids is sufficient.
    let found = token::asset_for(ai.key).ok_or(VaultError::InvalidTokenProgram)?;
    match asset {
        Some(a) if a != found => Err(VaultError::InvalidTokenProgram.into()),
        _ => Ok(found),
    }
}

/// Loads a mint owned by `token_program`, applying the extension policy.
fn load_mint(mint: &AccountInfo, token_program: &Pubkey) -> Result<MintInfo, ProgramError> {
    if mint.owner != token_program {
        return Err(VaultError::InvalidMint.into());
    }
    Ok(token::parse_mint(token_program, &mint.try_borrow_data()?)?)
}

/// Loads a token account owned by `token_program` for `mint`.
fn load_token_account(
    acct: &AccountInfo,
    token_program: &Pubkey,
    mint: &Pubkey,
) -> Result<TokenAccountInfo, ProgramError> {
    if acct.owner != token_program {
        return Err(VaultError::InvalidTokenAccount.into());
    }
    let t = token::parse_token_account(token_program, &acct.try_borrow_data()?)?;
    if t.mint != mint.to_bytes() {
        return Err(VaultError::InvalidTokenAccount.into());
    }
    Ok(t)
}

/// `TransferChecked` CPI: `[source (w), mint, destination (w), authority (s)]`.
#[allow(clippy::too_many_arguments)]
fn transfer_checked<'a>(
    token_program: &AccountInfo<'a>,
    source: &AccountInfo<'a>,
    mint: &AccountInfo<'a>,
    destination: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    amount: u64,
    decimals: u8,
    signer_seeds: &[&[&[u8]]],
) -> ProgramResult {
    let ix = Instruction::new_with_bytes(
        *token_program.key,
        &token::transfer_checked_data(amount, decimals),
        alloc::vec![
            AccountMeta::new(*source.key, false),
            AccountMeta::new_readonly(*mint.key, false),
            AccountMeta::new(*destination.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
    );
    invoke_signed(
        &ix,
        &[
            source.clone(),
            mint.clone(),
            destination.clone(),
            authority.clone(),
            token_program.clone(),
        ],
        signer_seeds,
    )
}

/// `DepositSpl`: `[depositor (s), source (w), mint, vault_token_account (w),
/// vault, token_program]`.
///
/// Anyone may deposit. The program checks that the destination is a token
/// account of the given mint whose owner is a live QShield vault, and that
/// the mint passes the extension policy, so tokens are never deposited where
/// this program could not later withdraw them.
fn deposit_spl(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
    decimals: u8,
) -> ProgramResult {
    let depositor = account(accounts, 0)?;
    let source = account(accounts, 1)?;
    let mint = account(accounts, 2)?;
    let vault_ta = account(accounts, 3)?;
    let vault = account(accounts, 4)?;
    let token_program = account(accounts, 5)?;
    require_signer(depositor)?;
    require_writable(source)?;
    require_writable(vault_ta)?;
    require_owned(vault, program_id)?;
    require_token_program(token_program, None)?;
    if amount == 0 {
        return Err(VaultError::ZeroAmount.into());
    }
    let v = Vault::load(&vault.try_borrow_data()?)?;
    if v.status == VaultStatus::Closed {
        return Err(VaultError::ActionNotPermitted.into());
    }
    let m = load_mint(mint, token_program.key)?;
    if m.decimals != decimals {
        return Err(VaultError::DecimalsMismatch.into());
    }
    let dest = load_token_account(vault_ta, token_program.key, mint.key)?;
    if dest.owner != vault.key.to_bytes() {
        return Err(VaultError::InvalidTokenAccount.into());
    }
    if source.key == vault_ta.key {
        return Err(VaultError::AccountMismatch.into());
    }
    transfer_checked(
        token_program,
        source,
        mint,
        vault_ta,
        depositor,
        amount,
        decimals,
        &[],
    )
}

// ---------------------------------------------------------------------------
// Signature buffers
// ---------------------------------------------------------------------------

/// `CreateSigBuffer`: `[creator (s,w), buffer (w), system_program]`.
fn create_sig_buffer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    vault: Bytes32,
    buffer_id: u64,
) -> ProgramResult {
    let creator = account(accounts, 0)?;
    let buffer = account(accounts, 1)?;
    let system = account(accounts, 2)?;
    require_signer(creator)?;
    require_writable(creator)?;
    require_writable(buffer)?;
    require_system_program(system)?;
    let id = buffer_id.to_le_bytes();
    let (expected, bump) = Pubkey::find_program_address(
        &[seeds::SIG_BUFFER, &vault, creator.key.as_ref(), &id],
        program_id,
    );
    if *buffer.key != expected {
        return Err(VaultError::AccountMismatch.into());
    }
    create_pda(
        program_id,
        creator,
        buffer,
        system,
        SigBuffer::LEN,
        &[
            seeds::SIG_BUFFER,
            &vault,
            creator.key.as_ref(),
            &id,
            &[bump],
        ],
    )?;
    SigBuffer {
        state: BufferState::Writing,
        bump,
        vault,
        creator: creator.key.to_bytes(),
        buffer_id,
    }
    .store(&mut buffer.try_borrow_mut_data()?)
}

fn load_buffer_for_creator(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> Result<SigBuffer, ProgramError> {
    let creator = account(accounts, 0)?;
    let buffer = account(accounts, 1)?;
    require_signer(creator)?;
    require_writable(buffer)?;
    require_owned(buffer, program_id)?;
    let b = SigBuffer::load(&buffer.try_borrow_data()?)?;
    require_key(creator, &b.creator)?;
    Ok(b)
}

/// `WriteSigBuffer`: `[creator (s), buffer (w)]`.
fn write_sig_buffer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    offset: u16,
    finalize: bool,
    bytes: &[u8],
) -> ProgramResult {
    let mut b = load_buffer_for_creator(program_id, accounts)?;
    if b.state != BufferState::Writing {
        return Err(VaultError::WrongBufferState.into());
    }
    let start = offset as usize;
    let end = start
        .checked_add(bytes.len())
        .ok_or(VaultError::OutOfBounds)?;
    if end > SIGNATURE_LEN {
        return Err(VaultError::OutOfBounds.into());
    }
    let buffer = account(accounts, 1)?;
    let mut d = buffer.try_borrow_mut_data()?;
    d[SigBuffer::DATA + start..SigBuffer::DATA + end].copy_from_slice(bytes);
    if finalize {
        b.state = BufferState::Finalized;
        b.store(&mut d)?;
    }
    Ok(())
}

/// `CloseSigBuffer`: `[creator (s,w), buffer (w)]`.
fn close_sig_buffer(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    load_buffer_for_creator(program_id, accounts)?;
    let creator = account(accounts, 0)?;
    require_writable(creator)?;
    close_account(account(accounts, 1)?, creator)
}

// ---------------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------------

enum SigSource<'a> {
    Inline(&'a [u8; SIGNATURE_LEN]),
    Buffer,
}

fn verify_signature(key_data: &[u8], auth: &[u8], sig: &[u8]) -> ProgramResult {
    let mut ws_buf = workspace_vec();
    let ws: &mut Workspace = ws_buf
        .as_mut_slice()
        .try_into()
        .map_err(|_| VaultError::Overflow)?;
    let result = match expanded_key_view(key_data) {
        Some(ek) => verify_expanded(&ek, auth, ML_DSA_CONTEXT, sig, ws),
        None => {
            // Account data not 4-byte aligned in memory: copy the expansion
            // to the heap (20 KiB) and verify against the copy.
            let mut polys = alloc::vec![[0u32; 256]; A_HAT_POLYS + 4];
            for (i, p) in polys.iter_mut().enumerate() {
                let off = key_off::A_HAT + i * 1024;
                for (j, c) in p.iter_mut().enumerate() {
                    let b = &key_data[off + 4 * j..off + 4 * j + 4];
                    *c = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                }
            }
            let (a, t) = polys.split_at(A_HAT_POLYS);
            let tr: &[u8; TR_LEN] = key_data[key_off::TR..key_off::A_HAT]
                .try_into()
                .map_err(|_| VaultError::InvalidAccount)?;
            let ek = ExpandedKey {
                a_hat: a.try_into().map_err(|_| VaultError::InvalidAccount)?,
                t1_hat: t.try_into().map_err(|_| VaultError::InvalidAccount)?,
                tr,
            };
            verify_expanded(&ek, auth, ML_DSA_CONTEXT, sig, ws)
        }
    };
    result.map_err(|_| VaultError::InvalidSignature.into())
}

/// `Execute` / `ExecuteWithBuffer`.
///
/// Common accounts: `[fee_payer (s,w), vault (w), key_account (w*)]`, then for
/// `ExecuteWithBuffer` `[buffer (w), buffer_creator (w)]`, then the action
/// accounts:
///
/// | action       | accounts |
/// |--------------|----------|
/// | WithdrawSol  | `destination (w)`, `[fee_recipient (w)]` |
/// | RotateKey    | `new_key_account (w)`, `old_key_creator (w)`, `[fee_recipient (w)]` |
/// | Pause/Unpause| `[fee_recipient (w)]` |
/// | CloseVault   | `destination (w)`, `key_creator (w)`, `[fee_recipient (w)]` |
/// | WithdrawSpl  | `vault_token_account (w)`, `mint`, `destination (w)`, `token_program`, `[fee_recipient (w)]` |
///
/// `fee_recipient` is present only when `fee_lamports > 0` and the
/// authorization names an explicit recipient; otherwise the fee (if any) goes
/// to `fee_payer`. `key_account` must be writable for RotateKey and CloseVault.
fn execute(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    auth_bytes: &[u8; AUTH_LEN],
    sig_src: SigSource,
) -> ProgramResult {
    let fee_payer = account(accounts, 0)?;
    let vault_ai = account(accounts, 1)?;
    let key_ai = account(accounts, 2)?;
    require_signer(fee_payer)?;
    require_writable(vault_ai)?;
    require_owned(vault_ai, program_id)?;
    require_owned(key_ai, program_id)?;

    // 1. Decode and bind the authorization to this cluster, program and vault.
    let auth = Authorization::decode(auth_bytes).map_err(|_| VaultError::MalformedAuthorization)?;
    if auth.cluster_id != CLUSTER_ID {
        return Err(VaultError::WrongCluster.into());
    }
    if auth.program_id != program_id.to_bytes() {
        return Err(VaultError::WrongProgram.into());
    }
    if auth.vault != vault_ai.key.to_bytes() {
        return Err(VaultError::WrongVault.into());
    }

    // 2. Vault state: nonce and status. A vault under a guardian policy only
    // accepts QSP-1 v2 (otherwise a v1 message would bypass the policy).
    let mut vault = Vault::load(&vault_ai.try_borrow_data()?)?;
    if vault.policy_mode != 0 {
        return Err(VaultError::PolicyActive.into());
    }
    if auth.nonce != vault.nonce {
        return Err(VaultError::WrongNonce.into());
    }
    let permitted = match (vault.status, auth.action) {
        (VaultStatus::Active, Action::Unpause) => false,
        (VaultStatus::Active, _) => true,
        (VaultStatus::Paused, Action::Unpause | Action::RotateKey) => true,
        _ => false,
    };
    if !permitted {
        return Err(VaultError::ActionNotPermitted.into());
    }

    // 3. Validity window, against the Clock sysvar's unix_timestamp.
    let now = Clock::get()?.unix_timestamp;
    if auth.valid_after != 0 && now < auth.valid_after {
        return Err(VaultError::NotYetValid.into());
    }
    if auth.expires_at != 0 && now >= auth.expires_at {
        return Err(VaultError::Expired.into());
    }

    // 4. The key account must be the vault's current, ready key.
    require_key(key_ai, &vault.key_account)?;
    let key_hdr = KeyHeader::load(&key_ai.try_borrow_data()?)?;
    if key_hdr.state != KeyState::Ready
        || !key_hdr.in_use
        || key_hdr.guardian
        || key_hdr.vault != vault_ai.key.to_bytes()
        || key_hdr.key_id != vault.key_id
    {
        return Err(VaultError::InvalidAccount.into());
    }

    // 5. Signature source.
    let (action_start, buffer) = match sig_src {
        SigSource::Inline(_) => (3, None),
        SigSource::Buffer => {
            let buf_ai = account(accounts, 3)?;
            let buf_creator = account(accounts, 4)?;
            require_writable(buf_ai)?;
            require_writable(buf_creator)?;
            require_owned(buf_ai, program_id)?;
            let b = SigBuffer::load(&buf_ai.try_borrow_data()?)?;
            if b.state != BufferState::Finalized {
                return Err(VaultError::WrongBufferState.into());
            }
            if b.vault != vault_ai.key.to_bytes() {
                return Err(VaultError::AccountMismatch.into());
            }
            require_key(buf_creator, &b.creator)?;
            (5, Some((buf_ai, buf_creator)))
        }
    };

    // 6. Verify the ML-DSA-44 signature over the exact authorization bytes.
    {
        let key_data = key_ai.try_borrow_data()?;
        match (&sig_src, buffer) {
            (SigSource::Inline(sig), _) => verify_signature(&key_data, auth_bytes, &sig[..])?,
            (SigSource::Buffer, Some((buf_ai, _))) => {
                let bd = buf_ai.try_borrow_data()?;
                verify_signature(
                    &key_data,
                    auth_bytes,
                    &bd[SigBuffer::DATA..SigBuffer::DATA + SIGNATURE_LEN],
                )?
            }
            (SigSource::Buffer, None) => return Err(VaultError::InvalidInstruction.into()),
        }
    }

    // 7. Consume the nonce.
    vault.nonce = vault.nonce.checked_add(1).ok_or(VaultError::Overflow)?;

    // 8. Perform the action.
    let action_accounts = accounts.get(action_start..).unwrap_or(&[]);
    let vault_rent = Rent::get()?.minimum_balance(Vault::LEN);
    let fee_target = |idx: usize| -> Result<&AccountInfo, ProgramError> {
        if auth.fee_recipient == ZERO32 {
            Ok(fee_payer)
        } else {
            let a = account(action_accounts, idx)?;
            require_key(a, &auth.fee_recipient)?;
            require_writable(a)?;
            Ok(a)
        }
    };
    match auth.action {
        Action::WithdrawSol => {
            let dest = account(action_accounts, 0)?;
            require_key(dest, &auth.destination)?;
            require_writable(dest)?;
            if dest.key == vault_ai.key {
                return Err(VaultError::AccountMismatch.into());
            }
            let total = auth
                .amount
                .checked_add(auth.fee_lamports)
                .ok_or(VaultError::Overflow)?;
            let available = vault_ai
                .lamports()
                .checked_sub(vault_rent)
                .ok_or(VaultError::InsufficientFunds)?;
            if total > available {
                return Err(VaultError::InsufficientFunds.into());
            }
            move_lamports(vault_ai, dest, auth.amount)?;
            if auth.fee_lamports > 0 {
                move_lamports(vault_ai, fee_target(1)?, auth.fee_lamports)?;
            }
        }
        Action::RotateKey => {
            require_writable(key_ai)?;
            let new_key = account(action_accounts, 0)?;
            let old_creator = account(action_accounts, 1)?;
            require_writable(new_key)?;
            require_writable(old_creator)?;
            require_owned(new_key, program_id)?;
            if new_key.key == key_ai.key {
                return Err(VaultError::AccountMismatch.into());
            }
            require_key(old_creator, &key_hdr.creator)?;
            let mut nh = KeyHeader::load(&new_key.try_borrow_data()?)?;
            if nh.state != KeyState::Ready
                || nh.in_use
                || nh.vault != vault_ai.key.to_bytes()
                || nh.key_id != auth.new_key_id
                || nh.algorithm != auth.new_algorithm
            {
                return Err(VaultError::AccountMismatch.into());
            }
            nh.in_use = true;
            nh.store(&mut new_key.try_borrow_mut_data()?)?;
            vault.key_id = nh.key_id;
            vault.key_account = new_key.key.to_bytes();
            vault.pq_algorithm = nh.algorithm;
            if auth.fee_lamports > 0 {
                let available = vault_ai
                    .lamports()
                    .checked_sub(vault_rent)
                    .ok_or(VaultError::InsufficientFunds)?;
                if auth.fee_lamports > available {
                    return Err(VaultError::InsufficientFunds.into());
                }
                move_lamports(vault_ai, fee_target(2)?, auth.fee_lamports)?;
            }
            close_account(key_ai, old_creator)?;
        }
        Action::Pause | Action::Unpause => {
            vault.status = if auth.action == Action::Pause {
                VaultStatus::Paused
            } else {
                VaultStatus::Active
            };
            if auth.fee_lamports > 0 {
                let available = vault_ai
                    .lamports()
                    .checked_sub(vault_rent)
                    .ok_or(VaultError::InsufficientFunds)?;
                if auth.fee_lamports > available {
                    return Err(VaultError::InsufficientFunds.into());
                }
                move_lamports(vault_ai, fee_target(0)?, auth.fee_lamports)?;
            }
        }
        Action::CloseVault => {
            require_writable(key_ai)?;
            let dest = account(action_accounts, 0)?;
            let key_creator = account(action_accounts, 1)?;
            require_key(dest, &auth.destination)?;
            require_writable(dest)?;
            require_writable(key_creator)?;
            require_key(key_creator, &key_hdr.creator)?;
            if dest.key == vault_ai.key {
                return Err(VaultError::AccountMismatch.into());
            }
            let available = vault_ai
                .lamports()
                .checked_sub(vault_rent)
                .ok_or(VaultError::InsufficientFunds)?;
            if auth.fee_lamports > available {
                return Err(VaultError::InsufficientFunds.into());
            }
            if auth.fee_lamports > 0 {
                move_lamports(vault_ai, fee_target(2)?, auth.fee_lamports)?;
            }
            move_lamports(vault_ai, dest, available - auth.fee_lamports)?;
            vault.status = VaultStatus::Closed;
            close_account(key_ai, key_creator)?;
        }
        Action::WithdrawSpl => {
            let source = account(action_accounts, 0)?;
            let mint = account(action_accounts, 1)?;
            let dest = account(action_accounts, 2)?;
            let token_program = account(action_accounts, 3)?;
            require_token_program(token_program, Some(auth.asset_type))?;
            require_key(mint, &auth.mint)?;
            require_key(dest, &auth.destination)?;
            require_writable(source)?;
            require_writable(dest)?;
            if source.key == dest.key {
                return Err(VaultError::AccountMismatch.into());
            }
            let m = load_mint(mint, token_program.key)?;
            if m.decimals != auth.decimals {
                return Err(VaultError::DecimalsMismatch.into());
            }
            // The source may be any token account of this mint whose
            // authority is the vault: which one is debited does not change
            // the signed effect (amount, mint, destination).
            let src = load_token_account(source, token_program.key, mint.key)?;
            if src.owner != vault_ai.key.to_bytes() || src.state != TokenAccountState::Initialized {
                return Err(VaultError::InvalidTokenAccount.into());
            }
            if src.amount < auth.amount {
                return Err(VaultError::InsufficientFunds.into());
            }
            let dst = load_token_account(dest, token_program.key, mint.key)?;
            if dst.state != TokenAccountState::Initialized {
                return Err(VaultError::InvalidTokenAccount.into());
            }
            if auth.fee_lamports > 0 {
                let available = vault_ai
                    .lamports()
                    .checked_sub(vault_rent)
                    .ok_or(VaultError::InsufficientFunds)?;
                if auth.fee_lamports > available {
                    return Err(VaultError::InsufficientFunds.into());
                }
            }
            // Token CPI first, then lamport movements (no direct lamport
            // edits are pending across the CPI).
            let bump = [vault.bump];
            let seeds: [&[u8]; 4] = [
                seeds::VAULT,
                &vault.initial_key_id,
                &vault.vault_seed,
                &bump,
            ];
            transfer_checked(
                token_program,
                source,
                mint,
                dest,
                vault_ai,
                auth.amount,
                auth.decimals,
                &[&seeds],
            )?;
            if auth.fee_lamports > 0 {
                move_lamports(vault_ai, fee_target(4)?, auth.fee_lamports)?;
            }
        }
    }

    vault.store(&mut vault_ai.try_borrow_mut_data()?)?;

    // 9. Consume the signature buffer.
    if let Some((buf_ai, buf_creator)) = buffer {
        close_account(buf_ai, buf_creator)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Guardian policy: QSP-1 v2 (ADR-0018)
// ---------------------------------------------------------------------------

/// Checks that `ai` is this vault's policy PDA. With `bump` the address is
/// re-derived cheaply; without (first creation) it is searched.
fn policy_pda(
    program_id: &Pubkey,
    vault: &Pubkey,
    ai: &AccountInfo,
    bump: Option<u8>,
) -> Result<u8, ProgramError> {
    let (addr, b) = match bump {
        Some(b) => (
            Pubkey::create_program_address(&[seeds::POLICY, vault.as_ref(), &[b]], program_id)
                .map_err(|_| VaultError::PolicyRequired)?,
            b,
        ),
        None => Pubkey::find_program_address(&[seeds::POLICY, vault.as_ref()], program_id),
    };
    if *ai.key != addr {
        return Err(VaultError::PolicyRequired.into());
    }
    Ok(b)
}

/// Loads a proposal and checks its address, owner and vault.
fn load_proposal(
    program_id: &Pubkey,
    vault: &Pubkey,
    ai: &AccountInfo,
) -> Result<Proposal, ProgramError> {
    require_owned(ai, program_id)?;
    let p = Proposal::load(&ai.try_borrow_data()?)?;
    let addr = Pubkey::create_program_address(
        &[
            seeds::PROPOSAL,
            vault.as_ref(),
            &p.id.to_le_bytes(),
            &[p.bump],
        ],
        program_id,
    )
    .map_err(|_| VaultError::InvalidAccount)?;
    if *ai.key != addr || p.vault != vault.to_bytes() {
        return Err(VaultError::InvalidAccount.into());
    }
    Ok(p)
}

/// Checks a key account that is about to become the everyday or guardian key.
fn check_new_key(
    vault: &Pubkey,
    ai: &AccountInfo,
    program_id: &Pubkey,
    key_id: &Bytes32,
    algorithm: u8,
) -> Result<KeyHeader, ProgramError> {
    require_writable(ai)?;
    require_owned(ai, program_id)?;
    let h = KeyHeader::load(&ai.try_borrow_data()?)?;
    if h.state != KeyState::Ready
        || h.in_use
        || h.vault != vault.to_bytes()
        || &h.key_id != key_id
        || h.algorithm != algorithm
    {
        return Err(VaultError::AccountMismatch.into());
    }
    Ok(h)
}

/// SOL transfer out of the vault, keeping it rent exempt.
fn vault_pay(vault: &AccountInfo, to: &AccountInfo, amount: u64, rent: u64) -> ProgramResult {
    if to.key == vault.key {
        return Err(VaultError::AccountMismatch.into());
    }
    require_writable(to)?;
    let available = vault
        .lamports()
        .checked_sub(rent)
        .ok_or(VaultError::InsufficientFunds)?;
    if amount > available {
        return Err(VaultError::InsufficientFunds.into());
    }
    move_lamports(vault, to, amount)
}

/// The SPL part of a withdrawal: same checks as v1 WithdrawSpl. `accts` =
/// `[vault_token_account (w), mint, destination (w), token_program]`.
/// Returns the destination token account's owner.
#[allow(clippy::too_many_arguments)]
fn vault_pay_spl<'a>(
    vault_ai: &AccountInfo<'a>,
    vault: &Vault,
    accts: &[AccountInfo<'a>],
    asset_type: AssetType,
    mint_key: &Bytes32,
    destination: &Bytes32,
    amount: u64,
    decimals: u8,
) -> Result<Bytes32, ProgramError> {
    let source = account(accts, 0)?;
    let mint = account(accts, 1)?;
    let dest = account(accts, 2)?;
    let token_program = account(accts, 3)?;
    require_token_program(token_program, Some(asset_type))?;
    require_key(mint, mint_key)?;
    require_key(dest, destination)?;
    require_writable(source)?;
    require_writable(dest)?;
    if source.key == dest.key {
        return Err(VaultError::AccountMismatch.into());
    }
    let m = load_mint(mint, token_program.key)?;
    if m.decimals != decimals {
        return Err(VaultError::DecimalsMismatch.into());
    }
    let src = load_token_account(source, token_program.key, mint.key)?;
    if src.owner != vault_ai.key.to_bytes() || src.state != TokenAccountState::Initialized {
        return Err(VaultError::InvalidTokenAccount.into());
    }
    if src.amount < amount {
        return Err(VaultError::InsufficientFunds.into());
    }
    let dst = load_token_account(dest, token_program.key, mint.key)?;
    if dst.state != TokenAccountState::Initialized {
        return Err(VaultError::InvalidTokenAccount.into());
    }
    let bump = [vault.bump];
    let seeds: [&[u8]; 4] = [
        seeds::VAULT,
        &vault.initial_key_id,
        &vault.vault_seed,
        &bump,
    ];
    transfer_checked(
        token_program,
        source,
        mint,
        dest,
        vault_ai,
        amount,
        decimals,
        &[&seeds],
    )?;
    Ok(dst.owner)
}

/// Number of transfer accounts for an asset type (SOL: destination; SPL:
/// token account, mint, destination, token program).
fn transfer_accounts(asset: AssetType) -> usize {
    if asset == AssetType::Sol {
        1
    } else {
        4
    }
}

/// `ExecuteV2` / `ExecuteV2WithBuffer`: QSP-1 v2 authorizations for vaults
/// with a guardian policy. Accounts: `[fee_payer (s,w), vault (w),
/// signer_key (w*), policy (w)]`, then `[buffer (w), buffer_creator (w)]`
/// for the buffered form, then the action accounts (`docs/PROTOCOL.md` §5)
/// and, last, the optional `fee_recipient (w)`.
fn execute_v2(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    auth_bytes: &[u8; AUTH_V2_LEN],
    sig_src: SigSource,
) -> ProgramResult {
    use ActionV2::*;
    let fee_payer = account(accounts, 0)?;
    let vault_ai = account(accounts, 1)?;
    let key_ai = account(accounts, 2)?;
    let policy_ai = account(accounts, 3)?;
    require_signer(fee_payer)?;
    require_writable(fee_payer)?;
    require_writable(vault_ai)?;
    require_writable(policy_ai)?;
    require_owned(vault_ai, program_id)?;
    require_owned(key_ai, program_id)?;

    // 1. Decode; bind to cluster, program and vault.
    let auth =
        AuthorizationV2::decode(auth_bytes).map_err(|_| VaultError::MalformedAuthorization)?;
    if auth.cluster_id != CLUSTER_ID {
        return Err(VaultError::WrongCluster.into());
    }
    if auth.program_id != program_id.to_bytes() {
        return Err(VaultError::WrongProgram.into());
    }
    if auth.vault != vault_ai.key.to_bytes() {
        return Err(VaultError::WrongVault.into());
    }
    let mut vault = Vault::load(&vault_ai.try_borrow_data()?)?;
    if vault.status == VaultStatus::Closed {
        return Err(VaultError::ActionNotPermitted.into());
    }

    // 2. Policy: required for everything except enabling it.
    let mut policy: Option<Policy> = None;
    let mut create_policy_bump: Option<u8> = None;
    if vault.policy_mode == 0 {
        if auth.action != EnablePolicy {
            return Err(VaultError::PolicyRequired.into());
        }
        let bump = policy_pda(program_id, vault_ai.key, policy_ai, None)?;
        if policy_ai.owner == program_id {
            // Re-enabling: keep the guardian nonce so old guardian
            // authorizations can never be replayed.
            let p = Policy::load(&policy_ai.try_borrow_data()?)?;
            if p.enabled || p.vault != vault_ai.key.to_bytes() {
                return Err(VaultError::InvalidAccount.into());
            }
            policy = Some(p);
        } else {
            create_policy_bump = Some(bump);
        }
    } else {
        if auth.action == EnablePolicy {
            return Err(VaultError::PolicyActive.into());
        }
        require_owned(policy_ai, program_id)?;
        let p = Policy::load(&policy_ai.try_borrow_data()?)?;
        policy_pda(program_id, vault_ai.key, policy_ai, Some(p.bump))?;
        if !p.enabled || p.vault != vault_ai.key.to_bytes() {
            return Err(VaultError::PolicyRequired.into());
        }
        policy = Some(p);
    }

    // 3. Signing key and nonce lane.
    let guardian = auth.role == Role::Guardian;
    let (expected_key, expected_key_id, nonce) = if guardian {
        let p = policy.as_ref().ok_or(VaultError::PolicyRequired)?;
        (p.guardian_key_account, p.guardian_key_id, p.guardian_nonce)
    } else {
        (vault.key_account, vault.key_id, vault.nonce)
    };
    if auth.nonce != nonce {
        return Err(VaultError::WrongNonce.into());
    }

    // 4. Status. Frozen (Paused) vaults accept only the guardian, and from
    // the everyday key only actions that tighten the policy.
    let permitted = match (vault.status, auth.action) {
        (VaultStatus::Active, Unpause) => false,
        (VaultStatus::Active, _) => true,
        (VaultStatus::Paused, Pause | WithdrawSol | WithdrawSpl | ProposeWithdraw) => false,
        (VaultStatus::Paused, ApproveWithdraw) => false,
        (VaultStatus::Paused, _) => true,
        (VaultStatus::Closed, _) => false,
    };
    if !permitted {
        return Err(VaultError::ActionNotPermitted.into());
    }
    // Nothing leaves a frozen vault on the everyday key, not even a fee.
    if vault.status == VaultStatus::Paused && !guardian && auth.fee_lamports > 0 {
        return Err(VaultError::ActionNotPermitted.into());
    }

    // 5. Validity window.
    let now = Clock::get()?.unix_timestamp;
    if !auth.is_live_at(now) {
        return Err(if auth.valid_after != 0 && now < auth.valid_after {
            VaultError::NotYetValid
        } else {
            VaultError::Expired
        }
        .into());
    }

    // 6. The signing key account.
    require_key(key_ai, &expected_key)?;
    let key_hdr = KeyHeader::load(&key_ai.try_borrow_data()?)?;
    if key_hdr.state != KeyState::Ready
        || !key_hdr.in_use
        || key_hdr.guardian != guardian
        || key_hdr.vault != vault_ai.key.to_bytes()
        || key_hdr.key_id != expected_key_id
    {
        return Err(VaultError::InvalidAccount.into());
    }

    // 7. Signature source and verification.
    let (action_start, buffer) = match sig_src {
        SigSource::Inline(_) => (4, None),
        SigSource::Buffer => {
            let buf_ai = account(accounts, 4)?;
            let buf_creator = account(accounts, 5)?;
            require_writable(buf_ai)?;
            require_writable(buf_creator)?;
            require_owned(buf_ai, program_id)?;
            let b = SigBuffer::load(&buf_ai.try_borrow_data()?)?;
            if b.state != BufferState::Finalized || b.vault != vault_ai.key.to_bytes() {
                return Err(VaultError::WrongBufferState.into());
            }
            require_key(buf_creator, &b.creator)?;
            (6, Some((buf_ai, buf_creator)))
        }
    };
    {
        let key_data = key_ai.try_borrow_data()?;
        match (&sig_src, buffer) {
            (SigSource::Inline(sig), _) => verify_signature(&key_data, auth_bytes, &sig[..])?,
            (SigSource::Buffer, Some((buf_ai, _))) => {
                let bd = buf_ai.try_borrow_data()?;
                verify_signature(
                    &key_data,
                    auth_bytes,
                    &bd[SigBuffer::DATA..SigBuffer::DATA + SIGNATURE_LEN],
                )?
            }
            (SigSource::Buffer, None) => return Err(VaultError::InvalidInstruction.into()),
        }
    }

    // 8. Consume the role's nonce.
    if guardian {
        let p = policy.as_mut().ok_or(VaultError::PolicyRequired)?;
        p.guardian_nonce = p
            .guardian_nonce
            .checked_add(1)
            .ok_or(VaultError::Overflow)?;
    } else {
        vault.nonce = vault.nonce.checked_add(1).ok_or(VaultError::Overflow)?;
    }

    // 9. Spending: refill the allowance; the fee always counts, for either
    // role, so a guardian signature alone never moves more than the allowance.
    let acts = accounts.get(action_start..).unwrap_or(&[]);
    let rent = Rent::get()?.minimum_balance(Vault::LEN);
    let mut spend = auth.fee_lamports;
    if let Some(p) = policy.as_mut() {
        p.refill(now);
    }

    // 10. The action. `fee_idx` is where the optional fee recipient sits.
    let fee_idx: usize = match auth.action {
        WithdrawSol => {
            let dest = account(acts, 0)?;
            require_key(dest, &auth.destination)?;
            let p = policy.as_ref().ok_or(VaultError::PolicyRequired)?;
            if !p.is_saved(&auth.destination) {
                spend = spend.checked_add(auth.amount).ok_or(VaultError::Overflow)?;
            }
            vault_pay(vault_ai, dest, auth.amount, rent)?;
            1
        }
        WithdrawSpl => {
            let owner = vault_pay_spl(
                vault_ai,
                &vault,
                &acts[..acts.len().min(4)],
                auth.asset_type,
                &auth.mint,
                &auth.destination,
                auth.amount,
                auth.decimals,
            )?;
            // Tokens move on the everyday key alone only to saved addresses.
            let p = policy.as_ref().ok_or(VaultError::PolicyRequired)?;
            if !p.is_saved(&owner) {
                return Err(VaultError::LimitExceeded.into());
            }
            4
        }
        ProposeWithdraw => {
            let prop_ai = account(acts, 0)?;
            let system = account(acts, 1)?;
            require_writable(prop_ai)?;
            require_system_program(system)?;
            let id_le = auth.nonce.to_le_bytes();
            let (addr, bump) = Pubkey::find_program_address(
                &[seeds::PROPOSAL, vault_ai.key.as_ref(), &id_le],
                program_id,
            );
            if *prop_ai.key != addr {
                return Err(VaultError::AccountMismatch.into());
            }
            create_pda(
                program_id,
                fee_payer,
                prop_ai,
                system,
                Proposal::LEN,
                &[seeds::PROPOSAL, vault_ai.key.as_ref(), &id_le, &[bump]],
            )?;
            Proposal {
                bump,
                asset_type: auth.asset_type as u8,
                decimals: auth.decimals,
                vault: vault_ai.key.to_bytes(),
                id: auth.nonce,
                created_at: now,
                expires_at: auth.expires_at,
                proposer_key_id: vault.key_id,
                mint: auth.mint,
                destination: auth.destination,
                amount: auth.amount,
                rent_payer: fee_payer.key.to_bytes(),
            }
            .store(&mut prop_ai.try_borrow_mut_data()?)?;
            2
        }
        ApproveWithdraw => {
            let prop_ai = account(acts, 0)?;
            let rent_payer = account(acts, 1)?;
            require_writable(prop_ai)?;
            require_writable(rent_payer)?;
            let prop = load_proposal(program_id, vault_ai.key, prop_ai)?;
            if prop.id != auth.ref_id {
                return Err(VaultError::ProposalMismatch.into());
            }
            if prop.proposer_key_id != vault.key_id
                || (prop.expires_at != 0 && now >= prop.expires_at)
            {
                return Err(VaultError::ProposalStale.into());
            }
            // The guardian signs the exact effect, not just an id.
            if prop.asset_type != auth.asset_type as u8
                || prop.mint != auth.mint
                || prop.destination != auth.destination
                || prop.amount != auth.amount
                || prop.decimals != auth.decimals
            {
                return Err(VaultError::ProposalMismatch.into());
            }
            require_key(rent_payer, &prop.rent_payer)?;
            let rest = &acts[2..];
            if auth.asset_type == AssetType::Sol {
                let dest = account(rest, 0)?;
                require_key(dest, &auth.destination)?;
                vault_pay(vault_ai, dest, auth.amount, rent)?;
            } else {
                vault_pay_spl(
                    vault_ai,
                    &vault,
                    &rest[..rest.len().min(4)],
                    auth.asset_type,
                    &auth.mint,
                    &auth.destination,
                    auth.amount,
                    auth.decimals,
                )?;
            }
            close_account(prop_ai, rent_payer)?;
            2 + transfer_accounts(auth.asset_type)
        }
        CancelProposal => {
            let prop_ai = account(acts, 0)?;
            let rent_payer = account(acts, 1)?;
            require_writable(prop_ai)?;
            require_writable(rent_payer)?;
            let prop = load_proposal(program_id, vault_ai.key, prop_ai)?;
            if prop.id != auth.ref_id {
                return Err(VaultError::ProposalMismatch.into());
            }
            require_key(rent_payer, &prop.rent_payer)?;
            close_account(prop_ai, rent_payer)?;
            2
        }
        Pause => {
            vault.status = VaultStatus::Paused;
            0
        }
        Unpause => {
            vault.status = VaultStatus::Active;
            0
        }
        RotateKey => {
            let new_key = account(acts, 0)?;
            let old_key = account(acts, 1)?;
            let old_creator = account(acts, 2)?;
            require_writable(old_key)?;
            require_writable(old_creator)?;
            require_key(old_key, &vault.key_account)?;
            let p = policy.as_ref().ok_or(VaultError::PolicyRequired)?;
            if auth.new_key_id == p.guardian_key_id {
                return Err(VaultError::KeyConflict.into());
            }
            let mut nh = check_new_key(
                vault_ai.key,
                new_key,
                program_id,
                &auth.new_key_id,
                auth.new_algorithm,
            )?;
            let old = KeyHeader::load(&old_key.try_borrow_data()?)?;
            require_key(old_creator, &old.creator)?;
            if new_key.key == old_key.key {
                return Err(VaultError::AccountMismatch.into());
            }
            nh.in_use = true;
            nh.guardian = false;
            nh.store(&mut new_key.try_borrow_mut_data()?)?;
            vault.key_id = nh.key_id;
            vault.key_account = new_key.key.to_bytes();
            vault.pq_algorithm = nh.algorithm;
            close_account(old_key, old_creator)?;
            3
        }
        RotateGuardian => {
            let new_key = account(acts, 0)?;
            let old_creator = account(acts, 1)?;
            require_writable(key_ai)?;
            require_writable(old_creator)?;
            require_key(old_creator, &key_hdr.creator)?;
            if auth.new_key_id == vault.key_id {
                return Err(VaultError::KeyConflict.into());
            }
            if new_key.key == key_ai.key {
                return Err(VaultError::AccountMismatch.into());
            }
            let mut nh = check_new_key(
                vault_ai.key,
                new_key,
                program_id,
                &auth.new_key_id,
                auth.new_algorithm,
            )?;
            nh.in_use = true;
            nh.guardian = true;
            nh.store(&mut new_key.try_borrow_mut_data()?)?;
            let p = policy.as_mut().ok_or(VaultError::PolicyRequired)?;
            p.guardian_key_id = nh.key_id;
            p.guardian_key_account = new_key.key.to_bytes();
            close_account(key_ai, old_creator)?;
            2
        }
        EnablePolicy => {
            let gk = account(acts, 0)?;
            let system = account(acts, 1)?;
            require_system_program(system)?;
            if auth.new_key_id == vault.key_id {
                return Err(VaultError::KeyConflict.into());
            }
            let mut gh = check_new_key(
                vault_ai.key,
                gk,
                program_id,
                &auth.new_key_id,
                auth.new_algorithm,
            )?;
            gh.in_use = true;
            gh.guardian = true;
            gh.store(&mut gk.try_borrow_mut_data()?)?;
            let (bump, guardian_nonce) = match (&policy, create_policy_bump) {
                (Some(p), _) => (p.bump, p.guardian_nonce),
                (None, Some(b)) => {
                    create_pda(
                        program_id,
                        fee_payer,
                        policy_ai,
                        system,
                        Policy::LEN,
                        &[seeds::POLICY, vault_ai.key.as_ref(), &[b]],
                    )?;
                    (b, 0)
                }
                (None, None) => return Err(VaultError::PolicyRequired.into()),
            };
            policy = Some(Policy {
                bump,
                enabled: true,
                vault: vault_ai.key.to_bytes(),
                guardian_key_id: gh.key_id,
                guardian_key_account: gk.key.to_bytes(),
                guardian_nonce,
                limit: auth.limit_lamports,
                period: auth.limit_period,
                available: auth.limit_lamports,
                last_refill: now,
                saved: [[0u8; 32]; MAX_SAVED],
                saved_len: 0,
            });
            vault.policy_mode = 1;
            // The fee of the enabling authorization is the single-key fee.
            spend = 0;
            2
        }
        SetLimit => {
            let p = policy.as_mut().ok_or(VaultError::PolicyRequired)?;
            if !guardian && (auth.limit_lamports > p.limit || auth.limit_period != p.period) {
                // The everyday key may only tighten the limit.
                return Err(VaultError::ActionNotPermitted.into());
            }
            p.limit = auth.limit_lamports;
            p.period = auth.limit_period;
            p.available = p.available.min(p.limit);
            0
        }
        AddAddress => {
            let p = policy.as_mut().ok_or(VaultError::PolicyRequired)?;
            if auth.destination == vault_ai.key.to_bytes() {
                return Err(VaultError::AccountMismatch.into());
            }
            if p.is_saved(&auth.destination) {
                return Err(VaultError::AlreadySaved.into());
            }
            let n = p.saved_len as usize;
            if n >= MAX_SAVED {
                return Err(VaultError::PolicyFull.into());
            }
            p.saved[n] = auth.destination;
            p.saved_len += 1;
            0
        }
        RemoveAddress => {
            let p = policy.as_mut().ok_or(VaultError::PolicyRequired)?;
            let n = p.saved_len as usize;
            let i = p.saved[..n]
                .iter()
                .position(|a| a == &auth.destination)
                .ok_or(VaultError::NotSaved)?;
            p.saved[i] = p.saved[n - 1];
            p.saved[n - 1] = ZERO32;
            p.saved_len -= 1;
            0
        }
        DisablePolicy => {
            require_writable(key_ai)?;
            let mut gh = key_hdr;
            gh.in_use = false;
            gh.guardian = false;
            gh.store(&mut key_ai.try_borrow_mut_data()?)?;
            let p = policy.as_mut().ok_or(VaultError::PolicyRequired)?;
            p.enabled = false;
            vault.policy_mode = 0;
            0
        }
    };

    // 11. Fee (signed amount to the signed recipient), and the allowance.
    if spend > 0 {
        let p = policy.as_mut().ok_or(VaultError::PolicyRequired)?;
        if spend > p.available {
            return Err(VaultError::LimitExceeded.into());
        }
        p.available -= spend;
    }
    if auth.fee_lamports > 0 {
        let target = if auth.fee_recipient == ZERO32 {
            fee_payer
        } else {
            let a = account(acts, fee_idx)?;
            require_key(a, &auth.fee_recipient)?;
            a
        };
        vault_pay(vault_ai, target, auth.fee_lamports, rent)?;
    }

    vault.store(&mut vault_ai.try_borrow_mut_data()?)?;
    if let Some(p) = policy {
        p.store(&mut policy_ai.try_borrow_mut_data()?)?;
    }
    if let Some((buf_ai, buf_creator)) = buffer {
        close_account(buf_ai, buf_creator)?;
    }
    Ok(())
}

/// `CloseProposal`: `[vault, proposal (w), rent_payer (w)]`. Anyone may close
/// a proposal that can no longer be approved — the vault is closed or has no
/// policy, the proposing key was replaced, or it expired — refunding its rent
/// to whoever paid it.
fn close_proposal(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let vault_ai = account(accounts, 0)?;
    let prop_ai = account(accounts, 1)?;
    let rent_payer = account(accounts, 2)?;
    require_owned(vault_ai, program_id)?;
    require_writable(prop_ai)?;
    require_writable(rent_payer)?;
    let vault = Vault::load(&vault_ai.try_borrow_data()?)?;
    let prop = load_proposal(program_id, vault_ai.key, prop_ai)?;
    require_key(rent_payer, &prop.rent_payer)?;
    let now = Clock::get()?.unix_timestamp;
    let dead = vault.status == VaultStatus::Closed
        || vault.policy_mode == 0
        || prop.proposer_key_id != vault.key_id
        || (prop.expires_at != 0 && now >= prop.expires_at);
    if !dead {
        return Err(VaultError::ActionNotPermitted.into());
    }
    close_account(prop_ai, rent_payer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::ml_dsa_44;
    use fips204::traits::{KeyGen, SerDes, Signer};

    /// Builds key-account bytes (header zeroed) holding the expansion of `pk`.
    fn key_account_bytes(pk: &[u8; PUBLIC_KEY_LEN]) -> alloc::vec::Vec<u8> {
        let mut d = alloc::vec![0u8; KeyHeader::LEN];
        d[key_off::PK..key_off::TR].copy_from_slice(pk);
        d[key_off::TR..key_off::A_HAT].copy_from_slice(&compute_tr(pk));
        let mut poly = [0u32; 256];
        for i in 0..(A_HAT_POLYS + 4) {
            let off = if i < A_HAT_POLYS {
                expand_a_entry(&mut poly, pk, i / 4, i % 4);
                key_off::A_HAT + i * 1024
            } else {
                expand_t1_hat_row(&mut poly, pk, i - A_HAT_POLYS);
                key_off::T1_HAT + (i - A_HAT_POLYS) * 1024
            };
            for (j, c) in poly.iter().enumerate() {
                d[off + 4 * j..off + 4 * j + 4].copy_from_slice(&c.to_le_bytes());
            }
        }
        d
    }

    #[test]
    fn aligned_and_misaligned_key_data_verify_identically() {
        let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&[42u8; 32]);
        let pk = pk.into_bytes();
        let auth = [7u8; AUTH_LEN];
        let sig = sk
            .try_sign_with_seed(&[0u8; 32], &auth, ML_DSA_CONTEXT)
            .unwrap();
        let data = key_account_bytes(&pk);

        // Place the same bytes at an aligned and at a misaligned address.
        let mut storage = alloc::vec![0u64; KeyHeader::LEN / 8 + 2];
        let raw: &mut [u8] = bytemuck::cast_slice_mut(&mut storage);
        raw[..KeyHeader::LEN].copy_from_slice(&data);
        assert!(expanded_key_view(&raw[..KeyHeader::LEN]).is_some());
        assert!(verify_signature(&raw[..KeyHeader::LEN], &auth, &sig).is_ok());

        raw[1..=KeyHeader::LEN].copy_from_slice(&data);
        let misaligned = &raw[1..=KeyHeader::LEN];
        assert!(
            expanded_key_view(misaligned).is_none(),
            "test must exercise the copy fallback"
        );
        assert!(verify_signature(misaligned, &auth, &sig).is_ok());

        let mut bad = sig;
        bad[5] ^= 1;
        assert!(verify_signature(&raw[..KeyHeader::LEN], &auth, &bad).is_err());
        assert!(verify_signature(misaligned, &auth, &bad).is_err());
    }
}
