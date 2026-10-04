//! Benchmark-only Solana program for measuring ML-DSA-44 verification under SBF.
//!
//! **Not a production program.** It has no access control and exists solely to
//! produce the measurements in `docs/MLDSA_SOLANA_FEASIBILITY.md`.
//!
//! Instruction data begins with an opcode byte:
//!
//! | op | name               | accounts                                  | data after opcode                            |
//! |----|--------------------|-------------------------------------------|----------------------------------------------|
//! | 0  | NOOP               | –                                         | –                                            |
//! | 1  | VERIFY_INLINE      | –                                         | pk ‖ sig ‖ ctx_len:u8 ‖ ctx ‖ msg            |
//! | 2  | VERIFY_ACCOUNTS    | [pk_acct, sig_acct]                       | ctx_len:u8 ‖ ctx ‖ msg                       |
//! | 3  | VERIFY_PREPARED    | [pk‖tr acct, sig_acct]                    | ctx_len:u8 ‖ ctx ‖ msg                       |
//! | 4  | PROFILE            | –                                         | pk ‖ sig                                     |
//! | 5  | WRITE              | [buffer (writable, owned by this program)]| offset:u32 LE ‖ bytes                        |
//! | 6  | VERIFY_PK_INLINE   | [sig_acct]                                | pk ‖ ctx_len:u8 ‖ ctx ‖ msg                  |
//! | 7  | VERIFY_SIG_INLINE  | [pk‖tr acct]                              | sig ‖ ctx_len:u8 ‖ ctx ‖ msg                 |
//! | 8  | VERIFY_EXPANDED    | [expanded key acct, sig_acct]             | ctx_len:u8 ‖ ctx ‖ msg                       |
//! | 9  | VERIFY_EXP_INLINE  | [expanded key acct]                       | sig ‖ ctx_len:u8 ‖ ctx ‖ msg                 |
//!
//! Expanded key account layout: `A_hat` (16 × 256 × u32 LE) ‖ `t1_hat` (4 × 256 × u32 LE) ‖ `tr` (64 bytes).
//!
//! Every verifying opcode logs `heap_peak=<bytes>` and fails with
//! `InvalidArgument` if the signature is rejected, so the harness can observe
//! both outcomes.
#![allow(unexpected_cfgs)]

extern crate alloc;

use qshield_mldsa::{
    compute_tr, poly, sample, verify, verify_expanded, verify_prepared, workspace_vec, ExpandedKey,
    PreparedPublicKey, Workspace, A_HAT_POLYS, PUBLIC_KEY_LEN, SIGNATURE_LEN, TR_LEN,
};
use solana_account_info::AccountInfo;
use solana_msg::msg;
use solana_program_error::{ProgramError, ProgramResult};
use solana_pubkey::Pubkey;

solana_program_entrypoint::entrypoint!(process_instruction);

// ---------------------------------------------------------------------------
// Instrumented bump allocator (records the heap high-water mark).
// ---------------------------------------------------------------------------

#[cfg(target_os = "solana")]
mod heap {
    use core::alloc::{GlobalAlloc, Layout};

    pub const HEAP_START: usize = solana_program_entrypoint::HEAP_START_ADDRESS as usize;
    pub const HEAP_LEN: usize = solana_program_entrypoint::HEAP_LENGTH;
    /// Bytes reserved at the start of the heap for allocator bookkeeping.
    const HEADER: usize = 16;

    pub struct PeakBump;

    #[inline(always)]
    fn cursor() -> *mut usize {
        HEAP_START as *mut usize
    }

    #[inline(always)]
    fn peak_slot() -> *mut usize {
        (HEAP_START + 8) as *mut usize
    }

    // SAFETY: the SBF runtime maps HEAP_LEN zero-initialised bytes at
    // HEAP_START for each invocation and programs are single-threaded. The
    // first 16 bytes are reserved for the cursor and peak counters.
    unsafe impl GlobalAlloc for PeakBump {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let mut pos = *cursor();
            if pos == 0 {
                pos = HEAP_START + HEADER;
            }
            let start = (pos + layout.align() - 1) & !(layout.align() - 1);
            let end = match start.checked_add(layout.size()) {
                Some(e) if e <= HEAP_START + HEAP_LEN => e,
                _ => return core::ptr::null_mut(),
            };
            *cursor() = end;
            if end - HEAP_START > *peak_slot() {
                *peak_slot() = end - HEAP_START;
            }
            start as *mut u8
        }
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }

    pub fn peak() -> usize {
        // SAFETY: see above.
        unsafe { *peak_slot() }
    }

    #[global_allocator]
    static A: PeakBump = PeakBump;
}

#[cfg(not(target_os = "solana"))]
mod heap {
    pub fn peak() -> usize {
        0
    }
}

/// Logs the remaining compute units ("Program consumption: N units remaining").
#[inline(always)]
fn log_cu() {
    #[cfg(target_os = "solana")]
    // SAFETY: syscall without arguments.
    unsafe {
        solana_define_syscall::definitions::sol_log_compute_units_()
    }
}

fn split_ctx_msg(data: &[u8]) -> Result<(&[u8], &[u8]), ProgramError> {
    let (&ctx_len, rest) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let ctx_len = ctx_len as usize;
    if rest.len() < ctx_len {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(rest.split_at(ctx_len))
}

fn workspace() -> alloc::vec::Vec<poly::Poly> {
    workspace_vec()
}

fn as_ws(v: &mut [poly::Poly]) -> &mut Workspace {
    v.try_into().expect("workspace size")
}

fn report(result: Result<(), qshield_mldsa::Error>) -> ProgramResult {
    msg!("heap_peak={}", heap::peak());
    match result {
        Ok(()) => {
            msg!("verify=ok");
            Ok(())
        }
        Err(e) => {
            msg!("verify=err:{:?}", e);
            Err(ProgramError::InvalidArgument)
        }
    }
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let (&op, rest) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match op {
        0 => Ok(()),
        1 => {
            if rest.len() < PUBLIC_KEY_LEN + SIGNATURE_LEN {
                return Err(ProgramError::InvalidInstructionData);
            }
            let (pk, rest) = rest.split_at(PUBLIC_KEY_LEN);
            let (sig, rest) = rest.split_at(SIGNATURE_LEN);
            let (ctx, m) = split_ctx_msg(rest)?;
            let mut ws = workspace();
            report(verify(pk, m, ctx, sig, as_ws(&mut ws)))
        }
        2 => {
            let [pk_acct, sig_acct, ..] = accounts else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            let pk_data = pk_acct.try_borrow_data()?;
            let sig_data = sig_acct.try_borrow_data()?;
            let (ctx, m) = split_ctx_msg(rest)?;
            let mut ws = workspace();
            report(verify(
                pk_data
                    .get(..PUBLIC_KEY_LEN)
                    .ok_or(ProgramError::AccountDataTooSmall)?,
                m,
                ctx,
                sig_data
                    .get(..SIGNATURE_LEN)
                    .ok_or(ProgramError::AccountDataTooSmall)?,
                as_ws(&mut ws),
            ))
        }
        3 | 7 => {
            let (key_acct, sig_owned_by_acct) = match (op, accounts) {
                (3, [k, s, ..]) => (k, Some(s)),
                (7, [k, ..]) => (k, None),
                _ => return Err(ProgramError::NotEnoughAccountKeys),
            };
            let key_data = key_acct.try_borrow_data()?;
            let pk = key_data
                .get(..PUBLIC_KEY_LEN)
                .ok_or(ProgramError::AccountDataTooSmall)?;
            let tr: [u8; TR_LEN] = key_data
                .get(PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + TR_LEN)
                .ok_or(ProgramError::AccountDataTooSmall)?
                .try_into()
                .map_err(|_| ProgramError::AccountDataTooSmall)?;
            let key = PreparedPublicKey::from_parts(pk, tr)
                .map_err(|_| ProgramError::InvalidAccountData)?;
            let mut ws = workspace();
            match sig_owned_by_acct {
                Some(sig_acct) => {
                    let sig_data = sig_acct.try_borrow_data()?;
                    let (ctx, m) = split_ctx_msg(rest)?;
                    let sig = sig_data
                        .get(..SIGNATURE_LEN)
                        .ok_or(ProgramError::AccountDataTooSmall)?;
                    report(verify_prepared(&key, m, ctx, sig, as_ws(&mut ws)))
                }
                None => {
                    if rest.len() < SIGNATURE_LEN {
                        return Err(ProgramError::InvalidInstructionData);
                    }
                    let (sig, rest) = rest.split_at(SIGNATURE_LEN);
                    let (ctx, m) = split_ctx_msg(rest)?;
                    report(verify_prepared(&key, m, ctx, sig, as_ws(&mut ws)))
                }
            }
        }
        4 => profile(rest),
        5 => {
            let [buf, ..] = accounts else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            if rest.len() < 4 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let (off, bytes) = rest.split_at(4);
            let off = u32::from_le_bytes(off.try_into().unwrap()) as usize;
            let mut d = buf.try_borrow_mut_data()?;
            let end = off
                .checked_add(bytes.len())
                .ok_or(ProgramError::InvalidArgument)?;
            d.get_mut(off..end)
                .ok_or(ProgramError::AccountDataTooSmall)?
                .copy_from_slice(bytes);
            Ok(())
        }
        6 => {
            let [sig_acct, ..] = accounts else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            if rest.len() < PUBLIC_KEY_LEN {
                return Err(ProgramError::InvalidInstructionData);
            }
            let (pk, rest) = rest.split_at(PUBLIC_KEY_LEN);
            let (ctx, m) = split_ctx_msg(rest)?;
            let sig_data = sig_acct.try_borrow_data()?;
            let sig = sig_data
                .get(..SIGNATURE_LEN)
                .ok_or(ProgramError::AccountDataTooSmall)?;
            let mut ws = workspace();
            report(verify(pk, m, ctx, sig, as_ws(&mut ws)))
        }
        8 | 9 => {
            let [key_acct, rest_accts @ ..] = accounts else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            let key_data = key_acct.try_borrow_data()?;
            let ek = expanded_key(&key_data)?;
            let mut ws = workspace();
            if op == 8 {
                let sig_acct = rest_accts
                    .first()
                    .ok_or(ProgramError::NotEnoughAccountKeys)?;
                let sig_data = sig_acct.try_borrow_data()?;
                let sig = sig_data
                    .get(..SIGNATURE_LEN)
                    .ok_or(ProgramError::AccountDataTooSmall)?;
                let (ctx, m) = split_ctx_msg(rest)?;
                report(verify_expanded(&ek, m, ctx, sig, as_ws(&mut ws)))
            } else {
                if rest.len() < SIGNATURE_LEN {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let (sig, rest) = rest.split_at(SIGNATURE_LEN);
                let (ctx, m) = split_ctx_msg(rest)?;
                report(verify_expanded(&ek, m, ctx, sig, as_ws(&mut ws)))
            }
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

const A_HAT_BYTES: usize = A_HAT_POLYS * 1024;
const T1_HAT_BYTES: usize = 4 * 1024;

/// Zero-copy view of an expanded key stored in account data. Fails if the
/// data is too short or not 4-byte aligned.
fn expanded_key(data: &[u8]) -> Result<ExpandedKey<'_>, ProgramError> {
    let a = data
        .get(..A_HAT_BYTES)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let t = data
        .get(A_HAT_BYTES..A_HAT_BYTES + T1_HAT_BYTES)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let tr = data
        .get(A_HAT_BYTES + T1_HAT_BYTES..A_HAT_BYTES + T1_HAT_BYTES + TR_LEN)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    Ok(ExpandedKey {
        a_hat: bytemuck::try_from_bytes(a).map_err(|_| ProgramError::InvalidAccountData)?,
        t1_hat: bytemuck::try_from_bytes(t).map_err(|_| ProgramError::InvalidAccountData)?,
        tr: tr
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?,
    })
}

/// Measures the cost of the individual building blocks of verification.
/// Logs `profile:<name>` markers followed by two compute-unit log lines.
fn profile(rest: &[u8]) -> ProgramResult {
    if rest.len() < PUBLIC_KEY_LEN + SIGNATURE_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let pk: &[u8; PUBLIC_KEY_LEN] = rest[..PUBLIC_KEY_LEN].try_into().unwrap();
    let sig = &rest[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + SIGNATURE_LEN];
    let mut ws = workspace();
    let [a, b, ..] = &mut ws[..] else {
        unreachable!()
    };
    let rho: &[u8; 32] = pk[..32].try_into().unwrap();
    let c_tilde: &[u8; 32] = sig[..32].try_into().unwrap();

    macro_rules! measure {
        ($name:literal, $e:expr) => {{
            // The harness pairs each "profile:<name>" marker with the two
            // surrounding "Program consumption" lines and subtracts the cost
            // of the empty measurement.
            msg!(concat!("profile:", $name));
            log_cu();
            let r = $e;
            log_cu();
            r
        }};
    }

    measure!("empty", ());
    let _tr = measure!("tr_shake256_1312B", compute_tr(pk));
    measure!("rej_ntt_poly", sample::rej_ntt_poly(a, rho, 0, 0));
    measure!("sample_in_ball", sample::sample_in_ball(b, c_tilde));
    measure!("ntt", poly::ntt(a));
    measure!("inv_ntt", poly::inv_ntt(a));
    measure!("pointwise_mul_acc", poly::pointwise_mul_acc(a, b, b));
    measure!(
        "decode_t1_row",
        qshield_mldsa::encoding::decode_t1_shifted(a, &pk[32..352])
    );
    msg!("heap_peak={}", heap::peak());
    Ok(())
}
