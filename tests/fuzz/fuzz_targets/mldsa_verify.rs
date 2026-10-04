#![no_main]
//! ML-DSA-44 verification on arbitrary (pk, signature, message, context) never
//! panics. Inputs are split as: ctx_len (1 byte) | ctx | pk (1312) | sig (2420) | msg.
use libfuzzer_sys::fuzz_target;
use qshield_mldsa::{verify, Workspace, PUBLIC_KEY_LEN, SIGNATURE_LEN};

fuzz_target!(|data: &[u8]| {
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    let n = (n as usize).min(rest.len());
    let (ctx, rest) = rest.split_at(n);
    if rest.len() < PUBLIC_KEY_LEN + SIGNATURE_LEN {
        let mut ws: Workspace = [[0u32; 256]; 7];
        let _ = verify(rest, b"", ctx, rest, &mut ws);
        return;
    }
    let (pk, rest) = rest.split_at(PUBLIC_KEY_LEN);
    let (sig, msg) = rest.split_at(SIGNATURE_LEN);
    let mut ws: Workspace = [[0u32; 256]; 7];
    let _ = verify(pk, msg, ctx, sig, &mut ws);
});
