//! Token-account and mint parsing (incl. Token-2022 TLV extension walk and
//! the mint policy) must never panic on arbitrary account data, and must be
//! consistent: a mint accepted by the policy has only allow-listed extensions.
#![no_main]

use libfuzzer_sys::fuzz_target;
use qshield_vault::token::{
    ext, mint_extensions, parse_mint, parse_token_account, TOKEN_2022_PROGRAM, TOKEN_PROGRAM,
};

fuzz_target!(|data: &[u8]| {
    for program in [TOKEN_PROGRAM, TOKEN_2022_PROGRAM] {
        let _ = parse_token_account(&program, data);
        if parse_mint(&program, data).is_ok() {
            let exts = mint_extensions(data).expect("accepted mint has well-formed TLV");
            assert!(exts.iter().all(|t| ext::MINT_ALLOWED.contains(t)));
        }
    }
});
