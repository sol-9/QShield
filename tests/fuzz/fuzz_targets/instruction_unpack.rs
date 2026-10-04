#![no_main]
//! Program instruction decoding never panics.
use libfuzzer_sys::fuzz_target;
use qshield_vault::instruction::VaultInstruction;

fuzz_target!(|data: &[u8]| {
    let _ = VaultInstruction::unpack(data);
});
