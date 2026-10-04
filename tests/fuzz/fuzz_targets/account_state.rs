#![no_main]
//! Account-state parsing never panics, and accepted states round-trip.
use libfuzzer_sys::fuzz_target;
use qshield_vault::state::{KeyHeader, SigBuffer, Vault};

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = Vault::load(data) {
        let mut d = vec![0u8; Vault::LEN];
        v.store(&mut d).unwrap();
        assert_eq!(Vault::load(&d).unwrap(), v);
    }
    if let Ok(b) = SigBuffer::load(data) {
        let mut d = data.to_vec();
        b.store(&mut d).unwrap();
        assert_eq!(SigBuffer::load(&d).unwrap(), b);
    }
    let _ = KeyHeader::load(data);
});
