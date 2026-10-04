#![no_main]
//! QSP-1 decoding: never panics; anything accepted re-encodes to the same bytes.
use libfuzzer_sys::fuzz_target;
use qshield_protocol::Authorization;

fuzz_target!(|data: &[u8]| {
    if let Ok(a) = Authorization::decode(data) {
        assert_eq!(&a.encode().unwrap()[..], data);
    }
});
