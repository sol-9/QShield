//! QShield recovery phrase v1: the 32-byte key seed as 24 words.
//!
//! * Words: the BIP-39 English list (2,048 words; SHA-256 of the file
//!   `2f5eed53…dbda`; first four letters unique).
//! * Bits: `seed (256) ‖ checksum (8)` = 264 bits = 24 × 11, where
//!   `checksum = SHA-256("QSHIELD_RECOVERY_PHRASE_V1" ‖ 0x01 ‖ seed)[0]`
//!   (0x01 = ML-DSA-44). The domain-separated checksum makes a BIP-39 wallet
//!   phrase fail here almost always, and a QShield phrase fail in wallets.
//! * The phrase *is* the key: anyone who reads it controls what the key
//!   controls. It is never derived from a password (a guessable phrase would
//!   be checked offline against the public key on-chain).
//!
//! On recovery, callers must check the resulting key id against the vault's
//! on-chain key (a much stronger check than the 8-bit checksum).

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

const WORDLIST_TEXT: &str = include_str!("wordlist/bip39-english.txt");
/// Domain separation for the checksum.
pub const PHRASE_DOMAIN: &[u8] = b"QSHIELD_RECOVERY_PHRASE_V1";
/// Words in a phrase.
pub const PHRASE_WORDS: usize = 24;

fn words() -> Vec<&'static str> {
    WORDLIST_TEXT.lines().collect()
}

fn checksum(seed: &[u8; 32]) -> u8 {
    let mut h = Sha256::new();
    h.update(PHRASE_DOMAIN);
    h.update([1u8]);
    h.update(seed);
    h.finalize()[0]
}

/// Encodes a seed as 24 words separated by single spaces.
pub fn phrase_from_seed(seed: &[u8; 32]) -> Zeroizing<String> {
    let list = words();
    let mut bits = Zeroizing::new([0u8; 33]);
    bits[..32].copy_from_slice(seed);
    bits[32] = checksum(seed);
    let mut out = Zeroizing::new(String::new());
    for i in 0..PHRASE_WORDS {
        let mut idx = 0usize;
        for b in 0..11 {
            let bit = i * 11 + b;
            idx = (idx << 1) | ((bits[bit / 8] >> (7 - bit % 8)) & 1) as usize;
        }
        if i > 0 {
            out.push(' ');
        }
        out.push_str(list[idx]);
    }
    out
}

/// Decodes a phrase. Accepts any case and whitespace, and words abbreviated
/// to their (unique) first four letters.
pub fn seed_from_phrase(phrase: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    let list = words();
    let ws: Vec<String> = phrase
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect();
    if ws.len() != PHRASE_WORDS {
        return Err(Error::InvalidInput(format!(
            "a recovery phrase has {PHRASE_WORDS} words, got {}",
            ws.len()
        )));
    }
    let mut bits = Zeroizing::new([0u8; 33]);
    for (i, w) in ws.iter().enumerate() {
        let idx = list
            .iter()
            .position(|x| x == w)
            .or_else(|| {
                if w.len() >= 4 {
                    let m: Vec<usize> = (0..list.len())
                        .filter(|&j| list[j].starts_with(w.as_str()))
                        .collect();
                    (m.len() == 1).then(|| m[0])
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                Error::InvalidInput(format!("word {} is not in the word list", i + 1))
            })?;
        for b in 0..11 {
            if (idx >> (10 - b)) & 1 == 1 {
                let bit = i * 11 + b;
                bits[bit / 8] |= 1 << (7 - bit % 8);
            }
        }
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bits[..32]);
    if checksum(&seed) != bits[32] {
        seed.zeroize();
        return Err(Error::InvalidInput(
            "the recovery phrase checksum does not match (a word is wrong or out of order)".into(),
        ));
    }
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_bip39_english() {
        let digest = Sha256::digest(WORDLIST_TEXT.as_bytes());
        assert_eq!(
            hex::encode(digest),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        let list = words();
        assert_eq!(list.len(), 2048);
        let mut p: Vec<&str> = list.iter().map(|w| &w[..w.len().min(4)]).collect();
        p.sort();
        p.dedup();
        assert_eq!(p.len(), 2048, "4-letter prefixes are unique");
    }

    #[test]
    fn roundtrip_prefixes_and_errors() {
        for s in [[0u8; 32], [0xff; 32], core::array::from_fn(|i| i as u8)] {
            let p = phrase_from_seed(&s);
            assert_eq!(p.split(' ').count(), 24);
            assert_eq!(*seed_from_phrase(&p).unwrap(), s);
            let short: Vec<String> = p.split(' ').map(|w| w.chars().take(4).collect()).collect();
            assert_eq!(
                *seed_from_phrase(&short.join("  ").to_uppercase()).unwrap(),
                s
            );
        }
        let p = phrase_from_seed(&[7; 32]);
        let mut ws: Vec<&str> = p.split(' ').collect();
        ws.swap(0, 1);
        assert!(seed_from_phrase(&ws.join(" ")).is_err(), "order matters");
        assert!(seed_from_phrase(&p.replace(ws[5], "qshieldx")).is_err());
        assert!(seed_from_phrase("abandon abandon").is_err());
        // A valid BIP-39 phrase is (almost always) not a QShield phrase.
        let bip39 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        assert!(seed_from_phrase(bip39).is_err());
    }
}
