//! YKOATH crypto: password key derivation, HMAC, code truncation, timesteps.

use std::num::NonZeroU32;

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Length of the key derived from the OATH password.
pub const KEY_LEN: usize = 16;
const PBKDF2_ROUNDS: u32 = 1000;

/// Key derived from the OATH password. Wiped from memory on drop.
pub type DerivedKey = Zeroizing<[u8; KEY_LEN]>;

/// HMAC hash used by a credential or by the VALIDATE exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    /// Map a YKOATH algorithm byte. Only the low nibble carries the
    /// algorithm; the high nibble is the credential type (HOTP or TOTP).
    pub fn from_ykoath(byte: u8) -> Option<Self> {
        match byte & 0x0F {
            0x01 => Some(Self::Sha1),
            0x02 => Some(Self::Sha256),
            0x03 => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// `PBKDF2-HMAC-SHA1(password, salt, 1000 rounds, 16 bytes)`. The salt is the
/// device ID from the SELECT response.
pub fn derive_key(password: &str, salt: &[u8]) -> DerivedKey {
    let mut key = Zeroizing::new([0; KEY_LEN]);
    pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, PBKDF2_ROUNDS, key.as_mut());
    key
}

/// HMAC of `message` under `key` with `algorithm`.
pub fn hmac(algorithm: Algorithm, key: &[u8], message: &[u8]) -> Vec<u8> {
    fn run<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
        // HMAC accepts keys of any length, so this cannot fail.
        let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(message);
        mac.finalize().into_bytes().to_vec()
    }
    match algorithm {
        Algorithm::Sha1 => run::<Hmac<Sha1>>(key, message),
        Algorithm::Sha256 => run::<Hmac<Sha256>>(key, message),
        Algorithm::Sha512 => run::<Hmac<Sha512>>(key, message),
    }
}

/// RFC 4226 section 5.3 dynamic truncation: pick 4 bytes of `mac` at the
/// offset given by its last nibble.
///
/// # Panics
///
/// If `mac` is shorter than 20 bytes. Every supported HMAC output is longer.
pub fn dynamic_truncate(mac: &[u8]) -> [u8; 4] {
    assert!(
        mac.len() >= 20,
        "HMAC output too short: {} bytes",
        mac.len()
    );
    let offset = usize::from(mac[mac.len() - 1] & 0x0F);
    let mut out = [0; 4];
    out.copy_from_slice(&mac[offset..offset + 4]);
    out
}

/// Turn a truncated value into a zero-padded code of `digits` digits.
/// The top bit is masked off as RFC 4226 requires.
pub fn format_code(digits: u8, value: [u8; 4]) -> String {
    let n = u64::from(u32::from_be_bytes(value) & 0x7FFF_FFFF);
    let n = 10u64.checked_pow(u32::from(digits)).map_or(n, |m| n % m);
    format!("{n:0width$}", width = usize::from(digits))
}

/// TOTP timestep: `floor(unix_time / period)`.
pub fn timestep(unix_time: u64, period: NonZeroU32) -> u64 {
    unix_time / u64::from(period.get())
}

/// Start (inclusive) and end (exclusive) of the period containing `unix_time`.
pub fn validity_window(unix_time: u64, period: NonZeroU32) -> (u64, u64) {
    let len = u64::from(period.get());
    let start = timestep(unix_time, period) * len;
    (start, start + len)
}

/// Compare in constant time for equal lengths. Different lengths are unequal.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // subtle returns false for different lengths without comparing contents.
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn period(secs: u32) -> NonZeroU32 {
        NonZeroU32::new(secs).unwrap()
    }

    // PBKDF2 expected values computed independently with Python
    // `hashlib.pbkdf2_hmac("sha1", password, salt, 1000, 16)`.
    #[test]
    fn derive_key_matches_independent_pbkdf2_vector() {
        assert_eq!(
            *derive_key("password", b"salt"),
            hex!("6e88be8bad7eae9d9e10aa061224034f")
        );
        assert_eq!(
            *derive_key("correct horse", &hex!("0102030405060708")),
            hex!("49561f12fb17065dd680fc5a61d740a6")
        );
    }

    #[test]
    fn derived_key_is_zeroizing() {
        let _key: Zeroizing<[u8; 16]> = derive_key("password", b"salt");
    }

    #[test]
    fn algorithm_maps_low_nibble() {
        assert_eq!(Algorithm::from_ykoath(0x01), Some(Algorithm::Sha1));
        assert_eq!(Algorithm::from_ykoath(0x02), Some(Algorithm::Sha256));
        assert_eq!(Algorithm::from_ykoath(0x03), Some(Algorithm::Sha512));
        // TOTP (0x20) and HOTP (0x10) type bits are ignored.
        assert_eq!(Algorithm::from_ykoath(0x22), Some(Algorithm::Sha256));
        assert_eq!(Algorithm::from_ykoath(0x13), Some(Algorithm::Sha512));
        assert_eq!(Algorithm::from_ykoath(0x00), None);
        assert_eq!(Algorithm::from_ykoath(0x04), None);
    }

    // RFC 2202 test cases 1 and 2.
    #[test]
    fn hmac_sha1_matches_rfc2202() {
        assert_eq!(
            hmac(Algorithm::Sha1, &[0x0b; 20], b"Hi There"),
            hex!("b617318655057264e28bc0b6fb378c8ef146be00")
        );
        assert_eq!(
            hmac(Algorithm::Sha1, b"Jefe", b"what do ya want for nothing?"),
            hex!("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
        );
    }

    // RFC 4231 test cases 1 and 2.
    #[test]
    fn hmac_sha256_matches_rfc4231() {
        assert_eq!(
            hmac(Algorithm::Sha256, &[0x0b; 20], b"Hi There"),
            hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        assert_eq!(
            hmac(Algorithm::Sha256, b"Jefe", b"what do ya want for nothing?"),
            hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn hmac_sha512_matches_rfc4231() {
        assert_eq!(
            hmac(Algorithm::Sha512, &[0x0b; 20], b"Hi There"),
            hex!(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
            )
        );
        assert_eq!(
            hmac(Algorithm::Sha512, b"Jefe", b"what do ya want for nothing?"),
            hex!(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            )
        );
    }

    // RFC 4226 section 5.4 worked example.
    #[test]
    fn dynamic_truncate_matches_rfc4226_example() {
        let mac = hex!("1f8698690e02ca16618550ef7f19da8e945b555a");
        assert_eq!(dynamic_truncate(&mac), hex!("50ef7f19"));
        assert_eq!(format_code(6, dynamic_truncate(&mac)), "872921");
    }

    #[test]
    #[should_panic]
    fn dynamic_truncate_panics_on_short_mac() {
        dynamic_truncate(&[0x0f; 19]);
    }

    #[test]
    fn format_code_handles_6_and_8_digits() {
        // 0x075BCD15 = 123456789
        assert_eq!(format_code(6, hex!("075bcd15")), "456789");
        assert_eq!(format_code(8, hex!("075bcd15")), "23456789");
    }

    #[test]
    fn format_code_zero_pads() {
        // 0x000003E8 = 1000
        assert_eq!(format_code(6, hex!("000003e8")), "001000");
        assert_eq!(format_code(8, [0; 4]), "00000000");
    }

    #[test]
    fn format_code_masks_top_bit() {
        // 0x80000001 masked to 1.
        assert_eq!(format_code(6, hex!("80000001")), "000001");
    }

    // RFC 6238 appendix B, through HMAC -> dynamic truncation -> format.
    #[test]
    fn rfc6238_vectors_through_truncation_path() {
        let sha1_seed = b"12345678901234567890";
        let sha256_seed = b"12345678901234567890123456789012";
        let sha512_seed = b"1234567890123456789012345678901234567890123456789012345678901234";
        let rows: [(u64, [&str; 3]); 6] = [
            (59, ["94287082", "46119246", "90693936"]),
            (1111111109, ["07081804", "68084774", "25091201"]),
            (1111111111, ["14050471", "67062674", "99943326"]),
            (1234567890, ["89005924", "91819424", "93441116"]),
            (2000000000, ["69279037", "90698825", "38618901"]),
            (20000000000, ["65353130", "77737706", "47863826"]),
        ];
        let algs: [(Algorithm, &[u8]); 3] = [
            (Algorithm::Sha1, sha1_seed),
            (Algorithm::Sha256, sha256_seed),
            (Algorithm::Sha512, sha512_seed),
        ];
        for (time, expected) in rows {
            let step = timestep(time, period(30)).to_be_bytes();
            for ((alg, seed), want) in algs.iter().zip(expected) {
                let mac = hmac(*alg, seed, &step);
                let code = format_code(8, dynamic_truncate(&mac));
                assert_eq!(code, want, "{alg:?} at t={time}");
            }
        }
    }

    #[test]
    fn timestep_at_30s_boundaries() {
        assert_eq!(timestep(0, period(30)), 0);
        assert_eq!(timestep(29, period(30)), 0);
        assert_eq!(timestep(30, period(30)), 1);
        assert_eq!(timestep(59, period(30)), 1);
        assert_eq!(timestep(60, period(30)), 2);
    }

    #[test]
    fn timestep_at_60s_boundaries() {
        assert_eq!(timestep(29, period(60)), 0);
        assert_eq!(timestep(30, period(60)), 0);
        assert_eq!(timestep(59, period(60)), 0);
        assert_eq!(timestep(60, period(60)), 1);
    }

    #[test]
    fn validity_window_brackets_the_current_period() {
        assert_eq!(validity_window(29, period(30)), (0, 30));
        assert_eq!(validity_window(30, period(30)), (30, 60));
        assert_eq!(validity_window(59, period(60)), (0, 60));
        assert_eq!(
            validity_window(1759752005, period(30)),
            (1759752000, 1759752030)
        );
    }

    #[test]
    fn constant_time_eq_compares_contents() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    #[test]
    fn constant_time_eq_is_false_for_different_lengths() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
    }
}
