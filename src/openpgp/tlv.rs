//! The BER-TLV subset used by OpenPGP card data objects.
//!
//! Tags are one byte, or two when the low five bits of the first byte are
//! all set (`5F50`, `7F49`). Lengths are as in [`crate::oath::tlv`]. A tag
//! whose first byte has bit `0x20` set is constructed: its value is itself a
//! sequence of TLVs.

use crate::oath::tlv::TlvError;

/// A parsed TLV borrowing its value from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u16,
    pub value: &'a [u8],
}

/// Encode one TLV and append it to `out`.
///
/// # Panics
///
/// If `value` is longer than 65535 bytes, which no OpenPGP card command
/// needs.
pub fn encode(out: &mut Vec<u8>, tag: u16, value: &[u8]) {
    match u8::try_from(tag) {
        Ok(short) => out.push(short),
        Err(_) => out.extend_from_slice(&tag.to_be_bytes()),
    }
    let len = value.len();
    match len {
        0..=0x7F => out.push(len as u8),
        0x80..=0xFF => out.extend_from_slice(&[0x81, len as u8]),
        0x100..=0xFFFF => {
            out.push(0x82);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => panic!("TLV value too long: {len} bytes"),
    }
    out.extend_from_slice(value);
}

/// Parse one TLV from the start of `input`, returning it and the rest.
pub fn parse(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), TlvError> {
    let (&first, rest) = input.split_first().ok_or(TlvError::Truncated)?;
    let (tag, rest) = if first & 0x1F == 0x1F {
        let (&second, rest) = rest.split_first().ok_or(TlvError::Truncated)?;
        (u16::from_be_bytes([first, second]), rest)
    } else {
        (u16::from(first), rest)
    };
    let (&len_byte, rest) = rest.split_first().ok_or(TlvError::Truncated)?;
    let (len, rest) = match len_byte {
        0x00..=0x7F => (usize::from(len_byte), rest),
        0x81 => {
            let (&b, rest) = rest.split_first().ok_or(TlvError::Truncated)?;
            (usize::from(b), rest)
        }
        0x82 => {
            let (bytes, rest) = rest.split_first_chunk::<2>().ok_or(TlvError::Truncated)?;
            (usize::from(u16::from_be_bytes(*bytes)), rest)
        }
        other => return Err(TlvError::BadLength(other)),
    };
    if rest.len() < len {
        return Err(TlvError::Truncated);
    }
    let (value, rest) = rest.split_at(len);
    Ok((Tlv { tag, value }, rest))
}

/// Parse a sequence of TLVs that must cover `input` exactly.
pub fn parse_all(mut input: &[u8]) -> Result<Vec<Tlv<'_>>, TlvError> {
    let mut out = Vec::new();
    while !input.is_empty() {
        let (tlv, rest) = parse(input)?;
        out.push(tlv);
        input = rest;
    }
    Ok(out)
}

/// Whether `tag` holds nested TLVs.
pub fn is_constructed(tag: u16) -> bool {
    let first = if tag > 0xFF {
        (tag >> 8) as u8
    } else {
        tag as u8
    };
    first & 0x20 != 0
}

/// The value of the first `tag` in `input`, searching depth first into
/// constructed TLVs. `None` if there is none.
pub fn find(input: &[u8], tag: u16) -> Result<Option<&[u8]>, TlvError> {
    for item in parse_all(input)? {
        if item.tag == tag {
            return Ok(Some(item.value));
        }
        if is_constructed(item.tag)
            && let Some(found) = find(item.value, tag)?
        {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn encoded(tag: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode(&mut out, tag, value);
        out
    }

    #[test]
    fn encodes_one_and_two_byte_tags() {
        assert_eq!(encoded(0x86, &[1, 2]), hex!("86020102"));
        assert_eq!(encoded(0x7F49, &[1]), hex!("7f490101"));
    }

    #[test]
    fn encodes_long_lengths() {
        assert_eq!(encoded(0x81, &[0; 200])[..3], [0x81, 0x81, 200]);
        assert_eq!(encoded(0x81, &[0; 256])[..4], [0x81, 0x82, 0x01, 0x00]);
    }

    #[test]
    #[should_panic(expected = "too long")]
    fn encode_panics_above_65535_bytes() {
        encoded(0x81, &vec![0; 65536]);
    }

    #[test]
    fn parses_two_byte_tag() {
        let (tlv, rest) = parse(&hex!("5f50020102ff")).unwrap();
        assert_eq!(
            tlv,
            Tlv {
                tag: 0x5F50,
                value: &[1, 2]
            }
        );
        assert_eq!(rest, [0xFF]);
    }

    #[test]
    fn parses_long_lengths() {
        let mut input = vec![0xC5, 0x81, 0x80];
        input.extend_from_slice(&[7; 0x80]);
        assert_eq!(parse(&input).unwrap().0.value.len(), 0x80);

        let mut input = vec![0x81, 0x82, 0x01, 0x00];
        input.extend_from_slice(&[7; 0x100]);
        assert_eq!(parse(&input).unwrap().0.value.len(), 0x100);
    }

    #[test]
    fn rejects_truncated_input() {
        for input in [
            &[][..],
            &[0x5F],
            &[0x5F, 0x50],
            &[0xC4],
            &[0xC4, 0x81],
            &[0xC4, 0x82, 0x01],
            &[0xC4, 0x02, 0x01],
        ] {
            assert_eq!(parse(input), Err(TlvError::Truncated), "{input:02x?}");
        }
    }

    #[test]
    fn rejects_unsupported_length_byte() {
        assert_eq!(parse(&[0xC4, 0x83]), Err(TlvError::BadLength(0x83)));
    }

    #[test]
    fn constructed_tags_are_recognised() {
        for tag in [0x6E, 0x73, 0x7A, 0x7F49, 0x65, 0xA6] {
            assert!(is_constructed(tag), "{tag:#x}");
        }
        for tag in [0x4F, 0x5F52, 0xC4, 0xC5, 0x81, 0x86, 0x93] {
            assert!(!is_constructed(tag), "{tag:#x}");
        }
    }

    #[test]
    fn find_searches_into_constructed_values_only() {
        // 6E { 4F 01 AA, 73 { C4 02 0102 } }, then a primitive C0 whose
        // value happens to look like a C4 TLV.
        let input = hex!("6e09 4f01aa 7304 c4020102 c004 c4020909");
        assert_eq!(find(&input, 0xC4).unwrap(), Some(&[1, 2][..]));
        assert_eq!(find(&input, 0x4F).unwrap(), Some(&[0xAA][..]));
        assert_eq!(find(&input, 0xC5).unwrap(), None);
        assert_eq!(find(&hex!("c004c4020909"), 0xC4).unwrap(), None);
    }

    #[test]
    fn find_reports_malformed_input() {
        assert_eq!(find(&hex!("6e05c402"), 0xC4), Err(TlvError::Truncated));
    }
}
