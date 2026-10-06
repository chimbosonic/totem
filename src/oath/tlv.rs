//! The simple TLV encoding used by YKOATH.
//!
//! Each item is a one-byte tag, a length, then the value. Lengths below
//! `0x80` are one byte. Longer lengths are `0x81 LL` (up to 255) or
//! `0x82 HH LL` (up to 65535).

/// A parsed TLV borrowing its value from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TlvError {
    #[error("TLV input ended early")]
    Truncated,
    #[error("unsupported TLV length byte {0:#04x}")]
    BadLength(u8),
    #[error("{0} unexpected bytes after TLV")]
    TrailingBytes(usize),
}

/// Encode one TLV and append it to `out`.
///
/// # Panics
///
/// If `value` is longer than 65535 bytes. YKOATH values are at most a few
/// dozen bytes, so this is a programming error.
pub fn encode(_out: &mut Vec<u8>, _tag: u8, _value: &[u8]) {}

/// Parse one TLV from the start of `input`, returning it and the remaining bytes.
pub fn parse(_input: &[u8]) -> Result<(Tlv<'_>, &[u8]), TlvError> {
    Err(TlvError::Truncated)
}

/// Parse exactly one TLV. Any bytes after it are an error.
pub fn parse_exact(_input: &[u8]) -> Result<Tlv<'_>, TlvError> {
    Err(TlvError::Truncated)
}

/// Parse a sequence of TLVs that must cover `input` exactly.
pub fn parse_all(_input: &[u8]) -> Result<Vec<Tlv<'_>>, TlvError> {
    Err(TlvError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode(&mut out, tag, value);
        out
    }

    #[test]
    fn encodes_short_value_with_single_length_byte() {
        assert_eq!(encoded(0x74, &[1, 2, 3]), [0x74, 0x03, 1, 2, 3]);
    }

    #[test]
    fn encodes_empty_value() {
        assert_eq!(encoded(0x71, &[]), [0x71, 0x00]);
    }

    #[test]
    fn encodes_127_bytes_with_single_length_byte() {
        let out = encoded(0x71, &[0xAA; 127]);
        assert_eq!(out[..2], [0x71, 0x7F]);
        assert_eq!(out.len(), 2 + 127);
    }

    #[test]
    fn encodes_128_to_255_bytes_with_0x81_prefix() {
        let out = encoded(0x71, &[0xAA; 128]);
        assert_eq!(out[..3], [0x71, 0x81, 0x80]);
        assert_eq!(out.len(), 3 + 128);

        let out = encoded(0x71, &[0xAA; 255]);
        assert_eq!(out[..3], [0x71, 0x81, 0xFF]);
    }

    #[test]
    fn encodes_256_bytes_and_up_with_0x82_prefix() {
        let out = encoded(0x71, &[0xAA; 256]);
        assert_eq!(out[..4], [0x71, 0x82, 0x01, 0x00]);
        assert_eq!(out.len(), 4 + 256);
    }

    #[test]
    #[should_panic(expected = "too long")]
    fn encode_panics_above_65535_bytes() {
        encoded(0x71, &vec![0; 65536]);
    }

    #[test]
    fn encode_appends_to_existing_buffer() {
        let mut out = vec![0x00, 0xA4];
        encode(&mut out, 0x74, &[9]);
        assert_eq!(out, [0x00, 0xA4, 0x74, 0x01, 9]);
    }

    #[test]
    fn parses_single_byte_length() {
        let input = [0x79, 0x03, 1, 2, 3];
        let (tlv, rest) = parse(&input).unwrap();
        assert_eq!(
            tlv,
            Tlv {
                tag: 0x79,
                value: &[1, 2, 3]
            }
        );
        assert!(rest.is_empty());
    }

    #[test]
    fn parses_0x81_and_0x82_lengths() {
        for len in [0, 1, 127, 128, 255, 256, 1000] {
            let value: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let bytes = encoded(0x75, &value);
            assert_eq!(
                parse_exact(&bytes).unwrap(),
                Tlv {
                    tag: 0x75,
                    value: &value
                },
                "length {len}"
            );
        }
    }

    #[test]
    fn parses_non_minimal_long_length() {
        // 0x81 0x02 is a valid, if wasteful, way to say "2".
        let input = [0x71, 0x81, 0x02, 7, 8];
        assert_eq!(
            parse_exact(&input).unwrap(),
            Tlv {
                tag: 0x71,
                value: &[7, 8]
            }
        );
    }

    #[test]
    fn parse_returns_remaining_bytes() {
        let input = [0x71, 0x01, 0xAA, 0x76, 0x00];
        let (tlv, rest) = parse(&input).unwrap();
        assert_eq!(
            tlv,
            Tlv {
                tag: 0x71,
                value: &[0xAA]
            }
        );
        assert_eq!(rest, [0x76, 0x00]);
    }

    #[test]
    fn parses_a_sequence_in_order() {
        let mut input = Vec::new();
        encode(&mut input, 0x71, b"one");
        encode(&mut input, 0x76, &[6, 0, 0, 0, 1]);
        encode(&mut input, 0x71, b"two");
        encode(&mut input, 0x7C, &[]);

        let tlvs = parse_all(&input).unwrap();
        let tags: Vec<u8> = tlvs.iter().map(|t| t.tag).collect();
        assert_eq!(tags, [0x71, 0x76, 0x71, 0x7C]);
        assert_eq!(tlvs[0].value, b"one");
        assert_eq!(tlvs[2].value, b"two");
        assert!(tlvs[3].value.is_empty());
    }

    #[test]
    fn parse_all_of_empty_input_is_empty() {
        assert_eq!(parse_all(&[]).unwrap(), vec![]);
    }

    #[test]
    fn rejects_truncated_input() {
        // Missing everything, missing length, value shorter than length.
        assert_eq!(parse(&[]), Err(TlvError::Truncated));
        assert_eq!(parse(&[0x71]), Err(TlvError::Truncated));
        assert_eq!(parse(&[0x71, 0x03, 1, 2]), Err(TlvError::Truncated));
        // Long-form length bytes missing.
        assert_eq!(parse(&[0x71, 0x81]), Err(TlvError::Truncated));
        assert_eq!(parse(&[0x71, 0x82, 0x01]), Err(TlvError::Truncated));
        // Long-form length exceeds remaining bytes.
        assert_eq!(parse(&[0x71, 0x81, 0x80, 0]), Err(TlvError::Truncated));
    }

    #[test]
    fn parse_all_rejects_truncated_last_item() {
        let input = [0x71, 0x01, 0xAA, 0x76, 0x05, 1];
        assert_eq!(parse_all(&input), Err(TlvError::Truncated));
    }

    #[test]
    fn rejects_unsupported_length_bytes() {
        assert_eq!(parse(&[0x71, 0x80]), Err(TlvError::BadLength(0x80)));
        assert_eq!(
            parse(&[0x71, 0x83, 0, 0, 1, 0]),
            Err(TlvError::BadLength(0x83))
        );
        assert_eq!(parse(&[0x71, 0xFF]), Err(TlvError::BadLength(0xFF)));
    }

    #[test]
    fn strict_parse_rejects_trailing_garbage() {
        let input = [0x71, 0x01, 0xAA, 0xDE, 0xAD];
        assert_eq!(parse_exact(&input), Err(TlvError::TrailingBytes(2)));
    }

    #[test]
    fn lenient_parse_ignores_trailing_garbage() {
        let input = [0x71, 0x01, 0xAA, 0xDE, 0xAD];
        let (tlv, rest) = parse(&input).unwrap();
        assert_eq!(tlv.value, [0xAA]);
        assert_eq!(rest, [0xDE, 0xAD]);
    }
}
