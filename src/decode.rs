use std::str::FromStr;
use std::fmt::{self, Display};
use std::error::Error;

use super::{HashType, Payload};
use super::{convert_bits, polymod, expand_prefix};

const SIZE_MASK: u8 = 0x07;
const TYPE_MASK: u8 = 0x78;

// The cashaddr character set for decoding
#[rustfmt::skip]
const CHARSET_REV: [Option<u8>; 128] = [
    None,     None,     None,     None,     None,     None,     None,     None,
    None,     None,     None,     None,     None,     None,     None,     None,
    None,     None,     None,     None,     None,     None,     None,     None,
    None,     None,     None,     None,     None,     None,     None,     None,
    None,     None,     None,     None,     None,     None,     None,     None,
    None,     None,     None,     None,     None,     None,     None,     None,
    Some(15), None,     Some(10), Some(17), Some(21), Some(20), Some(26), Some(30),
    Some(7),  Some(5),  None,     None,     None,     None,     None,     None,
    None,     Some(29), None,     Some(24), Some(13), Some(25), Some(9),  Some(8),
    Some(23), None,     Some(18), Some(22), Some(31), Some(27), Some(19), None,
    Some(1),  Some(0),  Some(3),  Some(16), Some(11), Some(28), Some(12), Some(14),
    Some(6),  Some(4),  Some(2),  None,     None,     None,     None,     None,
    None,     Some(29),  None,    Some(24), Some(13), Some(25), Some(9),  Some(8),
    Some(23), None,     Some(18), Some(22), Some(31), Some(27), Some(19), None,
    Some(1),  Some(0),  Some(3),  Some(16), Some(11), Some(28), Some(12), Some(14),
    Some(6),  Some(4),  Some(2),  None,     None,     None,     None,     None,
];


/// Error type describing something that went wrong during decoding a cashaddr string.
#[derive(Debug)]
pub enum DecodeError {
    /// Invalid character encountered during decoding
    InvalidChar(char),
    /// Invalid input length
    InvalidLength(usize),
    /// Failed Checksum
    ChecksumFailed(u64),
    /// Invalid Version byte encountered during decoding
    InvalidVersion(u8),
}

impl Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChar(c) => write!(f, "Invalid Character `{c}` encountered during decode."),
            Self::InvalidLength(len) => write!(f, "Invalid hash length detected: {}", len),
            Self::ChecksumFailed(cs) => write!(f, "Checksum failed validation: {}", cs),
            Self::InvalidVersion(vbit) => write!(f, "Invalid version byte detected {:X}", vbit),
        }
    }
}

impl Error for DecodeError {}


impl FromStr for Payload {
    type Err = DecodeError;

    fn from_str(addr_str: &str) -> Result<Self, DecodeError> {
        // Fail fast on empty strings
        if addr_str.is_empty() {
            return Err(DecodeError::InvalidLength(0));
        }

        let (prefix, payload_str) = match addr_str.split_once(":") {
            Some(x) => x,
            None => ("bitcoincash", addr_str),
        };

        // Decode payload to 5 bit array
        let payload_chars = payload_str.chars(); // Reintialize iterator here
        let payload_5_bits: Result<Vec<u8>, DecodeError> = payload_chars
            .map(|c| match CHARSET_REV.get(c as usize) {
                Some(Some(d)) => Ok(*d as u8),
                _ => Err(DecodeError::InvalidChar(c))
            })
            .collect();
        let payload_5_bits = payload_5_bits?;

        // Verify the checksum
        let checksum = polymod(&[&expand_prefix(prefix), &payload_5_bits[..]].concat());
        if checksum != 0 {
            return Err(DecodeError::ChecksumFailed(checksum));
        }

        // Convert from 5 bit array to byte array
        let len_5_bit = payload_5_bits.len();
        let payload = convert_bits(&payload_5_bits[..(len_5_bit - 8)], 5, 8, false);

        // Verify the version byte
        let version = payload[0];

        // Check length
        let body = &payload[1..];
        let body_len = body.len();
        let version_size = version & SIZE_MASK;

        match version_size {
            0x00 if body_len != 20 => Err(DecodeError::InvalidLength(body_len)),
            0x01 if body_len != 24 => Err(DecodeError::InvalidLength(body_len)),
            0x02 if body_len != 28 => Err(DecodeError::InvalidLength(body_len)),
            0x03 if body_len != 32 => Err(DecodeError::InvalidLength(body_len)),
            0x04 if body_len != 40 => Err(DecodeError::InvalidLength(body_len)),
            0x05 if body_len != 48 => Err(DecodeError::InvalidLength(body_len)),
            0x06 if body_len != 56 => Err(DecodeError::InvalidLength(body_len)),
            0x07 if body_len != 64 => Err(DecodeError::InvalidLength(body_len)),
            _ => Ok(())
        }?;

        // Extract the hash type and return
        let version_type = version & TYPE_MASK;
        let hash_type = HashType::try_from(version_type >> 3)?;

        Ok(Payload {
            payload: body.to_vec(),
            hash_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::*;

    use crate::test_vectors::{TEST_VECTORS, TestCase};

    #[test]
    fn decode() {
        for tc in TEST_VECTORS.lines().map(|s| TestCase::try_from(s).expect("Failed to parse test vector")) {
            let payload: Payload = tc.cashaddr.parse().expect("could not parse");
            assert_eq!(payload.payload, tc.pl, "Incorrect payload parsed");
            assert_eq!(payload.hash_type, tc.hashtype, "Incorrect Hash Type parsed")
        }
    }
    #[test]
    fn case_insensitive() {
        let cashaddr = "bitcoincash:qr6m7j9njldWWzlg9v7v53unlr4JKmx6Eylep8ekg2";
        let addr: Payload = cashaddr.parse().unwrap();
        let payload = hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9");
        assert_eq!(payload, addr.payload.as_ref());
        assert_eq!(HashType::P2PKH, addr.hash_type);
    }
    #[test]
    fn checksum() {
        let cashaddr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr3jkmx6eylep8ekg2";
        match cashaddr.parse::<Payload>() {
            Err(DecodeError::ChecksumFailed(_)) => (),
            Err(e) => panic!("Expected ChecksumFailed but found {e:?}"),
            Ok(_) => panic!(
                "Payload successfully parsed from cashaddr with invalid checksum. cashaddr was {}",
                cashaddr,
            ),
        }
    }
    #[test]
    fn invalid_char() {
        match  "bitcoincash:qr6m7j9njlbWWzlg9v7v53unlr4JKmx6Eylep8ekg2".parse::<Payload>() {
            Err(DecodeError::InvalidChar('b')) => (),
            Err(e) => panic!("Failed to detect invalid char, instead detected {:?}", e),
            Ok(_) => panic!("Failed to detect invalid char"),
        }
    }
}
