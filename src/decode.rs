use std::fmt::{self, Display};
use std::str::FromStr;

use super::{convert_bits, expand_prefix, polymod};
use super::{HashType, Payload};

const SIZE_MASK: u8 = 0x07;
const TYPE_MASK: u8 = 0x78;

type Result<T> = std::result::Result<T, Error>;

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
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid character encountered during decoding
    InvalidChar(char),
    /// Invalid input length
    InvalidLength(usize),
    /// Checksum failed during decoding. Inner value is the value of checksum computed by
    /// polymod(expanded prefix + paylaod), Note this is different from the encoded checksum which
    /// is just the last 8 characters (40 bits) of the payload
    ChecksumFailed(u64),
    /// Invalid Version byte encountered during decoding
    InvalidVersion(u8),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChar(c) => write!(f, "Invalid Character `{c}` encountered during decode."),
            Self::InvalidLength(len) => write!(f, "Invalid hash length detected: {}", len),
            Self::ChecksumFailed(cs) => write!(f, "Checksum failed validation: {}", cs),
            Self::InvalidVersion(vbit) => write!(f, "Invalid version byte detected {:X}", vbit),
        }
    }
}

impl std::error::Error for Error {}

impl FromStr for Payload {
    type Err = Error;

    fn from_str(addr_str: &str) -> Result<Self> {
        // Fail fast on empty strings
        if addr_str.is_empty() {
            return Err(Error::InvalidLength(0));
        }

        let (prefix, payload_str) = addr_str
            .split_once(":")
            .unwrap_or(("bitcoincash", addr_str));

        // Decode payload to 5 bit array
        let payload_5_bits: Vec<u8> = payload_str
            .chars()
            .map(|c| match CHARSET_REV.get(c as usize) {
                Some(Some(d)) => Ok(*d as u8),
                _ => Err(Error::InvalidChar(c)),
            })
            .collect::<Result<_>>()?;

        // Verify the checksum
        let checksum = polymod(&[&expand_prefix(prefix), &payload_5_bits[..]].concat());
        if checksum != 0 {
            return Err(Error::ChecksumFailed(checksum));
        }
        let checksum: u64 = payload_5_bits
            .iter()
            .rev()
            .take(8)
            .enumerate()
            .map(|(i, &val)| (val as u64) << (5 * i))
            .sum();

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
            0x00 if body_len != 20 => Err(Error::InvalidLength(body_len)),
            0x01 if body_len != 24 => Err(Error::InvalidLength(body_len)),
            0x02 if body_len != 28 => Err(Error::InvalidLength(body_len)),
            0x03 if body_len != 32 => Err(Error::InvalidLength(body_len)),
            0x04 if body_len != 40 => Err(Error::InvalidLength(body_len)),
            0x05 if body_len != 48 => Err(Error::InvalidLength(body_len)),
            0x06 if body_len != 56 => Err(Error::InvalidLength(body_len)),
            0x07 if body_len != 64 => Err(Error::InvalidLength(body_len)),
            _ => Ok(()),
        }?;

        // Extract the hash type and return
        let version_type = version & TYPE_MASK;
        let hash_type = HashType::try_from(version_type >> 3)?;

        Ok(Payload {
            payload: body.to_vec(),
            hash_type,
            checksum,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    use crate::test_vectors::{TestCase, TEST_VECTORS};

    #[test]
    fn decode() {
        for tc in TEST_VECTORS
            .lines()
            .map(|s| TestCase::try_from(s).expect("Failed to parse test vector"))
        {
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
            Err(Error::ChecksumFailed(_)) => (),
            Err(e) => panic!("Expected ChecksumFailed but found {e:?}"),
            Ok(_) => panic!(
                "Payload successfully parsed from cashaddr with invalid checksum. cashaddr was {}",
                cashaddr,
            ),
        }
    }
    #[test]
    fn invalid_char() {
        match "bitcoincash:qr6m7j9njlbWWzlg9v7v53unlr4JKmx6Eylep8ekg2".parse::<Payload>() {
            Err(Error::InvalidChar('b')) => (),
            Err(e) => panic!("Failed to detect invalid char, instead detected {:?}", e),
            Ok(_) => panic!("Failed to detect invalid char"),
        }
    }
}
