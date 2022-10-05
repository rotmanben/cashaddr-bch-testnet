use std::str::FromStr;

use super::HashType;
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

/// Representation of a parsed cashaddr payload.
///
/// This type provides the main interface for decoding cashaddr strings via the [`FromStr`] trait.
#[derive(Debug, PartialEq)]
pub struct Payload {
    /// payload bytes
    pub payload: Vec<u8>,
    /// hash type of the payload
    pub hash_type: HashType,
}

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

impl FromStr for Payload {
    type Err = DecodeError;

    fn from_str(addr_str: &str) -> Result<Self, DecodeError> {
        // Fail fast on empty strings
        if addr_str.is_empty() {
            return Err(DecodeError::InvalidLength(0));
        }

        let parts: Vec<&str> = addr_str.split(':').collect();
        if parts.len() != 2 {
            // TODO handle this case
            panic!("TODO, handle this case")
        }
        let prefix = parts[0];
        let payload_str = parts[1];

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
        let hash_type = HashType::try_from(version_type)?;

        Ok(Payload {
            payload: body.to_vec(),
            hash_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keyhash_20_main() {
        let cashaddr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        let addr: Payload = cashaddr.parse().unwrap();
        let payload = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        assert_eq!(payload, addr.payload);
    }
}
