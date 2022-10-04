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

/// Representation of a parsed string
#[derive(Debug)]
pub struct Address<'a> {
    pub payload: Vec<u8>,
    pub hash_type: HashType,
    pub prefix: &'a str,
}

/// Error type describing something that went wrong during decoding a cashaddr string.
#[derive(Debug)]
pub enum DecodeError {
    InvalidChar(char),
    InvalidLength(usize),
    ChecksumFailed(u64),
    InvalidVersion(u8),
}

pub trait CashDec: AsRef<str> {
    fn decode(&self) -> Result<Address, DecodeError> {
        let addr_str = self.as_ref();
        let parts: Vec<&str> = addr_str.split(':').collect();
        if parts.len() != 2 {
            // TODO handle this case
            panic!("TODO, handle this case")
        }
        let prefix = parts[0];
        let payload_str = parts[1];


        if addr_str.len() == 0 {
            return Err(DecodeError::InvalidLength(0));
        }
        //
        // Decode payload to 5 bit array
        let payload_chars = payload_str.chars(); // Reintialize iterator here
        let payload_5_bits: Result<Vec<u8>, DecodeError> = payload_chars
            .map(|c| {
                let i = c as usize;
                if let Some(Some(d)) = CHARSET_REV.get(i) {
                    Ok(*d as u8)
                } else {
                    Err(DecodeError::InvalidChar(c))
                }
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
        if (version_size == 0x00 && body_len != 20)
            || (version_size == 0x01 && body_len != 24)
            || (version_size == 0x02 && body_len != 28)
            || (version_size == 0x03 && body_len != 32)
            || (version_size == 0x04 && body_len != 40)
            || (version_size == 0x05 && body_len != 48)
            || (version_size == 0x06 && body_len != 56)
            || (version_size == 0x07 && body_len != 64)
        {
            return Err(DecodeError::InvalidLength(body_len));
        }

        // Extract the hash type and return
        let version_type = version & TYPE_MASK;
        let hash_type = if version_type == HashType::P2PKH as u8 {
            HashType::P2PKH
        } else if version_type == HashType::P2SH as u8 {
            HashType::P2SH
        } else {
            return Err(DecodeError::InvalidVersion(version));
        };

        Ok(Address {
            payload: body.to_vec(),
            hash_type,
            prefix,
        })
    }
}

impl<T: AsRef<str>> CashDec for T {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keyhash_20_main() {
        let cashaddr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        let addr = cashaddr.decode().unwrap();
        let payload = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        assert_eq!(payload, addr.payload);
    }
}
