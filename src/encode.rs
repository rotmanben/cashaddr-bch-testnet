use super::*;

/// Error type describing something that went wrong during enoding a sequence of `u8` into a
/// cashaddr String
#[derive(Debug)]
pub enum EncodeError {
    /// Incorrect payload length. Contained value describes the length of the sequence of `u8`
    IncorrectPayloadLen(usize),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncorrectPayloadLen(len) => write!(
                f, "Incorrect input length. Expected one of {:?}, got {}",
                ALLOWED_LENGTHS, len
            )
        }
    }
}

impl std::error::Error for EncodeError {}

fn enc(payload: &[u8], prefix: &str, raw_hashtype: u8) -> Result<String, EncodeError> {
    let len = payload.len();
    let version_byte = match len {
        20 => 0x00,
        24 => 0x01,
        28 => 0x02,
        32 => 0x03,
        40 => 0x04,
        48 => 0x05,
        56 => 0x06,
        64 => 0x07,
        _ => return Err(EncodeError::IncorrectPayloadLen(len))
    } | (raw_hashtype << 3);

    let mut pl_buf = Vec::with_capacity(len + 1);
    pl_buf.push(version_byte);
    pl_buf.extend(payload);
    let pl_5bit = convert_bits(&pl_buf, 8, 5, true);

    // Construct payload string using CHARSET
    let payload_str: String = pl_5bit
        .iter()
        .map(|b| CHARSET[*b as usize] as char)
        .collect();

    // Create checksum
    let expanded_prefix = expand_prefix(prefix);
    let checksum_input = [&expanded_prefix[..], &pl_5bit, &[0; 8]].concat();
    let checksum = polymod(&checksum_input);

    // Convert checksum to string
    let checksum_str: String = (0..8)
        .rev()
        .map(|i| CHARSET[((checksum >> (i * 5)) & 31) as usize] as char)
        .collect();

    // Concatentate all parts
    let cashaddr = [prefix, ":", &payload_str, &checksum_str].concat();
    Ok(cashaddr)
}

/// Encode a sequence of bytes (`u8`) as a cashaddr string. This trait is implemented for all types
/// implementing `AsRef<[u8]>` where the reference value is a slice of `u8` representing the hash
/// payload bytes.
pub trait CashEnc : AsRef<[u8]> {
    /// Encode self into cashaddr using `prefix` as the arbirtrary prefix and `hashtype` as the
    /// Hash type. `self` must have length of 20, 24, 28, 32, 40, 48, 56, or 64, otherwise and
    /// [`EncodeError`] is returned describing the lenth of the payload passed in.
    fn encode(&self, prefix: &str, hash_type: HashType) -> Result<String, EncodeError> {
        enc(self.as_ref(), prefix, u8::from(hash_type))
    }
    /// Conveninence method for encoding as P2PKH hash type
    fn encode_p2pkh(&self, prefix: &str) -> Result<String, EncodeError> {
        self.encode(prefix, HashType::P2PKH)
    }
    /// Conveninence method for encoding as P2SH hash type
    fn encode_p2sh(&self, prefix: &str) -> Result<String, EncodeError> {
        self.encode(prefix, HashType::P2SH)
    }
}
impl<T: AsRef<[u8]>> CashEnc for T {}

impl fmt::Display for Payload {
    /// Format the payload as as a cashaddr using `"bitcoincash"`, the default prefix for the
    /// bitcoin cash mainnet, as the prefix
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // encode result is safely unwrapped here because `Payload` instances can only be
        // constructed with valud payload fields because `Payload` uses priveate fields and
        // therefore can only be constructed via methods which guarantee valid payloads
        let string = self.payload.encode("bitcoincash", self.hash_type).unwrap();
        f.pad(&string)
    }
}

impl Payload {
    /// Return a cashaddr String for the payload, using `"bitcoincash"` as the prefix, but without
    /// including the prefix in the output.
    pub fn to_string_no_prefix(&self) -> String {
        let mut full = self.to_string();
        if let Some(sep_pos) = full.find(':') {
            full.replace_range(..sep_pos + 1, "");
        }
        full
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::{CashEnc, HashType, Payload};
    use crate::round_trip::TEST_VECTORS;


    #[test]
    fn cashenc() {
        for testcase in TEST_VECTORS.iter() {
            let cashaddr = testcase.payload.encode(testcase.prefix, testcase.hashtype).unwrap();
            assert_eq!(cashaddr, testcase.cashaddr);
        }
    }
    #[test]
    fn payload_to_string() {
        let cashaddr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        let payload: Payload = cashaddr.parse().expect("Couldn't parse cashaddr. Check test impl");
        // Just Check to make sure the the correct payload was parsed
        assert_eq!(payload.as_ref(), hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"));
        assert_eq!(payload.to_string(), cashaddr);
    }
    #[test]
    fn payload_to_str_no_prefix() {
        let cashaddr = "qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        let payload: Payload = cashaddr.parse().expect("Couldn't parse cashaddr. Check test impl");
        assert_eq!(payload.as_ref(), hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"));
        assert_eq!(payload.to_string_no_prefix(), cashaddr);
    }
    #[test]
    fn encode_p2pkh() {
        for testcase in TEST_VECTORS.iter().filter(|x| x.hashtype == HashType::P2PKH) {
            let cashaddr = testcase.payload.encode_p2pkh(testcase.prefix)
                .expect("Failed to parse testvector");
            assert_eq!(cashaddr, testcase.cashaddr);
        }
    }
    #[test]
    fn encode_p2sh() {
        for testcase in TEST_VECTORS.iter().filter(|x| x.hashtype == HashType::P2SH) {
            let cashaddr = testcase.payload.encode_p2sh(testcase.prefix)
                .expect("Failed to parse testvector");
            assert_eq!(cashaddr, testcase.cashaddr);
        }
    }
}
