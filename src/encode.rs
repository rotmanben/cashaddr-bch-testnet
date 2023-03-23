use super::*;

/// Error type describing something that went wrong during enoding a sequence of `u8` into a
/// cashaddr String
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Incorrect payload length. Contained value describes the length of the sequence of `u8`
    IncorrectPayloadLen(usize),
    InvalidHashType(u8),
}

type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncorrectPayloadLen(len) => write!(
                f,
                "Incorrect input length. Expected one of {:?}, got {}",
                ALLOWED_LENGTHS, len
            ),
            Self::InvalidHashType(x) => write!(
                f,
                "Invalid Custom HashType. Hashtype value must be on 0..16, but found {}",
                x
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Encode a hash as a cashaddr string.
///
/// # Usage
/// This trait provides the main encoding interface of the crate. It is implemented for `[u8]`
/// which allows encoding a sequence of arbitrary bytes as a cashaddr string. The main method for
/// this trait is [`CashEnc::encode`], which allows callers to encode input data as a cashaddr
/// using a custom human-readable prefix and a custom hash type.
///
/// ```
/// use cashaddr::{CashEnc, HashType};
/// use hex_literal::hex;
///
/// // Arbitrary payload bytes to encode as cashaddr string. Must be one of the allowed length
/// let payload: [u8; 20] = hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9");
///
/// // encode the payload bytes as a p2sh cashaddr, using "bchtest" as the human-readable prefix
/// assert_eq!(
///     payload.encode("bchtest", HashType::P2SH).as_deref(),
///     Ok("bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t")
/// );
///
/// // encode the payload bytes as a nonstandard hashtype using "foobar"  as the human-readable
/// // prefix
/// assert_eq!(
///     payload.encode("foobar", HashType::try_from(9)?).as_deref(),
///     Ok("foobar:fr6m7j9njldwwzlg9v7v53unlr4jkmx6eyxafk3sr7")
/// );
///
/// // provided methods provide a simpler interface for encoding P2PKH and P2SH cashaddr string
/// // without the need for HashType
/// assert_eq!(
///     payload.encode_p2sh("foo").as_deref(),
///     Ok("foo:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey0vepygtg")
/// );
/// # Ok::<(), cashaddr::DecodeError>(())
/// ```
///
/// The cashaddr codec only support encoding binary payload of specific lenghts, given by
/// [`ALLOWED_LENGTHS`]. Attempting to encode a byte sequence whose length is not one of these
/// allowed lengths results in an `Err` variant.
/// ```
/// use cashaddr::{CashEnc, EncodeError};
/// use hex_literal::hex;
///
/// // The cashaddr codec does not support 21-byte hashes/inputs, so an Err varient is returned
/// let payload: [u8; 21] = hex!("D5B307F0380BCCE6399DCD3987A0F4C2BC8E558FFD");
/// assert_eq!(payload.encode_p2pkh("someprefix"), Err(EncodeError::IncorrectPayloadLen(21)));
/// ```
pub trait CashEnc {
    /// Encode self into cashaddr using `prefix` as the arbirtrary prefix and `hashtype` as the
    /// Hash type.
    fn encode(&self, prefix: &str, hash_type: HashType) -> Result<String>;

    /// Conveninence method for encoding as P2PKH hash type
    fn encode_p2pkh(&self, prefix: &str) -> Result<String> {
        self.encode(prefix, HashType::P2PKH)
    }
    /// Conveninence method for encoding as P2SH hash type
    fn encode_p2sh(&self, prefix: &str) -> Result<String> {
        self.encode(prefix, HashType::P2SH)
    }
    /// Format self as a cashaddr string using `"bitcoincash"` as the user-defined prefix when
    /// computing the checksum, but omit it from the output. This is the elided prefix format
    /// commonly used when representing Bitcoin Cash mainnet addresses
    fn elided_prefix(&self, hash_type: HashType) -> Result<String> {
        let mut s = self.encode("bitcoincash", hash_type)?;
        s.replace_range(..12, "");
        Ok(s)
    }
}

/// `CashEnc` is implemented for `[u8]` where the data is the hash digest to be encoded. In this
/// case, the input bytes must have a length of 20, 24, 28, 32, 40, 48, 56, or 64, otherwise an
/// [`EncodeError`] describing the lenth of the input is returned.
impl CashEnc for [u8] {
    fn encode(&self, prefix: &str, hash_type: HashType) -> Result<String> {
        // Return an error if the HashType is out of range. This should be impossible because it is
        // intended that it is impossible to construct a `HashType` instance with an out-of-range
        // value.
        if hash_type.0 > 15 {
            return Err(Error::InvalidHashType(hash_type.0));
        }
        let payload = self.as_ref();
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
            _ => return Err(Error::IncorrectPayloadLen(len)),
        } | (hash_type.0 << 3);

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
}

impl fmt::Display for Payload {
    /// Format the payload as a cashaddr using `"bitcoincash"` as the user-defined prefix but omit
    /// it from the output. This is equivalent to [`CashEnc::elided_prefix`], except that it uses
    /// the hash type from the Payload instead of a passed in argument.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // encode result is safely unwrapped here because `Payload` instances can only be
        // constructed with valid payload fields because `Payload` uses private fields and
        // therefore can only be constructed via methods which guarantee valid Payloads
        let string = self.payload.elided_prefix(self.hash_type).unwrap();
        f.pad(&string)
    }
}

impl Payload {
    /// Format the payload as a cashaddr using human-readable prefix `hrp`
    pub fn with_prefix(&self, hrp: &str) -> String {
        // Safe to unwrap here because `Payload` constructors guarantee validity
        self.payload.encode(hrp, self.hash_type).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{CashEnc, Error, HashType, Payload};
    use crate::test_vectors::{TestCase, TEST_VECTORS};
    use hex_literal::hex;

    #[test]
    fn with_prefix() {
        for tc in TEST_VECTORS
            .lines()
            .map(|s| TestCase::try_from(s).expect("Failed to parse test vector"))
        {
            let (hrp, _) = tc
                .cashaddr
                .split_once(':')
                .expect("Could not extract hrp from test vector");
            let pl: Payload = tc
                .cashaddr
                .parse()
                .expect("Could not decode test vector cashaddr");
            assert_eq!(pl.payload, tc.pl);
            assert_eq!(pl.with_prefix(hrp), tc.cashaddr);
        }
    }
    #[test]
    fn cashenc() {
        for testcase in TEST_VECTORS
            .lines()
            .map(|s| TestCase::try_from(s).expect("Failed to parse test vector"))
        {
            let cashaddr = testcase
                .pl
                .encode(testcase.prefix, testcase.hashtype)
                .unwrap();
            assert_eq!(cashaddr, testcase.cashaddr);
        }
    }
    #[test]
    fn payload_to_string() {
        let cashaddr = "qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        let payload: Payload = cashaddr
            .parse()
            .expect("Couldn't parse cashaddr. Check test impl");
        // Just Check to make sure the the correct payload was parsed
        assert_eq!(
            payload.as_ref(),
            hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9")
        );
        assert_eq!(payload.to_string(), cashaddr);
    }
    #[test]
    fn encode_p2pkh() {
        for testcase in TEST_VECTORS.lines().filter_map(|s| {
            let tc = TestCase::try_from(s).expect("Failed to parse test vector");
            match tc.hashtype {
                HashType::P2PKH => Some(tc),
                _ => None,
            }
        }) {
            let cashaddr = testcase
                .pl
                .encode_p2pkh(testcase.prefix)
                .expect("Failed to parse testvector");
            assert_eq!(cashaddr, testcase.cashaddr);
        }
    }
    #[test]
    fn encode_p2sh() {
        for testcase in TEST_VECTORS.lines().filter_map(|s| {
            let tc = TestCase::try_from(s).expect("Failed to parse test vector");
            match tc.hashtype {
                HashType::P2SH => Some(tc),
                _ => None,
            }
        }) {
            let cashaddr = testcase
                .pl
                .encode_p2sh(testcase.prefix)
                .expect("Failed to parse testvector");
            assert_eq!(cashaddr, testcase.cashaddr);
        }
    }
    #[test]
    fn bad_custom_hashtype() {
        let payload = hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9");
        match payload.encode("pref", HashType(0xAA)) {
            Err(Error::InvalidHashType(0xAA)) => (), // pass
            Err(e) => panic!("Detected unexpected error: {:?}", e),
            Ok(_) => panic!("failed to detect invalid custom hash type"),
        }
    }
    #[test]
    fn incorrect_payload_len() {
        let payload = hex!("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA94");
        match payload.encode("someprefix", HashType::P2PKH) {
            Err(Error::IncorrectPayloadLen(len)) => assert_eq!(len, 25),
            Err(e) => panic!("Detected an unexpected error: {}", e),
            Ok(_) => panic!("Failed to detect incorrect payload length for encoding"),
        }
    }
}
