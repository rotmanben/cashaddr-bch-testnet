#![doc = include_str!("../README.md")]
//! # Usage
//! ## Encoding
//! Encoding a sequence of bytes into a cashaddr string is acheived via the [`CashEnc`] trait. This
//! trait's methods are used to encode the bytes sequence, and is implemented for all types which
//! implement [`AsRef<[u8]>`]
//! ```
//! use cashaddr::CashEnc;
//! let payload = b"\xf5\xbfH\xb3\x97\xda\xe7\x0b\xe8+<\xcaG\x93\xf8\xeb+l\xda\xc9";
//!
//! // encode the payload bytes as a p2sh cashaddr, using "bchtest" as the prefix
//! let cashaddr = "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t";
//! assert_eq!(payload.encode_p2sh("bchtest").unwrap(), cashaddr);
//!
//! // encode the payload bytes as a p2pkh cashaddr, using "bitcoincash" as the prefix
//! let cashaddr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
//! assert_eq!(payload.encode_p2pkh("bitcoincash").unwrap(), cashaddr);
//!
//! // arbitrary prefixes are supported
//! let cashaddr = "foobar:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eyde268tla";
//! assert_eq!(payload.encode_p2pkh("foobar").unwrap(), cashaddr);
//! ```
//!
//! Incorrect payload length is detected and captured during encoding
//! ```
//! use cashaddr::{CashEnc, EncodeError};
//! let payload = b"\xf5\xbfH\xb3\x97\xda\xe7\x0b\xe8+<\xcaG\x93\xf8\xeb+l\xda\xc9t";
//! match payload.encode_p2pkh("someprefix") {
//!     Err(EncodeError::IncorrectPayloadLen(21)) => (), // pass
//!     Err(EncodeError::IncorrectPayloadLen(_)) => panic!(
//!         "Detected incorrect payload length, but failed to capture the correct actual input len"
//!     ),
//!     Err(e) => panic!("Detected unexpected error {}", e),
//!     Ok(_) => panic!("Failed to detect incorrect payload length"),
//! }
//! ```
//!
//! ## Decoding
//! Decoding a cashaddr `str` to a binary payload is acheived via the [`Payload`] type which
//! encapsulates the payload itself and the detected hash type. Parsing is provided by the
//! [`FromStr`] trait
//!
//! ```
//! use cashaddr::{Payload, HashType, DecodeError};
//!
//! let EXPECTED_PAYLOAD = b"\xf5\xbfH\xb3\x97\xda\xe7\x0b\xe8+<\xcaG\x93\xf8\xeb+l\xda\xc9";
//!
//! // Use parse() to decode a P2PKH cashaddr string to a `Payload`
//! let cashaddr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
//! let payload: Payload = cashaddr.parse().unwrap();
//! assert_eq!(payload.as_ref(), EXPECTED_PAYLOAD);
//! assert_eq!(payload.hash_type(), HashType::P2PKH);
//!
//! // Use parse() to decode a P2SH cashaddr string to a `Payload`
//! let cashaddr = "bitcoincash:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyguug74nh";
//! let payload: Payload = cashaddr.parse().unwrap();
//! assert_eq!(payload.as_ref(), EXPECTED_PAYLOAD);
//! assert_eq!(payload.hash_type(), HashType::P2SH);
//!
//! // arbitrary prefix are supported in decoding
//! let cashaddr = "foobar:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eyde268tla";
//! let payload: Payload = cashaddr.parse().unwrap();
//! assert_eq!(payload.as_ref(), EXPECTED_PAYLOAD);
//! assert_eq!(payload.hash_type(), HashType::P2PKH);
//!
//! // Decoding is canse insensitive in the second part of the cashaddr
//! let cashaddr = "foobar:qr6M7j9NJLdwwzLG9v7v53UNlr4jkmX6eyDe268tla";
//! let payload: Payload = cashaddr.parse().unwrap();
//! assert_eq!(payload.as_ref(), EXPECTED_PAYLOAD);
//! assert_eq!(payload.hash_type(), HashType::P2PKH);
//!
//! // Decoding checks that the checksum is valid
//! // This char was changed to "8" -------↓
//! let cashaddr = "foobar:qr6M7j9NJLdwwzLG8v7v53UNlr4jkmX6eyDe268tla";
//! match cashaddr.parse::<Payload>() {
//!     Err(DecodeError::ChecksumFailed(_)) => (),
//!     _ => panic!("Failed to detect corrupt cashaddr checksum"),
//! }
//! ```


use std::fmt;
#[allow(unused_imports)]
use std::str::FromStr;

mod decode;
pub use decode::*;
mod encode;
pub use encode::*;

/// The cashaddr character set for encoding
pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// The set of allowed hash lengths for cashaddr encoding.
pub const ALLOWED_LENGTHS: [usize;8] = [20, 24, 28, 32, 40, 48, 56, 64];

// https://github.com/Bitcoin-ABC/bitcoin-abc/blob/2804a49bfc0764ba02ce2999809c52b3b9bb501e/src/cashaddr.cpp#L42
fn polymod(v: &[u8]) -> u64 {
    let mut c: u64 = 1;
    for d in v.iter() {
        let c0: u8 = (c >> 35) as u8;
        c = ((c & 0x0007_FFFF_FFFF) << 5) ^ u64::from(*d);
        if c0 & 0x01 != 0 { c ^= 0x0098_F2BC_8E61; }
        if c0 & 0x02 != 0 { c ^= 0x0079_B76D_99E2; }
        if c0 & 0x04 != 0 { c ^= 0x00F3_3E5F_B3C4; }
        if c0 & 0x08 != 0 { c ^= 0x00AE_2EAB_E2A8; }
        if c0 & 0x10 != 0 { c ^= 0x001E_4F43_E470; }
    }
    c ^ 1
}

// Expand the address prefix for the checksum operation.
fn expand_prefix(prefix: &str) -> Vec<u8> {
    let mut ret: Vec<u8> = prefix.chars().map(|c| (c as u8) & 0x1f).collect();
    ret.push(0);
    ret
}

fn convert_bits(data: &[u8], inbits: u8, outbits: u8, pad: bool) -> Vec<u8> {
    assert!(inbits <= 8 && outbits <= 8);
    let num_bytes = (data.len() * inbits as usize + outbits as usize - 1) / outbits as usize;
    let mut ret = Vec::with_capacity(num_bytes);
    let mut acc: u16 = 0; // accumulator of bits
    let mut num: u8 = 0;  // num bits in acc
    let groupmask = (1 << outbits) - 1;
    for d in data.iter() {
        // We push each input chunk into a 16-bit accumulator
        acc = (acc << inbits) | u16::from(*d);
        num += inbits;
        // Then we extract all the output groups we can
        while num > outbits {
            ret.push((acc >> (num - outbits)) as u8);
            acc &= !(groupmask << (num - outbits));
            num -= outbits;
        }
    }
    if pad {
        // If there's some bits left, pad and add it
        if num > 0 {
            ret.push((acc << (outbits - num)) as u8);
        }
    } else {
        // If there's some bits left, figure out if we need to remove padding and add it
        let padding = (data.len() * inbits as usize) % outbits as usize;
        if num as usize > padding {
            ret.push((acc >> padding) as u8);
        }
    }
    ret
}

/// Type of hash payload. Currently, either
/// [P2PKH](https://en.bitcoinwiki.org/wiki/Pay-to-Pubkey_Hash) or
/// [P2SH](https://en.bitcoinwiki.org/wiki/Pay-to-Script_Hash), but in the furture more variants
/// may be added if they are standardized by Bitcoin Cash developers.
#[non_exhaustive]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum HashType {
    P2PKH,
    P2SH,
    /// Custom HashType value for explicitly specifying the type bits. Type bits must be less than
    /// 16. Currently there is no standard for type bits semantics other than `0x00` for P2PKH and
    /// `0x01` for P2SH, but this variant allows using other values.
    Custom(u8),
}

impl From<HashType> for u8 {
    fn from(ht: HashType) -> Self {
        match ht {
            HashType::P2PKH => 0x00,
            HashType::P2SH => 0x01,
            HashType::Custom(x) => x,
        }
    }
}

impl TryFrom<u8> for HashType {
    type Error = DecodeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::P2PKH),
            0x01 => Ok(Self::P2SH),
            x if x <= 15 => Ok(Self::Custom(x)),
            _ => Err(DecodeError::InvalidVersion(value)),
        }
    }
}

/// Representation of a parsed cashaddr payload (i.e. the hash) and a hash type.
///
/// This type deliberately has private fields to guarantee that it can only be instantiated by
/// parseing a valid cashaddr str. As such, all `Payload` instances represent a deserialized,
/// valid, cashaddr.
///
///
/// ## Decoding
/// This type provides the main interface for decoding cashaddr strings via the [`FromStr`] trait.
/// ```
/// use cashaddr::{Payload, HashType};
///
/// // Parse a cashaddr `str` as a Payload using trait FromStr
/// let payload: Payload = "foobar:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eyde268tla".parse().unwrap();
///
/// // The payload exposes the hash (via AsRef, or payload())
/// assert_eq!(payload.as_ref(),  b"\xf5\xbfH\xb3\x97\xda\xe7\x0b\xe8+<\xcaG\x93\xf8\xeb+l\xda\xc9");
/// assert_eq!(payload.payload(), b"\xf5\xbfH\xb3\x97\xda\xe7\x0b\xe8+<\xcaG\x93\xf8\xeb+l\xda\xc9");
/// // the payload exposes the hash type via hashtype
/// assert_eq!(payload.hash_type(), HashType::P2PKH);
/// ```
///
/// ## Encoding
/// `Payload` supports encoding back to a cashaddr string via the [`fmt::Display`], and [`CashEnc`]
/// traits, as well as the [`Payload::to_string_no_prefix`] method.
///
/// ```
/// use cashaddr::{Payload, HashType, CashEnc};
/// let payload: Payload = "foobar:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eyde268tla".parse().unwrap();
///
/// // For convenience, `Payload` imlements `trait Display` for encoding the payload using the
/// // "bitcoincash" prefix, which is the standard prefix for the Bitcoin Cash mainnet:
/// assert_eq!(payload.to_string(), "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2");
///
/// // For convenience, `Payload` provides to_string_no_prefix method which, which does the same
/// // but omits the prefix, as is common as most application imply the "bitcoincash" prefix if it
/// // is absent
/// assert_eq!(payload.to_string_no_prefix(), "qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2");
///
/// // Because `Payload` implements `AsRef<[u8]>`, it also implements CashEnc so it can easily be
/// // encoded back into a cashaddr string
/// assert_eq!(
///     payload.encode_p2pkh("foobar").unwrap(),
///     "foobar:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eyde268tla"
/// );
/// ```
#[derive(Debug, PartialEq)]
pub struct Payload {
    /// payload bytes
    payload: Vec<u8>,
    /// hash type of the payload
    hash_type: HashType,
}

impl Payload {
    /// get a reference to the raw bytes comprising the payload
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Get the HashType
    pub fn hash_type(&self) -> HashType {
        self.hash_type
    }
}

impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] { &self.payload }
}

#[cfg(test)]
mod test_vectors;

#[cfg(test)]
mod round_trip {
    use super::{Payload, HashType, CashEnc};
    use hex_literal::hex;

    #[derive(Debug)]
    pub struct TestCase {
        pub hashtype: HashType,
        pub prefix: &'static str,
        pub payload: &'static [u8],
        pub cashaddr: &'static str,
    }

    pub static TEST_VECTORS: [TestCase; 32] = [
        TestCase {
            hashtype: HashType::P2PKH,
            prefix: "bitcoincash",
            payload: &hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
            cashaddr: "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "bchtest",
            payload: &hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
            cashaddr: "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "pref",
            payload: &hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
            cashaddr: "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5",
        },
        TestCase {
            hashtype: HashType::Custom(15),
            prefix: "prefix",
            payload: &hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
            cashaddr: "prefix:0r6m7j9njldwwzlg9v7v53unlr4jkmx6ey3qnjwsrf",
        },
        TestCase {
            hashtype: HashType::P2PKH,
            prefix: "bitcoincash",
            payload: &hex!("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"),
            cashaddr: "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "bchtest",
            payload: &hex!("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"),
            cashaddr: "bchtest:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2u94tsynr",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "pref",
            payload: &hex!("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"),
            cashaddr: "pref:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2khlwwk5v",
        },
        TestCase {
            hashtype: HashType::Custom(15),
            prefix: "prefix",
            payload: &hex!("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"),
            cashaddr: "prefix:09adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2p29kc2lp",
        },
        TestCase {
            hashtype: HashType::P2PKH,
            prefix: "bitcoincash",
            payload: &hex!("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"),
            cashaddr: "bitcoincash:qgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcw59jxxuz",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "bchtest",
            payload: &hex!("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"),
            cashaddr: "bchtest:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcvs7md7wt",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "pref",
            payload: &hex!("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"),
            cashaddr: "pref:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcrsr6gzkn",
        },
        TestCase {
            hashtype: HashType::Custom(15),
            prefix: "prefix",
            payload: &hex!("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"),
            cashaddr: "prefix:0gagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkc5djw8s9g",
        },
        TestCase {
            hashtype: HashType::P2PKH,
            prefix: "bitcoincash",
            payload: &hex!("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"),
            cashaddr: "bitcoincash:qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "bchtest",
            payload: &hex!("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"),
            cashaddr: "bchtest:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "pref",
            payload: &hex!("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"),
            cashaddr: "pref:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq4k9m7qf9",
        },
        TestCase {
            hashtype: HashType::Custom(15),
            prefix: "prefix",
            payload: &hex!("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"),
            cashaddr: "prefix:0vch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxqsh6jgp6w",
        },
        TestCase {
            hashtype: HashType::P2PKH,
            prefix: "bitcoincash",
            payload: &hex!("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"),
            cashaddr: "bitcoincash:qnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv39gr3uvz",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "bchtest",
            payload: &hex!("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"),
            cashaddr: "bchtest:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvmgm6ynej",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "pref",
            payload: &hex!("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"),
            cashaddr: "pref:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv0vx5z0w3",
        },
        TestCase {
            hashtype: HashType::Custom(15),
            prefix: "prefix",
            payload: &hex!("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"),
            cashaddr: "prefix:0nq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvwsvctzqy",
        },
        TestCase {
            hashtype: HashType::P2PKH,
            prefix: "bitcoincash",
            payload: &hex!("E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"),
            cashaddr: "bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "bchtest",
            payload: &hex!("E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"),
            cashaddr: "bchtest:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqnzf7mt6x",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "pref",
            payload: &hex!("E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"),
            cashaddr: "pref:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqjntdfcwg",
        },
        TestCase {
            hashtype: HashType::Custom(15),
            prefix: "prefix",
            payload: &hex!("E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"),
            cashaddr: "prefix:0h3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqakcssnmn",
        },
        TestCase {
            hashtype: HashType::P2PKH,
            prefix: "bitcoincash",
            payload: &hex!(
                "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C3407
                 7638E4DD1A701BD017842789982041"
            ),
            cashaddr: "bitcoincash:qmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57j\
                       uxsrhvw8ym5d8qx7sz7zz0zvcypqscw8jd03f",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "bchtest",
            payload: &hex!(
                "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C3407
                 7638E4DD1A701BD017842789982041"
            ),
            cashaddr: "bchtest:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsr\
                       hvw8ym5d8qx7sz7zz0zvcypqs6kgdsg2g",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "pref",
            payload: &hex!(
                "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C3407
                 7638E4DD1A701BD017842789982041"
            ),
            cashaddr: "pref:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw\
                       8ym5d8qx7sz7zz0zvcypqsammyqffl",
        },
        TestCase {
            hashtype: HashType::Custom(15),
            prefix: "prefix",
            payload: &hex!(
                "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C3407
                 7638E4DD1A701BD017842789982041"
            ),
            cashaddr: "prefix:0mvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrh\
                       vw8ym5d8qx7sz7zz0zvcypqsgjrqpnw8",
        },
        TestCase {
            hashtype: HashType::P2PKH,
            prefix: "bitcoincash",
            payload: &hex!(
                "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA
                 89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"
            ),
            cashaddr: "bitcoincash:qlg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46h\
                       udk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mtky5sv5w",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "bchtest",
            payload: &hex!(
                "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA
                 89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"
            ),
            cashaddr: "bchtest:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk\
                       5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mc773cwez",
        },
        TestCase {
            hashtype: HashType::P2SH,
            prefix: "pref",
            payload: &hex!(
                "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA
                 89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"
            ),
            cashaddr: "pref:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flt\
                       tj6ydvjc0pv3nchp52amk97tqa5zygg96mg7pj3lh8",
        },
        TestCase {
            hashtype: HashType::Custom(15),
            prefix: "prefix",
            payload: &hex!(
                "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA8
                 9FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"
            ),
            cashaddr: "prefix:0lg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5f\
                       lttj6ydvjc0pv3nchp52amk97tqa5zygg96ms92w6845",
        },
    ];

    #[test]
    fn forward() {
        use super::test_vectors::{TEST_VECTORS, TestCase};
        for testcase in super::test_vectors::TEST_VECTORS.lines().map(TestCase::from) {
            let payload: Payload = testcase.cashaddr.parse().unwrap();
            let recon = payload.encode(testcase.prefix, testcase.hashtype).expect("Encoding Failed");
            assert_eq!(testcase.cashaddr, recon);
        }
    }
    #[test]
    fn backward() {
        for testcase in TEST_VECTORS.iter() {
            let payload = Payload {
                payload: testcase.payload.iter().cloned().collect(),
                hash_type: testcase.hashtype,
            };
            let cashaddr = payload.to_string();
            let recon = cashaddr.parse().unwrap();
            assert_eq!(payload, recon);
        }
    }
}
