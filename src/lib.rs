#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
//! # Usage
//! Encoding hashes as cashaddr strings is implemented by [`CashEnc`] and decoding cashaddr string
//! as hashes is implemented by [`Payload`]. See the documentation for these itmes for details.

use std::fmt;
#[allow(unused_imports)]
use std::str::FromStr;

mod decode;
pub use decode::Error as DecodeError;
mod encode;
pub use encode::{CashEnc, Error as EncodeError};

/// The cashaddr character set for encoding
pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// The set of allowed hash lengths for cashaddr encoding.
pub const ALLOWED_LENGTHS: [usize; 8] = [20, 24, 28, 32, 40, 48, 56, 64];

// https://github.com/Bitcoin-ABC/bitcoin-abc/blob/2804a49bfc0764ba02ce2999809c52b3b9bb501e/src/cashaddr.cpp#L42
#[rustfmt::skip]
fn polymod(v: &[u8]) -> u64 {
    let mut c: u64 = 1;
    for d in v.iter() {
        let c0: u8 = (c >> 35) as u8;
        c = ((c & 0x0007_FFFF_FFFF) << 5) ^ *d as u64;
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
    let mut num: u8 = 0; // num bits in acc
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

/// Type of hash represented by a cashaddr string.
///
/// There are 16 valid hash types allowed in cashaddr, each associated with one of the first 16
/// natural numbers: `0x00`...`0x0F`. Two of them have standardized semantics and are provided as
/// constants on `HashType` for convenience.
///
/// | Numeric Value | Standardized Semantics | Convenience Constant |
/// | ------------- | ---------------------- | -------------------- |
/// | `0x00`        | [P2PKH](https://developer.bitcoin.org/devguide/transactions.html#p2pkh-script-validation) | `HashType::P2PKH`
/// | `0x01`        | [P2SH](https://developer.bitcoin.org/devguide/transactions.html#p2sh-scripts) | `HashType::P2SH`
///
/// <br/>
///
/// The remaining hash types (corresponding to `0x02`...`0x0F`) can be constructed using
/// [`TryFrom<u8>`]. The semantics of these hash hash types is not standardized and interpretation is
/// up to the application using them.
///
/// ```
/// use cashaddr::{HashType, DecodeError};
///
/// // Here are two different ways to construct a `HashType` using the `TryFrom<u8>` trait
/// let hash_type = HashType::try_from(3)?;
/// let hash_type: HashType = 9.try_into()?;
///
/// // Attempting to create a HashType that is out-of-range returns and Err type
/// assert_eq!(HashType::try_from(100), Err(DecodeError::InvalidVersion(100)));
/// # Ok::<(), DecodeError>(())
/// ```
#[derive(Debug, PartialEq, Eq, PartialOrd, Clone, Copy)]
pub struct HashType(u8);

impl HashType {
    /// Hash type for [P2PKH](https://developer.bitcoin.org/devguide/transactions.html#p2pkh-script-validation) addresses
    pub const P2PKH: Self = HashType(0);
    /// Hash type for [P2SH](https://developer.bitcoin.org/devguide/transactions.html#p2sh-scripts) addresses
    pub const P2SH: Self = HashType(1);

    /// The numeric value associated with this hash type
    pub fn numeric_value(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for HashType {
    type Error = DecodeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0..=15 => Ok(HashType(value)),
            _ => Err(DecodeError::InvalidVersion(value)),
        }
    }
}

/// Decoded cashaddr payload
///
/// This type provides the main decoding interface of the crate and encapsulates the decoded hash,
/// the hash type, and the checksum of a decoded cashaddr.
///
/// This type deliberately has private fields to guarantee that it can only be instantiated by
/// parsing a valid cashaddr string. As such, all `Payload` instances represent a deserialized,
/// valid, cashaddr payload.
///
///
/// # Decoding
/// Decoding a cashaddr string to a binary payload is acheived via the [`FromStr`] trait:
/// ```
/// use cashaddr::{Payload, HashType};
/// use hex_literal::hex;
/// # use cashaddr::DecodeError;
///
/// const EXPECTED_HASH: [u8; 20] = hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9");
/// const EXPECTED_CHECKSUM: u64 =  0x6E55A3AFFD;
///
/// // Parse a cashaddr `str` as a Payload using trait FromStr
/// let payload: Payload = "foobar:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eyde268tla".parse()?;
///
/// // Payload can expose the hash via AsRef::as_ref. It also has methods to expose the hash type
/// // and checksum
/// assert_eq!(payload.as_ref(), EXPECTED_HASH);
/// assert_eq!(*payload, EXPECTED_HASH);
/// assert_eq!(payload.checksum(), EXPECTED_CHECKSUM);
/// assert_eq!(payload.hash_type(), HashType::P2PKH);
///
/// // Parsing is case-insensitive over the payload part
/// let payload: Payload = "foobar:qr6M7j9njLDwWzlG9v7V53unLr4JkmX6eyDE268Tla".parse()?;
/// assert_eq!(payload.as_ref(), EXPECTED_HASH);
/// assert_eq!(payload.hash_type(), HashType::P2PKH);
/// assert_eq!(payload.checksum(), EXPECTED_CHECKSUM);
///
/// # Ok::<(), DecodeError>(())
/// ```
/// ### Error Detection
/// Payload provides comprehensive error detection: decoding with `parse` detects and reports all
/// possible invalidities in the input cashaddr string.
/// ```
/// use cashaddr::{DecodeError, Payload};
///
/// // This char was changed to "8" -------------------------------↓
/// let bad_checksum: Result<Payload, _> = "foobar:qr6M7j9NJLdwwzLG8v7v53UNlr4jkmX6eyDe268tla".parse();
/// assert_eq!(bad_checksum, Err(DecodeError::ChecksumFailed(0xD4537E8389)));
///
/// // This one has an illgal char ---------------------↓
/// let illegal_char: Result<Payload, _> =  "foobar:qr6mBj9njldwwzlg9v7v53unlr4jkmx6eyde268tla".parse();
/// assert_eq!(illegal_char, Err(DecodeError::InvalidChar('B')));
///
/// ```
///
///
/// # Encoding
/// `Payload` supports encoding back to a cashaddr string via the [`fmt::Display`] trait,
/// [`Payload::with_prefix`] method:
///
/// ```
/// use cashaddr::{Payload, HashType, CashEnc};
/// let payload: Payload = "foobar:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eyde268tla".parse().unwrap();
///
/// // For convenience, `Payload` imlements `trait Display` for encoding the payload back to a
/// // cashaddr string using the "bitcoincash" as the user-defined prefix, but omitting from the
/// // output. This is known as the "elided prefix" format and is commonly used to represent
/// // bitcoin cash addresses
/// assert_eq!(payload.to_string(), "qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2");
///
/// // Payload::with_prefix can also be used to encode the payload's hash back to a cashaddr string
/// // but with a custom prefix. This can be usedful for changing the prefix of cashaddr while
/// // reusing the same hash and hash type
/// assert_eq!(payload.with_prefix("newpre"), "newpre:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eynzn88urq");
/// ```
///
/// Because `Payload` implements `Deref<Target=[u8]>`, it can easily be used as a [`CashEnc`] via
/// deref coersion, allowing for full control over the prefix and hash type, while reusing only the
/// decoded hash.
/// ```
/// use cashaddr::{Payload, HashType, CashEnc};
/// let payload: Payload = "foobar:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eyde268tla".parse().unwrap();
///
/// assert_eq!(
///     payload.encode_p2pkh("bazquxx").as_deref(),
///     Ok("bazquxx:qr6m7j9njldwwzlg9v7v53unlr4jkmx6ey2r9dy5kd")
/// );
/// ```
#[derive(Debug, PartialEq)]
pub struct Payload {
    /// payload bytes
    payload: Vec<u8>,
    /// hash type of the payload
    hash_type: HashType,
    /// checksum
    checksum: u64,
}

impl Payload {
    /// Get the HashType
    pub fn hash_type(&self) -> HashType {
        self.hash_type
    }
    /// Get the Checksum. This is the last 40 bits of the payload interpreted as a big-endian
    /// number, represented as `u64`
    pub fn checksum(&self) -> u64 {
        self.checksum
    }
}

/// Expose the decoded hash digest of a parsed cashaddr payload
impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.payload
    }
}

impl std::ops::Deref for Payload {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.payload
    }
}

#[cfg(feature = "convert")]
pub mod convert;

#[cfg(test)]
mod test_vectors;

#[cfg(test)]
mod round_trip {
    use super::test_vectors::{TestCase, TEST_VECTORS};
    use super::{CashEnc, Payload};

    #[test]
    fn forward() {
        for testcase in TEST_VECTORS
            .lines()
            .map(|s| TestCase::try_from(s).expect("Failed to parse test vector"))
        {
            let payload: Payload = testcase.cashaddr.parse().unwrap();
            let recon = payload
                .encode(testcase.prefix, testcase.hashtype)
                .expect("Encoding Failed");
            assert_eq!(testcase.cashaddr, recon);
        }
    }
    #[test]
    fn backward() {
        for testcase in TEST_VECTORS
            .lines()
            .map(|s| TestCase::try_from(s).expect("Failed to parse test vector"))
        {
            let payload: Payload = testcase
                .cashaddr
                .parse()
                .expect("Failed to decode testcase");
            let (hrp, _) = testcase.cashaddr.split_once(':').unwrap();
            let cashaddr = payload.with_prefix(hrp);
            let recon = cashaddr.parse().unwrap();
            assert_eq!(payload, recon);
        }
    }
}
