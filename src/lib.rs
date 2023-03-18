#![doc = include_str!("../README.md")]
//! # Usage
//! Encoding hashes as cashaddr strings is implemented by [`CashEnc`] and decoding cashaddr string
//! as hashes is implemented by [`Payload`]. See the documentation for these itmes for details.


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
/// This type provides the main decoding interface of the crate and encapsulates the decoded hash
/// and the hash type.
///
/// This type deliberately has private fields to guarantee that it can only be instantiated by
/// parseing a valid cashaddr str. As such, all `Payload` instances represent a deserialized,
/// valid, cashaddr.
///
///
/// # Decoding
/// Decoding a cashaddr string to a binary payload is acheived via the [`FromStr`] trait:
/// ```
/// use cashaddr::{Payload, HashType};
/// use hex_literal::hex;
/// # use cashaddr::DecodeError;
///
/// // Parse a cashaddr `str` as a Payload using trait FromStr
/// let payload: Payload = "foobar:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eyde268tla".parse()?;
///
/// // Payload can expose the hash via AsRef, or payload()
/// assert_eq!(payload.as_ref(), hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"));
/// assert_eq!(payload.payload(), hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"));
/// // Payload exposes the hash type via the Payload::hashtype method
/// assert_eq!(payload.hash_type(), HashType::P2PKH);
///
/// // Parsing is case insensitive over the payload part
/// let payload: Payload = "foobar:qr6M7j9njLDwWzlG9v7V53unLr4JkmX6eyDE268Tla".parse()?;
/// assert_eq!(payload.as_ref(), hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"));
/// assert_eq!(payload.hash_type(), HashType::P2PKH);
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
/// // Because `Payload` implements `Deref<Target=[u8]>`, it can easily be encoded back into a
/// // cashaddr string via Deref coercion.
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

impl std::ops::Deref for Payload {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.payload
    }
}

#[cfg(test)]
mod test_vectors;

#[cfg(test)]
mod round_trip {
    use super::{Payload, CashEnc};
    use super::test_vectors::{TEST_VECTORS, TestCase};


    #[test]
    fn forward() {
        for testcase in TEST_VECTORS.lines().map(|s| TestCase::try_from(s).expect("Failed to parse test vector")) {
            let payload: Payload = testcase.cashaddr.parse().unwrap();
            let recon = payload.encode(testcase.prefix, testcase.hashtype).expect("Encoding Failed");
            assert_eq!(testcase.cashaddr, recon);
        }
    }
    #[test]
    fn backward() {
        for testcase in TEST_VECTORS.lines().map(|s| TestCase::try_from(s).expect("Failed to parse test vector")) {
            let payload = Payload {
                payload: testcase.pl,
                hash_type: testcase.hashtype,
            };
            let cashaddr = payload.to_string();
            let recon = cashaddr.parse().unwrap();
            assert_eq!(payload, recon);
        }
    }
}
