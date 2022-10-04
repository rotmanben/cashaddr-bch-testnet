//! Implements
//! [cashaddr](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md)
//! encoding for arbitrary borrowed sequences of `u8`. The main use of this crate is via the
//! [`CashEnc`] trait which provides and implementation for encoding any borrowed sequence of `u8`
//! into a cashaddr string with arbirary prefix.
//!
//! # Examples
//! ```
//! use hex;
//! use cashaddr::{CashEnc, HashType};
//! let payload: Vec<u8> = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
//!
//! // encode the payload bytes as a p2sh cashaddr, using "bchtest" as the prefix
//! let cashaddr = "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t";
//! assert_eq!(payload.encode_p2sh("bchtest").unwrap(), cashaddr);
//!
//! // encode the payload bytes as a p2pkh cashaddr, using "bitcoincash" as the prefix
//! let cashaddr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
//! assert_eq!(payload.encode_p2pkh("bitcoincash").unwrap(), cashaddr);
//! ```
//!
//! ## Attribution
//! Most of this code was forked from
//! [`bitcoincash-addr`](https://docs.rs/bitcoincash-addr/latest/bitcoincash_addr/). This library
//! was created to both provide a more convenient user interface, as well as support arbitrary
//! prefixes.


use std::fmt;

mod decode;
pub use decode::*;
mod encode;
pub use encode::*;

/// The cashaddr character set for encoding
pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// The set of allowed hash lenghts for cashaddr encoding.
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

/// Type of hash payload. Either [P2PKH](https://en.bitcoinwiki.org/wiki/Pay-to-Pubkey_Hash) or 
/// [P2SH](https://en.bitcoinwiki.org/wiki/Pay-to-Script_Hash)
#[derive(Debug, PartialEq)]
pub enum HashType {
    P2PKH = 0x00,
    P2SH = 0x08,
}

impl TryFrom<u8> for HashType {
    type Error = DecodeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::P2PKH),
            0x08 => Ok(Self::P2SH),
            _ => Err(DecodeError::InvalidVersion(value)),
        }
    }
}
