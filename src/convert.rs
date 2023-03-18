//! Module for converting between Legacy Bitcoin addresses and Cashaddr addresses.
use super::{CashEnc, Payload, HashType};

/// Errors arising in the convertion of a legacy Bitcoin address to cashaddr format
#[derive(Debug, PartialEq, Eq)]
pub enum L2CError {
    /// Decoding the Legacy the Bitcoin Address failed
    DecodeError(bs58::decode::Error),
    /// Encoding the cashaddr failed
    EncodeError(super::EncodeError),
}

/// Convert a legacy Bitcoin address to cashaddr format
pub fn from_legacy(s: &str) -> Result<String, L2CError> {
    let bytes = bs58::decode(s)
        .with_check(None)
        .into_vec()
        .map_err(|x| L2CError::DecodeError(x))?;
    let payload = &bytes[1..];
    match bytes[0] {
        0x00 => payload.encode_p2pkh("bitcoincash"),
        0x05 => payload.encode_p2sh("bitcoincash"),
        x => Err(super::EncodeError::InvalidHashType(x))
    }
        .map_err(|x| L2CError::EncodeError(x))
}

/// Errors arising in the conversion of a cashaddr to a legacy Bitcoin address
#[derive(Debug, PartialEq, Eq)]
pub enum C2LError {
    /// Error occurred during decoding cashaddr string
    DecodeError(super::DecodeError),
    /// Decoded cashaddr had a hash type not suitable for conversion to legacy Bitcoin format. Only
    /// `HashType::P2PKH` and `HashType::P2SH` are supported 
    InvalidVersionByte(u8),
}

/// Convert a cashaddr string to a Legacy Bitcoin address
pub fn to_legacy(s: &str) -> Result<String, C2LError> {
    let payload: Payload = s.parse().map_err(|x| C2LError::DecodeError(x))?;
    let vbyte = match payload.hash_type {
        HashType::P2PKH => 0x00,
        HashType::P2SH => 0x05,
        _ => return Err(C2LError::InvalidVersionByte(payload.hash_type.numeric_value()))
    };
    let mut payload = payload.payload;
    payload.insert(0, vbyte);
    Ok(bs58::encode(payload).with_check().into_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn from_legacy() {
        assert_eq!(
            super::from_legacy("1PrAtnrgtx3eZoDLfxWp54KGgX2uXrDdWe").as_deref(),
            Ok("bitcoincash:qraf76zhtyuaawjgystnsunzgeflef24zc27hn3sn7")
        );
    }
    #[test]
    fn to_legacy() {
        assert_eq!(
            super::to_legacy("bitcoincash:qraf76zhtyuaawjgystnsunzgeflef24zc27hn3sn7").as_deref(),
            Ok("1PrAtnrgtx3eZoDLfxWp54KGgX2uXrDdWe")
        );
    }
}
