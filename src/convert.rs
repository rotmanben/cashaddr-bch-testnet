//! Module for converting between Legacy Bitcoin addresses and Cashaddr addresses.
use super::{CashEnc, HashType, Payload};

/// Errors arising in the convertion of a legacy Bitcoin address to cashaddr format
#[derive(Debug, PartialEq, Eq)]
pub enum L2CError {
    /// Decoding the Legacy the Bitcoin Address failed
    DecodeError(bs58::decode::Error),
    /// Encoding the cashaddr failed
    EncodeError(super::EncodeError),
}

impl From<bs58::decode::Error> for L2CError {
    fn from(bs58_err: bs58::decode::Error) -> Self {
        Self::DecodeError(bs58_err)
    }
}

impl From<super::EncodeError> for L2CError {
    fn from(encode_err: super::EncodeError) -> Self {
        Self::EncodeError(encode_err)
    }
}

/// Convert a legacy Bitcoin address to cashaddr format
///
/// Decode string `legacy_addr` as a Legacy Bitcoin P2PKH or P2SH address and re-encode the
/// resulting hash payload as a cashaddr string using the approriate `HashType` and `hrp`
/// as the human-readable prefix.
pub fn from_legacy(legacy_addr: &str, hrp: &str) -> Result<String, L2CError> {
    let bytes = bs58::decode(legacy_addr).with_check(None).into_vec()?;
    let payload = &bytes[1..];
    Ok(match bytes[0] {
        0x00 => payload.encode_p2pkh(hrp),
        0x05 => payload.encode_p2sh(hrp),
        x => Err(super::EncodeError::InvalidHashType(x)),
    }?)
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
///
/// cashaddr string `cashaddr` is decoded and its hash payload is interpreted as either a
/// PubkeyHash or a ScriptHash depending on its hash type. This hash is then encoded as a Legacy
/// Bitcoin P2PKH address or a P2SH address, using the appropriate standard version byte matching
/// the cashaddr's hash type. `cashaddr` must have a hash type of either `HashType::P2PKH` or
/// `HashType::P2SH` as these are the only two hash types supported by the legacy Bitcoin address
/// formats.
///
/// If decoding `cashaddr` fails, return a [`C2LError::DecodeError`]. If `cashaddr` decodes
/// successfully but has an unsupported hash type, return a [`C2LError::InvalidVersionByte`].
/// Otherwise, the legacy address string is returned.
pub fn to_legacy(cashaddr: &str) -> Result<String, C2LError> {
    let payload: Payload = cashaddr.parse()?;
    let vbyte = match payload.hash_type {
        HashType::P2PKH => 0x00,
        HashType::P2SH => 0x05,
        _ => {
            let n = payload.hash_type.numeric_value();
            return Err(C2LError::InvalidVersionByte(n));
        }
    };
    let mut payload = payload.payload;
    payload.insert(0, vbyte);
    Ok(bs58::encode(payload).with_check().into_string())
}

impl From<super::DecodeError> for C2LError {
    fn from(decode_error: super::DecodeError) -> Self {
        C2LError::DecodeError(decode_error)
    }
}

#[cfg(test)]
mod tests {
    #[rustfmt::skip]
    const TEST_VECTORS: [(&str, &str); 6]= [
        ("1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"),
        ("1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR", "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy"),
        ("16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb",  "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r"),
        ("3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC", "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq"),
        ("3LDsS579y7sruadqu11beEJoTjdFiFCdX4", "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e"),
        ("31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw", "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37"),
    ];

    #[test]
    fn from_legacy() {
        for tc in TEST_VECTORS {
            assert_eq!(super::from_legacy(tc.0, "bitcoincash").as_deref(), Ok(tc.1));
        }
    }
    #[test]
    fn to_legacy() {
        for tc in TEST_VECTORS {
            assert_eq!(super::to_legacy(tc.1).as_deref(), Ok(tc.0));
        }
    }

    #[test]
    fn round_trip() {
        use super::{from_legacy, to_legacy};
        for tc in TEST_VECTORS {
            let cashaddr = from_legacy(tc.0, "bitcoincash").unwrap();
            assert_eq!(to_legacy(&cashaddr).as_deref(), Ok(tc.0));
            let legacy = to_legacy(tc.1).unwrap();
            assert_eq!(from_legacy(&legacy, "bitcoincash").as_deref(), Ok(tc.1));
        }
    }
}
