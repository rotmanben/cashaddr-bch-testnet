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

/// Encode any `AsRef<[u8]>` into a cashaddr string
pub trait CashEnc : AsRef<[u8]> {
    /// Encode self into cashaddr using `prefix` as the arbirtrary prefix and `hashtype` as the
    /// Hash type. `self` must have length of 20, 24, 28, 32, 40, 48, 56, or 64, otherwise and
    /// [`EncodeError`] is returned describing the lenth of the payload passed in.
    fn encode(&self, prefix: &str, hash_type: HashType) -> Result<String, EncodeError> {
        let hashflag = hash_type as u8;
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
            _ => return Err(EncodeError::IncorrectPayloadLen(len))
        } | hashflag;
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

#[cfg(test)]
mod tests {
    use super::{HashType, CashEnc};
    #[test]
    fn keyhash_20_main() {
        let payload = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let cashaddr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        assert_eq!(payload.encode("bitcoincash", HashType::P2PKH).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_20_bchtest() {
        let payload = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let cashaddr = "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t";
        assert_eq!(payload.encode("bchtest", HashType::P2SH).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_20_prefix() {
        let payload = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let cashaddr = "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5";
        assert_eq!(payload.encode("pref", HashType::P2SH).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_24() {
        let cashaddr = "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0";
        let payload = "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA";
        let payload = hex::decode(payload).unwrap();
        assert_eq!( payload.encode("bitcoincash", HashType::P2PKH).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_32() {
        let cashaddr = "bchtest:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6";
        let payload = hex::decode("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060").unwrap();
        assert_eq!( payload.encode("bchtest", HashType::P2SH).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_40_pref() {
        let cashaddr = "pref:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv0vx5z0w3";
        let payload = hex::decode("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB")
            .unwrap();
        assert_eq!( payload.encode("pref", HashType::P2SH).unwrap(), cashaddr);
    }
    #[test]
    fn keyhash_40() {
        let cashaddr =  "bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl";
        let payload = hex::decode("E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C")
            .unwrap();
        assert_eq!( payload.encode("bitcoincash", HashType::P2PKH).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_40_bchtest() {
        let cashaddr =  "bchtest:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvmgm6ynej";
        let payload = hex::decode("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB")
            .unwrap();
        assert_eq!( payload.encode("bchtest", HashType::P2SH).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_56() {
        let cashaddr =  "pref:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsammyqffl";
        let payload = hex::decode("D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041")
            .unwrap();
        assert_eq!( payload.encode("pref", HashType::P2SH).unwrap(), cashaddr);
    }
}
