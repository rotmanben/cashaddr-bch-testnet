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
        enc(self.as_ref(), prefix, hash_type as u8 >> 3)
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
    use super::{HashType, CashEnc, Payload, enc};
    use hex_literal::hex;

    #[derive(Debug)]
    struct TestCase {
        raw_hashtype: u8,
        prefix: &'static str,
        payload: &'static [u8],
        cashaddr: &'static str,
    }

    static TEST_VECTORS: [TestCase; 32] = [
        TestCase {
            raw_hashtype: 0,
            prefix: "bitcoincash",
            payload: &hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
            cashaddr: "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "bchtest",
            payload: &hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
            cashaddr: "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "pref",
            payload: &hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
            cashaddr: "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5",
        },
        TestCase {
            raw_hashtype: 15,
            prefix: "prefix",
            payload: &hex!("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
            cashaddr: "prefix:0r6m7j9njldwwzlg9v7v53unlr4jkmx6ey3qnjwsrf",
        },
        TestCase {
            raw_hashtype: 0,
            prefix: "bitcoincash",
            payload: &hex!("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"),
            cashaddr: "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "bchtest",
            payload: &hex!("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"),
            cashaddr: "bchtest:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2u94tsynr",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "pref",
            payload: &hex!("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"),
            cashaddr: "pref:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2khlwwk5v",
        },
        TestCase {
            raw_hashtype: 15,
            prefix: "prefix",
            payload: &hex!("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"),
            cashaddr: "prefix:09adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2p29kc2lp",
        },
        TestCase {
            raw_hashtype: 0,
            prefix: "bitcoincash",
            payload: &hex!("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"),
            cashaddr: "bitcoincash:qgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcw59jxxuz",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "bchtest",
            payload: &hex!("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"),
            cashaddr: "bchtest:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcvs7md7wt",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "pref",
            payload: &hex!("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"),
            cashaddr: "pref:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcrsr6gzkn",
        },
        TestCase {
            raw_hashtype: 15,
            prefix: "prefix",
            payload: &hex!("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"),
            cashaddr: "prefix:0gagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkc5djw8s9g",
        },
        TestCase {
            raw_hashtype: 0,
            prefix: "bitcoincash",
            payload: &hex!("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"),
            cashaddr: "bitcoincash:qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "bchtest",
            payload: &hex!("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"),
            cashaddr: "bchtest:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "pref",
            payload: &hex!("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"),
            cashaddr: "pref:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq4k9m7qf9",
        },
        TestCase {
            raw_hashtype: 15,
            prefix: "prefix",
            payload: &hex!("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"),
            cashaddr: "prefix:0vch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxqsh6jgp6w",
        },
        TestCase {
            raw_hashtype: 0,
            prefix: "bitcoincash",
            payload: &hex!("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"),
            cashaddr: "bitcoincash:qnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv39gr3uvz",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "bchtest",
            payload: &hex!("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"),
            cashaddr: "bchtest:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvmgm6ynej",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "pref",
            payload: &hex!("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"),
            cashaddr: "pref:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv0vx5z0w3",
        },
        TestCase {
            raw_hashtype: 15,
            prefix: "prefix",
            payload: &hex!("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"),
            cashaddr: "prefix:0nq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvwsvctzqy",
        },
        TestCase {
            raw_hashtype: 0,
            prefix: "bitcoincash",
            payload: &hex!("E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"),
            cashaddr: "bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "bchtest",
            payload: &hex!("E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"),
            cashaddr: "bchtest:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqnzf7mt6x",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "pref",
            payload: &hex!("E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"),
            cashaddr: "pref:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqjntdfcwg",
        },
        TestCase {
            raw_hashtype: 15,
            prefix: "prefix",
            payload: &hex!("E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"),
            cashaddr: "prefix:0h3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqakcssnmn",
        },
        TestCase {
            raw_hashtype: 0,
            prefix: "bitcoincash",
            payload: &hex!(
                "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C3407
                 7638E4DD1A701BD017842789982041"
            ),
            cashaddr: "bitcoincash:qmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57j\
                       uxsrhvw8ym5d8qx7sz7zz0zvcypqscw8jd03f",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "bchtest",
            payload: &hex!(
                "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C3407
                 7638E4DD1A701BD017842789982041"
            ),
            cashaddr: "bchtest:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsr\
                       hvw8ym5d8qx7sz7zz0zvcypqs6kgdsg2g",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "pref",
            payload: &hex!(
                "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C3407
                 7638E4DD1A701BD017842789982041"
            ),
            cashaddr: "pref:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw\
                       8ym5d8qx7sz7zz0zvcypqsammyqffl",
        },
        TestCase {
            raw_hashtype: 15,
            prefix: "prefix",
            payload: &hex!(
                "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C3407
                 7638E4DD1A701BD017842789982041"
            ),
            cashaddr: "prefix:0mvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrh\
                       vw8ym5d8qx7sz7zz0zvcypqsgjrqpnw8",
        },
        TestCase {
            raw_hashtype: 0,
            prefix: "bitcoincash",
            payload: &hex!(
                "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA
                 89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"
            ),
            cashaddr: "bitcoincash:qlg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46h\
                       udk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mtky5sv5w",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "bchtest",
            payload: &hex!(
                "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA
                 89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"
            ),
            cashaddr: "bchtest:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk\
                       5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mc773cwez",
        },
        TestCase {
            raw_hashtype: 1,
            prefix: "pref",
            payload: &hex!(
                "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA
                 89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"
            ),
            cashaddr: "pref:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flt\
                       tj6ydvjc0pv3nchp52amk97tqa5zygg96mg7pj3lh8",
        },
        TestCase {
            raw_hashtype: 15,
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
    fn encode() {
        for testcase in TEST_VECTORS.iter() {
            let cashaddr = enc(testcase.payload, testcase.prefix, testcase.raw_hashtype)
                .expect("Failed to parse cashaddr");
            assert_eq!(cashaddr, testcase.cashaddr, "Test failed for test case {:?}", testcase);
        }
    }

    #[test]
    fn payload_to_str() {
        let payload = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let payload = Payload { payload, hash_type: HashType::P2PKH };
        let cashaddr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        assert_eq!(payload.to_string(), cashaddr);
    }
    #[test]
    fn payload_to_str_no_prefix() {
        let payload = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let payload = Payload { payload, hash_type: HashType::P2PKH };
        let cashaddr = "qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        assert_eq!(payload.to_string_no_prefix(), cashaddr);
    }
}
