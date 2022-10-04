// The cashaddr character set for encoding
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

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

#[derive(Debug, PartialEq)]
pub enum HashType {
    Key = 0x00,
    Script = 0x08,
}

#[derive(Debug)]
pub enum EncodeError {
    IncorrectPayloadLen(usize),
}

pub trait CashEnc : AsRef<[u8]> {
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
    fn encode_p2pkh(&self, prefix: &str) -> Result<String, EncodeError> {
        self.encode(prefix, HashType::Key)
    }
    fn encode_p2sh(&self, prefix: &str) -> Result<String, EncodeError> {
        self.encode(prefix, HashType::Script)
    }
}
impl<T: AsRef<[u8]>> CashEnc for T {}

#[cfg(test)]
mod encode_test {
    use super::{HashType, CashEnc};
    #[test]
    fn keyhash_20_main() {
        let payload = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let cashaddr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        assert_eq!(payload.encode("bitcoincash", HashType::Key).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_20_bchtest() {
        let payload = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let cashaddr = "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t";
        assert_eq!(payload.encode("bchtest", HashType::Script).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_20_prefix() {
        let payload = hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        let cashaddr = "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5";
        assert_eq!(payload.encode("pref", HashType::Script).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_24() {
        let cashaddr = "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0";
        let payload = "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA";
        let payload = hex::decode(payload).unwrap();
        assert_eq!( payload.encode("bitcoincash", HashType::Key).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_32() {
        let cashaddr = "bchtest:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6";
        let payload = hex::decode("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060").unwrap();
        assert_eq!( payload.encode("bchtest", HashType::Script).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_40_pref() {
        let cashaddr = "pref:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv0vx5z0w3";
        let payload = hex::decode("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB")
            .unwrap();
        assert_eq!( payload.encode("pref", HashType::Script).unwrap(), cashaddr);
    }
    #[test]
    fn keyhash_40() {
        let cashaddr =  "bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl";
        let payload = hex::decode("E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C")
            .unwrap();
        assert_eq!( payload.encode("bitcoincash", HashType::Key).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_40_bchtest() {
        let cashaddr =  "bchtest:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvmgm6ynej";
        let payload = hex::decode("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB")
            .unwrap();
        assert_eq!( payload.encode("bchtest", HashType::Script).unwrap(), cashaddr);
    }
    #[test]
    fn scripthash_56() {
        let cashaddr =  "pref:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsammyqffl";
        let payload = hex::decode("D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041")
            .unwrap();
        assert_eq!( payload.encode("pref", HashType::Script).unwrap(), cashaddr);
    }
}
