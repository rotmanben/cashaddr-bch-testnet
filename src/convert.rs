use bs58::decode;

use super::CashEnc;

#[derive(Debug, PartialEq, Eq)]
pub enum ConversionError {
    Failed,
}

pub fn from_legacy(s: &str) -> Result<String, ConversionError> {
    let bytes = decode(s).into_vec().map_err(|_| ConversionError::Failed)?;
    let len = bytes.len();
    let payload = &dbg!(bytes)[1..len - 4];
    payload
        .encode_p2pkh("bitcoincash")
        .map_err(|_| ConversionError::Failed)
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
}
