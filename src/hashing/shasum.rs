use crate::errors::ShaSumError;
use crate::hashing::Hasher;
use digest::Digest;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// Hashes the data using the specified checksum type
macro_rules! hash_match {
    ($bits:expr, $data:expr) => {
        match $bits {
            160 => hex::encode(Sha1::digest($data)),
            256 => hex::encode(Sha256::digest($data)),
            512 => hex::encode(Sha512::digest($data)),
            _ => unreachable!(),
        }
    };
}

pub struct ShaSum<'a> {
    /// Bit length of the checksum (160, 256, or 512)
    checksum_bits: usize,

    /// Data to process
    data: &'a [u8],
}

impl<'a> Hasher<'a, ShaSumError> for ShaSum<'a> {
    const VALID_VALUES: &'static [usize] = &[160, 256, 512];

    fn get_checksum(&self) -> Result<String, ShaSumError> {
        match self.checksum_bits {
            bits @ (160 | 256 | 512) => Ok(hash_match!(bits, self.data)),
            _ => Err(ShaSumError::InvalidChecksumType(self.checksum_bits as i32)),
        }
    }
}

impl<'a> ShaSum<'a> {
    /// Keep `new(checksum_type: i32, ...)` to preserve external API.
    pub fn new(checksum_type: i32, data: &'a [u8]) -> Result<ShaSum<'a>, ShaSumError> {
        let bits = checksum_type as usize;
        if !Self::VALID_VALUES.contains(&bits) {
            return Err(ShaSumError::InvalidChecksumType(checksum_type));
        }

        Ok(ShaSum {
            checksum_bits: bits,
            data,
        })
    }
}

mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_sha512sum() {
        let data = b"i use arch btw\n";

        let checksummer = ShaSum::new(512, data).unwrap();

        // echo 'i use arch btw' | sha512sum -b
        let expected_checksum = "2ddbe9f9af5a630d3734ce469fac19088e8d0242541768630777de5c56dc4053d346a67527cb95de3ab094d6862f393392ba26bed459d9ad149b423aeae552a2"
            .to_owned();
        let actual_checksum = checksummer.get_checksum().unwrap();
        assert_eq!(actual_checksum, expected_checksum);
    }

    #[test]
    fn test_sha256sum() {
        let data = b"i use arch btw\n";

        let checksummer = ShaSum::new(256, data).unwrap();

        let expected_checksum =
            "80799b90f4c070668b52df31830b60ef767bb039000eec4266f285d498002bb5".to_owned();

        let actual_checksum = checksummer.get_checksum().unwrap();
        assert_eq!(actual_checksum, expected_checksum);
    }

    #[test]
    fn test_sha1sum() {
        let data = b"i use arch btw\n";

        let checksummer = ShaSum::new(160, data).unwrap();

        let expected_checksum = "821609590ef05d00b20c5f4c5a28c56627480eb7".to_owned();

        let actual_checksum = checksummer.get_checksum().unwrap();
        assert_eq!(actual_checksum, expected_checksum);
    }
}
