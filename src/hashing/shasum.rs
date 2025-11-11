use crate::errors::ShaSumError;
use crate::hashing::Hasher;
use digest::Digest;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

/// Hashes the data using the specified checksum type
macro_rules! hash_match {
    ($bits:expr, $data:expr) => {
        match $bits {
            160 => hex::encode(Sha1::digest($data)),
            224 => hex::encode(Sha224::digest($data)),
            256 => hex::encode(Sha256::digest($data)),
            384 => hex::encode(Sha384::digest($data)),
            512 => hex::encode(Sha512::digest($data)),
            _ => unreachable!(),
        }
    };
}

pub struct ShaSum<'a> {
    /// Bit length of the checksum (160, 224, 256, 384, or 512)
    checksum_bits: usize,

    /// Data to process
    data: &'a [u8],
}

impl Hasher for ShaSum<'_> {
    const VALID_VALUES: &'static [usize] = &[160, 224, 256, 384, 512];

    fn get_checksum(&self) -> String {
        match self.checksum_bits {
            bits @ (160 | 224 | 256 | 384 | 512) => hash_match!(bits, self.data),
            _ => unreachable!(),
        }
    }
}

impl<'a> ShaSum<'a> {
    pub fn new(checksum_type: usize, data: &'a [u8]) -> Result<ShaSum<'a>, ShaSumError> {
        let bits = checksum_type;
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
        let actual_checksum = checksummer.get_checksum();
        assert_eq!(actual_checksum, expected_checksum);
    }

    #[test]
    fn test_sha384sum() {
        let data = b"i use arch btw\n";

        let checksummer = ShaSum::new(384, data).unwrap();

        let expected_checksum =
            "263b578ab61613a5dff5b9c2aadf9601250e316aca387a5edb9b01da1aeb431f2b6e718b86e1b293adf51a14d058dceb"
                .to_owned();

        let actual_checksum = checksummer.get_checksum();
        assert_eq!(actual_checksum, expected_checksum);
    }

    #[test]
    fn test_sha256sum() {
        let data = b"i use arch btw\n";

        let checksummer = ShaSum::new(256, data).unwrap();

        let expected_checksum =
            "80799b90f4c070668b52df31830b60ef767bb039000eec4266f285d498002bb5".to_owned();

        let actual_checksum = checksummer.get_checksum();
        assert_eq!(actual_checksum, expected_checksum);
    }

    #[test]
    fn test_sha224sum() {
        let data = b"i use arch btw\n";

        let checksummer = ShaSum::new(224, data).unwrap();

        let expected_checksum =
            "990fe822fd00f196671004f5aeebf50d073da8de3d8fc45f466e7092".to_owned();

        let actual_checksum = checksummer.get_checksum();
        assert_eq!(actual_checksum, expected_checksum);
    }

    #[test]
    fn test_sha1sum() {
        let data = b"i use arch btw\n";

        let checksummer = ShaSum::new(160, data).unwrap();

        let expected_checksum = "821609590ef05d00b20c5f4c5a28c56627480eb7".to_owned();

        let actual_checksum = checksummer.get_checksum();
        assert_eq!(actual_checksum, expected_checksum);
    }
}
