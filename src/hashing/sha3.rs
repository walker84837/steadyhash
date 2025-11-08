use crate::errors::Sha3SumError;
use crate::hashing::Hasher;
use sha3::{Digest, Sha3_224, Sha3_256, Sha3_384, Sha3_512};

pub struct Sha3Sum<'a> {
    /// Bit length of the checksum
    checksum_type: i32,

    /// Data to process
    data: &'a [u8],
}

impl Hasher for Sha3Sum<'_> {
    const VALID_VALUES: &'static [usize] = &[224, 256, 384, 512];

    fn get_checksum(&self) -> String {
        match self.checksum_type {
            224 => {
                let mut hasher = Sha3_224::new();
                hasher.update(self.data);
                format!("{:x}", hasher.finalize())
            }
            256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(self.data);
                format!("{:x}", hasher.finalize())
            }
            384 => {
                let mut hasher = Sha3_384::new();
                hasher.update(self.data);
                format!("{:x}", hasher.finalize())
            }
            512 => {
                let mut hasher = Sha3_512::new();
                hasher.update(self.data);
                format!("{:x}", hasher.finalize())
            }
            _ => unreachable!(),
        }
    }
}

impl<'a> Sha3Sum<'a> {
    pub fn new(checksum_type: i32, data: &'a [u8]) -> Result<Sha3Sum<'a>, Sha3SumError> {
        if !Self::VALID_VALUES.contains(&(checksum_type as usize)) {
            return Err(Sha3SumError::InvalidChecksumType(checksum_type));
        }

        Ok(Sha3Sum {
            checksum_type,
            data,
        })
    }
}
