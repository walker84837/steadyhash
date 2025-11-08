use crate::errors::B2SumError;
use crate::hashing::Hasher;

use blake2::Blake2bVar;
use digest::{Update, VariableOutput};
use std::fmt::Write;

/// Blake2b hasher that supports runtime-specified bit lengths (multiples of 8, up to 512).
pub struct Blake2b<'a> {
    /// Bit length of the checksum (e.g. 256, 512, 384, 224, 128, ... but must be multiple of 8)
    checksum_type: i32,

    /// Data to process
    data: &'a [u8],
}

impl<'a> Hasher for Blake2b<'a> {
    // all valid multiples of 8 from 8..=512 (8 * 1 .. 8 * 64)
    const VALID_VALUES: &'static [usize] = &[
        8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160, 168,
        176, 184, 192, 200, 208, 216, 224, 232, 240, 248, 256, 264, 272, 280, 288, 296, 304, 312,
        320, 328, 336, 344, 352, 360, 368, 376, 384, 392, 400, 408, 416, 424, 432, 440, 448, 456,
        464, 472, 480, 488, 496, 504, 512,
    ];

    fn get_checksum(&self) -> String {
        // validate, even though this should already be validated in new(), but double-check here
        // just in case
        let bits = self.checksum_type as usize;
        if bits == 0 || !bits.is_multiple_of(8) || bits > 512 {
            unreachable!();
        }

        let out_bytes = bits / 8;

        let mut hasher = Blake2bVar::new(out_bytes).unwrap();

        hasher.update(self.data);

        // finalize into buffer of the requested size
        let mut buf = vec![0u8; out_bytes];
        hasher.finalize_variable(&mut buf).unwrap();

        // hex-encode without extra dependency
        let mut s = String::with_capacity(out_bytes * 2);
        for b in buf {
            write!(&mut s, "{:02x}", b).expect("writing to string cannot fail");
        }

        s
    }
}

impl<'a> Blake2b<'a> {
    pub fn new(checksum_type: i32, data: &'a [u8]) -> Result<Self, B2SumError> {
        if !Self::VALID_VALUES.contains(&(checksum_type as usize)) {
            return Err(B2SumError::InvalidChecksumType(checksum_type));
        }

        Ok(Blake2b {
            checksum_type,
            data,
        })
    }
}

mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_hi() {
        let text = b"hi";

        let checksum = Blake2b::new(512, text).unwrap();
        assert_eq!(
            checksum.get_checksum(),
            "bfbcbe7ade93034ee0a41a2ea7b5fd81d89bdb1d75d1af230ea37d7abe71078f1df6db4d251cbc6b58e8963db2546f0f539c80b0f08c0fdd8c0a71075c97b3e7"
        );
    }

    #[test]
    fn test_invalid_bit_length() {
        assert!(
            Blake2b::new(4, b"").is_err(),
            "bit length must be bigger or equal than 8"
        );
        assert!(
            Blake2b::new(13, b"").is_err(),
            "bit length must be a multiple of 8"
        );
    }

    #[test]
    fn test_valid_bit_lengths() {
        let mut i = 8;
        while i <= 512 {
            assert!(Blake2b::new(i, b"").is_ok());
            i += 8;
        }
    }
}
