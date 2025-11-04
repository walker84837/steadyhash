use crate::errors::Md5SumError;
use crate::hashing::Hasher;

pub struct Md5Sum<'a> {
    /// Data to process
    data: &'a [u8],
}

impl<'a> Hasher<'a, Md5SumError> for Md5Sum<'a> {
    const VALID_VALUES: &'static [usize] = &[128];

    fn get_checksum(&self) -> Result<String, Md5SumError> {
        let a = md5::compute(self.data);
        Ok(format!("{:x}", a))
    }
}

impl<'a> Md5Sum<'a> {
    pub fn new(data: &'a [u8]) -> Md5Sum<'a> {
        Md5Sum { data }
    }
}
