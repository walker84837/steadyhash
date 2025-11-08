use crate::hashing::Hasher;

pub struct Md5Sum<'a> {
    /// Data to process
    data: &'a [u8],
}

impl<'a> Hasher for Md5Sum<'a> {
    const VALID_VALUES: &'static [usize] = &[128];

    fn get_checksum(&self) -> String {
        let a = md5::compute(self.data);
        format!("{:x}", a)
    }
}

impl<'a> Md5Sum<'a> {
    pub fn new(data: &'a [u8]) -> Md5Sum<'a> {
        Md5Sum { data }
    }
}
