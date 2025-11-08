use crate::hashing::Hasher;

pub struct Md5Sum<'a> {
    /// Data to process
    data: &'a [u8],
}

impl Hasher for Md5Sum<'_> {
    const VALID_VALUES: &'static [usize] = &[128];

    fn get_checksum(&self) -> String {
        let a = md5::compute(self.data);
        format!("{a:x}")
    }
}

impl<'a> Md5Sum<'a> {
    pub fn new(data: &'a [u8]) -> Md5Sum<'a> {
        Md5Sum { data }
    }
}
