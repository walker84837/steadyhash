pub mod blake2b;
pub mod md5;
pub mod sha3;
pub mod shasum;

pub trait Hasher {
    const VALID_VALUES: &'static [usize];

    fn get_checksum(&self) -> String;
}
