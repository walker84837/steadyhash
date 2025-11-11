// TODO: errors doesn't seem all that descriptive whenever an invalid checksum type is provided
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ShaSumError {
    /// Error indicating that an invalid SHA checksum type has been provided.
    #[error(
        "Invalid checksum type 'SHA-{0}'. The only supported types are SHA1, SHA256 and SHA512"
    )]
    InvalidChecksumType(usize),
}

#[derive(Error, Debug)]
pub enum Sha3SumError {
    /// Error indicating that an invalid SHA3 checksum type has been provided.
    #[error(
        "Invalid checksum type 'SHA3-{0}'. The only supported types are SHA3-224, SHA3-256, SHA3-384 and SHA3-512"
    )]
    InvalidChecksumType(usize),
}

#[derive(Error, Debug)]
pub enum B2SumError {
    /// Error indicating that an invalid Blake2b checksum type has been provided.
    #[error(
        "Invalid checksum type 'BLAKE2B-{0}'. The only supported types are BLAKE2B-256 and BLAKE2B-512"
    )]
    InvalidChecksumType(usize),
}

#[derive(Debug)]
pub struct ParseChecksumError {
    pub value: String,
}

impl std::fmt::Display for ParseChecksumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid enum variant: {}", self.value)
    }
}

impl std::error::Error for ParseChecksumError {}
