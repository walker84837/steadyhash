use thiserror::Error;

#[derive(Error, Debug)]
pub enum ShaSumError {
    /// Error indicating that an invalid SHA checksum type has been provided.
    #[error(
        "Invalid checksum type 'SHA-{0}'. Supported types are SHA-160 (SHA1), SHA-224, SHA-256, SHA-384 and SHA-512"
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
        "Invalid checksum type 'BLAKE2b-{0}'. Supported values are multiples of 8 from 8 up to 512 (inclusive)"
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
