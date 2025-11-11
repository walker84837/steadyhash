use anyhow::Error;
use clap::Parser;
use std::{
    fmt::Display, fs::File, io::{self, BufReader, Read}, path::{Path, PathBuf}, str::FromStr
};

mod errors;
mod hashing;
use crate::{errors::ParseChecksumError, hashing::Hasher};
use hashing::{blake2b::Blake2b, md5::Md5Sum, sha3::Sha3Sum, shasum::ShaSum};

#[derive(Parser)]
#[clap(
    version,
    about = "Pure Rust utility which handles various checksum types"
)]
struct Args {
    #[clap(
        short = 'l',
        long = "length",
        help = "the bit length of the checksum",
        required_if_eq("checksum_type", "sha"),
        required_if_eq("checksum_type", "sha3"),
        required_if_eq("checksum_type", "blake2b")
    )]
    bit_length: Option<usize>,

    #[clap(
        short = 't',
        long = "type",
        help = "the type of checksum (sha or blake)"
    )]
    checksum_type: String,

    #[clap(name = "FILEs", help = "the files to process")]
    file_path: Vec<PathBuf>,

    #[clap(short, long, help = "read checksums from the FILEs and check them")]
    check: bool,

    #[clap(long = "bsd", help = "create a BSD-style checksum")]
    bsd: bool,

    #[clap(long, help = "read in binary mode")]
    binary: bool,

    #[clap(short, long, help = "read data from stdin")]
    stdin: bool,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum Checksum {
    Sha,
    Sha3,
    Md5,
    Blake2b,
}

impl Display for Checksum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Checksum::Blake2b => write!(f, "BLAKE2b"),
            Checksum::Md5 => write!(f, "MD5"),
            Checksum::Sha => write!(f, "SHA"),
            Checksum::Sha3 => write!(f, "SHA3")
        }
    }
}

impl FromStr for Checksum {
    type Err = ParseChecksumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const BLAKE2B_VALUES: &[&str] = &["blake", "b2", "blake2", "blake2b"];

        if BLAKE2B_VALUES.contains(&s.to_ascii_lowercase().as_str()) {
            Ok(Self::Blake2b)
        } else if s.eq_ignore_ascii_case("sha") {
            Ok(Self::Sha)
        } else if s.eq_ignore_ascii_case("md5") {
            Ok(Self::Md5)
        } else if s.eq_ignore_ascii_case("sha3") {
            Ok(Self::Sha3)
        } else {
            Err(ParseChecksumError { value: s.into() })
        }
    }
}

fn calculate_checksum(checksum: Checksum, bit_length: usize, data: &[u8]) -> Result<String, Error> {
    Ok(match checksum {
        Checksum::Sha => ShaSum::new(bit_length, data)?.get_checksum(),
        Checksum::Blake2b => Blake2b::new(bit_length, data)?.get_checksum(),
        Checksum::Md5 => Md5Sum::new(data).get_checksum(),
        Checksum::Sha3 => Sha3Sum::new(bit_length, data)?.get_checksum(),
    })
}

fn main() -> Result<(), Error> {
    let args = Args::parse();

    let checksum = Checksum::from_str(&args.checksum_type)?;
    let bit_length = if checksum == Checksum::Md5 {
        128
    } else {
        args.bit_length.unwrap()
    };

    for file in &args.file_path {
        if args.check {
            check_files(checksum, file, bit_length)?;
        } else {
            checksum_files(checksum, &args, file, bit_length)?;
        }
    }

    Ok(())
}

fn check_files(checksum: Checksum, file: &Path, bit_length: usize) -> Result<(), Error> {
    let mut reader = BufReader::new(File::open(file)?);

    let mut contents = String::new();

    reader.read_to_string(&mut contents)?;

    for line in contents.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 2 {
            continue;
        }

        let (expected_checksum, file_path) = if parts.len() >= 2 && parts[1].starts_with('(') {
            // BSD style

            let file_path = parts[1].trim_start_matches('(').trim_end_matches(')');

            (parts[3], file_path)
        } else {
            // default style

            (parts[0], parts[1])
        };

        let mut file_contents = Vec::new();

        let mut reader = BufReader::new(File::open(file_path)?);

        reader.read_to_end(&mut file_contents)?;

        let actual_checksum = calculate_checksum(checksum, bit_length, &file_contents)?;

        if actual_checksum == expected_checksum {
            println!("{file_path}: OK");
        } else {
            println!("{file_path}: FAILED");
        }
    }

    Ok(())
}

fn checksum_files(checksum: Checksum, args: &Args, file: &Path, bit_length: usize) -> Result<(), Error> {
    let mut contents = Vec::new();

    if args.stdin {
        io::stdin().read_to_end(&mut contents)?;
    } else {
        let mut reader = BufReader::new(File::open(&file)?);

        reader.read_to_end(&mut contents)?;
    }

    let checksum_str = calculate_checksum(checksum, bit_length, &contents)?;

    match checksum {
        Checksum::Sha => {
            if args.bsd {
                if bit_length == 160 {
                    println!("SHA1 ({}) = {}", file.display(), checksum_str);
                } else {
                    println!("SHA{} ({}) = {}", bit_length, file.display(), checksum_str);
                }
            } else {
                println!("{checksum_str} {}", file.display());
            }
        }

        Checksum::Blake2b => {
            if args.bsd {
                println!("BLAKE2b-{} ({}) = {}", bit_length, file.display(), checksum_str);
            } else {
                println!("{checksum_str}  {}", file.display());
            }
        }

        Checksum::Md5 => {
            if args.bsd {
                println!("MD5 ({}) = {checksum_str}", file.display());
            } else {
                println!("{checksum_str}  {}", file.display());
            }
        }

        Checksum::Sha3 => {
            if args.bsd {
                println!("SHA3-{bit_length} ({}) = {checksum_str}", file.display());
            } else {
                println!("{checksum_str}  {}", file.display());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_from_str() {
        // Test with lowercase
        assert_eq!(Checksum::from_str("sha").unwrap(), Checksum::Sha);
        assert_eq!(Checksum::from_str("blake2b").unwrap(), Checksum::Blake2b);
        assert_eq!(Checksum::from_str("md5").unwrap(), Checksum::Md5);
        assert_eq!(Checksum::from_str("sha3").unwrap(), Checksum::Sha3);

        // Test with uppercase
        assert_eq!(Checksum::from_str("SHa").unwrap(), Checksum::Sha);
        assert_eq!(Checksum::from_str("BLake2b").unwrap(), Checksum::Blake2b);
        assert_eq!(Checksum::from_str("mD5").unwrap(), Checksum::Md5);
        assert_eq!(Checksum::from_str("sHA3").unwrap(), Checksum::Sha3);
    }
}
