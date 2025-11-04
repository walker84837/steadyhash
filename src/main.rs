use anyhow::{anyhow, bail, Result};
use clap::Parser;
use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
};

mod errors;
mod hashing;
use crate::hashing::Hasher;
use hashing::{blake2b::Blake2b, md5::Md5Sum, sha3::Sha3Sum, shasum::ShaSum};

#[derive(Parser)]
#[clap(
    version,
    about = "Pure Rust utility which handles various checksum types"
)]
struct Args {
    #[clap(short = 'l', long = "length", help = "the bit length of the checksum")]
    bit_length: i32,

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

    #[clap(long = "tag", help = "create a BSD-style checksum")]
    bsd: bool,

    #[clap(long, help = "read in binary mode")]
    binary: bool,

    #[clap(short, long, help = "read data from stdin")]
    stdin: bool,
}

/// Get the file name in a path, like the `basename` Linux command
fn basename(file: &Path) -> Result<String> {
    Ok(file
        .file_name()
        .ok_or_else(|| anyhow!("File doesn't exist."))?
        .to_string_lossy()
        .into_owned()
        .chars()
        .filter(|&x| x != '\u{FFFD}')
        .collect())
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.check {
        check_files(&args)?;
    } else {
        for file in &args.file_path {
            let mut contents = Vec::new();

            if !args.stdin {
                let mut reader = BufReader::new(File::open(file)?);

                reader.read_to_end(&mut contents)?;
            } else {
                io::stdin().read_to_end(&mut contents)?;
            }

            match args.checksum_type.as_str() {
                "sha" => {
                    let hasher = ShaSum::new(args.bit_length, &contents)?;

                    let checksum = hasher.get_checksum()?;

                    let r#type = if args.bit_length == 160 {
                        1
                    } else {
                        args.bit_length
                    };

                    if args.bsd {
                        println!("SHA{} ({}) = {}", r#type, basename(file)?, checksum);
                    } else {
                        println!("{} {}", checksum, basename(file)?);
                    }
                }

                "blake" | "b2" | "blake2" => {
                    let hasher = Blake2b::new(args.bit_length, &contents)?;

                    let checksum = hasher.get_checksum()?;

                    if args.bsd {
                        println!(
                            "BLAKE2b-{} ({}) = {}",
                            args.bit_length,
                            basename(file)?,
                            checksum
                        );
                    } else {
                        println!("{}  {}", checksum, basename(file)?);
                    }
                }

                "md5" => {
                    let hasher = Md5Sum::new(&contents);

                    let checksum = hasher.get_checksum()?;

                    if args.bsd {
                        println!("MD5 ({}) = {}", basename(file)?, checksum);
                    } else {
                        println!("{}  {}", checksum, basename(file)?);
                    }
                }

                "sha3" => {
                    let hasher = Sha3Sum::new(args.bit_length, &contents)?;

                    let checksum = hasher.get_checksum()?;

                    if args.bsd {
                        println!(
                            "SHA3-{} ({}) = {}",
                            args.bit_length,
                            basename(file)?,
                            checksum
                        );
                    } else {
                        println!("{}  {}", checksum, basename(file)?);
                    }
                }

                _ => bail!("Invalid checksum type. Possible values are `sha` or `blake`."),
            }
        }
    }

    Ok(())
}

fn check_files(args: &Args) -> Result<()> {
    for file in &args.file_path {
        let mut reader = BufReader::new(File::open(file)?);

        let mut contents = String::new();

        reader.read_to_string(&mut contents)?;

        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() < 2 {
                continue;
            }

            let (expected_checksum, file_path) = if parts.len() >= 2 && parts[1].starts_with("(") {
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

            let actual_checksum = match args.checksum_type.as_str() {
                "sha" => {
                    let hasher = ShaSum::new(args.bit_length, &file_contents)?;

                    hasher.get_checksum()?
                }

                "blake" | "b2" | "blake2" => {
                    let hasher = Blake2b::new(args.bit_length, &file_contents)?;

                    hasher.get_checksum()?
                }

                "md5" => {
                    let hasher = Md5Sum::new(&file_contents);

                    hasher.get_checksum()?
                }

                "sha3" => {
                    let hasher = Sha3Sum::new(args.bit_length, &file_contents)?;

                    hasher.get_checksum()?
                }

                _ => bail!("Invalid checksum type."),
            };

            if actual_checksum == expected_checksum {
                println!("{}: OK", file_path);
            } else {
                println!("{}: FAILED", file_path);
            }
        }
    }

    Ok(())
}
