# steadyhash

SteadyHash is a reimagination of the Coreutils' `b2sum`, `sha256sum` (and so on) utilities. It aims to keep compatibility with their formats for checksum files. It provides a straightforward way to generate and verify SHA-1, SHA-256, SHA-512, SHA3-256, SHA3-512, Blake2b-512, Blake2b-256 and MD5 checksums.

## Usage

To use this utility, follow these steps:

1.  Ensure you have Rust and Cargo installed. If not, you can install them from Rust's [official website](https://www.rust-lang.org/tools/install).
2.  Clone this repository to your local machine.
3.  Navigate to the project directory.
4.  Run `cargo run --release` to run and build the utility.

### Command-line arguments

### Generating checksums

To generate a checksum for a file, use the following command:

Usage: `steadyhash [OPTIONS] --type <CHECKSUM> [FILEs]...`

Arguments: `[FILEs]... : the files to process`

Options:

|Flag/Option|Description|Possible Values|
|---|---|---|
|`-l, --length`|The bit length of the checksum|`sha`: `160`, `256`, `512`; `sha3`: `256`, `512`; `blake`: `256`, `512`|
|`-t, --type`|The type of checksum|`sha`, `sha3`, `md5`, `blake`, `b2`, `blake2`, `blake2b`|
|`-c, --check`|Read checksums from the FILEs and check them|-|
|`--bsd`|Create a BSD-style checksum|-|
|`--binary`|Read in binary mode|-|
|`-s, --stdin`|Read data from stdin|-|
|`-h, --help`|Print help|-|
|`-V, --version`|Print version|-|

#### Examples

  - Generate a SHA256 BSD-style checksum:
    ```console
    $ steadyhash -l 256 -t sha foo.bar
    ```

  - Generate a Blake2b-256 checksum:
    ```console
    $ steadyhash -l 256 -t b2 foo.bar
    ```

  - Generate a SHA1 BSD-style checksum:
    ```console
    $ steadyhash -l 160 -t sha --bsd foo.bar
    ```

  - Generate an MD5 checksum:
    ```console
    $ steadyhash -t md5 foo.bar
    ```

  - Generate a SHA3-256 checksum:
    ```console
    $ steadyhash -l 256 -t sha3 foo.bar
    ```

### Checking checksums

To check checksums from a file, use the following command:

Usage: `steadyhash [OPTIONS] --type <CHECKSUM> --check [FILEs]...`

#### Examples

  - Check SHA256 checksums from a file:
    ```console
    $ steadyhash -l 256 -t sha --check checksums.txt
    ```

  - Check MD5 checksums from a file:
    ```console
    $ steadyhash -t md5 --check checksums.txt
    ```

## Roadmap & Contributing

Contributions are warmly welcome! Feel free to submit pull requests with improvements or bug fixes, and if you're unsure about something, open an issue to discuss it further.

  - [X] Support for multiple platforms
  - [X] Support for checking checksums

Before contributing, please read [the contribution guidelines](CONTRIBUTING.md).

## Support

If you encounter any issues or have questions about this utility, feel free to [open an issue](https://github.com/walker84837/steadyhash/issues).

## License

This project is licensed under the [EUPL-1.2](LICENSE.md).
