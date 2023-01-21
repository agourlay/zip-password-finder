# zip-password-finder
[![Build](https://github.com/agourlay/zip-password-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/agourlay/zip-password-finder/actions/workflows/ci.yml)

`zip-password-finder` is a tool to find the password of protected zip files.

The initial design of this tool is described in details in the [following blog article](https://agourlay.github.io/brute-forcing-protected-zip-rust/) but the architecture has changed since it was published.

## Features

- Supports both ZipCrypto and AES encryption.
- Leverages multiple threads to speed up the process
- Dictionary attack to test passwords from a dictionary text file (one word per line)
- Brute force to generate all passwords for a given charset and a password length range

The available charsets for the password generation are:

- basic: lowercase letters
- easy: basic + upper case letters
- medium: easy + digits
- hard: medium + punctuations and extras

## Installation

### Releases

Using the provided binaries in https://github.com/agourlay/zip-password-finder/releases

### Crates.io

Using Cargo via [crates.io](https://crates.io/crates/zip-password-finder).

```bash
cargo install zip-password-finder
```

### AUR

You can install [`zip-password-finder`](https://aur.archlinux.org/packages?O=0&K=zip-password-finder) from the AUR using an [AUR helper](https://wiki.archlinux.org/title/AUR_helpers). For example:

```bash
paru -S zip-password-finder
```

## Usage

```bash
./zip-password-finder -h
Find the password of protected ZIP files

Usage: zip-password-finder [OPTIONS] --inputFile <inputFile>

Options:
  -i, --inputFile <inputFile>
          path to zip input file
  -w, --workers <workers>
          number of workers
  -p, --passwordDictionary <passwordDictionary>
          path to a password dictionary file
  -c, --charset <charset>
          charset to use to generate password [default: medium] [possible values: basic, easy, medium, hard]
      --minPasswordLen <minPasswordLen>
          minimum password length [default: 1]
      --maxPasswordLen <maxPasswordLen>
          maximum password length [default: 10]
  -h, --help
          Print help information
  -V, --version
          Print version information
```

## Performance

ZipCrypto is roughly a 1000 times cheaper to crack with brute force.

In general it is rather slow and seems to suffer from contention as the number of workers increases which makes it impractical for non-trivial passwords.