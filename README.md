# zip-password-finder
[![Build](https://github.com/agourlay/zip-password-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/agourlay/zip-password-finder/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/zip-password-finder.svg)](https://crates.io/crates/zip-password-finder)

`zip-password-finder` is a tool to find the password of protected zip files.

The design of this tool is described in details in the following blog articles:
- [Brute forcing protected ZIP archives in Rust](https://agourlay.github.io/brute-forcing-protected-zip-rust/)
- [Follow up on cracking ZIP archives in Rust](https://agourlay.github.io/follow-up-cracking-zip-rust/)

## Features

- Supports both ZipCrypto and AES encryption
- Multi-threaded, using all physical CPU cores by default
- Three attack modes: brute force, dictionary, and mask attack
- Graceful interruption with Ctrl-C, displaying the last password tested
- Resume brute force from a specific password with `--startingPassword`
- Automatic detection of encrypted files within multi-file archives
- Progress bar with throughput and ETA

## Attack modes

### Brute force (default)

Generates all passwords for a given charset and password length range. This is the default mode when no dictionary or mask is provided.

```bash
zip-password-finder -i archive.zip -c lud --minPasswordLen 1 --maxPasswordLen 6
```

The available charset presets are:

```
  l | abcdefghijklmnopqrstuvwxyz [a-z]
  u | ABCDEFGHIJKLMNOPQRSTUVWXYZ [A-Z]
  d | 0123456789                 [0-9]
  h | 0123456789abcdef           [0-9a-f]
  H | 0123456789ABCDEF           [0-9A-F]
  s | «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
```

Presets can be combined, e.g. `lud` (the default) uses lowercase + uppercase + digits.

Alternatively, a custom charset file can be provided with `--charsetFile`. It should be a text file containing a single line of characters to use for the generation.

To resume an interrupted brute force search, use `--startingPassword` to skip ahead:

```bash
zip-password-finder -i archive.zip --startingPassword "abc"
```

### Dictionary

Tests passwords from a text file, one word per line.

```bash
zip-password-finder -i archive.zip -p wordlist.txt
```

### Mask attack

Generates passwords matching a pattern where each position has its own charset. This is useful when you know part of the password structure (e.g. starts with uppercase, ends with digits).

```bash
zip-password-finder -i archive.zip --mask '?u?l?l?l?d?d'
```

The available mask tokens are:

```
  ?l | lowercase letters [a-z]
  ?u | uppercase letters [A-Z]
  ?d | digits [0-9]
  ?s | symbols
  ?a | all printable (lowercase + uppercase + digits + symbols)
  ?h | lowercase hex [0-9a-f]
  ?H | uppercase hex [0-9A-F]
  ?1 | custom charset 1 (--customCharset1)
  ?2 | custom charset 2 (--customCharset2)
  ?3 | custom charset 3 (--customCharset3)
  ?4 | custom charset 4 (--customCharset4)
  ?? | literal '?'
```

Any other character in the mask is treated as a literal.

Custom charsets are defined with `--customCharset1` through `--customCharset4` and can contain literal characters and/or built-in tokens. For example, `--customCharset1 "aeiou"` defines vowels, and `--customCharset1 "?l?d"` defines lowercase letters + digits.

Examples:

```bash
# 3 lowercase letters followed by 2 digits
zip-password-finder -i archive.zip --mask '?l?l?l?d?d'

# known prefix "pass" followed by 4 digits
zip-password-finder -i archive.zip --mask 'pass?d?d?d?d'

# uppercase, 4 lowercase, then a symbol
zip-password-finder -i archive.zip --mask '?u?l?l?l?l?s'

# custom charset: 2 vowels followed by a digit
zip-password-finder -i archive.zip -1 "aeiou" --mask '?1?1?d'
```

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
  -i, --inputFile <inputFile>                    path to zip input file
  -w, --workers <workers>                        number of workers
  -p, --passwordDictionary <passwordDictionary>  path to a password dictionary file
  -c, --charset <charset>                        charset to use to generate password [default: lud]
      --charsetFile <charsetFile>                path to a charset file
      --minPasswordLen <minPasswordLen>          minimum password length [default: 1]
      --maxPasswordLen <maxPasswordLen>          maximum password length [default: 10]
      --fileNumber <fileNumber>                  file number in the zip archive [default: 0]
  -s, --startingPassword <startingPassword>      password to start from
  -m, --mask <mask>                              mask pattern for mask attack (e.g. '?l?l?l?d?d')
  -1, --customCharset1 <customCharset1>          custom charset 1 for mask attack, referenced as ?1
  -2, --customCharset2 <customCharset2>          custom charset 2 for mask attack, referenced as ?2
  -3, --customCharset3 <customCharset3>          custom charset 3 for mask attack, referenced as ?3
  -4, --customCharset4 <customCharset4>          custom charset 4 for mask attack, referenced as ?4
  -h, --help                                     Print help
  -V, --version                                  Print version
```

## Performance

For AES make sure to use a CPU with `SHA` instructions (Intel Sandy Bridge or newer, AMD Bulldozer or newer) to get the best performance.

Native builds tend to perform better in general.

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

The number of workers defaults to the number of physical CPU cores. You can override this with `--workers`, but using more workers than physical cores typically does not help due to contention.

E.g. of scalability with an 8 core CPU with 16 threads as the number of workers increases:

![scalability example](finder-8-16.jpg "Scalability example")
