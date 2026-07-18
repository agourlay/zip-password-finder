# zip-password-finder
[![Build](https://github.com/agourlay/zip-password-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/agourlay/zip-password-finder/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/zip-password-finder.svg)](https://crates.io/crates/zip-password-finder)

`zip-password-finder` is a tool to find the password of protected zip files.

The design of this tool is described in details in the following blog articles:
- [Brute forcing protected ZIP archives in Rust](https://agourlay.github.io/brute-forcing-protected-zip-rust/)
- [Follow up on cracking ZIP archives in Rust](https://agourlay.github.io/follow-up-cracking-zip-rust/)

If this tool helped you recover an archive, consider [sponsoring the project on GitHub](https://github.com/sponsors/agourlay).

## Features

- Supports ZIP (ZipCrypto + AES) and 7z (AES-256) archives
- Multi-threaded, using all physical CPU cores by default
- Three attack modes: brute force, dictionary, and mask attack
- Graceful interruption with Ctrl-C, displaying the last password tested
- Resume brute force from a specific password with `--starting-password`
- Automatic detection of encrypted files within multi-file archives
- Progress bar with throughput and ETA

The archive type is detected from the file's contents (not its extension), and all three attack modes work the same way for both ZIP and 7z. See [7z support](#7z-support) for the caveats specific to 7z.

## Attack modes

### Brute force (default)

Generates all passwords for a given charset and password length range. This is the default mode when no dictionary or mask is provided.

```bash
zip-password-finder archive.zip -c lud --min-password-len 1 --max-password-len 6
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

Alternatively, a custom charset file can be provided with `--charset-file`. It should be a text file containing a single line of characters to use for the generation.

To resume an interrupted brute force search, use `--starting-password` to skip ahead:

```bash
zip-password-finder archive.zip --starting-password "abc"
```

### Dictionary

Tests passwords from a text file, one word per line.

```bash
zip-password-finder archive.zip -p wordlist.txt
```

### Mask attack

Generates passwords matching a pattern where each position has its own charset. This is useful when you know part of the password structure (e.g. starts with uppercase, ends with digits).

```bash
zip-password-finder archive.zip --mask '?u?l?l?l?d?d'
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
  ?1 | custom charset 1 (--custom-charset-1)
  ?2 | custom charset 2 (--custom-charset-2)
  ?3 | custom charset 3 (--custom-charset-3)
  ?4 | custom charset 4 (--custom-charset-4)
  ?? | literal '?'
```

Any other character in the mask is treated as a literal.

Custom charsets are defined with `--custom-charset-1` through `--custom-charset-4` and can contain literal characters and/or built-in tokens. For example, `--custom-charset-1 "aeiou"` defines vowels, and `--custom-charset-1 "?l?d"` defines lowercase letters + digits.

Examples:

```bash
# 3 lowercase letters followed by 2 digits
zip-password-finder archive.zip --mask '?l?l?l?d?d'

# known prefix "pass" followed by 4 digits
zip-password-finder archive.zip --mask 'pass?d?d?d?d'

# uppercase, 4 lowercase, then a symbol
zip-password-finder archive.zip --mask '?u?l?l?l?l?s'

# custom charset: 2 vowels followed by a digit
zip-password-finder archive.zip -1 "aeiou" --mask '?1?1?d'
```

## 7z support

7z archives are supported transparently — point the tool at a `.7z` file and use any of the attack modes above:

```bash
zip-password-finder archive.7z -p wordlist.txt
```

Both content-encrypted archives and header-encrypted ones (`7z a -mhe=on`) are handled; the type is auto-detected from the file signature.

A few things to keep in mind, all stemming from 7z's design rather than this tool:

- **Expect a much lower throughput than ZIP.** 7z derives its AES-256 key by iterating SHA-256 ~524,288 times per candidate (vs. 1,000 PBKDF2 rounds for ZIP-AES). This is deliberate and makes **brute force impractical** for anything but very short passwords — a **dictionary or mask attack is the realistic approach**.
- **AES-256 only**, which is what every recent 7z build produces.
- Unlike ZIP, 7z has no cheap per-candidate verifier, so each password is fully decrypt-and-checked. The `--file-number` option is **rejected** for 7z (it selects an entry in a multi-file ZIP; for 7z any encrypted entry proves the password). Verification uses whichever entry is cheapest to decode — the smallest one for non-solid archives — to keep the check fast even when the archive holds a large file.

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

Usage: zip-password-finder [OPTIONS] <file>

Arguments:
  <file>  path to the zip or 7z input file

Options:
  -w, --workers <count>               number of workers
  -p, --password-dictionary <file>    path to a password dictionary file
  -c, --charset <preset>              charset preset(s) to combine for brute force [default: lud]
      --charset-file <file>           path to a charset file
      --min-password-len <len>        minimum password length [default: 1]
      --max-password-len <len>        maximum password length [default: 6]
      --file-number <index>           file number in the zip archive [default: 0]
  -s, --starting-password <password>  password to start from
  -m, --mask <pattern>                mask pattern for mask attack (e.g. '?l?l?l?d?d')
  -1, --custom-charset-1 <chars>      custom charset 1 for mask attack, referenced as ?1 (e.g. 'aeiou' or '?l?d')
  -2, --custom-charset-2 <chars>      custom charset 2 for mask attack, referenced as ?2
  -3, --custom-charset-3 <chars>      custom charset 3 for mask attack, referenced as ?3
  -4, --custom-charset-4 <chars>      custom charset 4 for mask attack, referenced as ?4
  -q, --quiet                         suppress progress and status output (print only the result on stdout)
      --json                          print the result as a JSON object on stdout
  -h, --help                          Print help (see more with '--help')
  -V, --version                       Print version
```

### Output and scripting

The found password is written to **stdout**; progress and status go to **stderr**, so the result is easy to capture:

```bash
password=$(zip-password-finder archive.zip -p wordlist.txt --quiet) && echo "got: $password"
```

Exit codes follow the `grep` convention: **0** if the password was found, **1** if the search finished without it, **2** on error. Three output modes:

- default — human-readable `Password found: <password>` on stdout
- `--quiet` / `-q` — just the bare password on stdout (nothing if not found), no progress
- `--json` — a JSON object on stdout, e.g. `{"found":true,"password":"secret","file":"archive.zip","elapsed_ms":1234}`

## Performance

For AES make sure to use a CPU with `SHA` instructions (Intel Sandy Bridge or newer, AMD Bulldozer or newer) to get the best performance.

Native builds tend to perform better in general.

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

The number of workers defaults to the number of physical CPU cores. You can override this with `--workers`, but using more workers than physical cores typically does not help due to contention.

E.g. of scalability with an 8 core CPU with 16 threads as the number of workers increases:

![scalability example](finder-8-16.jpg "Scalability example")
