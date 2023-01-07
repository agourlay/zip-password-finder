# zip-password-finder
[![Build](https://github.com/agourlay/zip-password-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/agourlay/zip-password-finder/actions/workflows/ci.yml)

`zip-password-finder` is a tool to find the password of protected zip files.

The initial design of this tool is described in details in the [following blog article](https://agourlay.github.io/brute-forcing-protected-zip-rust/).

It supports two modes:

- dictionary: test passwords from a dictionary text file (one word per line)
- brute force: generate all passwords for a given charset and a password length range

The available charsets for generation are:

- basic: lowercase letters
- easy: basic + upper case letters
- medium: easy + digits
- hard: medium + punctuations and extras

## Usage

```
./zip-password-finder -h
Zip archive password finder

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

It is rather slow and seems to suffer from contention as the number of workers increases which makes it impractical for non-trivial passwords.