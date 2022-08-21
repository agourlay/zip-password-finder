# zip-password-finder
[![Build](https://github.com/agourlay/zip-password-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/agourlay/zip-password-finder/actions/workflows/ci.yml)

`zip-password-finder` is a tool to find the password of protected zip files.

It supports two modes:

- dictionary: test passwords from a dictionary text file (one word per line)
- brute force: generate all passwords for a given charset and a password length range

The available charsets for generation are:

- easy: lower case and upper case letters
- medium: easy + digits
- hard: medium + punctuations and extras

## Usage

```
./zip-password-finder -h

zip-password-finder x.x.x
Arnaud Gourlay <arnaud.gourlay@gmail.com>
Zip archive password finder

USAGE:
    zip-password-finder [OPTIONS] --inputFile <inputFile>

OPTIONS:
    -c, --charset <charset>
            charset to use to generate password [default: medium] [possible values: easy, medium,
            hard]

    -h, --help
            Print help information

    -i, --inputFile <inputFile>
            path to zip input file

        --maxPasswordLen <maxPasswordLen>
            maximum password length [default: 10]

        --minPasswordLen <minPasswordLen>
            minimum password length [default: 1]

    -p, --passwordDictionary <passwordDictionary>
            path to a password dictionary file

    -V, --version
            Print version information

    -w, --workers <workers>
            number of workers
```

## Performance

It is rather slow and seems to suffer from contention as the number of workers increases which makes it impractical for non-trivial passwords.