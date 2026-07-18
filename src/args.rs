use crate::charsets::{CharsetChoice, charset_from_choice};
use crate::finder_errors::FinderError;
use crate::finder_errors::FinderError::CliArgumentError;
use crate::password_mask::{CustomCharsets, parse_custom_charset};
use clap::{Arg, ArgAction, Command};
use clap::{crate_authors, crate_description, crate_name, crate_version, value_parser};
use std::path::Path;

fn command() -> Command {
    Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .after_help(
            "EXAMPLES:\n\
             \n  \
             Brute-force short passwords (default charset is letters+digits):\n  \
                 zip-password-finder archive.zip --max-password-len 6\n\
             \n  \
             Use a dictionary file:\n  \
                 zip-password-finder archive.zip -p wordlist.txt\n\
             \n  \
             Mask attack (3 lowercase letters + 2 digits):\n  \
                 zip-password-finder archive.zip -m '?l?l?l?d?d'\n\
             \n  \
             GPU acceleration (AES archives only):\n  \
                 zip-password-finder archive.zip --gpu -p wordlist.txt\n\
             \n  \
             Check that GPU acceleration is available on this system:\n  \
                 zip-password-finder --gpu-smoke-test",
        )
        .arg(
            Arg::new("inputFile")
                .help("path to the zip or 7z input file")
                .value_name("file")
                .index(1)
                // positional, but optional when only probing the GPU
                .required_unless_present("gpuSmokeTest"),
        )
        .arg(
            Arg::new("workers")
                .value_parser(value_parser!(usize))
                .help("number of workers")
                .value_name("count")
                .long("workers")
                .short('w')
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("passwordDictionary")
                .help("path to a password dictionary file")
                .value_name("file")
                .long("password-dictionary")
                .alias("passwordDictionary")
                .short('p')
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("charset")
                .help("charset preset(s) to combine for brute force")
                .long_help(
                    "charset preset(s) to combine for brute force:\n  \
                     l  lowercase [a-z]\n  \
                     u  uppercase [A-Z]\n  \
                     d  digits [0-9]\n  \
                     h  lowercase hex [0-9a-f]\n  \
                     H  uppercase hex [0-9A-F]\n  \
                     s  symbols\n\
                     Combine several, e.g. 'lud' = lowercase + uppercase + digits.",
                )
                .value_name("preset")
                .long("charset")
                .short('c')
                .default_value("lud")
                .required(false),
        )
        .arg(
            Arg::new("charsetFile")
                .help("path to a charset file")
                .value_name("file")
                .long("charset-file")
                .alias("charsetFile")
                .num_args(1)
                .conflicts_with_all(["passwordDictionary", "mask"])
                .required(false),
        )
        .arg(
            Arg::new("minPasswordLen")
                .value_parser(value_parser!(usize))
                .help("minimum password length")
                .value_name("len")
                .long("min-password-len")
                .alias("minPasswordLen")
                .num_args(1)
                .default_value("1")
                .required(false),
        )
        .arg(
            Arg::new("maxPasswordLen")
                .value_parser(value_parser!(usize))
                .help("maximum password length to brute-force")
                .long_help(
                    "maximum password length to brute-force. With the default 'lud' charset \
                     (62 chars) the search space grows as 62^N: length 6 ≈ 56 billion candidates \
                     (hours on GPU), length 8 ≈ 218 trillion (months), length 10 is effectively \
                     infeasible. Increase this when you suspect a longer password — but expect \
                     run-time to scale exponentially.",
                )
                .value_name("len")
                .long("max-password-len")
                .alias("maxPasswordLen")
                .num_args(1)
                .default_value("6")
                .required(false),
        )
        .arg(
            Arg::new("fileNumber")
                .value_parser(value_parser!(usize))
                .help("file number in the zip archive")
                .value_name("index")
                .long("file-number")
                .alias("fileNumber")
                .num_args(1)
                .default_value("0")
                .required(false),
        )
        .arg(
            Arg::new("startingPassword")
                .help("password to start from")
                .value_name("password")
                .long("starting-password")
                .alias("startingPassword")
                .short('s')
                .conflicts_with_all(["passwordDictionary", "mask"])
                .required(false),
        )
        .arg(
            Arg::new("mask")
                .help("mask pattern for mask attack (e.g. '?l?l?l?d?d')")
                .long_help("mask pattern for mask attack (e.g. '?l?l?l?d?d' for 3 lowercase + 2 digits).\n\nAvailable tokens:\n  ?l  lowercase letters [a-z]\n  ?u  uppercase letters [A-Z]\n  ?d  digits [0-9]\n  ?s  symbols\n  ?a  all printable (?l?u?d?s)\n  ?h  lowercase hex [0-9a-f]\n  ?H  uppercase hex [0-9A-F]\n  ?1  custom charset 1 (--custom-charset-1)\n  ?2  custom charset 2 (--custom-charset-2)\n  ?3  custom charset 3 (--custom-charset-3)\n  ?4  custom charset 4 (--custom-charset-4)\n  ??  literal '?'\n\nAny other character is treated as a literal.")
                .value_name("pattern")
                .long("mask")
                .short('m')
                .num_args(1)
                .conflicts_with("passwordDictionary")
                .required(false),
        )
        .arg(
            Arg::new("customCharset1")
                .help("custom charset 1 for mask attack, referenced as ?1 (e.g. 'aeiou' or '?l?d')")
                .value_name("chars")
                .long("custom-charset-1")
                .alias("customCharset1")
                .short('1')
                .num_args(1)
                .requires("mask")
                .required(false),
        )
        .arg(
            Arg::new("customCharset2")
                .help("custom charset 2 for mask attack, referenced as ?2")
                .value_name("chars")
                .long("custom-charset-2")
                .alias("customCharset2")
                .short('2')
                .num_args(1)
                .requires("mask")
                .required(false),
        )
        .arg(
            Arg::new("customCharset3")
                .help("custom charset 3 for mask attack, referenced as ?3")
                .value_name("chars")
                .long("custom-charset-3")
                .alias("customCharset3")
                .short('3')
                .num_args(1)
                .requires("mask")
                .required(false),
        )
        .arg(
            Arg::new("customCharset4")
                .help("custom charset 4 for mask attack, referenced as ?4")
                .value_name("chars")
                .long("custom-charset-4")
                .alias("customCharset4")
                .short('4')
                .num_args(1)
                .requires("mask")
                .required(false),
        )
        .arg(
            Arg::new("quiet")
                .help("suppress progress and status output (print only the result on stdout)")
                .long("quiet")
                .short('q')
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("json")
                .help("print the result as a JSON object on stdout")
                .long("json")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("gpu")
                .help("use the GPU (Vulkan/Metal/DX12 via wgpu) — requires AES-encrypted archive")
                .long("gpu")
                .short('g')
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("gpuSmokeTest")
                .help("list GPU adapters and run a trivial compute kernel, then exit (does not require an input file)")
                .long("gpu-smoke-test")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("gpuBatchSize")
                .value_parser(value_parser!(u32))
                .help("override the GPU batch size (passwords per dispatch). When omitted, a value is picked automatically from the GPU type. Only used with --gpu.")
                .value_name("size")
                .long("gpu-batch-size")
                .alias("gpuBatchSize")
                .num_args(1)
                .required(false),
        )
}

pub struct Arguments {
    pub input_file: Option<String>,
    pub workers: Option<usize>,
    pub charset_choice: CharsetChoice,
    pub min_password_len: usize,
    pub max_password_len: usize,
    pub file_number: usize,
    /// Whether `--file-number` was given on the command line (as opposed to its
    /// default), so the caller can reject it where it does not apply (7z).
    pub file_number_explicit: bool,
    pub password_dictionary: Option<String>,
    pub starting_password: Option<String>,
    pub mask: Option<String>,
    pub custom_charsets: CustomCharsets,
    pub quiet: bool,
    pub json: bool,
    pub use_gpu: bool,
    pub gpu_smoke_test: bool,
    pub gpu_batch_size: Option<u32>,
}

pub fn get_args() -> Result<Arguments, FinderError> {
    let command = command();
    let matches = command.get_matches();

    let input_file: Option<&String> = matches.try_get_one("inputFile")?;
    if let Some(path) = input_file
        && !Path::new(path).is_file()
    {
        return Err(CliArgumentError {
            message: format!("input file '{path}' does not exist"),
        });
    }

    let password_dictionary: Option<&String> = matches.try_get_one("passwordDictionary")?;
    if let Some(dict_path) = password_dictionary
        && !Path::new(&dict_path).is_file()
    {
        return Err(CliArgumentError {
            message: "'--password-dictionary' does not exist".to_string(),
        });
    }

    let charset_choice: &String = matches.get_one("charset").expect("impossible");

    let charset_file: Option<&String> = matches.try_get_one("charsetFile")?;
    if let Some(charset_file_path) = charset_file
        && !Path::new(&charset_file_path).is_file()
    {
        return Err(CliArgumentError {
            message: "'--charset-file' does not exist".to_string(),
        });
    }

    let workers: Option<&usize> = matches.try_get_one("workers")?;
    if workers == Some(&0) {
        return Err(CliArgumentError {
            message: "'--workers' must be positive".to_string(),
        });
    }

    let min_password_len: &usize = matches.get_one("minPasswordLen").expect("impossible");
    if *min_password_len == 0 {
        return Err(CliArgumentError {
            message: "'--min-password-len' must be positive".to_string(),
        });
    }

    let max_password_len: &usize = matches.get_one("maxPasswordLen").expect("impossible");
    if *max_password_len == 0 {
        return Err(CliArgumentError {
            message: "'--max-password-len' must be positive".to_string(),
        });
    }

    if min_password_len > max_password_len {
        return Err(CliArgumentError {
            message: "'--max-password-len' must be equal or greater than '--min-password-len'"
                .to_string(),
        });
    }

    let file_number: &usize = matches.get_one("fileNumber").expect("impossible");
    let file_number_explicit =
        matches.value_source("fileNumber") == Some(clap::parser::ValueSource::CommandLine);

    let charset_choice = if let Some(charset_file_path) = charset_file {
        // priority to charset file
        CharsetChoice::File(charset_file_path.clone())
    } else {
        CharsetChoice::Preset(charset_choice.clone())
    };

    let mask: Option<&String> = matches.try_get_one("mask")?;

    // parse custom charsets (clap already guarantees these require --mask)
    let custom_charset_names = [
        "customCharset1",
        "customCharset2",
        "customCharset3",
        "customCharset4",
    ];
    let mut custom_charsets: CustomCharsets = [None, None, None, None];
    for (i, arg_id) in custom_charset_names.iter().enumerate() {
        let value: Option<&String> = matches.try_get_one(arg_id)?;
        if let Some(definition) = value {
            custom_charsets[i] = Some(parse_custom_charset(definition)?);
        }
    }

    // Mutual exclusivity between the attack modes (mask / dictionary /
    // starting-password) is enforced by clap; only the value-level checks that
    // clap cannot express remain here.
    let starting_password: Option<&String> = matches.try_get_one("startingPassword")?;
    if let Some(starting_password) = starting_password {
        // validate startingPassword regarding charset
        let charset = charset_from_choice(&charset_choice)?;
        let out_of_charset = starting_password.chars().any(|c| !charset.contains(&c));
        if out_of_charset {
            return Err(CliArgumentError {
                message: "'--starting-password' uses characters out of the generation charset"
                    .to_string(),
            });
        }

        // validate startingPassword regarding len
        let starting_password_len = starting_password.chars().count();
        if starting_password_len > *max_password_len || starting_password_len < *min_password_len {
            return Err(CliArgumentError {
                message: "'--starting-password' does not respect '--max-password-len' or '--min-password-len' configuration".to_string(),
            });
        }
    }

    let use_gpu = matches.get_flag("gpu");
    let gpu_smoke_test = matches.get_flag("gpuSmokeTest");

    let gpu_batch_size: Option<&u32> = matches.try_get_one("gpuBatchSize")?;
    if let Some(&v) = gpu_batch_size
        && v == 0
    {
        return Err(CliArgumentError {
            message: "'--gpu-batch-size' must be positive".to_string(),
        });
    }

    Ok(Arguments {
        input_file: input_file.cloned(),
        workers: workers.copied(),
        charset_choice,
        min_password_len: *min_password_len,
        max_password_len: *max_password_len,
        file_number: *file_number,
        file_number_explicit,
        password_dictionary: password_dictionary.cloned(),
        starting_password: starting_password.cloned(),
        mask: mask.cloned(),
        custom_charsets,
        quiet: matches.get_flag("quiet"),
        json: matches.get_flag("json"),
        use_gpu,
        gpu_smoke_test,
        gpu_batch_size: gpu_batch_size.copied(),
    })
}

#[cfg(test)]
mod args_tests {
    use crate::args::command;

    #[test]
    fn verify_command() {
        command().debug_assert();
    }
}
