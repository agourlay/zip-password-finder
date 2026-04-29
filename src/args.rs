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
        .arg(
            Arg::new("inputFile")
                .help("path to zip input file")
                .long("inputFile")
                .short('i')
                .num_args(1)
                .required_unless_present("gpuSmokeTest"),
        )
        .arg(
            Arg::new("workers")
                .value_parser(value_parser!(usize))
                .help("number of workers")
                .long("workers")
                .short('w')
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("passwordDictionary")
                .help("path to a password dictionary file")
                .long("passwordDictionary")
                .short('p')
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("charset")
                .help("charset to use to generate password")
                .long("charset")
                .short('c')
                .default_value("lud")
                .required(false),
        )
        .arg(
            Arg::new("charsetFile")
                .help("path to a charset file")
                .long("charsetFile")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("minPasswordLen")
                .value_parser(value_parser!(usize))
                .help("minimum password length")
                .long("minPasswordLen")
                .num_args(1)
                .default_value("1")
                .required(false),
        )
        .arg(
            Arg::new("maxPasswordLen")
                .value_parser(value_parser!(usize))
                .help("maximum password length")
                .long("maxPasswordLen")
                .num_args(1)
                .default_value("10")
                .required(false),
        )
        .arg(
            Arg::new("fileNumber")
                .value_parser(value_parser!(usize))
                .help("file number in the zip archive")
                .long("fileNumber")
                .num_args(1)
                .default_value("0")
                .required(false),
        )
        .arg(
            Arg::new("startingPassword")
                .help("password to start from")
                .long("startingPassword")
                .short('s')
                .required(false),
        )
        .arg(
            Arg::new("mask")
                .help("mask pattern for mask attack (e.g. '?l?l?l?d?d')")
                .long_help("mask pattern for mask attack (e.g. '?l?l?l?d?d' for 3 lowercase + 2 digits).\n\nAvailable tokens:\n  ?l  lowercase letters [a-z]\n  ?u  uppercase letters [A-Z]\n  ?d  digits [0-9]\n  ?s  symbols\n  ?a  all printable (?l?u?d?s)\n  ?h  lowercase hex [0-9a-f]\n  ?H  uppercase hex [0-9A-F]\n  ?1  custom charset 1 (--customCharset1)\n  ?2  custom charset 2 (--customCharset2)\n  ?3  custom charset 3 (--customCharset3)\n  ?4  custom charset 4 (--customCharset4)\n  ??  literal '?'\n\nAny other character is treated as a literal.")
                .long("mask")
                .short('m')
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("customCharset1")
                .help("custom charset 1 for mask attack, referenced as ?1 (e.g. 'aeiou' or '?l?d')")
                .long("customCharset1")
                .short('1')
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("customCharset2")
                .help("custom charset 2 for mask attack, referenced as ?2")
                .long("customCharset2")
                .short('2')
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("customCharset3")
                .help("custom charset 3 for mask attack, referenced as ?3")
                .long("customCharset3")
                .short('3')
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("customCharset4")
                .help("custom charset 4 for mask attack, referenced as ?4")
                .long("customCharset4")
                .short('4')
                .num_args(1)
                .required(false),
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
                .help("list GPU adapters and run a trivial compute kernel, then exit (does not require --inputFile)")
                .long("gpu-smoke-test")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("gpuBatchSize")
                .value_parser(value_parser!(u32))
                .help("GPU batch size, passwords per dispatch (only used with --gpu). Larger values can lift throughput on discrete GPUs (try 65536 or 262144); the 16384 default is tuned for integrated GPUs.")
                .long("gpuBatchSize")
                .num_args(1)
                .default_value("16384")
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
    pub password_dictionary: Option<String>,
    pub starting_password: Option<String>,
    pub mask: Option<String>,
    pub custom_charsets: CustomCharsets,
    pub use_gpu: bool,
    pub gpu_smoke_test: bool,
    pub gpu_batch_size: u32,
}

pub fn get_args() -> Result<Arguments, FinderError> {
    let command = command();
    let matches = command.get_matches();

    let input_file: Option<&String> = matches.try_get_one("inputFile")?;
    if let Some(path) = input_file
        && !Path::new(path).is_file()
    {
        return Err(CliArgumentError {
            message: "'inputFile' does not exist".to_string(),
        });
    }

    let password_dictionary: Option<&String> = matches.try_get_one("passwordDictionary")?;
    if let Some(dict_path) = password_dictionary
        && !Path::new(&dict_path).is_file()
    {
        return Err(CliArgumentError {
            message: "'passwordDictionary' does not exist".to_string(),
        });
    }

    let charset_choice: &String = matches.get_one("charset").expect("impossible");

    let charset_file: Option<&String> = matches.try_get_one("charsetFile")?;
    if let Some(charset_file_path) = charset_file
        && !Path::new(&charset_file_path).is_file()
    {
        return Err(CliArgumentError {
            message: "'charsetFile' does not exist".to_string(),
        });
    }

    let workers: Option<&usize> = matches.try_get_one("workers")?;
    if workers == Some(&0) {
        return Err(CliArgumentError {
            message: "'workers' must be positive".to_string(),
        });
    }

    let min_password_len: &usize = matches.get_one("minPasswordLen").expect("impossible");
    if *min_password_len == 0 {
        return Err(CliArgumentError {
            message: "'minPasswordLen' must be positive".to_string(),
        });
    }

    let max_password_len: &usize = matches.get_one("maxPasswordLen").expect("impossible");
    if *max_password_len == 0 {
        return Err(CliArgumentError {
            message: "'maxPasswordLen' must be positive".to_string(),
        });
    }

    if min_password_len > max_password_len {
        return Err(CliArgumentError {
            message: "'maxPasswordLen' must be equal or greater than 'minPasswordLen'".to_string(),
        });
    }

    let file_number: &usize = matches.get_one("fileNumber").expect("impossible");

    let charset_choice = if let Some(charset_file_path) = charset_file {
        // priority to charset file
        CharsetChoice::File(charset_file_path.clone())
    } else {
        CharsetChoice::Preset(charset_choice.clone())
    };

    let mask: Option<&String> = matches.try_get_one("mask")?;

    // parse custom charsets
    let custom_charset_names = [
        "customCharset1",
        "customCharset2",
        "customCharset3",
        "customCharset4",
    ];
    let mut custom_charsets: CustomCharsets = [None, None, None, None];
    for (i, name) in custom_charset_names.iter().enumerate() {
        let value: Option<&String> = matches.try_get_one(name)?;
        if let Some(definition) = value {
            if mask.is_none() {
                return Err(CliArgumentError {
                    message: format!("'--{name}' can only be used with --mask"),
                });
            }
            custom_charsets[i] = Some(parse_custom_charset(definition)?);
        }
    }

    // validate that mask, dictionary, and starting_password are not used together
    if mask.is_some() && password_dictionary.is_some() {
        return Err(CliArgumentError {
            message: "'mask' cannot be used with a dictionary file".to_string(),
        });
    }

    let starting_password: Option<&String> = matches.try_get_one("startingPassword")?;
    if let Some(starting_password) = starting_password {
        // can't use with dictionary for now (a bit annoying to lookup in dictionary to start from a given word)
        if password_dictionary.is_some() {
            return Err(CliArgumentError {
                message: "'startingPassword' cannot be used with a dictionary file".to_string(),
            });
        }

        if mask.is_some() {
            return Err(CliArgumentError {
                message: "'startingPassword' cannot be used with mask attack".to_string(),
            });
        }

        // validate startingPassword regarding charset
        let charset = charset_from_choice(&charset_choice)?;
        let out_of_charset = starting_password.chars().any(|c| !charset.contains(&c));
        if out_of_charset {
            return Err(CliArgumentError {
                message: "'startingPassword' uses characters out of the generation charset"
                    .to_string(),
            });
        }

        // validate startingPassword regarding len
        let starting_password_len = starting_password.chars().count();
        if starting_password_len > *max_password_len || starting_password_len < *min_password_len {
            return Err(CliArgumentError {
                message: "'startingPassword' does not respect 'max_password_len' or 'min_password_len' configuration".to_string(),
            });
        }
    }

    let use_gpu = matches.get_flag("gpu");
    let gpu_smoke_test = matches.get_flag("gpuSmokeTest");

    let gpu_batch_size: &u32 = matches.get_one("gpuBatchSize").expect("impossible");
    if *gpu_batch_size == 0 {
        return Err(CliArgumentError {
            message: "'gpuBatchSize' must be positive".to_string(),
        });
    }

    Ok(Arguments {
        input_file: input_file.cloned(),
        workers: workers.copied(),
        charset_choice,
        min_password_len: *min_password_len,
        max_password_len: *max_password_len,
        file_number: *file_number,
        password_dictionary: password_dictionary.cloned(),
        starting_password: starting_password.cloned(),
        mask: mask.cloned(),
        custom_charsets,
        use_gpu,
        gpu_smoke_test,
        gpu_batch_size: *gpu_batch_size,
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
