use crate::charsets::{CharsetChoice, charset_from_choice};
use crate::finder_errors::FinderError;
use crate::finder_errors::FinderError::CliArgumentError;
use clap::{Arg, Command};
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
                .required(true),
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
}

pub struct Arguments {
    pub input_file: String,
    pub workers: Option<usize>,
    pub charset_choice: CharsetChoice,
    pub min_password_len: usize,
    pub max_password_len: usize,
    pub file_number: usize,
    pub password_dictionary: Option<String>,
    pub starting_password: Option<String>,
}

pub fn get_args() -> Result<Arguments, FinderError> {
    let command = command();
    let matches = command.get_matches();

    let input_file: &String = matches.get_one("inputFile").expect("impossible");
    if !Path::new(input_file).is_file() {
        return Err(CliArgumentError {
            message: "'inputFile' does not exist".to_string(),
        });
    }

    let password_dictionary: Option<&String> = matches.try_get_one("passwordDictionary")?;
    if let Some(dict_path) = password_dictionary {
        if !Path::new(&dict_path).is_file() {
            return Err(CliArgumentError {
                message: "'passwordDictionary' does not exist".to_string(),
            });
        }
    }

    let charset_choice: &String = matches.get_one("charset").expect("impossible");

    let charset_file: Option<&String> = matches.try_get_one("charsetFile")?;
    if let Some(charset_file_path) = charset_file {
        if !Path::new(&charset_file_path).is_file() {
            return Err(CliArgumentError {
                message: "'charsetFile' does not exist".to_string(),
            });
        }
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

    let starting_password: Option<&String> = matches.try_get_one("startingPassword")?;
    if let Some(starting_password) = starting_password {
        // can't use with dictionary for now (a bit annoying to lookup in dictionary to start from a given word)
        if password_dictionary.is_some() {
            return Err(CliArgumentError {
                message: "'startingPassword' cannot be used with a dictionary file".to_string(),
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

    Ok(Arguments {
        input_file: input_file.clone(),
        workers: workers.copied(),
        charset_choice,
        min_password_len: *min_password_len,
        max_password_len: *max_password_len,
        file_number: *file_number,
        password_dictionary: password_dictionary.cloned(),
        starting_password: starting_password.cloned(),
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
