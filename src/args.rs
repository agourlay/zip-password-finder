use crate::finder_errors::FinderError;
use crate::finder_errors::FinderError::CliArgumentError;
use clap::{crate_authors, crate_description, crate_name, crate_version, value_parser};
use clap::{Arg, Command};
use std::path::Path;

fn command() -> clap::Command<'static> {
    Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .arg(
            Arg::new("inputFile")
                .help("path to zip input file")
                .long("inputFile")
                .short('i')
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("workers")
                .value_parser(value_parser!(usize))
                .help("number of workers")
                .long("workers")
                .short('w')
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::new("passwordDictionary")
                .help("path to a password dictionary file")
                .long("passwordDictionary")
                .short('p')
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::new("charset")
                .help("charset to use to generate password")
                .long("charset")
                .short('c')
                .takes_value(true)
                .possible_values(["easy", "medium", "hard"]) // TODO this could be derived
                .default_value("medium")
                .required(false),
        )
        .arg(
            Arg::new("minPasswordLen")
                .value_parser(value_parser!(usize))
                .help("minimum password length")
                .long("minPasswordLen")
                .takes_value(true)
                .default_value("1")
                .required(false),
        )
        .arg(
            Arg::new("maxPasswordLen")
                .value_parser(value_parser!(usize))
                .help("maximum password length")
                .long("maxPasswordLen")
                .takes_value(true)
                .default_value("10")
                .required(false),
        )
}

pub struct Arguments {
    pub input_file: String,
    pub workers: Option<usize>,
    pub charset: String,
    pub min_password_len: usize,
    pub max_password_len: usize,
    pub password_dictionary: Option<String>,
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
                message: "'password_dictionary' does not exist".to_string(),
            });
        }
    }

    let charset: &String = matches.get_one("charset").expect("impossible");

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
            message: "'maxPasswordLen' must be greater than 'minPasswordLen'".to_string(),
        });
    }

    Ok(Arguments {
        input_file: input_file.clone(),
        workers: workers.cloned(),
        charset: charset.clone(),
        min_password_len: *min_password_len,
        max_password_len: *max_password_len,
        password_dictionary: password_dictionary.cloned(),
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
