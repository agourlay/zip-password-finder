mod args;
mod finder_errors;
mod password_finder;
mod password_gen;
mod password_reader;
mod password_worker;

use crate::args::{get_args, Arguments};
use crate::finder_errors::FinderError;
use crate::password_finder::password_finder;
use crate::password_finder::Strategy::{GenPasswords, PasswordFile};

use std::cmp::max;
use std::path::Path;

fn main() {
    let result = main_result();
    std::process::exit(match result {
        Ok(_) => 0,
        Err(err) => {
            eprintln!("{}", err);
            1
        }
    });
}

fn main_result() -> Result<(), FinderError> {
    // CLI args
    let Arguments {
        input_file,
        workers,
        charset,
        min_password_len,
        max_password_len,
        password_dictionary,
    } = get_args()?;

    let strategy = match password_dictionary {
        Some(dict_path) => {
            let path = Path::new(&dict_path);
            PasswordFile(path.to_path_buf())
        }
        None => GenPasswords {
            charset_choice: charset,
            min_password_len,
            max_password_len,
        },
    };

    // keep a thread for the password generator
    let workers = workers.unwrap_or_else(|| max(1, num_cpus::get() - 1));

    password_finder(&input_file, workers, strategy)?;
    Ok(())
}
