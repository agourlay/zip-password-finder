mod args;
mod charsets;
mod finder_errors;
mod password_finder;
mod password_gen;
mod password_mask;
mod password_reader;
mod password_worker;
mod sevenz_finder;
mod sevenz_utils;
mod sevenz_worker;
mod zip_utils;

use crate::args::{Arguments, get_args};
use crate::finder_errors::FinderError;
use crate::password_finder::Strategy::{GenPasswords, MaskGenPasswords, PasswordFile};
use crate::password_finder::password_finder;
use crate::sevenz_finder::sevenz_password_finder;

use crate::charsets::charset_from_choice;
use crate::password_mask::parse_mask;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

// Route by content, not extension: peek at the leading bytes and treat the file
// as 7z only if it carries the 7z signature. Anything else falls through to the
// existing zip path.
fn is_sevenz_archive(path: &str) -> bool {
    let mut buf = [0u8; 6];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .map(|()| sevenz_utils::has_sevenz_signature(&buf))
        .unwrap_or(false)
}

fn main() {
    let result = main_result();
    std::process::exit(match result {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{err}");
            1
        }
    });
}

fn main_result() -> Result<(), FinderError> {
    // CLI args
    let Arguments {
        input_file,
        workers,
        charset_choice,
        min_password_len,
        max_password_len,
        file_number,
        password_dictionary,
        starting_password,
        mask,
        custom_charsets,
    } = get_args()?;

    let strategy = if let Some(dict_path) = password_dictionary {
        let path = Path::new(&dict_path);
        PasswordFile(path.to_path_buf())
    } else if let Some(mask_pattern) = mask {
        let mask = parse_mask(&mask_pattern, &custom_charsets)?;
        MaskGenPasswords { mask }
    } else {
        let charset = charset_from_choice(&charset_choice)?;
        GenPasswords {
            charset,
            min_password_len,
            max_password_len,
            starting_password,
        }
    };

    // use physical cores by default to avoid issues with hyper-threading
    let workers = workers.unwrap_or_else(num_cpus::get_physical);
    let start_time = std::time::Instant::now();

    // stop signals to shut down threads
    let stop_signal = Arc::new(AtomicBool::new(false));

    // Intercept Ctrl-C signal to stop workers manually
    let stop_signal_interrupt = stop_signal.clone();
    ctrlc::set_handler(move || stop_signal_interrupt.store(true, Ordering::Relaxed))
        .expect("Error setting Ctrl-C handler");

    let password = if is_sevenz_archive(&input_file) {
        sevenz_password_finder(&input_file, workers, &strategy, stop_signal)?
    } else {
        password_finder(&input_file, workers, file_number, &strategy, stop_signal)?
    };
    let elapsed = start_time.elapsed();
    // display pretty time
    let elapsed = humantime::format_duration(elapsed);
    println!("Time elapsed: {elapsed}");
    match password {
        Some(password) => println!("Password found:{password}"),
        None => println!("Password not found"),
    }
    Ok(())
}
