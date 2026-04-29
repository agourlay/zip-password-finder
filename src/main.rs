mod args;
mod charsets;
mod finder_errors;
mod gpu;
mod gpu_worker;
mod password_finder;
mod password_gen;
mod password_mask;
mod password_reader;
mod password_worker;
mod zip_utils;

use crate::args::{Arguments, get_args};
use crate::finder_errors::FinderError;
use crate::password_finder::Strategy::{GenPasswords, MaskGenPasswords, PasswordFile};
use crate::password_finder::password_finder;

use crate::charsets::charset_from_choice;
use crate::password_mask::parse_mask;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
        use_gpu,
        gpu_smoke_test,
        gpu_batch_size,
    } = get_args()?;

    // --gpu-smoke-test exits before any of the search-related logic.
    if gpu_smoke_test {
        std::process::exit(gpu::run_smoke_test_cli());
    }

    let input_file = input_file.expect("clap requires --inputFile when --gpu-smoke-test is absent");

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

    let password = password_finder(
        &input_file,
        workers,
        file_number,
        &strategy,
        use_gpu,
        gpu_batch_size,
        stop_signal,
    )?;
    // Round to milliseconds — humantime would otherwise drag along ns precision
    // ("3s 445ms 537us 500ns") which adds noise without information.
    let elapsed = Duration::from_millis(start_time.elapsed().as_millis() as u64);
    let elapsed = humantime::format_duration(elapsed);
    println!("Time elapsed: {elapsed}");
    match password {
        Some(password) => println!("Password found:{password}"),
        None => println!("Password not found"),
    }
    Ok(())
}
