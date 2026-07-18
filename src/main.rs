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

// `--file-number` selects an entry inside a multi-file ZIP; it is meaningless
// for 7z, where every encrypted entry shares the password and verification runs
// against whichever entry is cheapest. Reject it explicitly instead of silently
// ignoring what the user asked for.
fn reject_inapplicable_options(
    is_sevenz: bool,
    file_number_explicit: bool,
) -> Result<(), FinderError> {
    if is_sevenz && file_number_explicit {
        return Err(FinderError::CliArgumentError {
            message:
                "'--file-number' does not apply to 7z archives (every entry shares the password)"
                    .to_string(),
        });
    }
    Ok(())
}

fn main() {
    // Exit codes follow the grep convention: 0 = password found, 1 = not found,
    // 2 = error. This lets scripts branch on the outcome without parsing output.
    std::process::exit(match main_result() {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(err) => {
            eprintln!("{err}");
            2
        }
    });
}

/// Runs the search and reports the outcome. Returns `Ok(true)` when a password
/// was found, `Ok(false)` when the search completed without one.
fn main_result() -> Result<bool, FinderError> {
    // CLI args
    let Arguments {
        input_file,
        workers,
        charset_choice,
        min_password_len,
        max_password_len,
        file_number,
        file_number_explicit,
        password_dictionary,
        starting_password,
        mask,
        custom_charsets,
        quiet,
        json,
    } = get_args()?;

    // Reject options that do not apply to the detected archive type before doing
    // any work, rather than silently ignoring them.
    let is_sevenz = is_sevenz_archive(&input_file);
    reject_inapplicable_options(is_sevenz, file_number_explicit)?;

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

    let password = if is_sevenz {
        sevenz_password_finder(&input_file, workers, &strategy, quiet, stop_signal)?
    } else {
        password_finder(
            &input_file,
            workers,
            file_number,
            &strategy,
            quiet,
            stop_signal,
        )?
    };
    let elapsed = start_time.elapsed();

    // stdout carries only the result; progress and status went to stderr. The
    // three modes: --json (structured), --quiet (bare password), default (human).
    if json {
        let file = json_escape(&input_file);
        let elapsed_ms = elapsed.as_millis();
        match &password {
            Some(pw) => println!(
                "{{\"found\":true,\"password\":\"{}\",\"file\":\"{}\",\"elapsed_ms\":{}}}",
                json_escape(pw),
                file,
                elapsed_ms
            ),
            None => println!(
                "{{\"found\":false,\"password\":null,\"file\":\"{}\",\"elapsed_ms\":{}}}",
                file, elapsed_ms
            ),
        }
    } else if quiet {
        if let Some(pw) = &password {
            println!("{pw}");
        }
    } else {
        eprintln!("Time elapsed: {}", humantime::format_duration(elapsed));
        match &password {
            Some(pw) => println!("Password found: {pw}"),
            None => println!("Password not found"),
        }
    }

    Ok(password.is_some())
}

/// Minimal JSON string escaping for the `--json` output, avoiding a dependency.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_number_rejected_only_for_sevenz_when_explicit() {
        // 7z + explicit --file-number -> rejected
        assert!(reject_inapplicable_options(true, true).is_err());
        // 7z without an explicit --file-number (default) -> accepted
        assert!(reject_inapplicable_options(true, false).is_ok());
        // zip always accepts --file-number
        assert!(reject_inapplicable_options(false, true).is_ok());
        assert!(reject_inapplicable_options(false, false).is_ok());
    }

    #[test]
    fn sevenz_signature_detection() {
        assert!(is_sevenz_archive("test-files/3.test.txt.7z"));
        assert!(!is_sevenz_archive("test-files/3.test.txt.zip"));
    }

    #[test]
    fn json_escape_handles_special_characters() {
        assert_eq!(json_escape("abc"), "abc");
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("line\nbreak\ttab"), "line\\nbreak\\ttab");
        assert_eq!(json_escape("\u{0001}"), "\\u0001");
        // non-ASCII stays as-is (valid UTF-8 in JSON)
        assert_eq!(json_escape("pässwörd"), "pässwörd");
    }
}
